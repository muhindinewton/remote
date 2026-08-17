//! Raw pixel buffers to encoder input — `docs/ARCHITECTURE.md` §3.5.
//!
//! Capture hands us BGRA8; encoders want NV12 or I420. The conversion is the first stage of the
//! pipeline and the first place picture quality can be thrown away.
//!
//! **Two decisions here are about text, not video.**
//!
//! 1. **Full range, not limited range.** Studio swing maps black to 16 and white to 235, which
//!    crushes exactly the pure black and pure white that dominate a desktop. Mis-signalled range is
//!    also the single most common cause of "the remote screen looks washed out".
//!
//! 2. **Box-filtered chroma, not nearest-neighbour.** 4:2:0 halves colour resolution in both
//!    dimensions. Naive downsampling picks one pixel of each 2×2 block and discards three, which
//!    makes thin coloured text — red error messages, syntax highlighting, links — fringe and smear.
//!    Averaging the block first costs a handful of adds per output sample and visibly helps.
//!    [`ChromaFilter`] makes the choice explicit, and a test measures the difference rather than
//!    asserting it.
//!
//! The RGB→YCbCr matrix is linear in gamma-encoded R'G'B', so averaging the block in RGB and then
//! converting is arithmetically identical to converting four pixels and averaging their chroma —
//! at a quarter of the multiplies.

use rda_capture::PixelFormat;

/// Colour matrix. BT.709 is what every HD encoder and decoder assumes by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorMatrix {
    /// ITU-R BT.709. The default, and correct for anything at 720p or above.
    #[default]
    Bt709,
    /// ITU-R BT.601. Only for interoperating with something that insists on it.
    Bt601,
}

/// Whether luma spans 0–255 or the studio 16–235 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorRange {
    /// 0–255. The default: desktop content is full of pure black and pure white.
    #[default]
    Full,
    /// 16–235 luma, 16–240 chroma. Required by some hardware decoders.
    Limited,
}

/// How the 2×2 chroma block is reduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChromaFilter {
    /// Average the block. Costs three extra adds per sample and materially improves coloured text.
    #[default]
    Box,
    /// Take the top-left pixel. Faster, and visibly worse on text — kept so the difference can be
    /// measured rather than argued about.
    Nearest,
}

/// Conversion settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConvertConfig {
    /// Colour matrix.
    pub matrix: ColorMatrix,
    /// Luma range.
    pub range: ColorRange,
    /// Chroma downsampling filter.
    pub chroma: ChromaFilter,
}

/// Why a conversion failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConvertError {
    /// Source dimensions were zero or absurd.
    #[error("invalid dimensions {width}x{height}")]
    BadDimensions {
        /// Width supplied.
        width: u32,
        /// Height supplied.
        height: u32,
    },
    /// The source buffer was smaller than its declared geometry requires.
    #[error("source buffer is {got} bytes, need at least {need}")]
    SourceTooSmall {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        got: usize,
    },
    /// Stride was below one row of pixels.
    #[error("stride {stride} is smaller than one row of {width} pixels")]
    BadStride {
        /// Declared stride.
        stride: usize,
        /// Declared width.
        width: u32,
    },
    /// The source pixel format is not one we convert from.
    #[error("unsupported source format {0:?}")]
    UnsupportedFormat(PixelFormat),
}

/// The planar output layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanarFormat {
    /// Y plane followed by interleaved CbCr at half resolution. What hardware encoders want.
    Nv12,
    /// Y, then Cb, then Cr, each chroma plane at half resolution.
    I420,
}

impl PlanarFormat {
    /// Total buffer size for the given dimensions.
    ///
    /// Identical for both formats — only the chroma arrangement differs.
    #[must_use]
    pub fn buffer_size(self, width: u32, height: u32) -> usize {
        let luma = width as usize * height as usize;
        let chroma_w = width.div_ceil(2) as usize;
        let chroma_h = height.div_ceil(2) as usize;
        luma + chroma_w * chroma_h * 2
    }
}

/// A converted frame in planar form, ready for the encoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanarFrame {
    /// Packed plane data.
    pub data: Vec<u8>,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Layout.
    pub format: PlanarFormat,
    /// Bytes per row of the luma plane. Equals `width` here — no padding is added.
    pub luma_stride: usize,
    /// Bytes per row of the chroma plane(s).
    pub chroma_stride: usize,
    /// Colour settings, which must be signalled to the encoder and carried in the bitstream.
    pub config: ConvertConfig,
}

impl PlanarFrame {
    /// The luma plane.
    #[must_use]
    pub fn luma(&self) -> &[u8] {
        &self.data[..self.width as usize * self.height as usize]
    }

    /// The chroma region: interleaved CbCr for NV12, Cb followed by Cr for I420.
    #[must_use]
    pub fn chroma(&self) -> &[u8] {
        &self.data[self.width as usize * self.height as usize..]
    }
}

// ---------------------------------------------------------------------------------------------
// Fixed-point coefficients
// ---------------------------------------------------------------------------------------------

/// Q16 fixed point. Integer arithmetic keeps the conversion deterministic across platforms —
/// a float path would let two machines produce different bitstreams from the same frame.
const SHIFT: u32 = 16;
const ROUND: i32 = 1 << (SHIFT - 1);

struct Coefficients {
    yr: i32,
    yg: i32,
    yb: i32,
    /// 1 / (2 * (1 - kb)), scaled.
    cb: i32,
    /// 1 / (2 * (1 - kr)), scaled.
    cr: i32,
}

/// BT.709: kr = 0.2126, kg = 0.7152, kb = 0.0722.
const BT709: Coefficients = Coefficients {
    yr: 13933,
    yg: 46871,
    yb: 4732,
    cb: 35318,
    cr: 41615,
};

/// BT.601: kr = 0.299, kg = 0.587, kb = 0.114.
/// Cb divisor 1.772, Cr divisor 1.402.
const BT601: Coefficients = Coefficients {
    yr: 19595,
    yg: 38470,
    yb: 7471,
    cb: 36985,
    cr: 46743,
};

fn coefficients(matrix: ColorMatrix) -> &'static Coefficients {
    match matrix {
        ColorMatrix::Bt709 => &BT709,
        ColorMatrix::Bt601 => &BT601,
    }
}

/// Converts one RGB triple to luma, in the requested range.
#[inline]
fn luma(c: &Coefficients, range: ColorRange, r: i32, g: i32, b: i32) -> u8 {
    let y = (c.yr * r + c.yg * g + c.yb * b + ROUND) >> SHIFT;
    match range {
        ColorRange::Full => y.clamp(0, 255) as u8,
        // Studio swing: 219 code values starting at 16.
        ColorRange::Limited => (16 + (y * 219 + 127) / 255).clamp(16, 235) as u8,
    }
}

/// Converts one RGB triple to a chroma pair, in the requested range.
#[inline]
fn chroma(c: &Coefficients, range: ColorRange, r: i32, g: i32, b: i32) -> (u8, u8) {
    let y = (c.yr * r + c.yg * g + c.yb * b + ROUND) >> SHIFT;
    let cb = ((c.cb * (b - y) + ROUND) >> SHIFT) + 128;
    let cr = ((c.cr * (r - y) + ROUND) >> SHIFT) + 128;
    match range {
        ColorRange::Full => (cb.clamp(0, 255) as u8, cr.clamp(0, 255) as u8),
        ColorRange::Limited => (
            (128 + ((cb - 128) * 224 + 127) / 255).clamp(16, 240) as u8,
            (128 + ((cr - 128) * 224 + 127) / 255).clamp(16, 240) as u8,
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------------------------

/// Converts a BGRA8 buffer to a planar format.
///
/// `stride` is the source's bytes per row, which is frequently larger than `width * 4` because
/// capture APIs align rows. Ignoring it produces a sheared image — a classic and immediately
/// visible bug.
pub fn bgra_to_planar(
    src: &[u8],
    width: u32,
    height: u32,
    stride: usize,
    format: PlanarFormat,
    config: ConvertConfig,
) -> Result<PlanarFrame, ConvertError> {
    validate(src, width, height, stride)?;

    let c = coefficients(config.matrix);
    let w = width as usize;
    let h = height as usize;
    let chroma_w = width.div_ceil(2) as usize;
    let chroma_h = height.div_ceil(2) as usize;

    let mut data = vec![0u8; format.buffer_size(width, height)];
    let (luma_plane, chroma_plane) = data.split_at_mut(w * h);

    // Luma at full resolution.
    for y in 0..h {
        let row = &src[y * stride..y * stride + w * 4];
        let out = &mut luma_plane[y * w..(y + 1) * w];
        for (x, px) in row.chunks_exact(4).enumerate() {
            // BGRA: byte order is blue, green, red, alpha.
            out[x] = luma(
                c,
                config.range,
                i32::from(px[2]),
                i32::from(px[1]),
                i32::from(px[0]),
            );
        }
    }

    // Chroma at half resolution.
    for cy in 0..chroma_h {
        for cx in 0..chroma_w {
            let (r, g, b) = match config.chroma {
                ChromaFilter::Nearest => sample_pixel(src, stride, cx * 2, cy * 2),
                ChromaFilter::Box => average_block(src, stride, w, h, cx * 2, cy * 2),
            };
            let (cb, cr) = chroma(c, config.range, r, g, b);

            match format {
                PlanarFormat::Nv12 => {
                    let i = (cy * chroma_w + cx) * 2;
                    chroma_plane[i] = cb;
                    chroma_plane[i + 1] = cr;
                }
                PlanarFormat::I420 => {
                    let plane = chroma_w * chroma_h;
                    chroma_plane[cy * chroma_w + cx] = cb;
                    chroma_plane[plane + cy * chroma_w + cx] = cr;
                }
            }
        }
    }

    Ok(PlanarFrame {
        data,
        width,
        height,
        format,
        luma_stride: w,
        chroma_stride: match format {
            PlanarFormat::Nv12 => chroma_w * 2,
            PlanarFormat::I420 => chroma_w,
        },
        config,
    })
}

fn validate(src: &[u8], width: u32, height: u32, stride: usize) -> Result<(), ConvertError> {
    if width == 0 || height == 0 || width > 16384 || height > 16384 {
        return Err(ConvertError::BadDimensions { width, height });
    }
    let min_stride = width as usize * 4;
    if stride < min_stride {
        return Err(ConvertError::BadStride { stride, width });
    }
    // The last row needs `width * 4` bytes, not a full stride — a tightly allocated buffer may
    // legitimately stop there, and rejecting it would refuse valid input.
    let need = stride * (height as usize - 1) + min_stride;
    if src.len() < need {
        return Err(ConvertError::SourceTooSmall {
            need,
            got: src.len(),
        });
    }
    Ok(())
}

#[inline]
fn sample_pixel(src: &[u8], stride: usize, x: usize, y: usize) -> (i32, i32, i32) {
    let i = y * stride + x * 4;
    (
        i32::from(src[i + 2]),
        i32::from(src[i + 1]),
        i32::from(src[i]),
    )
}

/// Averages the 2×2 block, clamping at the right and bottom edges for odd dimensions.
#[inline]
fn average_block(
    src: &[u8],
    stride: usize,
    width: usize,
    height: usize,
    x: usize,
    y: usize,
) -> (i32, i32, i32) {
    let x1 = (x + 1).min(width - 1);
    let y1 = (y + 1).min(height - 1);
    let mut r = 0;
    let mut g = 0;
    let mut b = 0;
    for &(px, py) in &[(x, y), (x1, y), (x, y1), (x1, y1)] {
        let i = py * stride + px * 4;
        b += i32::from(src[i]);
        g += i32::from(src[i + 1]);
        r += i32::from(src[i + 2]);
    }
    ((r + 2) / 4, (g + 2) / 4, (b + 2) / 4)
}

/// Converts a captured frame's surface.
///
/// Fails for surfaces that are not CPU-visible: a GPU handle must take the zero-copy path to the
/// encoder rather than being read back and converted here, which would spend the several
/// milliseconds per frame that `Surface` exists to avoid.
pub fn convert_surface(
    surface: &rda_capture::Surface,
    width: u32,
    height: u32,
    format: PlanarFormat,
    config: ConvertConfig,
) -> Result<PlanarFrame, ConvertError> {
    match surface {
        rda_capture::Surface::Cpu {
            data,
            stride,
            format: src_format,
        } => match src_format {
            PixelFormat::Bgra8 => bgra_to_planar(data, width, height, *stride, format, config),
            other => Err(ConvertError::UnsupportedFormat(*other)),
        },
        #[cfg(target_os = "macos")]
        rda_capture::Surface::IoSurface { .. } => {
            Err(ConvertError::UnsupportedFormat(PixelFormat::Nv12))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a solid-colour BGRA buffer.
    fn solid(width: u32, height: u32, r: u8, g: u8, b: u8) -> Vec<u8> {
        let mut v = Vec::with_capacity((width * height * 4) as usize);
        for _ in 0..width * height {
            v.extend_from_slice(&[b, g, r, 255]);
        }
        v
    }

    fn convert(src: &[u8], w: u32, h: u32, config: ConvertConfig) -> PlanarFrame {
        bgra_to_planar(src, w, h, w as usize * 4, PlanarFormat::Nv12, config).unwrap()
    }

    // --- correctness against the standard ---------------------------------------------------

    #[test]
    fn primaries_match_bt709_full_range() {
        // These are the published BT.709 full-range values. A drift here means every colour on
        // screen is subtly wrong in a way no one will be able to describe.
        let cases = [
            //  r    g    b      Y    Cb   Cr
            ((255, 255, 255), (255, 128, 128)), // white
            ((0, 0, 0), (0, 128, 128)),         // black
            ((255, 0, 0), (54, 99, 255)),       // red
            ((0, 255, 0), (182, 30, 12)),       // green
            ((0, 0, 255), (18, 255, 116)),      // blue
        ];
        for ((r, g, b), (ey, ecb, ecr)) in cases {
            let f = convert(&solid(2, 2, r, g, b), 2, 2, ConvertConfig::default());
            let (y, cb, cr) = (f.luma()[0], f.chroma()[0], f.chroma()[1]);
            assert!(y.abs_diff(ey) <= 1, "rgb({r},{g},{b}) Y={y}, expected {ey}");
            assert!(
                cb.abs_diff(ecb) <= 1,
                "rgb({r},{g},{b}) Cb={cb}, expected {ecb}"
            );
            assert!(
                cr.abs_diff(ecr) <= 1,
                "rgb({r},{g},{b}) Cr={cr}, expected {ecr}"
            );
        }
    }

    #[test]
    fn full_range_preserves_pure_black_and_white() {
        // The reason full range is the default: desktop UI is mostly these two values.
        let cfg = ConvertConfig {
            range: ColorRange::Full,
            ..Default::default()
        };
        assert_eq!(convert(&solid(2, 2, 0, 0, 0), 2, 2, cfg).luma()[0], 0);
        assert_eq!(
            convert(&solid(2, 2, 255, 255, 255), 2, 2, cfg).luma()[0],
            255
        );
    }

    #[test]
    fn limited_range_compresses_to_studio_swing() {
        let cfg = ConvertConfig {
            range: ColorRange::Limited,
            ..Default::default()
        };
        assert_eq!(convert(&solid(2, 2, 0, 0, 0), 2, 2, cfg).luma()[0], 16);
        assert_eq!(
            convert(&solid(2, 2, 255, 255, 255), 2, 2, cfg).luma()[0],
            235
        );
    }

    #[test]
    fn grey_stays_neutral() {
        // Any chroma drift on grey shows up as a colour cast across the entire desktop.
        for level in [1u8, 32, 64, 128, 192, 254] {
            let f = convert(
                &solid(2, 2, level, level, level),
                2,
                2,
                ConvertConfig::default(),
            );
            assert!(
                f.chroma()[0].abs_diff(128) <= 1,
                "grey {level} has Cb={}",
                f.chroma()[0]
            );
            assert!(
                f.chroma()[1].abs_diff(128) <= 1,
                "grey {level} has Cr={}",
                f.chroma()[1]
            );
        }
    }

    // --- the text legibility argument, measured ----------------------------------------------

    #[test]
    fn box_filtering_beats_nearest_neighbour_on_thin_coloured_detail() {
        // A one-pixel-wide vertical red line on white — the shape of antialiased text, and exactly
        // what 4:2:0 handles worst. Nearest-neighbour sampling drops whole columns; the box filter
        // retains their contribution.
        let (w, h) = (8u32, 4u32);
        let mut src = solid(w, h, 255, 255, 255);
        for y in 0..h as usize {
            for x in (1..w as usize).step_by(2) {
                let i = (y * w as usize + x) * 4;
                src[i] = 0; // B
                src[i + 1] = 0; // G
                src[i + 2] = 255; // R
            }
        }

        let boxed = convert(
            &src,
            w,
            h,
            ConvertConfig {
                chroma: ChromaFilter::Box,
                ..Default::default()
            },
        );
        let nearest = convert(
            &src,
            w,
            h,
            ConvertConfig {
                chroma: ChromaFilter::Nearest,
                ..Default::default()
            },
        );

        // Nearest samples only the even columns, which are all white, so the red vanishes from
        // chroma entirely.
        let nearest_cr: Vec<u8> = nearest
            .chroma()
            .iter()
            .skip(1)
            .step_by(2)
            .copied()
            .collect();
        assert!(
            nearest_cr.iter().all(|&v| v.abs_diff(128) <= 2),
            "nearest-neighbour should lose the red line: {nearest_cr:?}"
        );

        // The box filter keeps it: half the block is red, so Cr rises well above neutral.
        let boxed_cr: Vec<u8> = boxed.chroma().iter().skip(1).step_by(2).copied().collect();
        assert!(
            boxed_cr.iter().all(|&v| v > 140),
            "box filtering should retain the red line: {boxed_cr:?}"
        );

        // Luma is full-resolution either way, so the line survives there regardless — which is why
        // this only shows up as colour fringing rather than a missing line.
        assert!(boxed.luma().iter().any(|&v| v < 100));
    }

    // --- layout ------------------------------------------------------------------------------

    #[test]
    fn buffer_sizes_are_correct_for_both_layouts() {
        for f in [PlanarFormat::Nv12, PlanarFormat::I420] {
            assert_eq!(f.buffer_size(1920, 1080), 1920 * 1080 * 3 / 2);
            assert_eq!(f.buffer_size(2, 2), 4 + 2);
            // Odd dimensions round the chroma planes up.
            assert_eq!(f.buffer_size(3, 3), 9 + 2 * 2 * 2);
        }
    }

    #[test]
    fn nv12_interleaves_chroma_and_i420_separates_it() {
        let src = solid(4, 4, 255, 0, 0);
        let nv12 =
            bgra_to_planar(&src, 4, 4, 16, PlanarFormat::Nv12, ConvertConfig::default()).unwrap();
        let i420 =
            bgra_to_planar(&src, 4, 4, 16, PlanarFormat::I420, ConvertConfig::default()).unwrap();

        assert_eq!(nv12.data.len(), i420.data.len());
        // NV12: Cb, Cr, Cb, Cr, ...
        assert_eq!(nv12.chroma()[0], nv12.chroma()[2]);
        assert_eq!(nv12.chroma()[1], nv12.chroma()[3]);
        // I420: all Cb, then all Cr.
        let plane = 2 * 2;
        assert_eq!(i420.chroma()[0], nv12.chroma()[0]);
        assert_eq!(i420.chroma()[plane], nv12.chroma()[1]);
        assert_eq!(nv12.chroma_stride, 4);
        assert_eq!(i420.chroma_stride, 2);
    }

    #[test]
    fn padded_source_rows_are_handled() {
        // Capture APIs align rows, so stride is routinely larger than width * 4. Ignoring it
        // shears the image diagonally — obvious once seen, easy to write.
        let (w, h) = (3u32, 2u32);
        let stride = 32;
        let mut src = vec![0u8; stride * h as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = y * stride + x * 4;
                src[i] = 255; // blue
                src[i + 3] = 255;
            }
        }
        let f = bgra_to_planar(
            &src,
            w,
            h,
            stride,
            PlanarFormat::Nv12,
            ConvertConfig::default(),
        )
        .unwrap();
        // Every luma sample should be blue's luma, not garbage from the padding.
        assert!(
            f.luma().iter().all(|&v| v.abs_diff(18) <= 1),
            "{:?}",
            f.luma()
        );
    }

    #[test]
    fn odd_dimensions_do_not_read_out_of_bounds() {
        // The box filter clamps at the right and bottom edges; without that this panics.
        for (w, h) in [(1u32, 1u32), (3, 1), (1, 3), (5, 7), (7, 5)] {
            let src = solid(w, h, 200, 100, 50);
            let f = bgra_to_planar(
                &src,
                w,
                h,
                w as usize * 4,
                PlanarFormat::Nv12,
                ConvertConfig::default(),
            )
            .unwrap();
            assert_eq!(f.data.len(), PlanarFormat::Nv12.buffer_size(w, h));
        }
    }

    // --- validation --------------------------------------------------------------------------

    #[test]
    fn malformed_input_is_rejected_rather_than_read() {
        let src = solid(4, 4, 0, 0, 0);
        let cfg = ConvertConfig::default();

        assert!(matches!(
            bgra_to_planar(&src, 0, 4, 16, PlanarFormat::Nv12, cfg),
            Err(ConvertError::BadDimensions { .. })
        ));
        assert!(matches!(
            bgra_to_planar(&src, 4, 4, 8, PlanarFormat::Nv12, cfg),
            Err(ConvertError::BadStride { .. })
        ));
        assert!(matches!(
            bgra_to_planar(&src[..16], 4, 4, 16, PlanarFormat::Nv12, cfg),
            Err(ConvertError::SourceTooSmall { .. })
        ));
        assert!(matches!(
            bgra_to_planar(&src, 99999, 99999, 400_000, PlanarFormat::Nv12, cfg),
            Err(ConvertError::BadDimensions { .. })
        ));
    }

    #[test]
    fn a_tightly_allocated_buffer_is_accepted() {
        // The final row needs width*4 bytes, not a whole stride. Demanding the latter would reject
        // buffers that are perfectly valid.
        let (w, h, stride) = (4u32, 3u32, 32usize);
        let exact = stride * (h as usize - 1) + w as usize * 4;
        let src = vec![0u8; exact];
        assert!(bgra_to_planar(
            &src,
            w,
            h,
            stride,
            PlanarFormat::Nv12,
            ConvertConfig::default()
        )
        .is_ok());
    }

    #[test]
    fn conversion_is_deterministic() {
        // Integer arithmetic throughout: two machines must produce identical bitstreams from the
        // same frame, or a bug becomes unreproducible.
        let src = solid(16, 16, 173, 91, 44);
        let a = convert(&src, 16, 16, ConvertConfig::default());
        let b = convert(&src, 16, 16, ConvertConfig::default());
        assert_eq!(a, b);
    }

    #[test]
    fn converting_a_captured_frame_works_end_to_end() {
        use rda_capture::backend::test_pattern::TestPatternCapturer;
        use rda_capture::{CaptureConfig, ScreenCapturer};

        let mut cap = TestPatternCapturer::small();
        cap.start(0, CaptureConfig::default()).unwrap();
        let frame = cap
            .next_frame(std::time::Duration::from_millis(50))
            .unwrap()
            .unwrap();

        let planar = convert_surface(
            &frame.surface,
            frame.width,
            frame.height,
            PlanarFormat::Nv12,
            ConvertConfig::default(),
        )
        .unwrap();

        assert_eq!(planar.width, 640);
        assert_eq!(planar.data.len(), PlanarFormat::Nv12.buffer_size(640, 360));
        assert_eq!(planar.luma().len(), 640 * 360);
    }

    #[test]
    fn a_gpu_surface_is_refused_rather_than_read_back() {
        // Reading a GPU surface back to convert it here would spend exactly the milliseconds the
        // zero-copy path exists to save. Phase 4's VideoToolbox path takes it instead.
        #[cfg(target_os = "macos")]
        {
            let surface = rda_capture::Surface::IoSurface { id: 1 };
            assert!(
                convert_surface(&surface, 8, 8, PlanarFormat::Nv12, ConvertConfig::default())
                    .is_err()
            );
        }
    }
}
