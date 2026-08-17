//! Persisting the device identity across restarts.
//!
//! A remote desktop tool whose address changes every launch is not a tool. The device id is derived
//! from the public key ([`crate::identity`]), so persisting the identity *is* persisting the
//! address, and everything a user does with it — saving a machine in a list, granting it unattended
//! access, recognising it on reconnect — depends on this file surviving.
//!
//! **What this is.** A `0600` file, the same guarantee an SSH private key has. It refuses to load a
//! key whose permissions are wider than that, for the same reason `ssh` does: a private key another
//! local account can read has already failed, and loading it anyway would hide that.
//!
//! **What this is not.** The OS keystore — Keychain, DPAPI/CNG, Secret Service. Those additionally
//! protect the key at rest against an attacker with the disk, and can require user presence to
//! unlock. This does neither. The trade is deliberate for now: a file works identically on all three
//! platforms with no prompts and no entitlements, which is what unblocks the rest of the system, and
//! [`Keystore`] exists so the swap is one implementation rather than a refactor.
//!
//! Nothing here logs the key, and nothing here returns it. The only way out of this module is an
//! [`Identity`], which keeps its secret private.

use crate::identity::{Identity, IdentityError};
use base64::Engine as _;
use std::io;
use std::path::{Path, PathBuf};
use tracing::info;
#[cfg(not(unix))]
use tracing::warn;

/// First line of the file, so a future format change is detectable rather than silently misparsed.
const MAGIC: &str = "rda-identity-v1";

/// Why an identity could not be loaded or stored.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// The file could not be read or written.
    #[error("keystore i/o at {path}: {source}")]
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying failure.
        source: io::Error,
    },
    /// The file exists but is not a keystore file this version understands.
    #[error("{path} is not an rda identity file (expected a leading `{MAGIC}`)")]
    BadFormat {
        /// The file involved.
        path: PathBuf,
    },
    /// The key material in the file is not a valid Ed25519 key.
    #[error("the key in {path} is unusable: {source}")]
    BadKey {
        /// The file involved.
        path: PathBuf,
        /// The underlying failure.
        source: IdentityError,
    },
    /// The file is readable by users other than the owner.
    #[error(
        "{path} is readable by other users (mode {mode:o}); refusing to use it. \
         Run: chmod 600 {path}"
    )]
    Permissions {
        /// The file involved.
        path: PathBuf,
        /// The permission bits found.
        mode: u32,
    },
    /// No location could be determined for the identity file.
    #[error("could not determine a config directory; pass an explicit path")]
    NoConfigDir,
}

/// Where a device identity is stored.
///
/// A trait so the file implementation can be replaced by an OS keystore without touching callers.
pub trait Keystore {
    /// Loads the stored identity, or `Ok(None)` if none has been stored yet.
    fn load(&self) -> Result<Option<Identity>, KeystoreError>;

    /// Stores an identity, replacing anything already there.
    fn store(&self, identity: &Identity) -> Result<(), KeystoreError>;

    /// Loads the stored identity, generating and storing one on first run.
    fn load_or_create(&self) -> Result<Identity, KeystoreError> {
        if let Some(identity) = self.load()? {
            info!(device_id = %identity.device_id(), "loaded the stored device identity");
            return Ok(identity);
        }
        let identity = Identity::generate();
        self.store(&identity)?;
        info!(device_id = %identity.device_id(), "generated a new device identity");
        Ok(identity)
    }
}

/// The conventional location for one agent's identity file.
///
/// - Linux: `$XDG_CONFIG_HOME/rda/<agent>.key`, else `~/.config/rda/<agent>.key`
/// - macOS: `~/Library/Application Support/rda/<agent>.key`
/// - Windows: `%APPDATA%\rda\<agent>.key`
///
/// **Why the file is per agent rather than per machine.** A device has one identity and a *role*
/// per session — `docs/PROTOCOL.md` §3.3 has `role: "host" | "controller" | "both"` for exactly
/// that reason — so one file per machine looks right. It is not, yet: the host and the viewer are
/// separate processes today, the registry keys peers by device id, and registering the same id
/// twice replaces the first. Sharing a file therefore makes the viewer silently knock the host
/// offline, which presents as `peer refused the connection: Offline` and is thoroughly confusing.
/// When both roles live in one agent process that registers once as `both`, this collapses to a
/// single file.
pub fn default_path(agent: &str) -> Result<PathBuf, KeystoreError> {
    let base = if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|h| h.join("Library").join("Application Support"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|h| h.join(".config"))
            })
    };
    Ok(base
        .ok_or(KeystoreError::NoConfigDir)?
        .join("rda")
        .join(format!("{agent}.key")))
}

/// A device identity in a `0600` file.
#[derive(Debug, Clone)]
pub struct FileKeystore {
    path: PathBuf,
}

impl FileKeystore {
    /// Uses an explicit path.
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Uses [`default_path`] for the named agent.
    pub fn default_location(agent: &str) -> Result<Self, KeystoreError> {
        Ok(Self::at(default_path(agent)?))
    }

    /// The file this keystore reads and writes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn io(&self, source: io::Error) -> KeystoreError {
        KeystoreError::Io {
            path: self.path.clone(),
            source,
        }
    }

    /// Rejects a key file that other local users can read.
    ///
    /// A no-op on Windows, where the equivalent check is an ACL inspection rather than a mode; the
    /// file inherits the user profile's ACL, which is already user-only on a default install.
    #[cfg(unix)]
    fn check_permissions(&self) -> Result<(), KeystoreError> {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&self.path)
            .map_err(|e| self.io(e))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(KeystoreError::Permissions {
                path: self.path.clone(),
                mode,
            });
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_permissions(&self) -> Result<(), KeystoreError> {
        Ok(())
    }

    /// Creates or truncates the file with owner-only permissions.
    ///
    /// The mode is set in the `open` call rather than afterwards. Writing the key first and
    /// tightening permissions second leaves a window in which the secret is on disk and world
    /// readable, and a window is all an attacker needs.
    #[cfg(unix)]
    fn create_private(&self) -> Result<std::fs::File, KeystoreError> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.path)
            .map_err(|e| self.io(e))
    }

    #[cfg(not(unix))]
    fn create_private(&self) -> Result<std::fs::File, KeystoreError> {
        std::fs::File::create(&self.path).map_err(|e| self.io(e))
    }
}

impl Keystore for FileKeystore {
    fn load(&self) -> Result<Option<Identity>, KeystoreError> {
        let contents = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(self.io(e)),
        };
        self.check_permissions()?;

        let mut lines = contents.lines();
        if lines.next().map(str::trim) != Some(MAGIC) {
            return Err(KeystoreError::BadFormat {
                path: self.path.clone(),
            });
        }
        let encoded = lines
            .next()
            .map(str::trim)
            .ok_or_else(|| KeystoreError::BadFormat {
                path: self.path.clone(),
            })?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| KeystoreError::BadFormat {
                path: self.path.clone(),
            })?;
        let identity =
            Identity::from_secret_bytes(&bytes).map_err(|source| KeystoreError::BadKey {
                path: self.path.clone(),
                source,
            })?;
        Ok(Some(identity))
    }

    fn store(&self, identity: &Identity) -> Result<(), KeystoreError> {
        use std::io::Write as _;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| self.io(e))?;
        }
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(identity.secret_bytes_for_keystore());

        let mut file = self.create_private()?;
        writeln!(file, "{MAGIC}").map_err(|e| self.io(e))?;
        writeln!(file, "{encoded}").map_err(|e| self.io(e))?;
        writeln!(
            file,
            "# device id {} — this is a private key, treat it like ~/.ssh/id_ed25519",
            identity.device_id()
        )
        .map_err(|e| self.io(e))?;
        file.flush().map_err(|e| self.io(e))?;

        #[cfg(not(unix))]
        warn!(
            path = %self.path.display(),
            "the device key is stored without OS-level protection on this platform"
        );
        Ok(())
    }
}

/// An in-memory keystore that forgets everything on exit.
///
/// For tests, and for the `--ephemeral` flag: a session that should leave no trace of having
/// happened is a legitimate thing to want, and it is better served by an explicit choice than by
/// the accident of not having implemented persistence.
#[derive(Debug, Default)]
pub struct EphemeralKeystore;

impl Keystore for EphemeralKeystore {
    fn load(&self) -> Result<Option<Identity>, KeystoreError> {
        Ok(None)
    }

    fn store(&self, _identity: &Identity) -> Result<(), KeystoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temporary path per test, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "rda-keystore-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn file(&self) -> PathBuf {
            self.0.join("identity")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_identity_survives_a_round_trip() {
        let dir = TempDir::new("roundtrip");
        let ks = FileKeystore::at(dir.file());

        let created = ks.load_or_create().unwrap();
        let loaded = ks.load_or_create().unwrap();

        assert_eq!(
            created.device_id(),
            loaded.device_id(),
            "the device id is the user-visible address; it must not change across restarts"
        );
        assert_eq!(
            created.secret_bytes_for_keystore(),
            loaded.secret_bytes_for_keystore()
        );
    }

    #[test]
    fn loading_a_missing_file_is_not_an_error() {
        let dir = TempDir::new("missing");
        assert!(FileKeystore::at(dir.file()).load().unwrap().is_none());
    }

    #[test]
    fn the_key_file_is_created_owner_only() {
        let dir = TempDir::new("perms");
        let ks = FileKeystore::at(dir.file());
        ks.load_or_create().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.file()).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "a private key must not be group or world readable"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("loose");
        let ks = FileKeystore::at(dir.file());
        ks.load_or_create().unwrap();

        std::fs::set_permissions(dir.file(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            matches!(ks.load(), Err(KeystoreError::Permissions { .. })),
            "a key others can read has already failed; loading it anyway would hide that"
        );
    }

    #[test]
    fn a_foreign_file_is_rejected_rather_than_misparsed() {
        let dir = TempDir::new("foreign");
        std::fs::write(dir.file(), "some other program's data\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.file(), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            FileKeystore::at(dir.file()).load(),
            Err(KeystoreError::BadFormat { .. })
        ));
    }

    #[test]
    fn a_truncated_key_is_reported_as_a_bad_key() {
        let dir = TempDir::new("truncated");
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        std::fs::write(dir.file(), format!("{MAGIC}\n{short}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.file(), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            FileKeystore::at(dir.file()).load(),
            Err(KeystoreError::BadKey { .. })
        ));
    }

    #[test]
    fn storing_twice_replaces_rather_than_appends() {
        let dir = TempDir::new("replace");
        let ks = FileKeystore::at(dir.file());
        ks.store(&Identity::generate()).unwrap();
        let second = Identity::generate();
        ks.store(&second).unwrap();
        assert_eq!(ks.load().unwrap().unwrap().device_id(), second.device_id());
    }

    #[test]
    fn the_ephemeral_keystore_never_remembers() {
        let ks = EphemeralKeystore;
        let a = ks.load_or_create().unwrap();
        let b = ks.load_or_create().unwrap();
        assert_ne!(a.device_id(), b.device_id());
    }

    #[test]
    fn the_default_path_is_under_a_config_directory() {
        let path = default_path("host").expect("a config directory exists in a test environment");
        assert!(path.ends_with("rda/host.key"), "got {}", path.display());
    }

    #[test]
    fn different_agents_get_different_files() {
        // Sharing one file makes the viewer's registration evict the host's, and the host then
        // reports itself Offline to the very client that displaced it.
        assert_ne!(
            default_path("host").unwrap(),
            default_path("controller").unwrap()
        );
    }
}
