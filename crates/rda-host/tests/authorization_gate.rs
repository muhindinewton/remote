//! The Phase 3 acceptance test: unauthenticated input never reaches the operating system.
//!
//! Every other test in this workspace checks one layer. This one wires the real crypto, the real
//! session state machine and the real injector together and asserts the property the whole phase
//! exists to guarantee — that a peer which has not authenticated cannot move the mouse.
//!
//! The backend is a recorder rather than the OS, so the assertions are exact: not "it probably did
//! not inject", but "zero events reached the boundary".

use rda_capture::backend::test_pattern::TestPatternCapturer;
use rda_capture::{CaptureConfig, ScreenCapturer};
use rda_crypto::binding::{BindingProof, BindingVerifier, Fingerprint};
use rda_crypto::identity::{AddressBook, Identity};
use rda_crypto::pake::{self, PinAuth};
use rda_host::session::{
    binding_pair, ConsentDecision, HostSession, PeerCredentials, SessionState,
};
use rda_input::backend::RecordingBackend;
use rda_input::{AuditLog, DisplayGeometry, GuardError, Injector, LocalControl, SessionGrant};
use rda_proto::caps::SessionCaps;
use rda_proto::control::{ControlFrame, KeyAction, Modifiers, Payload, USAGE_PAGE_KEYBOARD};

const SESSION: &str = "sess_acceptance";

fn full_caps() -> SessionCaps {
    SessionCaps {
        view: true,
        input: true,
        clipboard: true,
        file: false,
        audio: false,
    }
}

fn displays() -> Vec<DisplayGeometry> {
    vec![DisplayGeometry {
        id: 0,
        x: 0,
        y: 0,
        width: 1920,
        height: 1080,
    }]
}

fn mouse_move(x: u16, y: u16) -> ControlFrame {
    ControlFrame::new(
        Payload::MouseMove {
            display_id: 0,
            flags: 0,
            x_norm: x,
            y_norm: y,
            modifiers: Modifiers::NONE,
        },
        1,
        0,
    )
}

fn key_press(usage: u16) -> ControlFrame {
    ControlFrame::new(
        Payload::KeyEvent {
            usage_page: USAGE_PAGE_KEYBOARD,
            usage_id: usage,
            action: KeyAction::Down,
            flags: 0,
            modifiers: Modifiers::NONE,
        },
        2,
        0,
    )
}

struct World {
    host_identity: Identity,
    controller: Identity,
    session: HostSession,
    injector: Injector<RecordingBackend>,
    audit: AuditLog,
    book: AddressBook,
    controller_binding: BindingVerifier,
    host_binding: BindingVerifier,
}

fn world() -> World {
    let controller = Identity::generate();
    let (cb, hb) = binding_pair(
        SESSION,
        Fingerprint::from_bytes([0xAA; 32]),
        Fingerprint::from_bytes([0xBB; 32]),
        BindingVerifier::generate_nonce(),
        BindingVerifier::generate_nonce(),
    );
    World {
        session: HostSession::new(SESSION, controller.device_id().clone(), full_caps(), 0),
        host_identity: Identity::generate(),
        controller,
        injector: Injector::new(RecordingBackend::default(), displays()),
        audit: AuditLog::new(64),
        book: AddressBook::new(),
        controller_binding: cb,
        host_binding: hb,
    }
}

/// Runs the honest handshake to completion.
fn authenticate(w: &mut World, pin_override: Option<&str>) -> Result<(), rda_host::SessionError> {
    w.session
        .apply_consent(ConsentDecision::Allow(full_caps()), 100, &mut w.audit)?;
    let pin = pin_override
        .map(str::to_owned)
        .unwrap_or_else(|| w.session.pin_display().unwrap().to_owned());

    let auth = PinAuth::start(SESSION, &pin).unwrap();
    let response = w.session.begin_pin_auth(auth.message(), 200)?;
    let key = auth.finish(&response.pake_message).unwrap();
    let confirmation = pake::confirm(&key, "controller", SESSION);
    let proof: BindingProof = w.controller_binding.prove(&w.controller);

    w.session.complete_pin_auth(
        &confirmation,
        PeerCredentials {
            identity: w.controller.public(),
            binding: &w.host_binding,
            proof: &proof,
        },
        &mut w.book,
        &mut w.audit,
        300,
    )
}

/// Applies a frame using whatever grant the session currently holds, or refuses if there is none.
fn try_inject(w: &mut World, frame: &ControlFrame) -> Result<(), GuardError> {
    match w.session.grant() {
        Some(grant) => {
            let grant: SessionGrant = grant.clone();
            w.injector.apply(&grant, frame, 400)
        }
        // No grant exists, so there is nothing to pass to the injector. This is the property under
        // test made concrete: the unauthenticated path is not merely refused, it is unreachable.
        None => Err(GuardError::InputNotGranted),
    }
}

#[test]
fn an_unauthenticated_peer_cannot_reach_the_operating_system() {
    let mut w = world();
    assert_eq!(*w.session.state(), SessionState::AwaitingConsent);

    for frame in [mouse_move(30000, 30000), key_press(0x04)] {
        assert_eq!(try_inject(&mut w, &frame), Err(GuardError::InputNotGranted));
    }
    assert!(
        w.injector.stats().injected == 0,
        "an unauthenticated peer must not inject a single event"
    );
}

#[test]
fn a_peer_that_only_got_consent_still_cannot_inject() {
    // Consent is not authentication. Between the two the session has a PIN on screen and nothing
    // else; a peer that stops here must get nowhere.
    let mut w = world();
    w.session
        .apply_consent(ConsentDecision::Allow(full_caps()), 100, &mut w.audit)
        .unwrap();
    assert_eq!(*w.session.state(), SessionState::Authenticating);
    assert!(w.session.grant().is_none());
    assert_eq!(
        try_inject(&mut w, &mouse_move(1, 1)),
        Err(GuardError::InputNotGranted)
    );
}

#[test]
fn a_peer_mid_pake_still_cannot_inject() {
    // The PAKE round has completed and a shared key exists — but it is unconfirmed, so it proves
    // nothing yet.
    let mut w = world();
    w.session
        .apply_consent(ConsentDecision::Allow(full_caps()), 100, &mut w.audit)
        .unwrap();
    let pin = w.session.pin_display().unwrap().to_owned();
    let auth = PinAuth::start(SESSION, &pin).unwrap();
    w.session.begin_pin_auth(auth.message(), 200).unwrap();

    assert_eq!(*w.session.state(), SessionState::AwaitingConfirmation);
    assert!(
        w.session.grant().is_none(),
        "an unconfirmed key must not authorise anything"
    );
    assert_eq!(
        try_inject(&mut w, &mouse_move(1, 1)),
        Err(GuardError::InputNotGranted)
    );
}

#[test]
fn a_wrong_pin_never_yields_injection() {
    let mut w = world();
    assert!(authenticate(&mut w, Some("000000")).is_err());
    assert_eq!(
        try_inject(&mut w, &mouse_move(1, 1)),
        Err(GuardError::InputNotGranted)
    );
    assert_eq!(w.injector.stats().injected, 0);
}

#[test]
fn an_authenticated_peer_reaches_the_operating_system() {
    // The positive case. Without it, every assertion above could be satisfied by an injector that
    // simply never works.
    let mut w = world();
    authenticate(&mut w, None).expect("the honest handshake must succeed");
    assert_eq!(*w.session.state(), SessionState::Established);

    try_inject(&mut w, &mouse_move(32768, 32768)).unwrap();
    try_inject(&mut w, &key_press(0x04)).unwrap();

    assert_eq!(w.injector.stats().injected, 2);
    assert!(w.session.short_authentication_string().is_some());
}

#[test]
fn a_view_only_session_sees_the_screen_but_cannot_touch_it() {
    let mut w = world();
    w.session
        .apply_consent(
            ConsentDecision::Allow(SessionCaps::view_only()),
            100,
            &mut w.audit,
        )
        .unwrap();
    let pin = w.session.pin_display().unwrap().to_owned();
    let auth = PinAuth::start(SESSION, &pin).unwrap();
    let response = w.session.begin_pin_auth(auth.message(), 200).unwrap();
    let key = auth.finish(&response.pake_message).unwrap();
    let proof = w.controller_binding.prove(&w.controller);
    w.session
        .complete_pin_auth(
            &pake::confirm(&key, "controller", SESSION),
            PeerCredentials {
                identity: w.controller.public(),
                binding: &w.host_binding,
                proof: &proof,
            },
            &mut w.book,
            &mut w.audit,
            300,
        )
        .unwrap();

    assert_eq!(*w.session.state(), SessionState::Established);
    let grant = w.session.grant().unwrap();
    assert!(
        grant.caps().view,
        "a view-only session may still see the screen"
    );
    assert_eq!(
        try_inject(&mut w, &mouse_move(1, 1)),
        Err(GuardError::InputNotGranted)
    );
    assert_eq!(w.injector.stats().injected, 0);
}

#[test]
fn a_man_in_the_middle_with_the_correct_pin_gets_nothing() {
    // The scenario the fingerprint binding exists for: an attacker who has somehow learned the PIN
    // but is terminating DTLS itself, so the certificate it presents is not the one it signed.
    let mut w = world();
    w.session
        .apply_consent(ConsentDecision::Allow(full_caps()), 100, &mut w.audit)
        .unwrap();
    let pin = w.session.pin_display().unwrap().to_owned();

    let auth = PinAuth::start(SESSION, &pin).unwrap();
    let response = w.session.begin_pin_auth(auth.message(), 200).unwrap();
    let key = auth.finish(&response.pake_message).unwrap();

    // Signed over a session whose host fingerprint is the attacker's, not the real host's.
    let (attacker_view, _) = binding_pair(
        SESSION,
        Fingerprint::from_bytes([0xAA; 32]),
        Fingerprint::from_bytes([0xEE; 32]),
        BindingVerifier::generate_nonce(),
        BindingVerifier::generate_nonce(),
    );
    let forged = attacker_view.prove(&w.controller);

    let result = w.session.complete_pin_auth(
        &pake::confirm(&key, "controller", SESSION),
        PeerCredentials {
            identity: w.controller.public(),
            binding: &w.host_binding,
            proof: &forged,
        },
        &mut w.book,
        &mut w.audit,
        300,
    );

    assert!(
        result.is_err(),
        "a substituted fingerprint must abort the session"
    );
    assert!(w.session.grant().is_none());
    assert_eq!(
        try_inject(&mut w, &mouse_move(1, 1)),
        Err(GuardError::InputNotGranted)
    );
    assert_eq!(w.injector.stats().injected, 0);
}

#[test]
fn closing_a_session_immediately_revokes_injection() {
    let mut w = world();
    authenticate(&mut w, None).unwrap();
    try_inject(&mut w, &mouse_move(1, 1)).unwrap();

    w.session.close("user ended the session", 500, &mut w.audit);
    assert_eq!(
        try_inject(&mut w, &mouse_move(2, 2)),
        Err(GuardError::InputNotGranted)
    );
}

#[test]
fn the_local_user_can_take_control_from_an_authenticated_peer() {
    let mut w = world();
    authenticate(&mut w, None).unwrap();
    try_inject(&mut w, &key_press(0xE0)).unwrap(); // hold Ctrl
    assert!(w.injector.key_state().is_held(0xE0));

    w.injector.set_local_control(LocalControl::Local).unwrap();
    assert!(
        w.injector.key_state().is_empty(),
        "takeover must release the peer's held keys"
    );
    assert_eq!(
        try_inject(&mut w, &mouse_move(1, 1)),
        Err(GuardError::LocalUserActive)
    );
}

#[test]
fn an_unattended_token_from_another_host_grants_nothing() {
    let mut w = world();
    let impostor_host = Identity::generate();
    let token = rda_crypto::token::TokenIssuer::new(&impostor_host)
        .issue(&w.controller.public(), full_caps(), 0, 3600)
        .unwrap();
    let proof = w.controller_binding.prove(&w.controller);

    let result = w.session.authenticate_with_token(
        &token.encode(),
        &w.host_identity,
        &rda_crypto::token::TokenStore::new(),
        PeerCredentials {
            identity: w.controller.public(),
            binding: &w.host_binding,
            proof: &proof,
        },
        &mut w.audit,
        1000,
    );
    assert!(result.is_err());
    assert_eq!(
        try_inject(&mut w, &mouse_move(1, 1)),
        Err(GuardError::InputNotGranted)
    );
}

#[test]
fn capture_and_authorization_are_independent_concerns() {
    // A session with no input rights still receives frames. Conflating the two would mean a
    // view-only session either sees nothing or can type.
    let mut w = world();
    w.session
        .apply_consent(
            ConsentDecision::Allow(SessionCaps::view_only()),
            100,
            &mut w.audit,
        )
        .unwrap();

    let mut capturer = TestPatternCapturer::small();
    capturer.start(0, CaptureConfig::default()).unwrap();
    let frame = capturer
        .next_frame(std::time::Duration::from_millis(50))
        .unwrap()
        .unwrap();

    assert_eq!(frame.width, 640);
    assert!(frame.is_worth_encoding());
    assert_eq!(
        try_inject(&mut w, &mouse_move(1, 1)),
        Err(GuardError::InputNotGranted)
    );
}
