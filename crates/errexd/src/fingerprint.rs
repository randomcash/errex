//! Fingerprint derivation for grouping similar events.
//!
//! Strategy is deliberately naive for the scaffold: hash the exception type
//! plus the topmost in-app frame (function + filename). Real Sentry-style
//! grouping needs more nuance (module normalization, frame-skip rules,
//! message templating), and that work belongs in a dedicated module.

use errex_proto::{Event, Fingerprint};

// FNV-1a, 64-bit. Vendored instead of using `DefaultHasher`: the standard
// library explicitly does not guarantee `DefaultHasher`'s output across
// compiler versions, but fingerprints are persisted in SQLite across
// upgrades — a toolchain bump must not silently re-group every issue.
// FNV-1a needs no crate and no cryptographic strength, just a fixed
// algorithm we control. Changing this algorithm regroups all existing
// issues once (there is no fingerprint migration for stored data), so
// treat the constants and byte layout below as pinned.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

struct Fnv1a(u64);

impl Fnv1a {
    fn new() -> Self {
        Self(FNV_OFFSET_BASIS)
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(FNV_PRIME);
        }
    }

    // Tags presence and terminates the field so adjacent fields can't be
    // confused with each other (e.g. ("ab", "c") vs ("a", "bc")).
    fn write_opt_str(&mut self, s: Option<&str>) {
        match s {
            Some(s) => {
                self.write(&[1]);
                self.write(s.as_bytes());
            }
            None => self.write(&[0]),
        }
        self.write(&[0xff]);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

pub fn derive(event: &Event) -> Fingerprint {
    let mut h = Fnv1a::new();

    if let Some(ex) = event.primary_exception() {
        h.write_opt_str(ex.ty.as_deref());
        if let Some(frame) = ex.first_frame() {
            h.write_opt_str(frame.function.as_deref());
            h.write_opt_str(frame.filename.as_deref());
        }
    } else if let Some(msg) = &event.message {
        h.write_opt_str(Some(msg));
    } else {
        // Nothing distinguishing — fall back to event id so each event is its
        // own group rather than collapsing all unknown events together.
        h.write(event.event_id.as_bytes());
    }

    Fingerprint::new(format!("{:016x}", h.finish()))
}

#[cfg(test)]
mod tests {
    //! Fingerprint behavior tests. Most tests here pin the *contract* (what
    //! produces equal vs distinct fingerprints) rather than concrete hash
    //! values. The `golden_*` tests below additionally pin exact output
    //! strings for our vendored FNV-1a: unlike `DefaultHasher`, this
    //! algorithm is ours to keep stable across Rust versions, and these
    //! tests fail loudly if it ever silently changes.

    use super::*;
    use chrono::Utc;
    use errex_proto::{ExceptionContainer, ExceptionInfo, Frame, Stacktrace};
    use uuid::Uuid;

    fn ev_with_exception(ty: &str, function: &str, filename: &str, lineno: u32) -> Event {
        Event {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            platform: None,
            level: None,
            environment: None,
            release: None,
            server_name: None,
            message: None,
            exception: Some(ExceptionContainer {
                values: vec![ExceptionInfo {
                    ty: Some(ty.into()),
                    value: None,
                    module: None,
                    stacktrace: Some(Stacktrace {
                        frames: vec![Frame {
                            filename: Some(filename.into()),
                            function: Some(function.into()),
                            module: None,
                            lineno: Some(lineno),
                            colno: None,
                            in_app: Some(true),
                        }],
                    }),
                }],
            }),
            breadcrumbs: None,
            tags: None,
            contexts: None,
            extra: None,
            user: None,
            request: None,
        }
    }

    fn ev_message(msg: &str) -> Event {
        Event {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            platform: None,
            level: None,
            environment: None,
            release: None,
            server_name: None,
            message: Some(msg.into()),
            exception: None,
            breadcrumbs: None,
            tags: None,
            contexts: None,
            extra: None,
            user: None,
            request: None,
        }
    }

    fn ev_empty() -> Event {
        Event {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            platform: None,
            level: None,
            environment: None,
            release: None,
            server_name: None,
            message: None,
            exception: None,
            breadcrumbs: None,
            tags: None,
            contexts: None,
            extra: None,
            user: None,
            request: None,
        }
    }

    // ----- shape -----

    #[test]
    fn output_is_16_hex_chars() {
        let fp = derive(&ev_with_exception("E", "f", "a.js", 1));
        let s = fp.as_str();
        assert_eq!(s.len(), 16);
        assert!(
            s.chars().all(|c| c.is_ascii_hexdigit()),
            "non-hex char: {s}"
        );
    }

    #[test]
    fn deterministic_across_calls() {
        let a = derive(&ev_with_exception("E", "f", "a.js", 1));
        let b = derive(&ev_with_exception("E", "f", "a.js", 1));
        assert_eq!(a, b, "same inputs must hash identically");
    }

    // ----- grouping (same fingerprint) -----

    #[test]
    fn lineno_and_event_id_do_not_affect_grouping() {
        // Two events with identical type+function+filename but different
        // lineno and event_id must group together. Otherwise every event
        // would be its own issue and the daemon's value vanishes.
        let a = derive(&ev_with_exception(
            "TypeError",
            "checkout",
            "src/pay.ts",
            10,
        ));
        let b = derive(&ev_with_exception(
            "TypeError",
            "checkout",
            "src/pay.ts",
            273,
        ));
        assert_eq!(a, b);
    }

    // ----- distinction (different fingerprints) -----

    #[test]
    fn different_exception_types_produce_different_fingerprints() {
        let a = derive(&ev_with_exception("TypeError", "f", "a.js", 1));
        let b = derive(&ev_with_exception("ReferenceError", "f", "a.js", 1));
        assert_ne!(a, b);
    }

    #[test]
    fn different_functions_produce_different_fingerprints() {
        let a = derive(&ev_with_exception("E", "alpha", "a.js", 1));
        let b = derive(&ev_with_exception("E", "beta", "a.js", 1));
        assert_ne!(a, b);
    }

    #[test]
    fn different_filenames_produce_different_fingerprints() {
        let a = derive(&ev_with_exception("E", "f", "a.js", 1));
        let b = derive(&ev_with_exception("E", "f", "b.js", 1));
        assert_ne!(a, b);
    }

    // ----- fallbacks -----

    #[test]
    fn message_only_events_group_by_message() {
        let a = derive(&ev_message("Database connection lost"));
        let b = derive(&ev_message("Database connection lost"));
        let c = derive(&ev_message("Different message"));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn empty_event_falls_back_to_event_id() {
        // No exception, no message: each event must be its own group rather
        // than collapsing all "unknown" events into a single noisy bucket.
        let a = derive(&ev_empty());
        let b = derive(&ev_empty());
        assert_ne!(a, b, "two empty events must produce distinct fingerprints");
    }

    // ----- golden values (pin the algorithm itself, not just the contract) -----

    #[test]
    fn golden_exception_with_frame() {
        let fp = derive(&ev_with_exception(
            "TypeError",
            "checkout",
            "src/pay.ts",
            10,
        ));
        assert_eq!(fp.as_str(), "d1337c46f0989069");
    }

    #[test]
    fn golden_exception_without_frame() {
        let event = Event {
            exception: Some(ExceptionContainer {
                values: vec![ExceptionInfo {
                    ty: Some("ReferenceError".into()),
                    value: None,
                    module: None,
                    stacktrace: None,
                }],
            }),
            ..ev_empty()
        };
        assert_eq!(derive(&event).as_str(), "adeacf91b32ef0ce");
    }

    #[test]
    fn golden_message_only() {
        let fp = derive(&ev_message("Database connection lost"));
        assert_eq!(fp.as_str(), "9e2ea9bc10aefce8");
    }

    #[test]
    fn golden_event_id_fallback() {
        let event = Event {
            event_id: Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap(),
            ..ev_empty()
        };
        assert_eq!(derive(&event).as_str(), "9900bf86b92101a5");
    }

    #[test]
    fn exception_takes_precedence_over_message() {
        // If an event has BOTH a message and an exception, the exception
        // is the grouping key. (The message often differs per occurrence
        // even when the exception is the same.)
        let mut with_ex = ev_with_exception("E", "f", "a.js", 1);
        with_ex.message = Some("changing message 1".into());
        let mut with_ex2 = ev_with_exception("E", "f", "a.js", 1);
        with_ex2.message = Some("changing message 2".into());
        assert_eq!(derive(&with_ex), derive(&with_ex2));
    }
}
