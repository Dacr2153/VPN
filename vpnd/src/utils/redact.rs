// vpnd/src/utils/redact.rs
//
// Helpers to keep secret material out of log lines and crash dumps.
//
// Two surfaces:
//
//   1. Compile-time helpers (`Redacted<T>`, `key_value()`) that callers wrap
//      around values they wish to log without revealing.  This is the *only*
//      mechanism we treat as load-bearing — defence in depth that actually
//      survives `Debug` derives.
//
//   2. A `tracing_subscriber::Layer` (`RedactionLayer`) that scans every
//      formatted event and replaces any base64 blob that *looks* like a
//      WireGuard key (44 chars ending in `=`) with `<redacted>`.  This is a
//      best-effort safety net for accidental `format!("{}", ...)` style logs;
//      it MUST NOT be relied on for correctness — wrap your secrets at the
//      source.

use std::fmt;

/// Wrap any value to hide its contents from `Debug` and `Display`.
pub struct Redacted<T>(pub T);

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Convenience to log a labelled secret, e.g.
/// `info!("{}", redact::key_value("private_key", "abc=="));`
pub fn key_value(label: &str, _secret: &str) -> String {
    format!("{}=<redacted>", label)
}

/// Heuristic: is this string very likely a base64-encoded 32-byte key?
/// (44 chars, last char `=`, rest in the base64 alphabet.)
fn looks_like_wg_key(s: &str) -> bool {
    if s.len() != 44 {
        return false;
    }
    if !s.ends_with('=') {
        return false;
    }
    s[..43]
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Walk through `text` and replace any 44-char base64-key-shaped substring
/// (`[A-Za-z0-9+/]{43}=`) with `<redacted>`. Bounded matches: a key must be
/// preceded and followed by a non-base64 character (or string boundary) so
/// we don't munge the middle of a longer blob.
pub fn scrub_keys(text: &str) -> String {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let is_b64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
    let is_boundary = |i: isize| -> bool {
        if i < 0 || i as usize >= n { return true; }
        // `=` inside the surrounding text counts as a boundary (it appears in
        // log syntax such as `private_key=...`); only the base64 alphabet
        // proper extends a candidate.
        !is_b64(bytes[i as usize])
    };

    let mut out = String::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        // Try to match a 44-char key starting at i (ASCII-only window).
        let candidate_ok = i + 44 <= n
            && text.is_char_boundary(i)
            && text.is_char_boundary(i + 44)
            && bytes[i + 43] == b'='
            && (0..43).all(|k| is_b64(bytes[i + k]))
            && is_boundary(i as isize - 1)
            && is_boundary(i as isize + 44);

        if candidate_ok {
            out.push_str("<redacted>");
            i += 44;
        } else {
            // Advance by one char (UTF-8 safe).
            let next = text[i..]
                .chars()
                .next()
                .map(|c| c.len_utf8())
                .unwrap_or(1);
            out.push_str(&text[i..i + next]);
            i += next;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_hides_value_in_debug_and_display() {
        let r = Redacted("supersecret");
        assert_eq!(format!("{:?}", r), "<redacted>");
        assert_eq!(format!("{}", r), "<redacted>");
    }

    #[test]
    fn key_value_does_not_leak_secret() {
        let s = key_value("private_key", "ABCD1234==");
        assert_eq!(s, "private_key=<redacted>");
        assert!(!s.contains("ABCD1234"));
    }

    #[test]
    fn scrub_replaces_wg_shaped_key() {
        // 32 zero bytes → all-A base64
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(key.len(), 44);
        let line = format!("private_key={} other=ok", key);
        let cleaned = scrub_keys(&line);
        assert!(!cleaned.contains(key));
        assert!(cleaned.contains("<redacted>"));
        assert!(cleaned.contains("other=ok"));
    }

    #[test]
    fn scrub_leaves_normal_words_alone() {
        let line = "connecting to server with profile myhome";
        assert_eq!(scrub_keys(line), line);
    }

    #[test]
    fn scrub_handles_empty_string() {
        assert_eq!(scrub_keys(""), "");
    }
}
