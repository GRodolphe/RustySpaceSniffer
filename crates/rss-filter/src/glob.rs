//! Case-insensitive `*`/`?` wildcard matching for masks (FR-4.2, FR-4.3).
//!
//! Windows semantics: matching is case-insensitive, `*` matches any
//! (possibly empty) character sequence, `?` matches exactly one character,
//! and the pattern is anchored — it must match the whole name.

/// Match `name` against a glob `pattern` case-insensitively.
///
/// The pattern is anchored: `*.jpg` matches `a.jpg` but not `a.jpgx`, and
/// `temp` does not match `temporary` (use `*temp*` for substring matching).
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    let n: Vec<char> = name.chars().flat_map(char::to_lowercase).collect();

    // Two-pointer scan with single-level backtracking to the last `*`.
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star_p, mut star_n) = (usize::MAX, 0usize);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = pi;
            star_n = ni;
            pi += 1;
        } else if star_p != usize::MAX {
            pi = star_p + 1;
            star_n += 1;
            ni = star_n;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn plain_and_case_insensitive() {
        assert!(glob_match("temp", "temp"));
        assert!(glob_match("temp", "TEMP"));
        assert!(glob_match("TEMP", "temp"));
        assert!(!glob_match("temp", "temporary"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "a"));
    }

    #[test]
    fn star() {
        assert!(glob_match("*.jpg", "a.jpg"));
        assert!(glob_match("*.jpg", "A.JPG"));
        assert!(!glob_match("*.jpg", "a.jpgx"));
        assert!(!glob_match("*.jpg", "ajpg"));
        assert!(glob_match("*", "anything at all"));
        assert!(glob_match("*", ""));
        assert!(glob_match("*internet*", "internet cache"));
        assert!(glob_match("*internet*", "xinternety"));
        assert!(!glob_match("*internet*", "intranet"));
        assert!(glob_match("a*b*c", "abc"));
        assert!(glob_match("a*b*c", "axbyc"));
        assert!(!glob_match("a*b*c", "acb"));
    }

    #[test]
    fn question_mark() {
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(!glob_match("a?c", "abbc"));
        assert!(glob_match("??", "ab"));
        assert!(glob_match("?.jpg", "x.jpg"));
    }

    #[test]
    fn unicode_names() {
        assert!(glob_match("*.jpg", "foto Ü.jpg"));
        assert!(glob_match("föt?", "fötü"));
        assert!(!glob_match("föt?", "fötüx"));
    }
}
