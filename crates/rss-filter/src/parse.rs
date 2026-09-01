//! Parser: filter string → typed AST with per-condition spans and collected,
//! non-fatal warnings (SPEC.md §5.6 step 1, FR-4.13).
//!
//! Conditions are separated by `;`. Empty conditions (e.g. from a trailing
//! `;`) are silently skipped. A malformed condition produces a
//! [`ParseWarning`] and is dropped (fail-open); it never aborts the parse.
//!
//! Keyword and unit resolution (FR-4.9): full documented words, documented
//! fuzzy aliases (`disk`/`dsk`/`dsksz` for `disksize`), and prefixes that are
//! unambiguous *by resolved meaning* — e.g. `d` matches `disksize`, `disk`,
//! `dsk` and `dsksz`, which all mean the same thing, so it is accepted. Input
//! that resolves to more than one meaning (e.g. the unit `m`, which can be
//! minutes or months) yields a specific ambiguity warning instead of a silent
//! guess.

use rss_core::{NodeFlags, Tag};

use crate::ast::{
    AgeField, AttrRequirement, AttrTest, CmpOp, Condition, ConditionKind, FileClass, ParseWarning,
    SizeMetric, Span, TagExpr, TagSet,
};

/// Age units in seconds (FR-4.5). One month is exactly 30 days and one year
/// exactly 365 days — documented fixed values, not calendar arithmetic.
const AGE_UNITS: &[(&str, u64)] = &[
    ("seconds", 1),
    ("minutes", 60),
    ("hours", 3_600),
    ("days", 86_400),
    ("weeks", 604_800),
    ("months", 30 * 86_400),
    ("years", 365 * 86_400),
];

/// Size units, binary (kb = 1024 b, FR-4.4).
const SIZE_UNITS: &[(&str, u64)] = &[
    ("b", 1),
    ("kb", 1 << 10),
    ("mb", 1 << 20),
    ("gb", 1 << 30),
    ("tb", 1 << 40),
];

/// Size keywords (FR-4.4). `disksize`/`clustersize` and the bare `size`
/// keyword all mean the allocated ("disk") size — the documented default.
const SIZE_KEYWORDS: &[(&str, SizeMetric)] = &[
    ("disksize", SizeMetric::Disk),
    ("clustersize", SizeMetric::Disk),
    ("filesize", SizeMetric::Logical),
    ("logicalsize", SizeMetric::Logical),
    ("size", SizeMetric::Disk),
    // Documented fuzzy aliases (FR-4.9).
    ("disk", SizeMetric::Disk),
    ("dsk", SizeMetric::Disk),
    ("dsksz", SizeMetric::Disk),
];

/// Age keywords (FR-4.5); default (no keyword) is the modify date.
const AGE_KEYWORDS: &[(&str, AgeField)] = &[
    ("creation", AgeField::Creation),
    ("created", AgeField::Creation),
    ("modify", AgeField::Modify),
    ("modified", AgeField::Modify),
    ("access", AgeField::Access),
    ("accessed", AgeField::Access),
];

/// Attribute names for `:attr:` (FR-4.7). The explicit `a` alias for
/// `archive` disambiguates it from `ads`; `ro` and `sp` are documented short
/// forms. Note that `s` is deliberately *not* an alias: it is an ambiguous
/// prefix of `system`/`sparse` and produces a warning (FR-4.9).
const ATTR_NAMES: &[(&str, NodeFlags)] = &[
    ("archive", NodeFlags::ARCHIVE),
    ("a", NodeFlags::ARCHIVE),
    ("system", NodeFlags::SYSTEM),
    ("readonly", NodeFlags::READONLY),
    ("ro", NodeFlags::READONLY),
    ("hidden", NodeFlags::HIDDEN),
    ("compressed", NodeFlags::COMPRESSED),
    ("encrypted", NodeFlags::ENCRYPTED),
    ("offline", NodeFlags::OFFLINE),
    ("temporary", NodeFlags::TEMPORARY),
    ("notindexed", NodeFlags::NOT_INDEXED),
    ("sparse", NodeFlags::SPARSE),
    ("sp", NodeFlags::SPARSE),
    ("ads", NodeFlags::ADS),
];

/// Parse a filter string into conditions and non-fatal warnings.
pub(crate) fn parse_filter(
    input: &str,
    classes: &[FileClass],
) -> (Vec<Condition>, Vec<ParseWarning>) {
    let mut conditions = Vec::new();
    let mut warnings = Vec::new();
    let mut offset = 0usize;
    for piece in input.split(';') {
        let piece_start = offset;
        offset += piece.len() + 1; // + 1 for the ';'
        let trimmed = piece.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lead_ws = piece.len() - piece.trim_start().len();
        let span = Span::new(piece_start + lead_ws, piece_start + lead_ws + trimmed.len());
        match parse_condition(trimmed, span, classes) {
            Ok(cond) => conditions.push(cond),
            Err(w) => warnings.push(w),
        }
    }
    (conditions, warnings)
}

fn warn(span: Span, message: impl Into<String>) -> ParseWarning {
    ParseWarning {
        span,
        message: message.into(),
    }
}

fn parse_condition(
    text: &str,
    span: Span,
    classes: &[FileClass],
) -> Result<Condition, ParseWarning> {
    // Leading `|` negates (masks, tags, attributes, classes).
    let (negated, rest) = match text.strip_prefix('|') {
        Some(r) => (true, r.trim_start()),
        None => (false, text),
    };
    if rest.is_empty() {
        return Err(warn(span, "empty condition"));
    }
    let kind = if let Some(mask) = rest.strip_prefix('\\') {
        // Folder mask (FR-4.3).
        if mask.is_empty() {
            return Err(warn(span, "empty folder mask after '\\'"));
        }
        ConditionKind::FolderMask {
            pattern: mask.into(),
            negated,
        }
    } else if let Some(cmd) = rest.strip_prefix(':') {
        parse_command(cmd, negated, span, classes)?
    } else if rest.contains('<') || rest.contains('>') {
        // `<`/`>` are not valid in (Windows) file names, so any condition
        // containing them is meant to be a size/age condition.
        if negated {
            return Err(warn(
                span,
                "negation '|' is only supported for masks, tags, attributes and classes",
            ));
        }
        parse_measure(rest, span)?
    } else {
        ConditionKind::FileMask {
            pattern: rest.into(),
            negated,
        }
    };
    Ok(Condition { kind, span })
}

/// Parse a `:`-prefixed command condition: `:tag:`, `:attr:`, `:class:`, or a
/// legacy tag like `:red` (FR-4.6..FR-4.8).
fn parse_command(
    cmd: &str,
    negated: bool,
    span: Span,
    classes: &[FileClass],
) -> Result<ConditionKind, ParseWarning> {
    let lower = cmd.to_lowercase();
    let payload = |prefix: &str| {
        lower
            .starts_with(prefix)
            .then(|| cmd[prefix.len()..].trim())
    };

    if let Some(p) = payload("tag:").or_else(|| payload("tags:")) {
        let expr = parse_tag_expr(p).map_err(|m| warn(span, m))?;
        return Ok(ConditionKind::Tag { expr, negated });
    }
    if let Some(p) = payload("attr:").or_else(|| payload("attrs:")) {
        let tests = parse_attr_expr(p).map_err(|m| warn(span, m))?;
        return Ok(ConditionKind::Attr { tests, negated });
    }
    if let Some(p) = payload("class:") {
        if p.is_empty() {
            return Err(warn(span, "empty file class name"));
        }
        return match classes.iter().find(|c| c.name.eq_ignore_ascii_case(p)) {
            Some(c) => Ok(ConditionKind::Class {
                name: c.name.clone().into_boxed_str(),
                extensions: c
                    .extensions
                    .iter()
                    .map(|e| e.clone().into_boxed_str())
                    .collect(),
                negated,
            }),
            None => Err(warn(span, format!("unknown file class '{p}'"))),
        };
    }
    // Legacy 1.x tag syntax: :red / :r / :1 .. :all / :a (FR-4.6).
    match legacy_tag(&lower) {
        Some(expr) => Ok(ConditionKind::Tag { expr, negated }),
        None => Err(warn(span, format!("unknown filter command ':{cmd}'"))),
    }
}

/// Map a legacy tag name/abbreviation/number to a tag (FR-4.6).
fn tag_of(word: &str) -> Option<Tag> {
    match word {
        "red" | "r" | "1" => Some(Tag::Red),
        "yellow" | "y" | "2" => Some(Tag::Yellow),
        "green" | "g" | "3" => Some(Tag::Green),
        "blue" | "b" | "4" => Some(Tag::Blue),
        _ => None,
    }
}

/// Legacy single-tag condition: `:red`, `:r`, `:1`, `:all`, `:a`.
fn legacy_tag(word: &str) -> Option<TagExpr> {
    if word == "all" || word == "a" {
        return Some(TagExpr {
            include: TagSet::ALL,
            exclude: TagSet::EMPTY,
        });
    }
    tag_of(word).map(|t| TagExpr {
        include: TagSet::from_tag(t),
        exclude: TagSet::EMPTY,
    })
}

/// Parse a 2.x tag expression like `red+green-b` or `1,3,-red` (FR-4.6):
/// comma-separated items, each with optional inline `+`/`-` signs; unsigned
/// items are inclusions, `-` items exclusions.
fn parse_tag_expr(payload: &str) -> Result<TagExpr, String> {
    let mut include = TagSet::EMPTY;
    let mut exclude = TagSet::EMPTY;
    for_each_signed(payload, |excluded, name| {
        let w = name.trim().to_lowercase();
        let bits = if w == "all" || w == "a" {
            TagSet::ALL
        } else {
            let tag = tag_of(&w).ok_or_else(|| format!("unknown tag '{w}'"))?;
            TagSet::from_tag(tag)
        };
        if excluded {
            exclude.set_union(bits);
        } else {
            include.set_union(bits);
        }
        Ok(())
    })?;
    if include.is_empty() && exclude.is_empty() {
        return Err("empty tag expression".into());
    }
    Ok(TagExpr { include, exclude })
}

/// Parse an `:attr:` expression like `+a-ro,h` (FR-4.7): same `,`/`+`/`-`
/// item syntax as tags; `+` or bare = must be set, `-` = must be clear.
fn parse_attr_expr(payload: &str) -> Result<Vec<AttrTest>, String> {
    let mut tests = Vec::new();
    for_each_signed(payload, |excluded, name| {
        let flags = lookup_attr(name.trim())?;
        tests.push(AttrTest {
            flags,
            requirement: if excluded {
                AttrRequirement::Clear
            } else {
                AttrRequirement::Set
            },
        });
        Ok(())
    })?;
    if tests.is_empty() {
        return Err("empty attribute expression".into());
    }
    Ok(tests)
}

/// Run `f(excluded, name)` over each signed item of a `,`-separated list in
/// which items may carry inline `+`/`-` signs (e.g. `red+green-b`, `+a-ro,h`).
fn for_each_signed(
    payload: &str,
    mut f: impl FnMut(bool, &str) -> Result<(), String>,
) -> Result<(), String> {
    for part in payload.split(',') {
        let mut excluded = false;
        let mut seg_start: Option<usize> = None;
        let mut emitted = 0;
        for (idx, ch) in part.char_indices() {
            if ch == '+' || ch == '-' {
                if let Some(s) = seg_start.take() {
                    f(excluded, &part[s..idx])?;
                    emitted += 1;
                }
                excluded = ch == '-';
            } else if seg_start.is_none() {
                seg_start = Some(idx);
            }
        }
        if let Some(s) = seg_start {
            f(excluded, &part[s..])?;
            emitted += 1;
        }
        if emitted == 0 {
            return Err(format!("empty item in '{payload}'"));
        }
    }
    Ok(())
}

/// Result of resolving a word against an alias table.
enum Lookup<T> {
    Found(T),
    Ambiguous(Vec<&'static str>),
    Unknown,
}

/// Resolve `word` against a lowercase alias table: exact match first, then
/// prefixes that are unambiguous by *meaning* (all matching entries must map
/// to the same value). Anything else is `Ambiguous` (FR-4.9) or `Unknown`.
fn lookup<T: Copy + Eq>(word: &str, table: &[(&'static str, T)]) -> Lookup<T> {
    let w = word.trim().to_lowercase();
    if w.is_empty() {
        return Lookup::Unknown;
    }
    for (name, value) in table {
        if *name == w {
            return Lookup::Found(*value);
        }
    }
    let matches: Vec<&(&'static str, T)> =
        table.iter().filter(|(n, _)| n.starts_with(&*w)).collect();
    match matches.split_first() {
        None => Lookup::Unknown,
        Some((first, rest)) => {
            if rest.iter().any(|m| m.1 != first.1) {
                Lookup::Ambiguous(matches.iter().map(|m| m.0).collect())
            } else {
                Lookup::Found(first.1)
            }
        }
    }
}

fn lookup_attr(name: &str) -> Result<NodeFlags, String> {
    match lookup(name, ATTR_NAMES) {
        Lookup::Found(f) => Ok(f),
        Lookup::Ambiguous(names) => Err(format!(
            "ambiguous attribute '{name}' (could be {})",
            names.join(" or ")
        )),
        Lookup::Unknown => Err(format!("unknown attribute '{name}'")),
    }
}

/// Parse a size or age condition: `[keyword] <op> <n> [unit]`, with optional
/// whitespace between the parts (FR-4.4, FR-4.5, FR-4.9).
fn parse_measure(text: &str, span: Span) -> Result<ConditionKind, ParseWarning> {
    let b = text.as_bytes();
    let mut i = 0usize;
    skip_ws(b, &mut i);
    let kw_start = i;
    while i < b.len() && b[i].is_ascii_alphabetic() {
        i += 1;
    }
    let keyword = &text[kw_start..i];
    skip_ws(b, &mut i);
    if i >= b.len() {
        return Err(warn(span, "expected '<' or '>'"));
    }
    let op = match b[i] {
        b'<' => CmpOp::Lt,
        b'>' => CmpOp::Gt,
        c => {
            return Err(warn(
                span,
                format!("expected '<' or '>', found '{}'", c as char),
            ))
        }
    };
    i += 1;
    skip_ws(b, &mut i);
    if i < b.len() && b[i] == b'=' {
        return Err(warn(span, "'=' is not supported; use '<' or '>'"));
    }
    let num_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if num_start == i {
        return Err(warn(span, "expected a number after the operator"));
    }
    let value: u64 = text[num_start..i]
        .parse()
        .map_err(|_| warn(span, "number is too large"))?;
    skip_ws(b, &mut i);
    let unit_start = i;
    while i < b.len() && b[i].is_ascii_alphabetic() {
        i += 1;
    }
    let unit = &text[unit_start..i];
    skip_ws(b, &mut i);
    if i != b.len() {
        return Err(warn(
            span,
            format!("unexpected character '{}'", b[i] as char),
        ));
    }
    resolve_measure(keyword, op, value, unit, span)
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && b[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

/// Combine keyword/operator/value/unit into a size or age condition.
///
/// A keyword alone decides the kind when the unit agrees (`c<3days` is
/// creation age because `days` is not a size unit; `c>1kb` is cluster size);
/// with no keyword the unit decides (`<3months` age vs `>1mb` size), and a
/// bare `>100` is size in bytes. Any ambiguity is a warning (FR-4.9).
fn resolve_measure(
    keyword: &str,
    op: CmpOp,
    value: u64,
    unit: &str,
    span: Span,
) -> Result<ConditionKind, ParseWarning> {
    let ks = if keyword.is_empty() {
        Lookup::Found(SizeMetric::Disk) // default: disk size (FR-4.4)
    } else {
        lookup(keyword, SIZE_KEYWORDS)
    };
    let ka = if keyword.is_empty() {
        Lookup::Found(AgeField::Modify) // default: modify date (FR-4.5)
    } else {
        lookup(keyword, AGE_KEYWORDS)
    };
    let us = (!unit.is_empty()).then(|| lookup(unit, SIZE_UNITS));
    let ua = (!unit.is_empty()).then(|| lookup(unit, AGE_UNITS));

    // Ambiguity guard (FR-4.9): never silently pick one meaning.
    if let Lookup::Ambiguous(names) = &ks {
        return Err(warn(
            span,
            format!(
                "ambiguous keyword '{keyword}' (could be {})",
                names.join(" or ")
            ),
        ));
    }
    if let Lookup::Ambiguous(names) = &ka {
        return Err(warn(
            span,
            format!(
                "ambiguous keyword '{keyword}' (could be {})",
                names.join(" or ")
            ),
        ));
    }
    for res in [&us, &ua] {
        if let Some(Lookup::Ambiguous(names)) = res {
            return Err(warn(
                span,
                format!("ambiguous unit '{unit}' (could be {})", names.join(" or ")),
            ));
        }
    }

    let size = match (&ks, &us) {
        (Lookup::Found(m), None) => Some((*m, 1u64)),
        (Lookup::Found(m), Some(Lookup::Found(u))) => Some((*m, *u)),
        _ => None,
    };
    let age = match (&ka, &ua) {
        (Lookup::Found(f), Some(Lookup::Found(u))) => Some((*f, *u)),
        _ => None,
    };

    match (size, age) {
        (Some((metric, mult)), None) => {
            let bytes = value
                .checked_mul(mult)
                .ok_or_else(|| warn(span, "size value is too large"))?;
            Ok(ConditionKind::Size { metric, op, bytes })
        }
        (None, Some((field, mult))) => {
            let seconds = value
                .checked_mul(mult)
                .ok_or_else(|| warn(span, "age value is too large"))?;
            Ok(ConditionKind::Age { field, op, seconds })
        }
        (Some(_), Some(_)) => Err(warn(span, "ambiguous size/age condition")),
        (None, None) => {
            let msg = if !keyword.is_empty()
                && matches!(ks, Lookup::Unknown)
                && matches!(ka, Lookup::Unknown)
            {
                format!("unknown size/age keyword '{keyword}'")
            } else if !unit.is_empty()
                && matches!(us, Some(Lookup::Unknown))
                && matches!(ua, Some(Lookup::Unknown))
            {
                format!("unknown unit '{unit}'")
            } else if matches!(ka, Lookup::Found(_))
                && unit.is_empty()
                && matches!(ks, Lookup::Unknown)
            {
                format!("age condition '{keyword}' needs a unit (seconds..years)")
            } else {
                "malformed size/age condition (expected e.g. '>100kb' or '<3months')".to_string()
            };
            Err(warn(span, msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Filter;

    fn parse(input: &str) -> Filter {
        Filter::parse(input, &[])
    }

    fn only_condition(input: &str) -> Condition {
        let f = parse(input);
        assert!(
            f.warnings().is_empty(),
            "warnings for {input:?}: {:?}",
            f.warnings()
        );
        assert_eq!(f.conditions().len(), 1, "conditions for {input:?}");
        f.conditions()[0].clone()
    }

    /// Canonical manual example (FR-4.4/§4.4): `*.jpg;>1mb;<3months;|:yellow`.
    #[test]
    fn canonical_manual_example() {
        let f = parse("*.jpg;>1mb;<3months;|:yellow");
        assert!(f.warnings().is_empty());
        assert_eq!(f.conditions().len(), 4);

        match &f.conditions()[0].kind {
            ConditionKind::FileMask { pattern, negated } => {
                assert_eq!(&**pattern, "*.jpg");
                assert!(!negated);
            }
            k => panic!("unexpected {k:?}"),
        }
        assert_eq!(f.conditions()[0].span, Span { start: 0, end: 5 });

        match &f.conditions()[1].kind {
            ConditionKind::Size { metric, op, bytes } => {
                assert_eq!(*metric, SizeMetric::Disk);
                assert_eq!(*op, CmpOp::Gt);
                assert_eq!(*bytes, 1024 * 1024);
            }
            k => panic!("unexpected {k:?}"),
        }
        assert_eq!(f.conditions()[1].span, Span { start: 6, end: 10 });

        match &f.conditions()[2].kind {
            ConditionKind::Age { field, op, seconds } => {
                assert_eq!(*field, AgeField::Modify); // default is modify date
                assert_eq!(*op, CmpOp::Lt);
                assert_eq!(*seconds, 3 * 30 * 86_400); // a month is 30 days
            }
            k => panic!("unexpected {k:?}"),
        }

        match &f.conditions()[3].kind {
            ConditionKind::Tag { expr, negated } => {
                assert!(negated);
                assert_eq!(expr.include, TagSet::YELLOW);
                assert_eq!(expr.exclude, TagSet::EMPTY);
            }
            k => panic!("unexpected {k:?}"),
        }
    }

    /// Second canonical manual example: `*.jpg;*.gif;>100kb;<6months`.
    #[test]
    fn second_manual_example() {
        let f = parse("*.jpg;*.gif;>100kb;<6months");
        assert!(f.warnings().is_empty());
        assert_eq!(f.conditions().len(), 4);
        assert!(matches!(
            &f.conditions()[0].kind,
            ConditionKind::FileMask { pattern, negated: false } if &**pattern == "*.jpg"
        ));
        assert!(matches!(
            &f.conditions()[1].kind,
            ConditionKind::FileMask { pattern, negated: false } if &**pattern == "*.gif"
        ));
        assert!(matches!(
            &f.conditions()[2].kind,
            ConditionKind::Size {
                metric: SizeMetric::Disk,
                op: CmpOp::Gt,
                bytes: 102_400
            }
        ));
        assert!(matches!(
            &f.conditions()[3].kind,
            ConditionKind::Age { field: AgeField::Modify, op: CmpOp::Lt, seconds } if *seconds == 6 * 30 * 86_400
        ));
    }

    /// Manual tag expression: `:tag:red+green-b` and `|:tag:1,3,-red` (FR-4.6).
    #[test]
    fn tag_expressions() {
        let c = only_condition(":tag:red+green-b");
        match &c.kind {
            ConditionKind::Tag { expr, negated } => {
                assert!(!negated);
                assert_eq!(expr.include, TagSet::RED.union(TagSet::GREEN));
                assert_eq!(expr.exclude, TagSet::BLUE);
            }
            k => panic!("unexpected {k:?}"),
        }

        let c = only_condition("|:tag:1,3,-red");
        match &c.kind {
            ConditionKind::Tag { expr, negated } => {
                assert!(negated);
                assert_eq!(expr.include, TagSet::RED.union(TagSet::GREEN));
                assert_eq!(expr.exclude, TagSet::RED);
            }
            k => panic!("unexpected {k:?}"),
        }

        // `:tags:` alias and `all`.
        let c = only_condition(":tags:all-b");
        match &c.kind {
            ConditionKind::Tag { expr, .. } => {
                assert_eq!(expr.include, TagSet::ALL);
                assert_eq!(expr.exclude, TagSet::BLUE);
            }
            k => panic!("unexpected {k:?}"),
        }
    }

    /// Legacy tag syntax (FR-4.6): `:red`/`:r`/`:1`..`:all`/`:a`, `|:red`.
    #[test]
    fn legacy_tags() {
        for (input, set) in [
            (":red", TagSet::RED),
            (":r", TagSet::RED),
            (":1", TagSet::RED),
            (":yellow", TagSet::YELLOW),
            (":y", TagSet::YELLOW),
            (":2", TagSet::YELLOW),
            (":green", TagSet::GREEN),
            (":g", TagSet::GREEN),
            (":3", TagSet::GREEN),
            (":blue", TagSet::BLUE),
            (":b", TagSet::BLUE),
            (":4", TagSet::BLUE),
            (":all", TagSet::ALL),
            (":a", TagSet::ALL),
            (":RED", TagSet::RED), // case-insensitive
        ] {
            let c = only_condition(input);
            match &c.kind {
                ConditionKind::Tag { expr, negated } => {
                    assert!(!negated, "{input}");
                    assert_eq!(expr.include, set, "{input}");
                    assert_eq!(expr.exclude, TagSet::EMPTY, "{input}");
                }
                k => panic!("unexpected {k:?} for {input}"),
            }
        }
        let c = only_condition("|:red");
        assert!(matches!(&c.kind, ConditionKind::Tag { negated: true, .. }));
    }

    /// Manual attribute expression: `:attr:+a-ro,h` (FR-4.7).
    #[test]
    fn attr_expression() {
        let c = only_condition(":attr:+a-ro,h");
        match &c.kind {
            ConditionKind::Attr { tests, negated } => {
                assert!(!negated);
                assert_eq!(
                    tests.as_slice(),
                    &[
                        AttrTest {
                            flags: NodeFlags::ARCHIVE,
                            requirement: AttrRequirement::Set
                        },
                        AttrTest {
                            flags: NodeFlags::READONLY,
                            requirement: AttrRequirement::Clear
                        },
                        AttrTest {
                            flags: NodeFlags::HIDDEN,
                            requirement: AttrRequirement::Set
                        },
                    ]
                );
            }
            k => panic!("unexpected {k:?}"),
        }

        // `:attrs:` alias, full names, negation.
        let c = only_condition("|:attrs:-system,+sparse");
        match &c.kind {
            ConditionKind::Attr { tests, negated } => {
                assert!(negated);
                assert_eq!(
                    tests.as_slice(),
                    &[
                        AttrTest {
                            flags: NodeFlags::SYSTEM,
                            requirement: AttrRequirement::Clear
                        },
                        AttrTest {
                            flags: NodeFlags::SPARSE,
                            requirement: AttrRequirement::Set
                        },
                    ]
                );
            }
            k => panic!("unexpected {k:?}"),
        }

        // Prefixes and the ads attribute.
        let c = only_condition(":attr:comp,enc,off,temp,noti,ads");
        match &c.kind {
            ConditionKind::Attr { tests, .. } => {
                assert_eq!(tests.len(), 6);
                assert_eq!(tests[5].flags, NodeFlags::ADS);
            }
            k => panic!("unexpected {k:?}"),
        }
    }

    /// Folder masks (FR-4.3): `\*internet*`, `\temp`, `|\temp`.
    #[test]
    fn folder_masks() {
        let c = only_condition("\\*internet*");
        assert!(matches!(
            &c.kind,
            ConditionKind::FolderMask { pattern, negated: false } if &**pattern == "*internet*"
        ));
        let c = only_condition("\\temp");
        assert!(matches!(
            &c.kind,
            ConditionKind::FolderMask { pattern, negated: false } if &**pattern == "temp"
        ));
        let c = only_condition("|\\temp");
        assert!(matches!(
            &c.kind,
            ConditionKind::FolderMask { pattern, negated: true } if &**pattern == "temp"
        ));
    }

    /// Size keywords, aliases, unambiguous prefixes, units (FR-4.4, FR-4.9).
    #[test]
    fn size_conditions() {
        let cases: &[(&str, SizeMetric, CmpOp, u64)] = &[
            (">100kb", SizeMetric::Disk, CmpOp::Gt, 100 * 1024),
            ("disksize>100kb", SizeMetric::Disk, CmpOp::Gt, 100 * 1024),
            ("clustersize>1kb", SizeMetric::Disk, CmpOp::Gt, 1024),
            ("filesize<1mb", SizeMetric::Logical, CmpOp::Lt, 1 << 20),
            ("logicalsize>2gb", SizeMetric::Logical, CmpOp::Gt, 2 << 30),
            ("size>10", SizeMetric::Disk, CmpOp::Gt, 10),
            ("disk>1mb", SizeMetric::Disk, CmpOp::Gt, 1 << 20),
            ("dsk>1mb", SizeMetric::Disk, CmpOp::Gt, 1 << 20),
            ("dsksz>1mb", SizeMetric::Disk, CmpOp::Gt, 1 << 20),
            ("d>1kb", SizeMetric::Disk, CmpOp::Gt, 1024), // unambiguous prefix
            (">100", SizeMetric::Disk, CmpOp::Gt, 100),   // bare number = bytes
            ("size > 10 mb", SizeMetric::Disk, CmpOp::Gt, 10 << 20), // spaced form
            (">1tb", SizeMetric::Disk, CmpOp::Gt, 1 << 40),
            (">42B", SizeMetric::Disk, CmpOp::Gt, 42), // case-insensitive unit
        ];
        for (input, metric, op, bytes) in cases {
            let c = only_condition(input);
            match &c.kind {
                ConditionKind::Size {
                    metric: m,
                    op: o,
                    bytes: b,
                } => {
                    assert_eq!((*m, *o, *b), (*metric, *op, *bytes), "{input}");
                }
                k => panic!("unexpected {k:?} for {input}"),
            }
        }
    }

    /// Age keywords, defaults, units (FR-4.5). Month = 30 days, year = 365.
    #[test]
    fn age_conditions() {
        let cases: &[(&str, AgeField, CmpOp, u64)] = &[
            ("<3months", AgeField::Modify, CmpOp::Lt, 3 * 30 * 86_400),
            ("a>1year", AgeField::Access, CmpOp::Gt, 365 * 86_400),
            ("m<2weeks", AgeField::Modify, CmpOp::Lt, 2 * 604_800),
            ("c<3days", AgeField::Creation, CmpOp::Lt, 3 * 86_400), // unit disambiguates `c`
            ("creation>1hours", AgeField::Creation, CmpOp::Gt, 3_600),
            ("modify>30minutes", AgeField::Modify, CmpOp::Gt, 1_800),
            ("access<10seconds", AgeField::Access, CmpOp::Lt, 10),
            (">1y", AgeField::Modify, CmpOp::Gt, 365 * 86_400), // unambiguous unit prefix
        ];
        for (input, field, op, seconds) in cases {
            let c = only_condition(input);
            match &c.kind {
                ConditionKind::Age {
                    field: f,
                    op: o,
                    seconds: s,
                } => {
                    assert_eq!((*f, *o, *s), (*field, *op, *seconds), "{input}");
                }
                k => panic!("unexpected {k:?} for {input}"),
            }
        }
        // `c` with a size unit is cluster size, not creation age.
        let c = only_condition("c>1kb");
        assert!(matches!(
            &c.kind,
            ConditionKind::Size {
                metric: SizeMetric::Disk,
                ..
            }
        ));
    }

    /// File classes (FR-4.8): case-insensitive name lookup, extension
    /// expansion at parse time, negation.
    #[test]
    fn class_conditions() {
        let classes = [
            FileClass::new("Audio/Music", ["mp3", ".wav"]),
            FileClass::new("Images", ["jpg", "gif"]),
        ];
        let f = Filter::parse(":class:Audio/Music", &classes);
        assert!(f.warnings().is_empty());
        match &f.conditions()[0].kind {
            ConditionKind::Class {
                name,
                extensions,
                negated,
            } => {
                assert_eq!(&**name, "Audio/Music");
                assert!(!negated);
                let exts: Vec<&str> = extensions.iter().map(|e| &**e).collect();
                assert_eq!(exts, ["mp3", "wav"]); // `.wav` normalized
            }
            k => panic!("unexpected {k:?}"),
        }
        // Case-insensitive lookup and negation.
        let f = Filter::parse("|:class:images", &classes);
        assert!(f.warnings().is_empty());
        assert!(matches!(
            &f.conditions()[0].kind,
            ConditionKind::Class { negated: true, name, .. } if &**name == "Images"
        ));
        // Unknown class: warning, condition dropped.
        let f = Filter::parse(":class:Nope", &classes);
        assert_eq!(f.warnings().len(), 1);
        assert!(f.warnings()[0].message.contains("unknown file class"));
        assert!(f.conditions().is_empty());
    }

    /// Empty conditions are skipped silently; the rest still parses.
    #[test]
    fn empty_conditions_skipped() {
        let f = parse("*.jpg;;>1mb;");
        assert!(f.warnings().is_empty());
        assert_eq!(f.conditions().len(), 2);
        assert!(Filter::parse("", &[]).is_empty());
        assert!(Filter::parse(" ; ; ", &[]).is_empty());
    }

    /// Spans track the trimmed condition positions (FR-4.13).
    #[test]
    fn condition_spans() {
        let f = parse("*.jpg; >1mb ;<3months");
        assert_eq!(f.conditions()[0].span, Span { start: 0, end: 5 });
        assert_eq!(f.conditions()[1].span, Span { start: 7, end: 11 });
        assert_eq!(f.conditions()[2].span, Span { start: 13, end: 21 });
    }

    /// Malformed input produces warnings with spans, never panics, and the
    /// bad condition is dropped (FR-4.9, FR-4.13).
    #[test]
    fn malformed_input_warnings() {
        let cases: &[(&str, &str)] = &[
            (">10zz", "unknown unit"),
            ("<3m", "ambiguous unit"), // minutes or months?
            ("foo>3", "unknown size/age keyword"),
            ("modify>3", "needs a unit"),
            (":tag:purple", "unknown tag"),
            (":tag:", "empty item"),
            (":attr:q", "unknown attribute"),
            (":attr:s", "ambiguous attribute"), // system or sparse?
            (":foo:bar", "unknown filter command"),
            ("|", "empty condition"),
            ("\\", "empty folder mask"),
            ("|>1mb", "negation"),
            (">=3", "'=' is not supported"),
            (">", "expected a number"),
        ];
        for (input, msg_part) in cases {
            let f = parse(input);
            assert_eq!(f.warnings().len(), 1, "{input}: {:?}", f.warnings());
            assert!(
                f.warnings()[0].message.contains(msg_part),
                "{input}: message {:?} should contain {msg_part:?}",
                f.warnings()[0].message
            );
            assert!(f.conditions().is_empty(), "{input}");
            let span = f.warnings()[0].span;
            assert_eq!(&input[span.start..span.end], input.trim(), "{input}");
        }
        // A bad condition does not sink its neighbors.
        let f = parse("*.jpg;>10zz;*.gif");
        assert_eq!(f.warnings().len(), 1);
        assert_eq!(f.conditions().len(), 2);
    }

    #[test]
    fn negated_file_mask() {
        let c = only_condition("|*.jpg");
        assert!(matches!(
            &c.kind,
            ConditionKind::FileMask { pattern, negated: true } if &**pattern == "*.jpg"
        ));
    }

    #[test]
    fn masks_may_contain_colons_and_spaces() {
        // ADS-style names and spaces stay plain file masks (no '<'/'>').
        let c = only_condition("*:Zone.Identifier");
        assert!(matches!(
            &c.kind,
            ConditionKind::FileMask { negated: false, .. }
        ));
        let c = only_condition("my file*");
        assert!(matches!(
            &c.kind,
            ConditionKind::FileMask { pattern, .. } if &**pattern == "my file*"
        ));
    }
}
