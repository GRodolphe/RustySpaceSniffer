//! SpaceSniffer-compatible filter DSL: parser, typed AST, and evaluator
//! (SPEC.md §4.4 with FR-4.1..FR-4.14, and the §5.6 pipeline).
//!
//! # Pipeline (§5.6)
//!
//! 1. **Parse**: [`Filter::parse`] splits the filter string on `;` into typed
//!    [`Condition`]s with per-condition [`Span`]s. Malformed conditions are
//!    dropped and reported as non-fatal [`ParseWarning`]s for the inline
//!    filter-field warning UI (FR-4.13) — parsing never fails wholesale.
//! 2. **Evaluate**: [`evaluate`] tests a filter against one tree node and
//!    returns the [`FilterVerdict`] tri-state (FR-4.11).
//! 3. **Combine**: conditions combine exactly per FR-4.10 — see [`eval`].
//!
//! Filters are pure functions of (tree, filter, tags); they never touch the
//! model, so changing a filter mid-scan never triggers a rescan (FR-4.1).
//!
//! # Syntax summary (§4.4)
//!
//! - `*.jpg` — file mask, `*`/`?` wildcards, case-insensitive (FR-4.2);
//!   `|*.jpg` negates.
//! - `\temp`, `\*internet*` — folder mask; matches when the node itself (if a
//!   directory) or any ancestor folder matches (FR-4.3).
//! - `>100kb`, `disksize>1mb`, `filesize<2gb` — size conditions; keywords
//!   `disksize`/`clustersize` (allocated, the default) and
//!   `filesize`/`logicalsize`, units `b`/`kb`/`mb`/`gb`/`tb` binary (FR-4.4).
//! - `<3months`, `a>1year` — age conditions against modify (default),
//!   creation, or access time; units seconds..years (FR-4.5). Note: one
//!   month is exactly 30 days and one year exactly 365 days.
//! - `:red`, `:r`, `:1`, `:all` — legacy tag conditions; `:tag:red+green-b`
//!   and `|:tag:1,3,-red` — 2.x tag expressions (FR-4.6).
//! - `:attr:+a-ro,h` — attribute conditions; `+`/bare = must be set, `-` =
//!   must be clear (FR-4.7).
//! - `:class:Audio/Music` — file class, expanded at parse time against the
//!   caller-provided [`FileClass`] table (FR-4.8).
//!
//! Keywords and units accept the documented aliases and prefixes that are
//! unambiguous by meaning; ambiguous input (e.g. the unit `m`) produces a
//! specific warning rather than a silent guess (FR-4.9).
//!
//! Canonical manual examples, all covered by unit tests:
//! `*.jpg;>1mb;<3months;|:yellow`, `*.jpg;*.gif;>100kb;<6months`,
//! `:tag:red+green-b`, `:attr:+a-ro,h`, `\*internet*`.
//!
//! # Windows-only considerations
//!
//! None — the crate is pure Rust and platform-clean.

#![forbid(unsafe_code)]

mod ast;
mod eval;
mod glob;
mod parse;

pub use ast::{
    AgeField, AttrRequirement, AttrTest, CmpOp, Condition, ConditionKind, FileClass, ParseWarning,
    SizeMetric, Span, TagExpr, TagSet,
};
pub use eval::{evaluate, FilterVerdict};
pub use glob::glob_match;

/// A parsed filter: typed conditions plus non-fatal parse warnings.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    conditions: Vec<Condition>,
    warnings: Vec<ParseWarning>,
}

impl Filter {
    /// Parse a filter string, expanding `:class:` names against the
    /// caller-provided `classes` table (FR-4.8). Pass `&[]` when no classes
    /// are configured; unknown class names yield warnings, not errors.
    pub fn parse(input: &str, classes: &[FileClass]) -> Self {
        let (conditions, warnings) = parse::parse_filter(input, classes);
        Self {
            conditions,
            warnings,
        }
    }

    /// The empty filter: everything passes.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parsed conditions, in source order.
    pub fn conditions(&self) -> &[Condition] {
        &self.conditions
    }

    /// Non-fatal parse warnings, with spans into the original filter string
    /// (FR-4.13).
    pub fn warnings(&self) -> &[ParseWarning] {
        &self.warnings
    }

    /// True when the filter has no conditions (everything passes).
    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty()
    }
}
