//! Typed AST for the SpaceSniffer-compatible filter DSL (SPEC.md §4.4, §5.6).

use rss_core::{NodeFlags, Tag};

/// Byte-offset span of a condition within the original filter string.
///
/// Used to underline the offending condition for the inline warning UI
/// (FR-4.13).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Span {
    /// Byte offset of the first character (inclusive).
    pub start: usize,
    /// Byte offset one past the last character (exclusive).
    pub end: usize,
}

impl Span {
    pub(crate) fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Length of the span in bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the span covers zero bytes.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// A non-fatal problem found while parsing a filter string (FR-4.13).
///
/// The offending condition is dropped from the AST (fail-open: it does not
/// filter anything); the rest of the filter still applies.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[error("at {}..{}: {}", .span.start, .span.end, .message)]
pub struct ParseWarning {
    /// Span of the offending condition in the original filter string.
    pub span: Span,
    /// Human-readable description of the problem.
    pub message: String,
}

/// A single parsed condition with its source span.
#[derive(Clone, PartialEq, Debug)]
pub struct Condition {
    /// What to test.
    pub kind: ConditionKind,
    /// Byte span of this condition within the original filter string.
    pub span: Span,
}

/// The condition kinds of the filter DSL (SPEC.md §4.4).
#[derive(Clone, PartialEq, Debug)]
pub enum ConditionKind {
    /// File mask with `*`/`?` wildcards, matched case-insensitively against
    /// the node name (FR-4.2). `negated` corresponds to a leading `|`.
    FileMask { pattern: Box<str>, negated: bool },
    /// Folder mask (`\` prefix, FR-4.3): matches when the node itself (if a
    /// directory) or any ancestor directory name matches the pattern.
    FolderMask { pattern: Box<str>, negated: bool },
    /// Size condition (FR-4.4), compared against the node's own size.
    Size {
        metric: SizeMetric,
        op: CmpOp,
        bytes: u64,
    },
    /// Age condition (FR-4.5); `seconds` is the threshold age. Note: one
    /// month is exactly 30 days and one year exactly 365 days.
    Age {
        field: AgeField,
        op: CmpOp,
        seconds: u64,
    },
    /// Tag condition (FR-4.6), evaluated against the node's own tag plus
    /// tags inherited from ancestors (FR-5.2).
    Tag { expr: TagExpr, negated: bool },
    /// Attribute condition (FR-4.7); all entries must hold (AND-ed).
    Attr { tests: Vec<AttrTest>, negated: bool },
    /// File-class condition (FR-4.8): the class name was expanded to its
    /// extension list at parse time; matches when the node's extension is in
    /// the list.
    Class {
        name: Box<str>,
        extensions: Box<[Box<str>]>,
        negated: bool,
    },
}

/// Which size a [`ConditionKind::Size`] condition inspects (FR-4.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SizeMetric {
    /// Allocated ("disk" / "cluster") size — the documented default, also
    /// used by the bare `size` keyword and by conditions with no keyword.
    Disk,
    /// Logical ("file") size.
    Logical,
}

/// Which timestamp an age condition inspects (FR-4.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AgeField {
    /// Creation time (`creation`).
    Creation,
    /// Modification time (`modify`) — the documented default.
    Modify,
    /// Access time (`access`).
    Access,
}

/// Comparison operator; only `<` and `>` exist in the DSL.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CmpOp {
    /// Strictly less than.
    Lt,
    /// Strictly greater than.
    Gt,
}

impl CmpOp {
    pub(crate) fn apply(self, lhs: u64, rhs: u64) -> bool {
        match self {
            CmpOp::Lt => lhs < rhs,
            CmpOp::Gt => lhs > rhs,
        }
    }
}

/// A `:tag:` expression (FR-4.6): the `include` set is OR-ed, the `exclude`
/// set is subtracted.
///
/// An empty `include` set means "any tag" (the `:all` behavior), so e.g.
/// `:tag:-blue` matches any node carrying a tag other than blue (and requires
/// some tag to be present).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TagExpr {
    /// Tags that match (OR-ed). Empty means "any tag".
    pub include: TagSet,
    /// Tags that veto a match.
    pub exclude: TagSet,
}

impl TagExpr {
    /// Test the expression against the effective tag set of a node (own tag
    /// plus inherited ancestor tags, FR-5.2).
    pub(crate) fn matches(&self, effective: TagSet) -> bool {
        let include = if self.include.is_empty() {
            TagSet::ALL
        } else {
            self.include
        };
        effective.intersects(include) && !effective.intersects(self.exclude)
    }
}

/// Bit set over the four tag colors (FR-5.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TagSet(u8);

impl TagSet {
    /// No tags.
    pub const EMPTY: Self = Self(0);
    /// All four tags.
    pub const ALL: Self = Self(0b1111);
    /// Only red.
    pub const RED: Self = Self(1 << 0);
    /// Only yellow.
    pub const YELLOW: Self = Self(1 << 1);
    /// Only green.
    pub const GREEN: Self = Self(1 << 2);
    /// Only blue.
    pub const BLUE: Self = Self(1 << 3);

    fn bit(tag: Tag) -> u8 {
        match tag {
            Tag::Red => Self::RED.0,
            Tag::Yellow => Self::YELLOW.0,
            Tag::Green => Self::GREEN.0,
            Tag::Blue => Self::BLUE.0,
        }
    }

    /// Singleton set containing `tag`.
    pub fn from_tag(tag: Tag) -> Self {
        Self(Self::bit(tag))
    }

    /// Whether `tag` is in the set.
    pub fn contains(self, tag: Tag) -> bool {
        self.0 & Self::bit(tag) != 0
    }

    /// Add `tag` to the set.
    pub fn insert(&mut self, tag: Tag) {
        self.0 |= Self::bit(tag);
    }

    /// Union of two sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether the two sets share at least one tag.
    pub fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Whether the set is empty.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) fn set_union(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// Whether an attribute must be set or clear (FR-4.7 `+`/`-` prefixes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttrRequirement {
    /// The attribute must be set (`+x` or bare `x`).
    Set,
    /// The attribute must be clear (`-x`).
    Clear,
}

/// One entry of an `:attr:` condition (FR-4.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AttrTest {
    /// The attribute flag to test.
    pub flags: NodeFlags,
    /// Whether the flag must be set or clear.
    pub requirement: AttrRequirement,
}

impl AttrTest {
    pub(crate) fn matches(&self, flags: NodeFlags) -> bool {
        match self.requirement {
            AttrRequirement::Set => flags.contains(self.flags),
            AttrRequirement::Clear => !flags.contains(self.flags),
        }
    }
}

/// Caller-provided file class definition used to expand `:class:` conditions
/// (FR-4.8): a name plus the extension list it stands for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileClass {
    /// Class name (matched case-insensitively by `:class:` conditions).
    pub name: String,
    /// Extensions (normalized: lowercase, no leading dot, no empties).
    pub extensions: Vec<String>,
}

impl FileClass {
    /// Create a class, normalizing its extensions (lowercased, leading dots
    /// stripped, empties dropped) so matching is case-insensitive.
    pub fn new(
        name: impl Into<String>,
        extensions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            extensions: extensions
                .into_iter()
                .map(|e| e.into().trim_start_matches('.').to_lowercase())
                .filter(|e| !e.is_empty())
                .collect(),
        }
    }
}
