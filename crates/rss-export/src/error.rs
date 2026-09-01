//! Error type for the export crate.

use rss_core::NodeId;

/// Errors returned by the exporters.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The given root id does not refer to a live node in the tree.
    #[error("invalid root node id {0}")]
    InvalidRoot(NodeId),
    /// Writing to the output sink failed.
    #[error("I/O error during export: {0}")]
    Io(#[from] std::io::Error),
    /// The CSV writer failed.
    #[error("CSV export failed: {0}")]
    Csv(#[from] csv::Error),
    /// JSON serialization failed.
    #[error("JSON export failed: {0}")]
    Json(#[from] serde_json::Error),
}
