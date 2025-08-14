use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable on-disk manifest representation you can evolve over time.
/// Keep this strictly the subset you want both CLI and runner to share.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    // Add capability fields here gradually as you split code out of `zerok`
    // e.g., pub capabilities: Capabilities,
}

/// Simple header description matching your README table.
/// (Byte parsing can live here later; keeping it plain for now.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KpkgHeader {
    pub magic: [u8; 4],       // "KPKG"
    pub version: u16,         // e.g., 1
    pub manifest_size: u32,   // bytes
    pub binary_size: u64,     // bytes
    pub binary_offset: u64,   // start offset
    pub manifest_offset: u64, // start offset
}

impl fmt::Display for KpkgHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KPKG v{} (manifest: {}B @ {}, binary: {}B @ {})",
            self.version,
            self.manifest_size,
            self.manifest_offset,
            self.binary_size,
            self.binary_offset
        )
    }
}

/// Common error type placeholder for future parsing/verification routines.
#[derive(thiserror::Error, Debug)]
pub enum CoreError {
    #[error("invalid magic")]
    InvalidMagic,
    #[error("truncated header")]
    TruncatedHeader,
    #[error("offset/size out of bounds")]
    Bounds,
    #[error("{0}")]
    Other(String),
}
