//! Shared fixtures for the fuzz targets: one throwaway vault per process.
//!
//! The vaults live under the system temp dir in a `sg-fuzz-*` directory that is never removed by
//! the process (a fuzz run can abort at any time); `scripts/fuzz.sh` deletes leftovers.

use sg_core::{crypto::random_key, KeyInput, Vault};
use std::sync::Arc;

pub fn temp_vault() -> Arc<Vault> {
    let dir = tempfile::Builder::new()
        .prefix("sg-fuzz-")
        .tempdir()
        .expect("tempdir")
        .keep();
    Arc::new(Vault::init(&dir.join("v.db"), KeyInput::Raw(random_key())).expect("vault init"))
}

/// Cap a lossy-decoded string so one iteration stays cheap.
pub fn lossy(data: &[u8], max: usize) -> String {
    let data = &data[..data.len().min(max)];
    String::from_utf8_lossy(data).into_owned()
}
