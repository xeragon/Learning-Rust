use crate::registry::RegistryHive;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct HiveBuilder;

impl HiveBuilder {
    pub fn build(hive: &RegistryHive) -> Result<Vec<u8>, i32> {
        let mut output = Vec::new();

        // Build 4KB header
        let header = Self::build_header();
        output.extend_from_slice(&header);

        // Build body (key records + value records + data cells)
        let body = Self::build_body(&hive.root)?;
        output.extend_from_slice(&body);

        Ok(output)
    }

    fn build_header() -> [u8; 4096] {
        let mut header = [0u8; 4096];

        // Magic bytes "regf"
        header[0..4].copy_from_slice(b"regf");

        // Primary sequence number (offset 4, 4 bytes)
        header[4..8].copy_from_slice(&1u32.to_le_bytes());

        // Secondary sequence number (offset 8, 4 bytes)
        header[8..12].copy_from_slice(&1u32.to_le_bytes());

        // File modification time (offset 12, 8 bytes) - use current time
        let filetime = get_filetime();
        header[12..20].copy_from_slice(&filetime.to_le_bytes());

        // Version (offset 20, 4 bytes)
        header[20..24].copy_from_slice(&4u32.to_le_bytes()); // Version 4

        // Hive format version (offset 24, 4 bytes)
        header[24..28].copy_from_slice(&6u32.to_le_bytes()); // Format version 6

        // Root key offset (offset 32, 4 bytes) - set to 0x20 (first key record offset)
        header[32..36].copy_from_slice(&0x20u32.to_le_bytes());

        // Hive data size (offset 40, 4 bytes) - will be updated
        header[40..44].copy_from_slice(&0x1000u32.to_le_bytes()); // Minimum 4KB

        // Cluster size (offset 44, 4 bytes)
        header[44..48].copy_from_slice(&1u32.to_le_bytes());

        header
    }

    fn build_body(_root_key: &crate::registry::RegistryKey) -> Result<Vec<u8>, i32> {
        // Simplified: just create minimal valid structure
        // Full implementation would recursively build all key/value records
        let mut body = Vec::new();

        // Minimal key record (nk record) - 76 bytes minimum
        let mut key_record = vec![0u8; 76];
        key_record[0..2].copy_from_slice(b"nk"); // Record type

        body.extend_from_slice(&key_record);
        Ok(body)
    }
}

fn get_filetime() -> u64 {
    const EPOCH_DIFF: u64 = 116444736000000000; // 100-nanosecond intervals between 1601 and 1970
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (now * 10000000) + EPOCH_DIFF
}
