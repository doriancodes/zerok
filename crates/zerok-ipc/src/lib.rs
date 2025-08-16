use serde::{Deserialize, Serialize};

pub const PLAN_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Debug)]
pub struct PlanV1 {
    pub exec_dir: String,  // e.g. "/var/lib/zerok/stage/abc123"
    pub exec_name: String, // usually "binary"
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,

    // (optional) policy knobs; add more as you wire sandboxing in the launcher
    pub memory_max: Option<u64>,
    pub pids_max: Option<u64>,
    pub file_read_allow: Vec<String>,
    pub net_allow: Vec<(String, u16)>,
}

/// Very simple framing: [u32 json_len][json][u64 bin_len][bin]
pub fn write_framed<W: std::io::Write>(mut w: W, plan: &PlanV1, bin: &[u8]) -> std::io::Result<()> {
    let json = serde_json::to_vec(plan).expect("serialize plan");
    w.write_all(&(json.len() as u32).to_be_bytes())?;
    w.write_all(&json)?;
    w.write_all(&(bin.len() as u64).to_be_bytes())?;
    w.write_all(bin)?;
    Ok(())
}

pub fn read_framed<R: std::io::Read>(mut r: R) -> std::io::Result<(PlanV1, Vec<u8>)> {
    use std::io::{Error, ErrorKind, Read};
    let mut u32b = [0u8; 4];
    let mut u64b = [0u8; 8];

    r.read_exact(&mut u32b)?;
    let json_len = u32::from_be_bytes(u32b) as usize;
    if json_len > (16 << 20) {
        return Err(Error::new(ErrorKind::InvalidData, "json too large"));
    }
    let mut json = vec![0u8; json_len];
    r.read_exact(&mut json)?;
    let plan: PlanV1 = serde_json::from_slice(&json)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("plan decode: {e}")))?;

    r.read_exact(&mut u64b)?;
    let bin_len = u64::from_be_bytes(u64b) as usize;
    if bin_len > (1 << 32) {
        return Err(Error::new(ErrorKind::InvalidData, "binary too large"));
    }
    let mut bin = vec![0u8; bin_len];
    r.read_exact(&mut bin)?;

    Ok((plan, bin))
}
