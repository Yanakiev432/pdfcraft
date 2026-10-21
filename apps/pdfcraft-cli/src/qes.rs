//! Explicitly opted-in local DSS verification, delegated to the pinned Python adapter.
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

pub(crate) fn verify(args: &[String]) -> Result<String, String> {
    if args.len() != 5 || args.get(1).map(String::as_str) != Some("--adapter") || args.get(3).map(String::as_str) != Some("--python") {
        return Err("usage: verify-qes <file.pdf> --adapter PATH --python PATH".into());
    }
    let pdf = &args[0];
    let adapter = &args[2];
    let python = &args[4];
    if !Path::new(pdf).is_file() || !Path::new(adapter).is_file() || !Path::new(python).is_file() {
        return Err("PDF, adapter and Python executable must exist".into());
    }
    let mut command = Command::new(python);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let output = command
        .arg("-I")
        .arg(adapter)
        .arg(pdf)
        .env_remove("PDFCRAFT_DSS_LOCAL_ENDPOINT")
        .output()
        .map_err(|e| format!("local DSS adapter execution failed: {e}"))?;
    if !output.status.success() {
        return Err(format!("local DSS adapter failed: {}", output.status));
    }
    let verdict: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|e| format!("invalid local DSS JSON: {e}"))?;
    if verdict.get("schema").and_then(serde_json::Value::as_str) != Some("pdfcraft.eidas.independent-dss.v1") {
        return Err("unexpected DSS adapter schema".into());
    }
    let pdf_bytes = std::fs::read(pdf).map_err(|e| format!("PDF digest read failed: {e}"))?;
    let actual_digest = Sha256::digest(&pdf_bytes).iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    if verdict.get("pdf_sha256").and_then(serde_json::Value::as_str) != Some(actual_digest.as_str()) {
        return Err("PDF SHA-256 mismatch between adapter report and current file".into());
    }
    Ok(verdict.to_string())
}

#[cfg(test)]
mod tests {
    use super::verify;

    #[test]
    fn requires_explicit_opt_in_arguments() {
        assert!(verify(&[]).is_err());
        assert!(verify(&["document.pdf".to_owned()]).is_err());
    }

    #[test]
    fn rejects_missing_local_inputs() {
        let args = ["not-a-real-document.pdf", "--adapter", "not-a-real-adapter.py", "--python", "not-a-real-python.exe"].map(str::to_owned);
        assert!(verify(&args).is_err());
    }
}
