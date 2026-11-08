//! Opt-in, loopback-only independent EU DSS QES verification.
//! Never signs documents, selects a certificate, imports trust anchors or loads
//! B-Trust middleware. The Rust CLI is a boundary around the pinned local
//! Python DSS adapter and independently rechecks the exact file digest.

use super::CliError;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

const MAX_PDF_SIZE: u64 = 64 * 1024 * 1024;
const ADAPTER_SCHEMA: &str = "pdfcraft.eidas.independent-dss.v1";
// Execute only the validator code embedded at build time. No arbitrary
// user-supplied Python adapter can be substituted for a QES verdict.
const PINNED_DSS_ADAPTER: &str = include_str!("../../../tools/eidas_dss_local_verify.py");

fn parse_options(args: &[String]) -> Result<(&str, &str, u16), String> {
    if args.len() != 3 && args.len() != 5 {
        return Err("usage: verify-qes <file.pdf> --python PATH [--dss-port 18080|8080]".into());
    }
    if args[1] != "--python" {
        return Err("verify-qes: --python must be explicit; no external validator script is accepted".into());
    }
    let port = if args.len() == 5 {
        if args[3] != "--dss-port" {
            return Err("verify-qes: unsupported option".into());
        }
        args[4].parse::<u16>().map_err(|_| "verify-qes: invalid DSS port")?
    } else {
        18080
    };
    if port != 18080 && port != 8080 {
        return Err("verify-qes: only explicitly configured local ports 18080 or 8080 are permitted".into());
    }
    Ok((&args[0], &args[2], port))
}

pub(crate) fn verify(args: &[String]) -> Result<String, CliError> {
    let (pdf, python, port) = parse_options(args)?;
    let path = Path::new(pdf);
    if !path.is_file() || path.extension().and_then(|x| x.to_str()).is_none_or(|x| !x.eq_ignore_ascii_case("pdf")) {
        return Err("verify-qes: supply an existing saved PDF".into());
    }
    let metadata = std::fs::metadata(path).map_err(|e| format!("verify-qes: PDF metadata: {e}"))?;
    if metadata.len() > MAX_PDF_SIZE {
        return Err("verify-qes: PDF exceeds 64 MiB local DSS QA limit".into());
    }
    if !Path::new(python).is_file() {
        return Err("verify-qes: explicit local Python interpreter must exist".into());
    }
    let endpoint = format!("http://127.0.0.1:{port}/services/rest/validation/validateSignature");
    let mut command = Command::new(python);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let output = command
        .arg("-I")
        .arg("-c")
        .arg(PINNED_DSS_ADAPTER)
        .arg(pdf)
        // Ignore inherited environment; use only this known loopback address.
        .env_remove("PDFCRAFT_DSS_LOCAL_ENDPOINT")
        .env("PDFCRAFT_DSS_LOCAL_ENDPOINT", endpoint)
        .output()
        .map_err(|e| format!("verify-qes: local DSS adapter failed to start: {e}"))?;
    if !output.status.success() {
        return Err(format!("verify-qes: DSS adapter did not validate the PDF (exit {:?})", output.status.code()).into());
    }
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| format!("verify-qes: invalid adapter JSON: {e}"))?;
    if report.get("schema").and_then(serde_json::Value::as_str) != Some(ADAPTER_SCHEMA) {
        return Err("verify-qes: unexpected independent DSS report schema".into());
    }
    let bytes = std::fs::read(path).map_err(|e| format!("verify-qes: PDF hash read failed: {e}"))?;
    let actual = Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    if report.get("pdf_sha256").and_then(serde_json::Value::as_str) != Some(actual.as_str()) {
        return Err("verify-qes: source file SHA-256 changed during independent validation".into());
    }
    if report.get("independent_dss_qes_pass").and_then(serde_json::Value::as_bool) != Some(true)
        || report.get("dss_indication").and_then(serde_json::Value::as_str) != Some("TOTAL_PASSED")
        || report.get("dss_signature_level").and_then(serde_json::Value::as_str) != Some("QESig")
    {
        return Err("verify-qes: local DSS did not confirm a Qualified Electronic Signature".into());
    }
    Ok(report.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_options;

    #[test]
    fn requires_explicit_options() {
        assert!(parse_options(&[]).is_err());
        assert!(parse_options(&["document.pdf".into()]).is_err());
    }
    #[test]
    fn rejects_unapproved_port() {
        let options = ["file.pdf", "--python", "python.exe", "--dss-port", "8081"].map(str::to_owned);
        assert!(parse_options(&options).is_err());
    }
    #[test]
    fn rejects_an_external_python_adapter_override() {
        let injected = ["file.pdf", "--adapter", "malicious.py", "--python", "python.exe"].map(str::to_owned);
        assert!(parse_options(&injected).is_err());
        assert!(super::PINNED_DSS_ADAPTER.contains("NoRedirect"));
        assert!(super::PINNED_DSS_ADAPTER.contains("PDFCRAFT_DSS_LOCAL_ENDPOINT"));
    }

    #[test]
    fn defaults_to_local_18080_and_explicit_8080() {
        let normal = ["file.pdf", "--python", "python.exe"].map(str::to_owned);
        assert_eq!(parse_options(&normal).map(|(_, _, port)| port).ok(), Some(18080));
        let custom = ["file.pdf", "--python", "python.exe", "--dss-port", "8080"].map(str::to_owned);
        assert_eq!(parse_options(&custom).map(|(_, _, port)| port).ok(), Some(8080));
    }
}
