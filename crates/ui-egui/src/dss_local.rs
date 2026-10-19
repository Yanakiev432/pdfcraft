//! Opt-in local EU DSS check. Independent from PdfCraft's native trust verdict.
#[cfg(not(target_arch = "wasm32"))]
use sha2::{Digest, Sha256};
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileStamp {
    len: u64,
    modified: std::time::SystemTime,
}

impl FileStamp {
    fn read(path: &str) -> std::io::Result<Self> {
        let m = std::fs::metadata(path)?;
        Ok(Self { len: m.len(), modified: m.modified()? })
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct State {
    pub(crate) pending: bool,
    pub(crate) checked_path: Option<String>,
    pub(crate) message: String,
    verified_stamp: Option<FileStamp>,
    pub(crate) outcome: Option<std::sync::Arc<std::sync::Mutex<Option<Result<(String, FileStamp), String>>>>>,
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn start(state: &mut State, pdf: Option<&str>, dirty: bool) {
    if state.pending {
        return;
    }
    state.checked_path = pdf.map(str::to_owned);
    state.verified_stamp = None;
    if dirty {
        state.message = "Save the document before independent DSS validation.".into();
        return;
    }
    let Some(pdf) = pdf.filter(|p| std::path::Path::new(p).is_file()) else {
        state.message = "Independent DSS requires a saved local PDF.".into();
        return;
    };
    // Operator-supplied paths: no hidden interpreter or script discovery.
    let (Ok(python), Ok(adapter)) = (std::env::var("PDFCRAFT_DSS_PYTHON"), std::env::var("PDFCRAFT_DSS_ADAPTER")) else {
        state.message = "Configure PDFCRAFT_DSS_PYTHON and PDFCRAFT_DSS_ADAPTER to enable local DSS.".into();
        return;
    };
    if !std::path::Path::new(&python).is_file() || !std::path::Path::new(&adapter).is_file() {
        state.message = "Configured local DSS Python or adapter path does not exist.".into();
        return;
    }
    let path = pdf.to_owned();
    let result = std::sync::Arc::new(std::sync::Mutex::new(None));
    let worker_result = std::sync::Arc::clone(&result);
    state.checked_path = Some(path.clone());
    state.pending = true;
    state.message = "Independent EU DSS validation in progress...".into();
    state.outcome = Some(result);
    std::thread::spawn(move || {
        let outcome = run(&python, &adapter, &path);
        if let Ok(mut guard) = worker_result.lock() {
            *guard = Some(outcome);
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn run(python: &str, adapter: &str, pdf: &str) -> Result<(String, FileStamp), String> {
    let output = std::process::Command::new(python)
        .arg("-I")
        .arg(adapter)
        .arg(pdf)
        .env_remove("PDFCRAFT_DSS_LOCAL_ENDPOINT")
        .output()
        .map_err(|e| format!("Could not start local DSS adapter: {e}"))?;
    if !output.status.success() {
        return Err(format!("Local DSS validation unavailable or failed ({}).", output.status));
    }
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|_| "Local DSS returned invalid JSON.".to_owned())?;
    if report.get("schema").and_then(serde_json::Value::as_str) != Some("pdfcraft.eidas.independent-dss.v1") {
        return Err("Unexpected independent DSS report schema.".into());
    }
    let before = FileStamp::read(pdf).map_err(|e| format!("Cannot stat PDF: {e}"))?;
    let actual_sha256 =
        Sha256::digest(std::fs::read(pdf).map_err(|e| format!("Cannot re-read PDF: {e}"))?).iter().map(|b| format!("{b:02x}")).collect::<String>();
    let after = FileStamp::read(pdf).map_err(|e| format!("Cannot stat verified PDF: {e}"))?;
    if before != after {
        return Err("PDF changed during verification.".into());
    }
    if report.get("pdf_sha256").and_then(serde_json::Value::as_str) != Some(actual_sha256.as_str()) {
        return Err("PDF changed during DSS validation (SHA-256 mismatch).".into());
    }
    // Only an independent, positive DSS report is displayed as QES PASS.
    let passed = report.get("independent_dss_qes_pass").and_then(serde_json::Value::as_bool) == Some(true)
        && report.get("dss_indication").and_then(serde_json::Value::as_str) == Some("TOTAL_PASSED")
        && report.get("dss_signature_level").and_then(serde_json::Value::as_str) == Some("QESig");
    let result = if passed { "QES PASS" } else { "No QES PASS" };
    Ok((format!("Independent EU DSS: {result}. Native validation is separate."), after))
}

impl State {
    /// False for a replaced/saved PDF, even when its path is unchanged.
    pub(crate) fn checked_file_unchanged(&self, path: Option<&str>) -> bool {
        match (&self.verified_stamp, path) {
            (Some(expected), Some(path)) => FileStamp::read(path).is_ok_and(|actual| actual == *expected),
            (None, _) => true,
            _ => false,
        }
    }

    pub(crate) fn poll(&mut self) {
        let Some(outcome) = self.outcome.as_ref() else { return };
        let completed = outcome.lock().ok().and_then(|mut guard| guard.take());
        if let Some(result) = completed {
            match result {
                Ok((message, stamp)) => {
                    self.message = message;
                    self.verified_stamp = Some(stamp);
                }
                Err(e) => {
                    self.message = format!("Independent DSS: {e}");
                    self.verified_stamp = None;
                }
            }
            self.pending = false;
            self.outcome = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::State;

    #[test]
    fn starts_unconfigured_and_without_qes_claim() {
        let state = State::default();
        assert!(!state.pending);
        assert!(state.message.is_empty());
        assert!(state.outcome.is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn dirty_document_rejected_without_running_worker() {
        let mut state = State::default();
        super::start(&mut state, Some("saved.pdf"), true);
        assert!(!state.pending);
        assert!(state.message.contains("Save"));
        assert!(state.outcome.is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn saved_pdf_replacement_invalidates_previous_validation() {
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("pdfcraft-dss-stamp-{}-{unique}.pdf", std::process::id()));
        let filename = path.to_str().unwrap();
        std::fs::write(&path, b"original").unwrap();
        let mut state = State::default();
        state.verified_stamp = Some(super::FileStamp::read(filename).unwrap());
        assert!(state.checked_file_unchanged(Some(filename)));
        std::fs::write(&path, b"modified PDF bytes and length").unwrap();
        assert!(!state.checked_file_unchanged(Some(filename)));
        std::fs::remove_file(&path).unwrap();
    }
}
