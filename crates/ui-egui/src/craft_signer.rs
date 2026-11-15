//! Opt-in Windows GUI adapter for an authenticated Craft Signer broker.
//! No token PIN, QES signing or file mutation occurs here. QES verification
//! reports historical, byte-bound evidence rather than perpetual validity.
use pdfcraft_sign::craft_signer_client::{self, FileStamp};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

type Outcome = Result<(String, FileStamp), String>;
type Shared = Arc<Mutex<Option<Outcome>>>;
type Refresh = Arc<Mutex<Option<Result<FileStamp, String>>>>;
const REHASH_INTERVAL: Duration = Duration::from_secs(5);
const MAX_REFRESH_DURATION: Duration = Duration::from_secs(30);
const STALE_NOTICE: &str = "PDF changed or another document became active. The old QES result is not valid for this view. Save and check again.";

#[derive(Clone, Debug, Default)]
pub(crate) struct State {
    pub(crate) pending: bool,
    pub(crate) checked_path: Option<String>,
    pub(crate) message: String,
    stamp: Option<FileStamp>,
    outcome: Option<Shared>,
    stale: bool,
    refresh: Option<Refresh>,
    refresh_started: Option<Instant>,
    last_refresh: Option<Instant>,
}
impl State {
    /// Never compute SHA-256 from the UI thread. Per-frame metadata checks
    /// immediately reject ordinary changes. A periodic background digest
    /// checks same-size/content-only changes without blocking egui painting.
    pub(crate) fn unchanged(&self, path: Option<&str>) -> bool {
        if self.stale || self.checked_path.as_deref() != path {
            return false;
        }
        match (&self.stamp, path) {
            (Some(stamp), Some(p)) => stamp.matches_metadata(Path::new(p)),
            (None, _) => true,
            _ => false,
        }
    }

    pub(crate) fn freshness_pending(&self) -> bool {
        self.refresh.is_some()
    }

    fn invalidate(&mut self) {
        self.stale = true;
        self.stamp = None;
        self.message = STALE_NOTICE.into();
    }

    /// Called by the app logic even when the Signatures panel is hidden.
    /// Observed context changes permanently invalidate a pending or prior
    /// verdict until the user explicitly starts another verification.
    pub(crate) fn observe(&mut self, current: Option<&str>, dirty: bool, visible: bool) {
        let Some(checked) = self.checked_path.as_deref() else { return };
        if dirty || current != Some(checked) {
            self.invalidate();
            return;
        }
        if self.stale || self.pending {
            return;
        }
        let Some(stamp) = self.stamp.clone() else { return };
        let path = Path::new(checked);
        if !stamp.matches_metadata(path) {
            self.invalidate();
            return;
        }
        if let Some(started) = self.refresh_started {
            if self.refresh.is_some() && started.elapsed() >= MAX_REFRESH_DURATION {
                self.invalidate();
                self.refresh = None;
                self.refresh_started = None;
            }
            return;
        }
        if !visible || self.refresh.is_some() || self.last_refresh.is_some_and(|at| at.elapsed() < REHASH_INTERVAL) {
            return;
        }
        let file = checked.to_owned();
        let result: Refresh = Arc::new(Mutex::new(None));
        let worker_result = Arc::clone(&result);
        if std::thread::Builder::new()
            .name("pdfcraft-signer-freshness".into())
            .spawn(move || {
                let snapshot =
                    std::panic::catch_unwind(|| FileStamp::read(Path::new(&file))).unwrap_or_else(|_| Err("PDF freshness worker failed".into()));
                if let Ok(mut slot) = worker_result.lock() {
                    *slot = Some(snapshot);
                }
            })
            .is_err()
        {
            self.invalidate();
            return;
        }
        self.refresh = Some(result);
        self.refresh_started = Some(Instant::now());
    }

    pub(crate) fn poll(&mut self) {
        if let Some(outcome) = &self.outcome {
            let completed = outcome.lock().ok().and_then(|mut guard| guard.take());
            if let Some(res) = completed {
                if self.stale {
                    self.invalidate();
                } else {
                    match res {
                        Ok((msg, stamp)) => {
                            self.message = msg;
                            self.stamp = Some(stamp);
                            self.last_refresh = Some(Instant::now());
                        }
                        Err(msg) => {
                            self.message = msg;
                            self.stamp = None;
                        }
                    }
                }
                self.pending = false;
                self.outcome = None;
            }
        }
        if let Some(refresh) = &self.refresh {
            let completed = refresh.lock().ok().and_then(|mut guard| guard.take());
            if let Some(res) = completed {
                if !matches!(res, Ok(ref checked) if self.stamp.as_ref() == Some(checked)) {
                    self.invalidate();
                }
                self.last_refresh = Some(Instant::now());
                self.refresh_started = None;
                self.refresh = None;
            }
        }
    }
}
pub(crate) fn start(state: &mut State, pdf: Option<&str>, dirty: bool) {
    if state.pending {
        return;
    }
    state.checked_path = pdf.map(str::to_owned);
    state.stamp = None;
    state.stale = false;
    state.refresh = None;
    state.refresh_started = None;
    state.last_refresh = None;
    state.outcome = None;
    if dirty {
        state.message = "Save the PDF before checking its signature.".into();
        return;
    }
    let Some(path) = pdf.filter(|p| Path::new(p).is_file()) else {
        state.message = "Craft Signer needs a saved local PDF.".into();
        return;
    };
    let path = path.to_owned();
    state.pending = true;
    state.message = "Checking with the approved Craft Signer module...".into();
    let result: Shared = Arc::new(Mutex::new(None));
    let worker_result = Arc::clone(&result);
    state.outcome = Some(result);
    if std::thread::Builder::new()
        .name("pdfcraft-signer-verify".into())
        .spawn(move || {
            let res = std::panic::catch_unwind(|| craft_signer_client::verify_pdf(Path::new(&path)).map(|(verdict, stamp)| (verdict.message, stamp)))
                .unwrap_or_else(|_| Err("Craft Signer verification worker failed".into()));
            if let Ok(mut slot) = worker_result.lock() {
                *slot = Some(res);
            }
        })
        .is_err()
    {
        state.pending = false;
        state.outcome = None;
        state.message = "Cannot start Craft Signer verification worker.".into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(suffix: &str) -> (String, FileStamp) {
        let path = std::env::temp_dir().join(format!("pdfcraft-signer-view-{}-{suffix}.pdf", std::process::id(),));
        std::fs::write(&path, b"synthetic QA fixture (not a signed PDF)").unwrap();
        let stamp = FileStamp::read(&path).unwrap();
        (path.to_string_lossy().to_string(), stamp)
    }

    #[test]
    fn a_view_switch_cannot_resurrect_a_previous_qes_result() {
        let (path, stamp) = fixture("switch");
        let mut state =
            State { checked_path: Some(path.clone()), stamp: Some(stamp), message: "QES PASS at check time".into(), ..Default::default() };
        assert!(state.unchanged(Some(&path)));
        state.observe(Some("C:\\Another\\document.pdf"), false, true);
        state.observe(Some(&path), false, true);
        assert!(!state.unchanged(Some(&path)));
        assert!(!state.message.contains("QES PASS"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn external_pdf_change_invalidates_without_ui_thread_hashing() {
        let (path, stamp) = fixture("external");
        let mut state = State { checked_path: Some(path.clone()), stamp: Some(stamp), ..Default::default() };
        assert!(state.unchanged(Some(&path)));
        std::fs::write(&path, b"modified and longer synthetic PDF QA bytes").unwrap();
        state.observe(Some(&path), false, false);
        assert!(!state.unchanged(Some(&path)));
        assert!(state.stale);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn pending_positive_worker_result_is_rejected_after_document_switch() {
        let (path, stamp) = fixture("pending");
        let response: Shared = Arc::new(Mutex::new(Some(Ok(("PDF_QES_PASS".into(), stamp)))));
        let mut state = State { pending: true, checked_path: Some(path.clone()), outcome: Some(response), ..Default::default() };
        state.observe(None, false, true);
        state.observe(Some(&path), false, true);
        state.poll();
        assert!(!state.pending);
        assert!(state.stale);
        assert!(state.stamp.is_none());
        assert!(!state.message.contains("PDF_QES_PASS"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn background_digest_result_rejects_same_size_content_rewrite() {
        let (path, stamp) = fixture("refresh");
        let mut state = State { checked_path: Some(path.clone()), stamp: Some(stamp.clone()), ..Default::default() };
        let replacement = vec![b'x'; std::fs::metadata(&path).unwrap().len() as usize];
        std::fs::write(&path, replacement).unwrap();
        let changed = FileStamp::read(Path::new(&path)).unwrap();
        assert_eq!(stamp.sha256().len(), changed.sha256().len());
        assert_ne!(stamp.sha256(), changed.sha256());
        state.refresh = Some(Arc::new(Mutex::new(Some(Ok(changed)))));
        state.poll();
        assert!(state.stale);
        assert!(!state.unchanged(Some(&path)));
        std::fs::remove_file(path).unwrap();
    }
}
