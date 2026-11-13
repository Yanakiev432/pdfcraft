//! Opt-in asynchronous Windows GUI adapter; all security and broker code
//! is shared with the headless automation tool in pdfcraft-sign.
use pdfcraft_sign::craft_signer_client::{self, FileStamp};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

type Outcome = Result<(String, FileStamp), String>;
type Shared = Arc<Mutex<Option<Outcome>>>;

#[derive(Clone, Debug, Default)]
pub(crate) struct State {
    pub(crate) pending: bool,
    pub(crate) checked_path: Option<String>,
    pub(crate) message: String,
    stamp: Option<FileStamp>,
    outcome: Option<Shared>,
}
impl State {
    pub(crate) fn unchanged(&self, path: Option<&str>) -> bool {
        match (&self.stamp, path) {
            (Some(stamp), Some(p)) => FileStamp::read(Path::new(p)).is_ok_and(|now| now == *stamp),
            (None, _) => true,
            _ => false,
        }
    }
    pub(crate) fn poll(&mut self) {
        let Some(outcome) = &self.outcome else { return };
        let completed = outcome.lock().ok().and_then(|mut guard| guard.take());
        if let Some(res) = completed {
            match res {
                Ok((msg, stamp)) => {
                    self.message = msg;
                    self.stamp = Some(stamp);
                }
                Err(msg) => {
                    self.message = msg;
                    self.stamp = None;
                }
            }
            self.pending = false;
            self.outcome = None;
        }
    }
}
pub(crate) fn start(state: &mut State, pdf: Option<&str>, dirty: bool) {
    if state.pending {
        return;
    }
    state.checked_path = pdf.map(str::to_owned);
    state.stamp = None;
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
    std::thread::spawn(move || {
        let res = craft_signer_client::verify_pdf(Path::new(&path)).map(|(verdict, stamp)| (verdict.message, stamp));
        if let Ok(mut slot) = worker_result.lock() {
            *slot = Some(res);
        }
    });
}
