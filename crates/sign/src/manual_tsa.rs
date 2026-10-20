//! Explicit offline/manual RFC3161 request/response handoff for an in-flight signature.
//!
//! Does not contact the TSA and does not assert eIDAS QTSA qualification.
//! The caller retains its signer in the SAME process while a human obtains TSR.
//! A timeout/termination fails closed: a stale TSQ must NOT be retried by signing again.
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::timestamp::{TimestampAuthority, parse_request, parse_response};
use crate::{DigestAlg, SignError};

const MAX_REQUEST: usize = 1024 * 1024;
const MAX_RESPONSE: u64 = 4 * 1024 * 1024;
const POLL: Duration = Duration::from_millis(250);

fn invalid(msg: &str) -> SignError {
    SignError::Malformed(format!("manual RFC3161 handoff: {msg}"))
}
fn io_error(context: &str, e: std::io::Error) -> SignError {
    SignError::Crypto(format!("manual RFC3161 {context}: {e}"))
}

/// A one-shot, non-resumable manual RFC3161 request for a signature held
/// alive inside `sign_with_timestamp`. No credentials or PDF data are sent.
///
/// The caller must create `<session>.tsq`, then in a browser upload it only
/// where legally authorized. Save the reply as `<session>.tsr` and create
/// `<session>.tsr.ready` only after the TSR file has been fully written.
/// The marker prevents a partial download from being mistaken for a reply.
///
/// A cancelled/timed-out run cannot be resumed merely by reusing the TSQ;
/// a new signing attempt has a different CMS signature value.
/// The signer/private key and PIN remain entirely with the signing provider.
pub struct ManualTsaHandoff {
    directory: PathBuf,
    session: String,
    wait: Duration,
}

impl ManualTsaHandoff {
    pub fn new(directory: &Path, session: &str, wait: Duration) -> Result<Self, SignError> {
        if !(8..=64).contains(&session.len()) || !session.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
            return Err(invalid("session id must be 8..64 ASCII alphanumeric, hyphen or underscore characters"));
        }
        if wait.is_zero() || wait > Duration::from_secs(1800) {
            return Err(invalid("handoff timeout must be between 1 and 1800 seconds"));
        }
        let meta = fs::symlink_metadata(directory).map_err(|e| io_error("directory missing", e))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(invalid("handoff directory must be a real local directory, not a symlink"));
        }
        let directory = fs::canonicalize(directory).map_err(|e| io_error("canonical directory", e))?;
        let instance = Self { directory, session: session.into(), wait };
        if instance.tsq_path().exists() || instance.tsr_path().exists() || instance.ready_path().exists() {
            return Err(invalid("session files already exist: refuse reuse of a prior signing attempt"));
        }
        Ok(instance)
    }

    pub fn tsq_path(&self) -> PathBuf {
        self.directory.join(format!("{}.tsq", self.session))
    }
    pub fn tsr_path(&self) -> PathBuf {
        self.directory.join(format!("{}.tsr", self.session))
    }
    pub fn ready_path(&self) -> PathBuf {
        self.directory.join(format!("{}.tsr.ready", self.session))
    }
}

impl TimestampAuthority for ManualTsaHandoff {
    fn timestamp(&self, request: &[u8]) -> Result<Vec<u8>, SignError> {
        if request.is_empty() || request.len() > MAX_REQUEST {
            return Err(invalid("request is missing or larger than 1 MiB"));
        }
        let query = parse_request(request)?;
        if query.digest != DigestAlg::Sha256 || !query.certificate_request || !query.nonce.is_some_and(|n| n > 0) {
            return Err(invalid("requires SHA256, a positive nonce, and certReq=true"));
        }
        if self.tsq_path().exists() || self.tsr_path().exists() || self.ready_path().exists() {
            return Err(invalid("session already used, cannot replay or overwrite"));
        }
        {
            let mut file = OpenOptions::new().write(true).create_new(true).open(self.tsq_path()).map_err(|e| io_error("create exclusive TSQ", e))?;
            file.write_all(request).map_err(|e| io_error("write TSQ", e))?;
            file.sync_all().map_err(|e| io_error("sync TSQ", e))?;
        }
        eprintln!("MANUAL_TSQ_READY={}", self.tsq_path().display());
        eprintln!("Submit only the .tsq to your chosen authorized provider; then write the matching .tsr and create .tsr.ready");
        let began = Instant::now();
        loop {
            if let Ok(marker) = fs::symlink_metadata(self.ready_path()) {
                if !marker.file_type().is_file() {
                    return Err(invalid("ready marker must be a regular file, not a symlink"));
                }
                let meta = fs::symlink_metadata(self.tsr_path()).map_err(|e| io_error("response missing after ready marker", e))?;
                if !meta.file_type().is_file() || meta.len() < 10 || meta.len() > MAX_RESPONSE {
                    return Err(invalid("response must be a regular DER file 10 bytes..4 MiB"));
                }
                // Read from one open handle, with an explicit in-memory cap even if a
                // local writer grows or replaces the file after the metadata check.
                let file = fs::File::open(self.tsr_path()).map_err(|e| io_error("open response", e))?;
                let opened = file.metadata().map_err(|e| io_error("inspect response", e))?;
                if !opened.is_file() || opened.len() < 10 || opened.len() > MAX_RESPONSE {
                    return Err(invalid("response changed or exceeds 4 MiB"));
                }
                let mut bytes = Vec::with_capacity(opened.len() as usize);
                file.take(MAX_RESPONSE + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| io_error("read bounded response", e))?;
                if bytes.len() < 10 || bytes.len() as u64 > MAX_RESPONSE {
                    return Err(invalid("response changed or exceeds 4 MiB"));
                }
                // Cryptographically verifies CMS signature and binds imprint, nonce and policy.
                // Does NOT establish signer trust or qualified QTSA status.
                parse_response(&bytes, &query)?;
                return Ok(bytes);
            }
            if began.elapsed() >= self.wait {
                return Err(invalid("waiting for manual TSA response timed out: TSQ is orphaned, start a FRESH signing session"));
            }
            thread::sleep(POLL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Time;
    use crate::pkcs12;
    use crate::timestamp::{TimestampQuery, respond};

    fn tmp() -> PathBuf {
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        let name = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let p = std::env::temp_dir().join(format!("pdfcraft-manual-tsa-{name}"));
        fs::create_dir(&p).unwrap();
        p
    }

    fn query() -> Vec<u8> {
        TimestampQuery::new(DigestAlg::Sha256, DigestAlg::Sha256.digest(&[b"test CMS signature"]))
            .unwrap()
            .with_random_nonce()
            .unwrap()
            .encode()
            .unwrap()
    }

    #[test]
    fn manual_handoff_accepts_only_fresh_session_names_and_fails_closed_on_timeout() {
        let dir = tmp();
        assert!(ManualTsaHandoff::new(&dir, "../traverse", Duration::from_secs(1)).is_err());
        assert!(ManualTsaHandoff::new(&dir, "good-session", Duration::ZERO).is_err());
        let handoff = ManualTsaHandoff::new(&dir, "good-session", Duration::from_secs(1)).unwrap();
        assert!(handoff.timestamp(&query()).is_err());
        assert!(handoff.tsq_path().exists());
        assert!(ManualTsaHandoff::new(&dir, "good-session", Duration::from_secs(1)).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn already_present_response_must_not_be_used() {
        let dir = tmp();
        fs::write(dir.join("existing1.tsr"), b"malicious").unwrap();
        assert!(ManualTsaHandoff::new(&dir, "existing1", Duration::from_secs(2)).is_err());
        assert!(!dir.join("existing1.tsq").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn accepts_real_locally_signed_test_tsr_without_network() {
        let dir = tmp();
        let handoff = ManualTsaHandoff::new(&dir, "freshlocal", Duration::from_secs(8)).unwrap();
        let tsq_path = handoff.tsq_path();
        let tsr_path = handoff.tsr_path();
        let ready_path = handoff.ready_path();
        let producer = thread::spawn(move || {
            let start = Instant::now();
            while !tsq_path.exists() {
                assert!(start.elapsed() < Duration::from_secs(6));
                thread::sleep(Duration::from_millis(50));
            }
            let q = parse_request(&fs::read(tsq_path).unwrap()).unwrap();
            let data = fs::read(format!("{}/tests/data/rsa-aes.p12", env!("CARGO_MANIFEST_DIR"))).unwrap();
            let id = pkcs12::open(&data, "test").unwrap();
            let tsr = respond(
                &id.key,
                &id.certificate,
                &id.chain,
                DigestAlg::Sha256,
                &q,
                "1.2.3.4",
                Time { year: 2026, month: 10, day: 20, hour: 7, minute: 0, second: 0 },
                17,
            )
            .unwrap();
            fs::write(tsr_path, &tsr).unwrap();
            fs::write(ready_path, b"").unwrap();
        });
        let result = handoff.timestamp(&query()).unwrap();
        assert!(!result.is_empty());
        producer.join().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
