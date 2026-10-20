//! Manual RFC 3161 PAdES B-T *test* candidate, holding ONE CMS signature in flight.
//! Does not touch B-Trust hardware, assert eIDAS qualification or call any network.
//! A human may obtain a matching .tsr from an authorized nonprofit/manual TSA form.
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pdfcraft_cos::Document;
use pdfcraft_sign::{ManualTsaHandoff, SignOptions, Status, TrustStore, pkcs12, sign_with_timestamp, signatures};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 7 && args.len() != 8 {
        return Err(
            "usage: rfc3161_manual_pades_bt <source.pdf> <nonexistent-output.pdf> <TEST-key.p12> <handoff-directory> <unique-session-id> <PDF-date> [timeout-seconds]"
                .into(),
        );
    }
    let source = Path::new(&args[1]);
    let dest = Path::new(&args[2]);
    let key = Path::new(&args[3]);
    let directory = Path::new(&args[4]);
    let session = &args[5];
    let timeout: u64 = args.get(7).map(|s| s.parse()).transpose()?.unwrap_or(900);
    if !source.is_file() || !key.is_file() || !directory.is_dir() {
        return Err("source PDF, TEST PKCS#12 and existing handoff directory are required".into());
    }
    if !source.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
        || !dest.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
        || dest.exists()
        || fs::canonicalize(source).ok() == fs::canonicalize(dest).ok()
    {
        return Err("output must be a distinct, nonexistent .pdf".into());
    }
    // Intentional restriction: only a disposable test software certificate.
    // Real B-Trust hardware signing belongs to an explicitly authorized CNG/PKCS#11
    // adapter with PIN entry through the official provider UI, never this CLI.
    let pass = env::var("PDFCRAFT_TEST_PKCS12_PASSWORD")
        .map_err(|_| "set PDFCRAFT_TEST_PKCS12_PASSWORD for a disposable TEST key")?;
    let id = pkcs12::open(&fs::read(key)?, &pass)?;
    let original = fs::read(source)?;
    let doc = Document::open(Arc::new(original.clone()))?;
    let authority = ManualTsaHandoff::new(directory, session, Duration::from_secs(timeout))?;
    eprintln!("HANDOFF_TSQ_LOCATION={}", authority.tsq_path().display());
    eprintln!("HANDOFF_TSR_LOCATION={}", authority.tsr_path().display());
    eprintln!("HANDOFF_READY_MARKER={}", authority.ready_path().display());
    let opts = SignOptions {
        date: args[6].clone(),
        page: 0,
        rect: Some([20.0, 100.0, 200.0, 150.0]),
        ..SignOptions::default()
    };
    let signed = sign_with_timestamp(&doc, &id, &opts, &authority)?;
    if fs::read(source)? != original {
        return Err("source PDF was modified during the manual timestamp handoff: no output written".into());
    }
    let signed_doc = Document::open(Arc::new(signed.clone()))?;
    let verified = signatures(&signed_doc, &signed, &TrustStore::default());
    if !verified.iter().any(|s| s.signed && !s.doc_timestamp && s.timestamp && s.signed_len == signed.len() && s.status != Status::Invalid) {
        return Err("final test PDF has no intact CMS signature timestamp".into());
    }
    let mut output = OpenOptions::new().write(true).create_new(true).open(dest)?;
    if let Err(error) = output.write_all(&signed).and_then(|_| output.sync_all()) {
        drop(output);
        let _ = fs::remove_file(dest);
        return Err(error.into());
    }
    println!("MANUAL_RFC3161_PADES_B_T_TEST_ONLY bytes={}", signed.len());
    println!("BTRUST_QES=NOT_TESTED QTSA=NOT_CHECKED EU_DSS=NOT_CHECKED QUALIFIED_RELEASE=NO_GO");
    Ok(())
}
