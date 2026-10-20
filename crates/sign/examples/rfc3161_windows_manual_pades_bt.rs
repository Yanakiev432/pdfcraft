//! Windows CNG / B-Trust-compatible manual RFC3161 in-flight PAdES test lane.
//! Uses the Windows Current User certificate store, never exports the private key
//! or handles a PIN; the provider's own UI controls hardware authorization.
//! Does NOT claim that a certificate or TSA is qualified for eIDAS.

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("Windows certificate store manual signing is only supported on Windows.");
}

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use pdfcraft_cos::Document;
    use pdfcraft_sign::{ManualTsaHandoff, SignOptions, Status, TrustStore, sign_with_timestamp, signatures, windows};

    let args: Vec<String> = env::args().collect();
    if args.len() != 7 && args.len() != 8 {
        return Err(
            "usage: rfc3161_windows_manual_pades_bt <source.pdf> <new-output.pdf> <windows:certificate-sha256> <existing-handoff-dir> <fresh-session-id> <PDF-date> [timeout-seconds]"
                .into(),
        );
    }
    let source = Path::new(&args[1]);
    let dest = Path::new(&args[2]);
    let identity_ref = &args[3];
    let directory = Path::new(&args[4]);
    let session = &args[5];
    let timeout: u64 = args.get(7).map(|s| s.parse()).transpose()?.unwrap_or(900);
    if !identity_ref.starts_with("windows:")
        || identity_ref.len() != "windows:".len() + 64
        || !identity_ref["windows:".len()..].bytes().all(|ch| ch.is_ascii_hexdigit())
    {
        return Err("select identity by its exact Windows certificate SHA-256 reference, not an ambiguous display name".into());
    }
    if !source.is_file() || !directory.is_dir() {
        return Err("source PDF and handoff directory must exist".into());
    }
    if !source.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
        || !dest.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
        || dest.exists()
        || fs::canonicalize(source).ok() == fs::canonicalize(dest).ok()
    {
        return Err("output must be a new, distinct .pdf file".into());
    }
    // Explicitly chosen user certificate from Windows Personal store.
    // This call does not sign; CNG invokes the legitimate provider UI at signing time.
    let id = windows::find(identity_ref)?;
    if windows::reference(&id.certificate) != *identity_ref {
        return Err("certificate reference does not match selected Windows identity".into());
    }
    let original = fs::read(source)?;
    let doc = Document::open(Arc::new(original.clone()))?;
    let authority = ManualTsaHandoff::new(directory, session, Duration::from_secs(timeout))?;
    eprintln!("SIGNER_CERTIFICATE_REFERENCE={identity_ref}");
    eprintln!("MANUAL_TSQ_LOCATION={}", authority.tsq_path().display());
    eprintln!("MANUAL_TSR_LOCATION={}", authority.tsr_path().display());
    eprintln!("READY_MARKER_LOCATION={}", authority.ready_path().display());

    let opts = SignOptions { date: args[6].clone(), page: 0, rect: Some([20.0, 100.0, 200.0, 150.0]), ..SignOptions::default() };
    // One provider-authorized CMS signature is held in memory throughout manual TSA work.
    // A cancelled PIN or expired handoff fails with no published signed output.
    let result = sign_with_timestamp(&doc, &id, &opts, &authority)?;
    if fs::read(source)? != original {
        return Err("PDF changed during the manual handoff; refusing output".into());
    }
    let signed_doc = Document::open(Arc::new(result.clone()))?;
    let checks = signatures(&signed_doc, &result, &TrustStore::default());
    if !checks.iter().any(|s| s.signed && !s.doc_timestamp && s.timestamp && s.signed_len == result.len() && s.status != Status::Invalid) {
        return Err("resulting signature or timestamp is not intact".into());
    }
    let mut f = OpenOptions::new().write(true).create_new(true).open(dest)?;
    if let Err(error) = f.write_all(&result).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = fs::remove_file(dest);
        return Err(error.into());
    }
    println!("WINDOWS_CNG_MANUAL_PADES_B_T_CRYPTOGRAPHIC_CANDIDATE bytes={}", result.len());
    println!("BTRUST_QES=NOT_INDEPENDENTLY_VERIFIED QTSA=NOT_CHECKED EU_DSS=NOT_CHECKED QUALIFIED_RELEASE=NO_GO");
    Ok(())
}
