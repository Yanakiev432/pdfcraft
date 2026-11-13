//! Verified client for an explicitly installed, publisher-approved Craft Signer.
//! Windows-only. Does not sign documents, use a token PIN or start any service.
use crate::{Certificate, DigestAlg, cms, der::Tlv};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const MOD_ID: &str = "org.craftopensource.signer";
const MAX_PDF: u64 = 64 * 1024 * 1024;
const MAX_EXE: u64 = 160 * 1024 * 1024;
const REPARSE_POINT: u32 = 0x400;
const FILE_SHARE_READ: u32 = 1;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const BROKER_TIMEOUT: Duration = Duration::from_secs(90);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileStamp {
    size: u64,
    modified: SystemTime,
    sha256: String,
}
impl FileStamp {
    /// Exact checked bytes, not a filename/mtime proxy.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn read(path: &Path) -> Result<Self, String> {
        guarded_path(path)?;
        let before = fs::metadata(path).map_err(|_| "Cannot read saved PDF metadata")?;
        if !before.is_file() || before.len() > MAX_PDF {
            return Err("PDF must be a local file smaller than 64 MiB".into());
        }
        let modified = before.modified().map_err(|_| "Cannot read PDF timestamp")?;
        let hash = digest_file(path, MAX_PDF)?;
        let after = fs::metadata(path).map_err(|_| "PDF disappeared during hashing")?;
        if before.len() != after.len() || after.modified().ok() != Some(modified) {
            return Err("PDF changed during hashing".into());
        }
        Ok(Self { size: before.len(), modified, sha256: hash })
    }
}

/// Windows canonicalize produces \\?\C:\... for normal local files.
/// Permit only a DOS drive path and strip that extended prefix *before*
/// handing the path to the C# broker, which deliberately rejects device paths.
fn local_dos_path(path: &Path) -> Result<PathBuf, String> {
    let value = path.to_str().ok_or("Non-Unicode local path is not supported")?;
    let dos = value.strip_prefix(r"\\?\").unwrap_or(value);
    let bytes = dos.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || !matches!(bytes[2], b'\\' | b'/') {
        return Err("Network and device paths are not permitted".into());
    }
    let normalized = PathBuf::from(dos);
    if !normalized.is_absolute() {
        return Err("An absolute local path is required".into());
    }
    Ok(normalized)
}

fn guarded_path(path: &Path) -> Result<(), String> {
    let local = local_dos_path(path)?;
    for p in local.ancestors() {
        if p.as_os_str().is_empty() {
            break;
        }
        if let Ok(meta) = fs::symlink_metadata(p) {
            if meta.file_attributes() & REPARSE_POINT != 0 {
                return Err("Reparse points and junctions are not accepted".into());
            }
        }
    }
    Ok(())
}

fn digest_file(path: &Path, max: u64) -> Result<String, String> {
    guarded_path(path)?;
    let mut f = File::open(path).map_err(|_| "Cannot read file for SHA-256")?;
    if f.metadata().map_err(|_| "Cannot stat file")?.len() > max {
        return Err("File exceeds the safety limit".into());
    }
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = f.read(&mut buf).map_err(|_| "File read failed")?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(lower_hex(&hash.finalize()))
}
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    guarded_path(path)?;
    let file = File::open(path).map_err(|_| "A signed module file is missing")?;
    if file.metadata().map_err(|_| "Cannot stat signed module")?.len() > max {
        return Err("Signed module file too large".into());
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).map_err(|_| "Cannot read signed module")?;
    if bytes.len() as u64 > max {
        return Err("Signed module exceeds limit".into());
    }
    Ok(bytes)
}
fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, String> {
    v.get(name).and_then(Value::as_str).ok_or_else(|| format!("Missing module field: {name}"))
}
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.as_bytes().iter().all(u8::is_ascii_hexdigit)
}
fn release_leaf(s: &str) -> bool {
    s.len() <= 70 && !s.is_empty() && !s.starts_with('.') && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
}
fn parse_json(path: &Path, max: u64) -> Result<Value, String> {
    serde_json::from_slice(&read_bounded(path, max)?).map_err(|_| "Invalid module JSON".into())
}
fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}
fn authenticate_signed_manifest(
    manifest_bytes: &[u8],
    manifest_signature: &[u8],
    publisher_bytes: &[u8],
    publisher_key: &str,
) -> Result<Value, String> {
    let signed: Value = serde_json::from_slice(manifest_bytes).map_err(|_| "Invalid signed manifest JSON")?;
    let cert = Certificate::parse(publisher_bytes).map_err(|_| "Invalid publisher certificate")?;
    if sha(&cert.public_key.spki()) != publisher_key.to_ascii_lowercase() {
        return Err("Approved public key does not match the signer".into());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "Invalid system time")?.as_secs() as i64;
    if now < cert.not_before.unix() || now > cert.not_after.unix() {
        return Err("Publisher certificate is not currently valid".into());
    }
    // The generic CMS parser exposes the first signer; demand exactly one.
    let cms_der = Tlv::parse_all(manifest_signature).map_err(|_| "Invalid signed catalog DER")?;
    let ci = cms_der.children().map_err(|_| "Invalid signed catalog ContentInfo")?;
    let sd = ci
        .get(1)
        .ok_or("Missing signed catalog data")?
        .inner()
        .map_err(|_| "Invalid signed catalog data")?
        .children()
        .map_err(|_| "Invalid signed catalog fields")?;
    let infos = sd.last().ok_or("Missing signerInfos")?.children().map_err(|_| "Invalid signerInfos")?;
    if infos.len() != 1 {
        return Err("Exactly one publisher signature is required".into());
    }
    let cms = cms::SignedData::parse(manifest_signature).map_err(|_| "Cannot parse CMS catalog signature")?;
    if cms.content.is_some() {
        return Err("Signed module catalog unexpectedly embeds content".into());
    }
    if cms.econtent_type != cms::DATA {
        return Err("Signed module catalog has an unexpected content type".into());
    }
    if cms.signer.digest != DigestAlg::Sha256 {
        return Err("Signed module catalog has an unapproved digest algorithm".into());
    }
    let content_hash = Sha256::digest(manifest_bytes);
    // RFC 5652 permits a detached id-data signature without signedAttrs:
    // it then signs the content digest directly. A message-digest attribute
    // is mandatory *when signedAttrs exist*; never accept unsigned attributes
    // as a substitute for a cryptographically checked signature.
    if cms.signer.signed_attrs.is_some() {
        if cms.signer.message_digest.as_deref() != Some(content_hash.as_slice()) {
            return Err("Signed module catalog content digest does not match the manifest".into());
        }
    } else if cms.signer.message_digest.is_some() {
        return Err("Unexpected unsigned message digest attribute in module catalog".into());
    }
    if cms.signer_certificate().is_none_or(|c| c.raw != publisher_bytes) {
        return Err("Signed module catalog signer certificate did not match publisher".into());
    }
    if cms.verify_signature(&cert, &content_hash).ok() != Some(true) {
        return Err("Signed module catalog cryptographic signature failed".into());
    }
    Ok(signed)
}

/// Fail closed before CreateProcess: the module is under a fixed owner-specific
/// directory, with a locally approved publisher key and a signed manifest.
fn approved_broker() -> Result<(PathBuf, File), String> {
    let local = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is unavailable")?;
    let root = PathBuf::from(local).join("Craft").join("Extensions");
    let policy = parse_json(&root.join("_trust").join("org.craftopensource.signer.json"), 8192)
        .map_err(|_| "Craft Signer is not installed with approved publisher policy")?;
    if field(&policy, "schema")? != "craft.signer/local-developer-approval/1" || field(&policy, "moduleId")? != MOD_ID {
        return Err("Publisher approval policy is not valid".into());
    }
    let publisher_key = field(&policy, "keySha256")?;
    if !is_hex64(publisher_key) {
        return Err("Invalid approved publisher key".into());
    }

    let module = root.join(MOD_ID);
    let registration = parse_json(&module.join("current.json"), 8192).map_err(|_| "No independently installed Craft Signer module was found")?;
    if field(&registration, "moduleId")? != MOD_ID
        || registration.get("protocolMajor").and_then(Value::as_u64) != Some(1)
        || !field(&registration, "publisherPublicKeySha256")?.eq_ignore_ascii_case(publisher_key)
    {
        return Err("Current module registration is not approved".into());
    }
    let leaf = field(&registration, "releaseDirectory")?;
    if !release_leaf(leaf) {
        return Err("Invalid signer release path".into());
    }
    let release = module.join("releases").join(leaf);
    guarded_path(&release)?;
    let manifest_bytes = read_bounded(&release.join("manifest.json"), 16384)?;
    let manifest_signature = read_bounded(&release.join("manifest.p7s"), 65536)?;
    let publisher_bytes = read_bounded(&release.join("publisher.cer"), 16384)?;
    let signed = authenticate_signed_manifest(&manifest_bytes, &manifest_signature, &publisher_bytes, publisher_key)?;
    if field(&signed, "schema")? != "craft.signer/module-preview-v2"
        || field(&signed, "moduleId")? != MOD_ID
        || field(&signed, "moduleVersion")? != field(&registration, "moduleVersion")?
        || signed.get("protocolMajor").and_then(Value::as_u64) != Some(1)
    {
        return Err("Unsupported or changed signed module manifest".into());
    }
    let expected_leaf = format!("{}-{}", field(&signed, "moduleVersion")?, sha(&manifest_bytes)[..16].to_ascii_uppercase());
    if leaf != expected_leaf {
        return Err("Signed catalog does not match registered release directory".into());
    }
    let actions = signed.get("actions").and_then(Value::as_array).ok_or("Missing signed command list")?;
    if actions.as_slice() != [json!("document.sign"), json!("document.verify")] {
        return Err("Signed module command list is not approved".into());
    }
    let workers = signed.get("workers").and_then(Value::as_array).ok_or("Missing signed worker list")?;
    if workers.len() != 3 {
        return Err("Signed module must have three executables".into());
    }
    for name in ["craft-signer-broker.exe", "wordcraft-cli.exe", "gridcraft-cli.exe"] {
        if workers.iter().filter(|w| w.get("file").and_then(Value::as_str) == Some(name)).count() != 1 {
            return Err("Signed worker catalog mismatch".into());
        }
    }
    let worker =
        workers.iter().find(|w| w.get("file").and_then(Value::as_str) == Some("craft-signer-broker.exe")).ok_or("Signed broker not listed")?;
    let expected = field(worker, "sha256")?;
    if !is_hex64(expected) {
        return Err("Invalid signed broker SHA-256".into());
    }
    let broker = release.join("craft-signer-broker.exe");
    guarded_path(&broker)?;
    // Keep a no-write/no-delete share lock until the process starts.
    let mut locked = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(&broker).map_err(|_| "Cannot lock signed broker executable")?;
    if locked.metadata().map_err(|_| "Cannot stat signed broker")?.len() > MAX_EXE {
        return Err("Signed broker exceeds size limit".into());
    }
    let mut digest = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = locked.read(&mut buf).map_err(|_| "Cannot read signed broker")?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    if lower_hex(&digest.finalize()) != expected.to_ascii_lowercase() {
        return Err("Signed broker executable has been changed".into());
    }
    Ok((broker, locked))
}
fn uuid4() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| "Could not create request ID")?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}
/// A checked, bounded broker verdict: a human message and machine-readable result.
/// A transport or authentication failure is Err, never a positive verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub code: String,
    pub qes_passed: bool,
    pub message: String,
}
fn reply_status(v: &Value, request_id: &str, digest: &str) -> Result<Verdict, String> {
    if v.get("protocolMajor").and_then(Value::as_u64) != Some(1)
        || v.get("requestId").and_then(Value::as_str) != Some(request_id)
        || v.get("documentKind").and_then(Value::as_str) != Some("pdf")
    {
        return Err("Broker response did not match the PDF request".into());
    }
    let code = field(v, "code")?;
    let status = field(v, "status")?;
    if code == "PDF_QES_PASS" {
        let ev = v.get("pdfEvidence").ok_or("Missing independent DSS evidence")?;
        if status != "ok"
            || ev.get("qualifiedSignatureConfirmed").and_then(Value::as_bool) != Some(true)
            || ev.get("documentSha256").and_then(Value::as_str).is_none_or(|x| !x.eq_ignore_ascii_case(digest))
            || ev.get("indication").and_then(Value::as_str) != Some("TOTAL_PASSED")
            || ev.get("qualification").and_then(Value::as_str) != Some("QESig")
        {
            return Err("Contradictory QES report; result rejected".into());
        }
        Ok(Verdict {
            code: "PDF_QES_PASS".into(),
            qes_passed: true,
            message: "Independent Craft Signer / EU DSS: QES PASS for this saved PDF.".into(),
        })
    } else {
        let safe_code = if code.len() <= 64 && code.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
            code
        } else {
            "VERIFICATION_UNAVAILABLE"
        };
        Ok(Verdict { code: safe_code.into(), qes_passed: false, message: format!("Craft Signer / EU DSS: {safe_code} (no confirmed QES PASS).") })
    }
}
pub fn verify_pdf(path: &Path) -> Result<(Verdict, FileStamp), String> {
    guarded_path(path)?;
    if !path.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf")) {
        return Err("Craft Signer accepts only PDF documents".into());
    }
    let before = FileStamp::read(path)?;
    let (broker, locked) = approved_broker()?;
    let request_id = uuid4()?;
    let request = json!({"protocolMajor":1,"requestId":request_id,"action":"document.verify",
        "document":{"kind":"pdf","sourcePath":local_dos_path(path)?.to_string_lossy(),"sha256AtDispatch":before.sha256,"saved":true,"dirty":false}});
    let mut child = Command::new(&broker)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Approved Craft Signer could not start")?;
    // The share lock prevented replacement before CreateProcess.
    drop(locked);
    if let Some(mut stdin) = child.stdin.take() {
        if serde_json::to_writer(&mut stdin, &request).is_err() || stdin.flush().is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Cannot write signer IPC request".into());
        }
    }
    let start = Instant::now();
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < BROKER_TIMEOUT => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Craft Signer timed out".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Could not wait for Craft Signer".into());
            }
        }
    };
    let mut output = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        stdout.take(32_769).read_to_end(&mut output).map_err(|_| "Cannot read signer reply")?;
    }
    if output.len() > 32_768 {
        return Err("Signer response exceeded limit".into());
    }
    let reply: Value = serde_json::from_slice(&output).map_err(|_| "Signer returned malformed JSON")?;
    let after = FileStamp::read(path)?;
    if after != before {
        return Err("Saved PDF changed during verification".into());
    }
    if !exit.success() && reply.get("status").and_then(Value::as_str) == Some("ok") {
        return Err("Signer exit code contradicts its response".into());
    }
    Ok((reply_status(&reply, &request_id, &before.sha256)?, after))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn non_qes_status_never_claims_qualification() {
        let v = json!({"protocolMajor":1,"requestId":"test","documentKind":"pdf",
            "status":"rejected","code":"PDF_NOT_QES"});
        let result = reply_status(&v, "test", "abcd").expect("non-QES report has a safe verdict");
        assert!(!result.qes_passed);
        assert_eq!(result.code, "PDF_NOT_QES");
    }
    #[test]
    fn request_id_mismatch_rejects_apparent_qes() {
        let v = json!({"protocolMajor":1,"requestId":"wrong","documentKind":"pdf","status":"ok",
            "code":"PDF_QES_PASS","pdfEvidence":{"documentSha256":"abcd","indication":"TOTAL_PASSED",
            "qualification":"QESig","qualifiedSignatureConfirmed":true}});
        assert!(reply_status(&v, "expected", "abcd").is_err());
    }
    #[test]
    fn unknown_broker_code_does_not_claim_qes() {
        let v = json!({"protocolMajor":1,"requestId":"test","documentKind":"pdf",
            "status":"error","code":"malformed unsafe code"});
        let result = reply_status(&v, "test", "abcd").expect("unknown errors are safe negative verdicts");
        assert_eq!(result.code, "VERIFICATION_UNAVAILABLE");
        assert!(!result.qes_passed);
    }
    #[test]
    fn canonical_local_drive_path_is_not_a_network_device() {
        let canonical = local_dos_path(Path::new(r"\\?\C:\sandbox\document.pdf")).expect("local extended DOS path");
        assert_eq!(canonical.to_string_lossy(), r"C:\sandbox\document.pdf");
        assert!(local_dos_path(Path::new(r"\\?\UNC\server\share\document.pdf")).is_err());
        assert!(local_dos_path(Path::new(r"\\.\PhysicalDrive0")).is_err());
        assert!(local_dos_path(Path::new(r"\\server\share\document.pdf")).is_err());
    }
    #[test]
    fn network_path_rejected_before_any_document_access() {
        assert!(guarded_path(Path::new(r"\\server\share\document.pdf")).is_err());
    }
    #[test]
    fn saved_pdf_hash_changes_when_bytes_change() {
        let file = std::env::temp_dir().join(format!("craft-signer-stamp-{}.pdf", uuid4().expect("random test id")));
        std::fs::write(&file, b"%PDF-1.7 synthetic A").expect("create fixture");
        let a = FileStamp::read(&file).expect("hash first fixture");
        std::fs::write(&file, b"%PDF-1.7 synthetic B").expect("replace fixture bytes");
        let b = FileStamp::read(&file).expect("hash second fixture");
        let _ = std::fs::remove_file(&file);
        assert_ne!(a.sha256(), b.sha256());
    }

    /// Interop QA: exercise the *same* authenticated parser against the actual
    /// detached CMS catalog created by the .NET 8 signer on authorized Windows.
    /// The files hold only a public certificate, a manifest and a signature.
    #[test]
    #[ignore = "requires the locally signed .NET QA package public catalog"]
    fn dotnet_signed_catalog_matches_independent_parser() {
        let root =
            PathBuf::from(std::env::var_os("CRAFT_SIGNER_DOTNET_CMS_QA_DIR").expect("set CRAFT_SIGNER_DOTNET_CMS_QA_DIR to signed ModuleV2/Package"));
        let manifest = read_bounded(&root.join("manifest.json"), 16384).expect("manifest");
        let sig = read_bounded(&root.join("manifest.p7s"), 65536).expect("CMS signature");
        let publisher = read_bounded(&root.join("publisher.cer"), 16384).expect("public cert");
        let cert = Certificate::parse(&publisher).expect("X.509");
        let pin = sha(&cert.public_key.spki());

        let signed = authenticate_signed_manifest(&manifest, &sig, &publisher, &pin).expect(".NET detached CMS accepted by independent Rust checker");
        assert_eq!(signed["moduleVersion"], "0.2.2-qa");
        assert_eq!(signed["protocolMajor"], 1);
        assert_eq!(signed["workers"].as_array().map(Vec::len), Some(3));

        let mut altered_manifest = manifest.clone();
        altered_manifest[0] ^= 1;
        assert!(authenticate_signed_manifest(&altered_manifest, &sig, &publisher, &pin).is_err());

        let mut altered_signature = sig.clone();
        let end = altered_signature.len() - 1;
        altered_signature[end] ^= 1;
        assert!(authenticate_signed_manifest(&manifest, &altered_signature, &publisher, &pin).is_err());

        assert!(authenticate_signed_manifest(&manifest, &sig, &publisher, &"0".repeat(64)).is_err());
        let mut altered_certificate = publisher.clone();
        let end = altered_certificate.len() - 1;
        altered_certificate[end] ^= 1;
        assert!(authenticate_signed_manifest(&manifest, &sig, &altered_certificate, &pin).is_err());
    }
    #[test]
    fn release_paths_reject_traversal() {
        for s in ["../other", ".staging-bad", r"c:\tmp", "x/y", "", "a_b"] {
            assert!(!release_leaf(s));
        }
        assert!(release_leaf("0.2.1-qa-abcdef1234567890"));
    }
    #[test]
    fn missing_qes_evidence_is_a_safe_failure() {
        // Static protocol cases require no installed module, private key or network.
        assert!(
            reply_status(
                &json!({"protocolMajor":1,"requestId":"a","documentKind":"pdf",
            "status":"ok","code":"PDF_QES_PASS","pdfEvidence":{"documentSha256":"bad"}}),
                "a",
                "abc"
            )
            .is_err()
        );
    }
    #[test]
    fn contradictory_qes_reply_is_not_pass() {
        let v = json!({"protocolMajor":1,"requestId":"test","documentKind":"pdf","status":"ok",
          "code":"PDF_QES_PASS","pdfEvidence":{"documentSha256":"abcd","indication":"TOTAL_PASSED",
          "qualification":"QESig","qualifiedSignatureConfirmed":false}});
        assert!(reply_status(&v, "test", "abcd").is_err());
    }
    #[test]
    fn verified_qes_requires_all_evidence() {
        let v = json!({"protocolMajor":1,"requestId":"test","documentKind":"pdf","status":"ok",
          "code":"PDF_QES_PASS","pdfEvidence":{"documentSha256":"abcd","indication":"TOTAL_PASSED",
          "qualification":"QESig","qualifiedSignatureConfirmed":true}});
        assert!(reply_status(&v, "test", "abcd").is_ok());
    }
}
