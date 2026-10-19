//! On-demand local RFC 3161 transport bridge for a software-key PAdES B-T test.
//! The third-party service is not a trust oracle: request/response are validated by
//! pdfcraft-sign::sign_with_timestamp. No B-Trust USB token, PIN, or QES qualification.
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use pdfcraft_cos::Document;
use pdfcraft_sign::{SignError, SignOptions, TimestampAuthority, pkcs12, sign_with_timestamp};

struct TempExchange {
    req: PathBuf,
    resp: PathBuf,
}
impl TempExchange {
    fn new() -> Result<Self, SignError> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|e| SignError::Crypto(format!("temporary request RNG unavailable: {e}")))?;
        let suffix = random.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let base = env::temp_dir().join(format!("pdfcraft-rfc3161-{}-{suffix}", std::process::id()));
        Ok(Self { req: base.with_extension("tsq"), resp: base.with_extension("tsr") })
    }
}
impl Drop for TempExchange {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.req);
        let _ = fs::remove_file(&self.resp);
    }
}

struct LocalPowerShellTsa {
    powershell: PathBuf,
    script: PathBuf,
    provider: String,
    confirm_personal_use: bool,
}
impl TimestampAuthority for LocalPowerShellTsa {
    fn timestamp(&self, request: &[u8]) -> Result<Vec<u8>, SignError> {
        if request.is_empty() || request.len() > 1024 * 1024 {
            return Err(SignError::Malformed("RFC3161 query empty or oversized".into()));
        }
        let exchange = TempExchange::new()?;
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&exchange.req)
                .map_err(|e| SignError::Crypto(format!("cannot create exclusive RFC3161 request file: {e}")))?;
            f.write_all(request).map_err(|e| SignError::Crypto(format!("cannot write RFC3161 request: {e}")))?;
            f.sync_all().map_err(|e| SignError::Crypto(format!("cannot sync RFC3161 request: {e}")))?;
        }
        // Executable + script are explicit, no shell command interpolation or redirects.
        let mut process = Command::new(&self.powershell);
        process.env_remove("PDFCRAFT_TEST_PKCS12_PASSWORD");
        process
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-File")
            .arg(&self.script)
            .arg("-Provider")
            .arg(&self.provider)
            .arg("-RequestPath")
            .arg(&exchange.req)
            .arg("-ResponsePath")
            .arg(&exchange.resp)
            .arg("-TimeoutSeconds")
            .arg("15");
        if self.confirm_personal_use {
            process.arg("-ConfirmPersonalUse");
        }
        let out = process.output().map_err(|e| SignError::Crypto(format!("cannot run configured RFC3161 transport: {e}")))?;
        if !out.status.success() {
            return Err(SignError::Crypto(format!("RFC3161 provider rejected request: exit status {}", out.status)));
        }
        let metadata = fs::metadata(&exchange.resp).map_err(|e| SignError::Crypto(format!("no RFC3161 reply file: {e}")))?;
        if metadata.len() == 0 || metadata.len() > 4 * 1024 * 1024 {
            return Err(SignError::Malformed("RFC3161 reply empty or oversized".into()));
        }
        fs::read(&exchange.resp).map_err(|e| SignError::Crypto(format!("cannot read RFC3161 reply: {e}")))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 8 && args.len() != 9 {
        return Err("usage: rfc3161_external_pades_bt <source.pdf> <dest.pdf> <test-key.p12> <pwsh.exe> <rfc3161_provider_probe.ps1> <open-tsa|accv-personal> <PDF-date> [--confirm-personal-use]".into());
    }
    let source = Path::new(&args[1]);
    let dest = Path::new(&args[2]);
    let key = Path::new(&args[3]);
    let powershell = PathBuf::from(&args[4]);
    let script = PathBuf::from(&args[5]);
    let provider = args[6].as_str();
    let confirm = args.get(8).is_some_and(|s| s == "--confirm-personal-use");
    if !["open-tsa", "accv-personal"].contains(&provider) {
        return Err("unknown provider: use explicit provider allowlist".into());
    }
    if provider == "accv-personal" && !confirm {
        return Err("ACCV requires explicit --confirm-personal-use".into());
    }
    if args.len() == 9 && !confirm {
        return Err("unknown command-line option".into());
    }
    if !source.is_file() || !key.is_file() || !powershell.is_file() || !script.is_file() {
        return Err("input PDF, PKCS#12 test key, pwsh and provider script must exist".into());
    }
    if !source.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
        || !dest.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
        || dest.exists()
        || fs::canonicalize(source).ok() == fs::canonicalize(dest).ok()
    {
        return Err("output must be a distinct, nonexistent .pdf".into());
    }
    let pass = env::var("PDFCRAFT_TEST_PKCS12_PASSWORD").map_err(|_| "set PDFCRAFT_TEST_PKCS12_PASSWORD for a **test** software key only")?;
    let digital_id = pkcs12::open(&fs::read(key)?, &pass)?;
    let original = fs::read(source)?;
    let document = Document::open(Arc::new(original))?;
    let tsa = LocalPowerShellTsa { powershell, script, provider: provider.into(), confirm_personal_use: confirm };
    let opts = SignOptions { date: args[7].clone(), page: 0, ..SignOptions::default() };
    let signed = sign_with_timestamp(&document, &digital_id, &opts, &tsa)?;
    // A fully validated timestamp response does NOT make an otherwise untrusted
    // test certificate qualified. Never claim independent EU DSS or QES here.
    let mut output = OpenOptions::new().write(true).create_new(true).open(dest)?;
    if let Err(e) = output.write_all(&signed).and_then(|_| output.sync_all()) {
        drop(output);
        let _ = fs::remove_file(dest);
        return Err(e.into());
    }
    println!("RFC3161_EXTERNAL_PADES_B_T_TEST_CANDIDATE bytes={} provider={provider}", signed.len());
    println!("QUALIFIED_EIDAS=NOT_CHECKED EU_DSS=NOT_CHECKED QES=NO_GO");
    Ok(())
}
