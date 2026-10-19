//! Opt-in local-only structurally authenticated DSS append, NOT PAdES-B-LT QES.
//! Does not access private keys or call remote providers; never overwrites input.
//! Usage: lt_dss_local signed.pdf signer.pem issuer.pem evidence.crl new.pdf YYYYMMDDHHMMSS

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use pdfcraft_sign::Time;
use pdfcraft_sign::dss::Evidence;
use pdfcraft_sign::dss_checked::embed_checked;
use pdfcraft_sign::keys::DigestAlg;
use pdfcraft_sign::x509::load_certificates;

fn parse_utc(value: &str) -> Result<Time, String> {
    if value.len() != 14 || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err("expected 14-digit YYYYMMDDHHMMSS (UTC); this is not a trusted timestamp".into());
    }
    let d = |s: usize, e: usize| value[s..e].parse::<u32>().map_err(|err| err.to_string());
    let t = Time { year: d(0, 4)?, month: d(4, 6)?, day: d(6, 8)?, hour: d(8, 10)?, minute: d(10, 12)?, second: d(12, 14)? };
    if !(1..=12).contains(&t.month) || !(1..=31).contains(&t.day) || t.hour > 23 || t.minute > 59 || t.second > 59 {
        return Err("invalid UTC time components".into());
    }
    Ok(t)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 7 {
        return Err("usage: lt_dss_local signed.pdf signer.pem issuer.pem evidence.crl new.pdf YYYYMMDDHHMMSS".into());
    }
    let input = Path::new(&a[1]);
    let output = Path::new(&a[5]);
    if input == output || output.exists() || input.extension().is_none_or(|e| e != "pdf") || output.extension().is_none_or(|e| e != "pdf") {
        return Err("source and output must be different .pdf files and output must not exist".into());
    }
    let signer = load_certificates(&fs::read(&a[2])?)?.into_iter().next().ok_or("missing signer certificate")?;
    let issuer = load_certificates(&fs::read(&a[3])?)?.into_iter().next().ok_or("missing issuer certificate")?;
    let signed_bytes = fs::read(input)?;
    let result = embed_checked(
        &signed_bytes,
        &Evidence { certs: vec![signer.raw, issuer.raw.clone()], ocsps: vec![], crls: vec![fs::read(&a[4])?] },
        &issuer,
        parse_utc(&a[6])?,
    )?;
    if !result.starts_with(&signed_bytes) {
        return Err("the original signed PDF revision was not preserved".into());
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(output)?;
    if let Err(e) = file.write_all(&result).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(output);
        return Err(e.into());
    }
    let sha = DigestAlg::Sha256.digest(&[&result]).iter().map(|b| format!("{b:02x}")).collect::<String>();
    println!("DSS_STRUCTURAL_ONLY=PASS bytes={} sha256={sha}", result.len());
    println!("PADES_B_LT_QUALIFIED=NO_GO trusted_time_and_historical_eutsl_not_proven");
    Ok(())
}
