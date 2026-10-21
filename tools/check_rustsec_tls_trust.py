#!/usr/bin/env python3
"""Fail-closed exact RustSec TLS trust fix guard for PdfCraft Cargo.lock.

RUSTSEC-2026-0382: rustls-webpki <0.103.16 in the stable 0.103 line.
RUSTSEC-2026-0383: webpki-root-certs <1.0.10 in the 1.0 line.
Allowing other major/minor tracks needs an explicit engineering review.
This does not replace cargo-deny or a runtime trust-list validation.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import tomllib


class UnpatchedLockfile(ValueError):
    pass


def verify_lock(data: bytes) -> dict:
    doc=tomllib.loads(data.decode("utf-8"))
    packages=doc.get("package")
    if not isinstance(packages,list):
        raise UnpatchedLockfile("Cargo.lock package array missing")
    targets={"rustls-webpki":(0,103,16),"webpki-root-certs":(1,0,10)}
    observed={}
    for name,(major,minor,min_patch) in targets.items():
        versions=[p.get("version") for p in packages if isinstance(p,dict) and p.get("name")==name]
        if len(versions)!=1:
            raise UnpatchedLockfile(f"{name} must have exactly one locked dependency")
        version=versions[0]
        if not isinstance(version,str):
            raise UnpatchedLockfile(f"{name} version absent")
        parts=version.split(".")
        if len(parts)!=3 or any(not segment.isascii() or not segment.isdecimal() for segment in parts):
            raise UnpatchedLockfile(f"{name} must use a stable semver (review prerelease manually)")
        parsed=tuple(int(s) for s in parts)
        if parsed[:2]!=(major,minor) or parsed[2]<min_patch:
            raise UnpatchedLockfile(f"{name} has vulnerable or unreviewed locked version: {version}")
        observed[name]=version
    return {"status":"PASS","schema":"pdfcraft.rustsec-tls-trust.v1","locked":observed,
            "certificate_chain_external_qualification":"NOT_CHECKED",
            "trusted_release_ready":False}


def regression_tests():
    valid={"version":4,"package":[{"name":"rustls-webpki","version":"0.103.16"},
                                   {"name":"webpki-root-certs","version":"1.0.10"}]}
    import copy
    def test(source):
        lines=['version = 4']
        for package in source["package"]:
            lines+=["","[[package]]",f'name = "{package["name"]}"',f'version = "{package["version"]}"']
        return "\n".join(lines).encode("utf-8")
    assert verify_lock(test(valid))["status"]=="PASS"
    attacks=[("rustls-webpki","0.103.15"),("webpki-root-certs","1.0.9"),
             ("rustls-webpki","0.103.16-rc.1"),("webpki-root-certs","0.26.10"),
             ("rustls-webpki","0.104.0-alpha.8")]
    for name,version in attacks:
        mutable=copy.deepcopy(valid)
        next(p for p in mutable["package"] if p["name"]==name)["version"]=version
        try:
            verify_lock(test(mutable))
        except UnpatchedLockfile:
            continue
        raise AssertionError(f"Unsafe lockfile accepted: {name} {version}")
    mutable=copy.deepcopy(valid)
    mutable["package"].append({"name":"rustls-webpki","version":"0.103.15"})
    try:
        verify_lock(test(mutable))
    except UnpatchedLockfile:
        pass
    else:
        raise AssertionError("Duplicate vulnerable lockfile dependency accepted")


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lock",type=Path,default=Path(__file__).resolve().parents[1]/"Cargo.lock")
    p.add_argument("--self-test",action="store_true")
    args=p.parse_args()
    data=verify_lock(args.lock.read_bytes())
    if args.self_test:regression_tests()
    import json
    print(json.dumps(data,sort_keys=True))


if __name__=="__main__":
    main()
