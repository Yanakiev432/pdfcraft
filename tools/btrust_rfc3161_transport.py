#!/usr/bin/env python3
"""Transport RFC 3161 requests to BORICA B-Trust; never a validation oracle.

Only DER TimeStampReq is sent (a digest + nonce, not the original document).
No request is made without an explicit command. Production requires an
additional opt-in flag. The caller must independently cryptographically
validate and qualify the returned TimeStampResp using Rust and EU DSS.
"""
from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import sys
from typing import Callable
from urllib import error, request

TEST_URL = "http://tsatest.b-trust.org"
PRODUCTION_URL = "https://tsa.b-trust.org"
MAX_REQUEST = 1024 * 1024
MAX_RESPONSE = 4 * 1024 * 1024
DEFAULT_TIMEOUT = 15


class TimestampTransportError(ValueError):
    """No validated timestamp has been produced."""


class RejectRedirects(request.HTTPRedirectHandler):
    """Never follow redirects carrying TSA credentials or document digests."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TimestampTransportError("TSA redirects are not permitted")


def trusted_urlopen(req: request.Request, timeout: int):
    # Uses the platform's TLS certificate verification; redirect following is
    # disabled even for an unauthenticated test request.
    return request.build_opener(RejectRedirects()).open(req, timeout=timeout)


def prepare_request(
    der: bytes,
    *,
    server: str,
    allow_production: bool = False,
    username: str | None = None,
    password: str | None = None,
) -> request.Request:
    if not der or len(der) > MAX_REQUEST or der[0] != 0x30:
        raise TimestampTransportError("request is empty, oversized or not a DER SEQUENCE")
    if server not in {"test", "production"}:
        raise TimestampTransportError("unknown B-Trust TSA profile")
    if server == "production" and not allow_production:
        raise TimestampTransportError("production requires explicit --allow-production")
    url = TEST_URL if server == "test" else PRODUCTION_URL
    if bool(username) != bool(password):
        raise TimestampTransportError("TSA username and password must be provided together")
    if (username or password) and not url.startswith("https://"):
        raise TimestampTransportError("refusing authentication over non-TLS test TSA endpoint")
    headers = {
        "Content-Type": "application/timestamp-query",
        "Accept": "application/timestamp-reply",
        "User-Agent": "PdfCraft-RFC3161-Transport/0.1",
    }
    if username is not None and password is not None:
        # This optional scheme must be agreed with the provider first. Never log it.
        raw = (username + ":" + password).encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    return request.Request(url, data=der, headers=headers, method="POST")


def transport(
    der: bytes,
    *,
    server: str,
    allow_production: bool = False,
    username: str | None = None,
    password: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    opener: Callable[..., object] = trusted_urlopen,
) -> bytes:
    if not 1 <= timeout <= 60:
        raise TimestampTransportError("timeout must be between 1 and 60 seconds")
    query = prepare_request(
        der, server=server, allow_production=allow_production,
        username=username, password=password,
    )
    try:
        with opener(query, timeout=timeout) as resp:
            if resp.status != 200:
                raise TimestampTransportError(f"TSA HTTP status {resp.status}")
            content_type = resp.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/timestamp-reply":
                raise TimestampTransportError("unexpected TSA content type")
            blob = resp.read(MAX_RESPONSE + 1)
    except error.HTTPError as exc:
        raise TimestampTransportError(f"TSA HTTP error {exc.code}") from None
    except error.URLError:
        raise TimestampTransportError("TSA transport/network failure") from None
    if not blob or len(blob) > MAX_RESPONSE or blob[0] != 0x30:
        raise TimestampTransportError("TSA reply is empty, oversized or not a DER SEQUENCE")
    return blob


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", choices=["test", "production"], required=True)
    parser.add_argument("--allow-production", action="store_true")
    parser.add_argument("--request", type=Path, required=True, help="Existing DER TimeStampReq, not a PDF")
    parser.add_argument("--response", type=Path, required=True, help="New DER TimeStampResp file")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)

    try:
        original = args.request.resolve(strict=True)
        dest = args.response.resolve(strict=False)
        if not original.is_file() or original == dest or dest.exists():
            raise TimestampTransportError("request must exist; output must be distinct and nonexistent")
        if original.stat().st_size > MAX_REQUEST:
            raise TimestampTransportError("RFC 3161 request file exceeds limit")
        query = original.read_bytes()
        result = transport(
            query,
            server=args.server,
            allow_production=args.allow_production,
            username=os.environ.get("PDFCRAFT_TSA_USERNAME"),
            password=os.environ.get("PDFCRAFT_TSA_PASSWORD"),
            timeout=args.timeout,
        )
        # No output file is created for HTTP or protocol failures. Exclusive open
        # prevents clobbering an existing file, including a concurrent producer.
        created = False
        try:
            with dest.open("xb") as out:
                created = True
                out.write(result)
                out.flush()
                os.fsync(out.fileno())
        except Exception:
            # If exclusive creation failed, NEVER delete the pre-existing file.
            if created:
                dest.unlink(missing_ok=True)
            raise
        print("TRANSPORT_ONLY: RFC3161 response received; independent cryptographic/EU-DSS verification still REQUIRED")
        return 0
    except (TimestampTransportError, OSError, ValueError) as exc:
        # Avoid logging URLs with secrets, request bytes or personal document names.
        print(f"RFC3161_TRANSPORT_NO_GO: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
