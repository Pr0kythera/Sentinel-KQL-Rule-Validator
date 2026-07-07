#!/usr/bin/env python3
"""
Vendor the pinned MITRE ATT&CK STIX bundle.

Downloads the Enterprise ATT&CK STIX bundle described in
config/attack/pinned_version.json, verifies its SHA-256 against the pinned
value, and writes it next to that metadata file. Run this once at setup time
(and again to refresh); the linter itself never fetches from the network.

Usage:
  python scripts/vendor_attack_data.py            # download + verify pinned bundle
  python scripts/vendor_attack_data.py --check     # verify an existing local file only
  python scripts/vendor_attack_data.py --force     # re-download even if present/valid

To bump the pinned ATT&CK version, edit config/attack/pinned_version.json
(attack_version, filename, source_url, sha256, size_bytes) and re-run this script.

Exit codes: 0 on success, 1 on any failure (download error, hash mismatch,
missing metadata). No non-ASCII output.
"""

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ATTACK_DIR = Path(__file__).resolve().parent.parent / "config" / "attack"
PINNED_FILE = ATTACK_DIR / "pinned_version.json"


def load_pinned():
    if not PINNED_FILE.exists():
        raise FileNotFoundError(
            "Pinned metadata not found: {}".format(PINNED_FILE)
        )
    with open(PINNED_FILE, "r", encoding="utf-8") as handle:
        return json.load(handle)


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path, expected_sha256):
    if not path.exists():
        return False, "file not found: {}".format(path)
    actual = sha256_of(path)
    if actual != expected_sha256:
        return False, "sha256 mismatch: expected {}, got {}".format(
            expected_sha256, actual
        )
    return True, "ok"


def download(url, dest):
    print("Downloading {} ...".format(url))
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    with urllib.request.urlopen(url, timeout=300) as response:
        data = response.read()
    with open(tmp, "wb") as handle:
        handle.write(data)
    tmp.replace(dest)
    print("Wrote {} ({} bytes)".format(dest, dest.stat().st_size))


def main():
    parser = argparse.ArgumentParser(description="Vendor the pinned ATT&CK STIX bundle")
    parser.add_argument("--check", action="store_true",
                        help="Only verify an existing local bundle against the pinned hash")
    parser.add_argument("--force", action="store_true",
                        help="Re-download even if a valid local copy exists")
    args = parser.parse_args()

    try:
        pinned = load_pinned()
    except Exception as exc:  # noqa: BLE001 - top-level CLI guard
        print("ERROR: {}".format(exc))
        return 1

    dest = ATTACK_DIR / pinned["filename"]
    expected = pinned["sha256"]

    if args.check:
        ok, msg = verify(dest, expected)
        print("Verify {}: {}".format(dest, msg))
        return 0 if ok else 1

    if dest.exists() and not args.force:
        ok, msg = verify(dest, expected)
        if ok:
            print("Already vendored and verified: {}".format(dest))
            return 0
        print("Existing file failed verification ({}); re-downloading.".format(msg))

    try:
        download(pinned["source_url"], dest)
    except Exception as exc:  # noqa: BLE001 - network/IO guard
        print("ERROR: download failed: {}".format(exc))
        return 1

    ok, msg = verify(dest, expected)
    if not ok:
        print("ERROR: downloaded file failed verification: {}".format(msg))
        print("The pinned sha256 in {} may be stale, or the download was corrupt."
              .format(PINNED_FILE))
        return 1

    print("ATT&CK v{} bundle vendored and verified.".format(pinned["attack_version"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
