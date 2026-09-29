#!/usr/bin/env bash
# Tests for tools/scan_secrets.py
#
# Fixtures are built at run time from fragments so that this file itself never
# contains a flag-shaped or key-shaped literal -- otherwise the repository's own
# sanitization gate (tools/verify-seed.sh) would have to special-case its own
# test suite, which is exactly the kind of exception a secret gate must not have.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
scanner="$repo/tools/scan_secrets.py"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
fail=0

# fragments, never assembled at rest
FLAGPREFIX="HT"
FLAGPREFIX="${FLAGPREFIX}B"
FAKE_FLAG="${FLAGPREFIX}{f4k3_t3st_v4lu3_n0t_r34l}"
KEYALGO="RSA"
FAKE_KEY_LINE="-----BEGIN ${KEYALGO} PRIVATE KEY-----"
FAKE_AWS="AK""IA""IOSFODNN7EXAMPLE"
FAKE_OPENAI="sk-""test""0000000000000000000000FAKE"
FAKE_ASSIGN_VALUE="Zx7Qw2Lm9Rt4Yb8N"

check() { # check <expected-exit> <name> <path...>
    local expected="$1" name="$2"; shift 2
    local out rc
    out="$(python3 "$scanner" "$@" 2>&1)"; rc=$?
    if [[ "$rc" == "$expected" ]]; then
        pass=$((pass + 1)); printf 'ok   %-46s (exit %s)\n' "$name" "$rc"
    else
        fail=$((fail + 1)); printf 'FAIL %-46s (exit %s, expected %s)\n' "$name" "$rc" "$expected"
        printf '%s\n' "$out" | sed 's/^/       | /'
    fi
}

check_contains() { # check_contains <needle> <name> <path...>
    local needle="$1" name="$2"; shift 2
    local out
    out="$(python3 "$scanner" --summary "$@" 2>&1)"
    if grep -q -- "$needle" <<<"$out"; then
        pass=$((pass + 1)); printf 'ok   %-46s (found %s)\n' "$name" "$needle"
    else
        fail=$((fail + 1)); printf 'FAIL %-46s (missing %s)\n' "$name" "$needle"
        printf '%s\n' "$out" | sed 's/^/       | /'
    fi
}

check_not_contains() { # check_not_contains <needle> <name> <path...>
    local needle="$1" name="$2"; shift 2
    local out
    out="$(python3 "$scanner" "$@" 2>&1)"
    if grep -qF -- "$needle" <<<"$out"; then
        fail=$((fail + 1)); printf 'FAIL %-46s (leaked value in output)\n' "$name"
    else
        pass=$((pass + 1)); printf 'ok   %-46s (value not leaked)\n' "$name"
    fi
}

echo "== fixtures in $work"
mkdir -p "$work/clean" "$work/dirty"
printf 'ordinary knowledge text, no secrets here\nport 445 open, smb signing disabled\n' >"$work/clean/note.md"
printf 'A password reset is performed through the web console.\n' >>"$work/clean/note.md"
printf 'the api_key field is documented as optional in the schema\n' >>"$work/clean/note.md"

printf 'captured value: %s\n' "$FAKE_FLAG" >"$work/dirty/flag.md"
printf '%s\nMIIEowIBAAKCAQEAxxxx\n' "$FAKE_KEY_LINE" >"$work/dirty/key.pem"
printf 'aws_access_key_id = %s\n' "$FAKE_AWS" >"$work/dirty/aws.txt"
printf 'OPENAI_API_KEY=%s\n' "$FAKE_OPENAI" >"$work/dirty/openai.env"
printf 'api_key = "%s"\n' "$FAKE_ASSIGN_VALUE" >"$work/dirty/assign.conf"
printf 'password: <REDACTED>\nsecret = CHANGEME\n' >"$work/dirty/placeholders.conf"
printf 'scanned host 192.0.2.44 and 198.51.100.7 with nmap\n' >"$work/dirty/ips.txt"
printf 'log written to /home/someuser/tools/out.txt\n' >"$work/dirty/paths.txt"

# archives, one poisoned member each (built with python: `zip` may be absent)
mkdir -p "$work/pack" "$work/pack_dirty"
cp "$work/clean/note.md" "$work/pack/note.md"
cp "$work/clean/note.md" "$work/pack_dirty/note.md"
cp "$work/dirty/flag.md" "$work/pack_dirty/evidence.md"
python3 - "$work" <<'PY'
import os, sys, tarfile, zipfile
work = sys.argv[1]

def zipsrc(archive, srcdir):
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(os.listdir(srcdir)):
            zf.write(os.path.join(srcdir, name), name)

def tarsrc(archive, srcdir):
    with tarfile.open(archive, "w:gz") as tf:
        for name in sorted(os.listdir(srcdir)):
            tf.add(os.path.join(srcdir, name), arcname=name)

zipsrc(os.path.join(work, "clean.zip"), os.path.join(work, "pack"))
zipsrc(os.path.join(work, "dirty.zip"), os.path.join(work, "pack_dirty"))
tarsrc(os.path.join(work, "clean.tar.gz"), os.path.join(work, "pack"))
tarsrc(os.path.join(work, "dirty.tar.gz"), os.path.join(work, "pack_dirty"))
PY

echo
echo "== scanner behaviour"
check 0 "clean directory"                 "$work/clean"
check 1 "flag literal"                    "$work/dirty/flag.md"
check 1 "private key block"               "$work/dirty/key.pem"
check 1 "cloud access key"                "$work/dirty/aws.txt"
check 1 "provider api key"                "$work/dirty/openai.env"
check 1 "secret-shaped assignment"        "$work/dirty/assign.conf"
check 0 "placeholders are not secrets"    "$work/dirty/placeholders.conf"
check 0 "ip literals warn only"           "$work/dirty/ips.txt"
check 1 "ip literals fail under --strict-warn" --strict-warn "$work/dirty/ips.txt"
check 0 "home paths warn only"            "$work/dirty/paths.txt"
check 1 "poisoned zip member"             "$work/dirty.zip"
check 1 "poisoned tar.gz member"          "$work/dirty.tar.gz"
check 0 "clean zip"                       "$work/clean.zip"
check 0 "clean tar.gz"                    "$work/clean.tar.gz"
check 1 "whole dirty directory"           "$work/dirty"
check 1 "exclude does not hide another dir" --exclude '*.md' "$work/dirty"

echo
echo "== classification"
check_contains "flag_htb"        "flag classified"      "$work/dirty/flag.md"
check_contains "private_key"     "key classified"       "$work/dirty/key.pem"
check_contains "aws_access_key"  "aws key classified"   "$work/dirty/aws.txt"
check_contains "BLOCK total"     "summary shape"        "$work/dirty"

echo
echo "== no value ever printed"
check_not_contains "$FAKE_FLAG"         "flag not echoed"    "$work/dirty/flag.md"
check_not_contains "$FAKE_AWS"          "aws key not echoed" "$work/dirty/aws.txt"
check_not_contains "$FAKE_ASSIGN_VALUE" "secret not echoed"  "$work/dirty/assign.conf"

echo
echo "== json output parses"
json_out="$(python3 "$scanner" --json "$work/dirty/flag.md" 2>/dev/null)"
if grep -q . <<<"$json_out" && python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["blocked"]==1, d; assert d["findings"][0]["class"]=="flag_htb", d' "$json_out" 2>/dev/null; then
    pass=$((pass + 1)); echo "ok   json contract"
else
    fail=$((fail + 1)); echo "FAIL json contract"
    printf '%s\n' "$json_out" | sed 's/^/       | /'
fi

echo
echo "== an address written after a letter is still an address"
# A word boundary does not exist between a letter and a digit, so the obvious pattern
# (`\b` + the address) missed every occurrence written the way documents write it:
# an escaped newline, then the address.  Four real addresses survived redaction that way,
# and the scanner could not see them either.  This locks the lookaround version in.
mkdir -p "$work/boundary"
printf 'correttamente:\\n95.245.249.208 e anche a fine frase 95.245.249.208. Poi 10.10.14.5\n' >"$work/boundary/ip.md"
boundary_out="$(python3 "$scanner" --json "$work/boundary/ip.md" 2>/dev/null)"
if python3 -c 'import json,sys; d=json.loads(sys.argv[1]); kinds=[f["class"] for f in d["findings"]]; assert "ipv4" in kinds, d' "$boundary_out" 2>/dev/null; then
    pass=$((pass + 1)); echo "ok   address after a letter is detected"
else
    fail=$((fail + 1)); echo "FAIL address after a letter is detected"
fi
# ...and a longer dotted number must not be mistaken for one.
printf 'version 12345.6.7.8 is not an address\n' >"$work/boundary/version.md"
version_out="$(python3 "$scanner" --json "$work/boundary/version.md" 2>/dev/null)"
if python3 -c 'import json,sys; d=json.loads(sys.argv[1]); kinds=[f["class"] for f in d["findings"]]; assert "ipv4" not in kinds, d' "$version_out" 2>/dev/null; then
    pass=$((pass + 1)); echo "ok   a version-like number is not an address"
else
    fail=$((fail + 1)); echo "FAIL a version-like number is not an address"
fi

echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" == 0 ]]
