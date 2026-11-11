#!/usr/bin/env bash
# End-to-end check of the ejsonkms binary against local-kms, a KMS emulator
# that really encrypts and really enforces encryption contexts (the mock used
# by `cargo test` only imitates that).
#
#   docker compose up -d awskms
#   tests/local-kms.sh target/debug/ejsonkms
#
# Needs jq. Exits non-zero at the first case that doesn't behave as expected.
set -euo pipefail

BIN=$(cd "$(dirname "${1:?usage: $0 path/to/ejsonkms}")" && pwd)/$(basename "$1")
KEY_A=bc436485-5092-42b8-92a3-0aa8b93536dc
KEY_B=7d3f0c2a-6b1e-4f5d-9a8c-2e4b6d8f0a1c
ALIAS_A=alias/testing

export AWS_ENDPOINT_URL_KMS=${AWS_ENDPOINT_URL_KMS:-http://localhost:8080}
export AWS_ACCESS_KEY_ID=123 AWS_SECRET_ACCESS_KEY=xyz AWS_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true
unset AWS_SESSION_TOKEN AWS_PROFILE

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

# Add a secret to a freshly generated file and encrypt it.
add_secret() {
  jq '.environment = {"my_secret": "secret123"}' "$1" > "$1.tmp"
  mv "$1.tmp" "$1"
  "$BIN" encrypt "$1" > /dev/null
}

# The file decrypts and `env` prints the secret.
expect_secret() {
  local out
  out=$("$BIN" env "$1") || fail "$1: env failed"
  [ "$out" = "export my_secret='secret123'" ] || fail "$1: unexpected env output: $out"
  echo "ok: $1 decrypts"
}

# Decrypting the file fails, mentions $2, and prints no plaintext.
expect_refused() {
  local out
  if out=$("$BIN" decrypt "$1" 2> "$1.err"); then
    fail "$1: decrypt succeeded but should have been refused"
  fi
  [ -z "$out" ] || fail "$1: plaintext on stdout despite the failure"
  grep -q "$2" "$1.err" || fail "$1: expected $2, got: $(cat "$1.err")"
  echo "ok: $1 refused ($2)"
}

has_marker() { [ "$(jq -r '._kms_encryption_context // ""' "$1")" = "public_key" ]; }

step "wait for local-kms at $AWS_ENDPOINT_URL_KMS"
for _ in $(seq 1 60); do
  if curl -s -o /dev/null "$AWS_ENDPOINT_URL_KMS"; then break; fi
  sleep 0.5
done
curl -s -o /dev/null "$AWS_ENDPOINT_URL_KMS" || fail "local-kms is not reachable"

step "unbound key"
"$BIN" keygen --kms-key-id "$KEY_A" -o plain.ejson
add_secret plain.ejson
has_marker plain.ejson && fail "plain.ejson: unexpected _kms_encryption_context"
expect_secret plain.ejson

step "key bound to the public key"
"$BIN" keygen --kms-key-id "$KEY_A" --bind-public-key -o bound.ejson
add_secret bound.ejson
has_marker bound.ejson || fail "bound.ejson: no _kms_encryption_context"
expect_secret bound.ejson

step "tampering is refused"
jq 'del(._kms_encryption_context)' bound.ejson > stripped.ejson
jq --arg enc "$(jq -r ._private_key_enc bound.ejson)" \
  '._private_key_enc = $enc | ._kms_encryption_context = "public_key"' plain.ejson > lifted.ejson
jq '._kms_encryption_context = "public_key"' plain.ejson > marked.ejson
expect_refused stripped.ejson InvalidCiphertextException
expect_refused lifted.ejson InvalidCiphertextException
expect_refused marked.ejson InvalidCiphertextException

step "rewrap to another key changes only the wrapped key"
cp plain.ejson before.ejson
"$BIN" rewrap --kms-key-id "$KEY_B" plain.ejson
changed=$(diff before.ejson plain.ejson | grep -c '^[<>]' || true)
[ "$changed" = 2 ] || fail "rewrap changed $changed lines, expected the one _private_key_enc line"
diff before.ejson plain.ejson | grep '^[<>]' | grep -vq '_private_key_enc' \
  && fail "rewrap changed something other than _private_key_enc"
expect_secret plain.ejson

step "rewrap --bind-public-key through an alias"
"$BIN" rewrap --kms-key-id "$ALIAS_A" --bind-public-key plain.ejson
has_marker plain.ejson || fail "plain.ejson: rewrap did not add _kms_encryption_context"
expect_secret plain.ejson

step "a later rewrap keeps the binding"
"$BIN" rewrap --kms-key-id "$KEY_B" plain.ejson
has_marker plain.ejson || fail "plain.ejson: rewrap dropped _kms_encryption_context"
expect_secret plain.ejson
jq 'del(._kms_encryption_context)' plain.ejson > plain-stripped.ejson
expect_refused plain-stripped.ejson InvalidCiphertextException

step "v2 (post-quantum hybrid) key, bound"
"$BIN" keygen --kms-key-id "$KEY_A" --pqc --bind-public-key -o v2.ejson
add_secret v2.ejson
grep -q 'EJ\[2:' v2.ejson || fail "v2.ejson: values are not v2 ciphertexts"
expect_secret v2.ejson

step "an unknown KMS key is reported cleanly"
if "$BIN" keygen --kms-key-id alias/does-not-exist > /dev/null 2> missing.err; then
  fail "keygen with an unknown key succeeded"
fi
grep -q 'NotFoundException' missing.err || fail "expected NotFoundException, got: $(cat missing.err)"
grep -q 'ServiceError' missing.err && fail "error message contains SDK debug output: $(cat missing.err)"
echo "ok: $(cat missing.err)"

printf '\nAll local-kms checks passed.\n'
