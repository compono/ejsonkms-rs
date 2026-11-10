# Security Policy

ejsonkms protects secrets, so security reports are taken seriously and handled
ahead of other work.

## Supported versions

Only the `3.x` series is supported. Security fixes are made on `main` and
released as a new `3.x` version; `2.x` and `1.x` receive no fixes, so please
upgrade before reporting (see [UPGRADING.md](UPGRADING.md)).

| Version | Supported |
| ------- | --------- |
| `3.x`   | ✅        |
| `2.x`   | ❌        |
| `1.x`   | ❌        |

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a
security problem.**

Report it privately through GitHub instead:
[**Report a vulnerability**](https://github.com/runlevel5/ejsonkms-rs/security/advisories/new)
(Security tab → Advisories → Report a vulnerability).

Please include:

- the ejsonkms version (`ejsonkms --version`) and platform;
- the file format (JSON, YAML, TOML), if relevant;
- steps or a minimal file to reproduce, and what an attacker gains.

Never include real private keys, secrets, AWS credentials or KMS key ARNs in a
report. Generate a throwaway keypair with `ejsonkms keygen` against a test KMS
key for any reproduction.

## What to expect

- An acknowledgement within a few days.
- An assessment, and a fix or mitigation plan, as soon as the issue is
  understood.
- A GitHub security advisory (and a RustSec advisory where appropriate) when
  the fix is released. Reporters are credited unless they prefer otherwise.

## Scope

In scope: anything that lets someone read secrets they shouldn't, tamper with
encrypted values or keys undetected, or run code via ejsonkms. That includes
the CLI, the `ejsonkms` library crate, how the KMS-encrypted private key is
stored and handled, and the release and packaging pipeline (GitHub Releases,
Homebrew formula, crates.io).

Problems in the encryption itself or the `EJ[...]` wire format belong to the
underlying [ejson](https://github.com/runlevel5/ejson-rs/security/advisories/new)
crate; report them there.

Out of scope: attacks that already require permission to use the KMS key or to
read the memory of a running `ejsonkms` process, and weaknesses in the user's
own AWS account or IAM configuration.
