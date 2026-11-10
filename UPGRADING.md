# Upgrading to ejsonkms 3.0

ejsonkms 3.0 keeps the file formats and the way the private key is stored.
Files created with 1.x or 2.x decrypt with 3.0, and files 3.0 creates by
default decrypt with 2.x and with the Go `ejsonkms`.

What changes is the Rust library API, a few behaviours of the command-line
tool, and two new opt-in features that older tools cannot read.

## Command-line tool

| Situation | 2.x | 3.0 |
| --- | --- | --- |
| `ejsonkms keygen` | printed `Private Key: …` first, then `EJSON File:` and the document | prints only the document; add `--show-private-key` for the old output |
| `ejsonkms keygen -o FILE` | printed `Private Key: …` | prints nothing; add `--show-private-key` to print the key |
| `ejsonkms keygen -o FILE` when `FILE` exists | overwrote it | fails: `FILE already exists; refusing to overwrite it` |
| `FAKE_AWSKMS_URL` | redirected KMS requests to that URL | ignored; set `AWS_ENDPOINT_URL_KMS` instead |

The private key is no longer printed because nothing needs it: the file
carries it encrypted with KMS, and that is the copy `decrypt` and `env` use.
If a script reads the key from `keygen`'s output, add `--show-private-key`.
If a script reads the document from stdout, it no longer has to skip the
`EJSON File:` line:

```text
ejsonkms keygen --kms-key-id alias/my-key > secrets.ejson
```

### Error messages

If a script matches on error text, check it against the new wording:

| 2.x | 3.0 |
| --- | --- |
| `Decryption failed: io error: No such file or directory (os error 2)` | `Decryption failed: secrets.ejson: No such file or directory (os error 2)` |
| `Decryption failed: utf-8 error: …` (a TOML file that is not UTF-8) | `Decryption failed: toml error: …` |
| `Key generation failed: unable to encrypt parameter: service error: NotFoundException: Alias … is not found. (ServiceError(ServiceError { source: …` | `Key generation failed: unable to encrypt parameter: service error: NotFoundException: Alias … is not found.` |

KMS failures used to end with several hundred characters of the AWS SDK's
internal state; they now stop after the cause.

### New commands and options

None of these change existing behaviour.

| | |
| --- | --- |
| `keygen --scheme v2` (or `--pqc`) | a hybrid X25519 + ML-KEM-768 keypair. The Go tools cannot read such files. |
| `keygen --bind-public-key` | binds the KMS-encrypted key to the file's public key with a KMS encryption context. ejsonkms before 3.0 and the Go tool cannot decrypt such files. |
| `rewrap --kms-key-id KEY FILE...` | re-encrypts a file's private key with another KMS key; `--bind-public-key` also binds it. |
| `env --shell posix\|fish\|auto` | the output syntax; the default is still `posix`. |
| `env --trim-underscore-prefix` | exports `_HOST` as `HOST`. |
| `completions <shell>`, `man` | a completion script, and the manual page. |

Files created with `--bind-public-key` contain
`"_kms_encryption_context": "public_key"`. Roll 3.0 out to everything that
decrypts before creating or rewrapping files with that option.

## Library

Add the dependency without the command-line tool's dependencies:

```toml
[dependencies]
ejsonkms = { version = "3", default-features = false }
```

### A `Client` instead of free functions

`keygen`, `decrypt` and `decrypt_env` are methods on a `Client`, which loads
the AWS configuration once. The region is set on the client instead of being
passed to every call, and `None` for "the default region" becomes simply not
setting one.

| 2.x | 3.0 |
| --- | --- |
| `ejsonkms::keygen(id, "us-east-1")` | `client.keygen(id, &KeygenOptions::default())` |
| `ejsonkms::decrypt(path, "us-east-1")` | `client.decrypt(path)` |
| `ejsonkms::decrypt(path, "")` | `Client::new().await.decrypt(path)` |
| `ejsonkms::actions::env_action(path, region, quiet, &mut out)` | `client.decrypt_env(path, UnderscorePrefix::Keep)`, then `ejson::env::export` |
| `ejsonkms::actions::keygen_action(id, region, out)` | `client.keygen(..)`, then `EjsonKmsKeys::to_document` |
| `ejsonkms::actions::encrypt_action(&files)` | `ejson::encrypt_file_in_place(file)` |
| `ejsonkms::actions::decrypt_action(path, region, out)` | `client.decrypt(path)`, then write the bytes |

The `actions` module was the command-line tool's own code and is no longer
public.

```rust,no_run
use ejson::UnderscorePrefix;
use ejson::env::{ExportStyle, Shell};
use ejsonkms::{Client, KeygenOptions};

# async fn example() -> ejsonkms::Result<()> {
// Region and credentials from the usual AWS configuration ...
let client = Client::new().await;
// ... or a specific region (and, for a local KMS, endpoint).
let client = Client::builder().region("us-east-1").build().await;

// keygen: the keys, and the document to write to a new secrets file.
let keys = client.keygen("alias/my-key", &KeygenOptions::default()).await?;
std::fs::write("secrets.ejson", keys.to_document(ejson::FileFormat::Json)?)?;

// decrypt: the plaintext document, wiped from memory when dropped.
let plaintext = client.decrypt("secrets.ejson").await?;

// env: the values under `environment`, written as shell assignments.
let environment = client
    .decrypt_env("secrets.ejson", UnderscorePrefix::Keep)
    .await?;
ejson::env::export(
    std::io::stdout(),
    &environment,
    Shell::Posix,
    ExportStyle::Exported,
)
.map_err(ejsonkms::Error::Env)?;
# Ok(())
# }
```

### Changed types

| 2.x | 3.0 |
| --- | --- |
| `decrypt` returns `Vec<u8>` | `Zeroizing<Vec<u8>>`; it dereferences to `Vec<u8>` |
| file paths are `&str` | `impl AsRef<Path>` |
| `EjsonKmsKeys { public_key, private_key_enc, private_key }` of `String`s | `#[non_exhaustive]`; `private_key` is `Zeroizing<String>`; adds `scheme` and `binding` |
| `EjsonKmsKeys` implements `Zeroize` and `ZeroizeOnDrop` | it doesn't; only the private key is wiped, on drop |
| `EjsonKmsError` | `Error`; the old name is a deprecated alias |
| – | `ejsonkms::Result<T>` |

`EjsonKmsKeys` can no longer be built with a struct literal, and a pattern on
it needs `..`:

```rust
# fn example(keys: ejsonkms::EjsonKmsKeys) {
let ejsonkms::EjsonKmsKeys {
    public_key,
    private_key_enc,
    ..
} = keys;
# }
```

### Errors

`Error` is `#[non_exhaustive]`, so a `match` on it needs a wildcard arm. Its
variants no longer contain other crates' error types or pre-formatted
strings:

| 2.x | 3.0 |
| --- | --- |
| `Json(serde_json::Error)`, `Yaml(serde_norway::Error)`, `Toml(toml::de::Error)`, `Base64(base64::DecodeError)` | each holds a `SourceError`, which displays the same message |
| `TomlSer(toml::ser::Error)`, `Utf8(Utf8Error)` | `Toml(SourceError)` |
| `Kms(String)` | `Kms(KmsError)`: `Decrypt`, `Encrypt`, `NoPlaintext`, `NoCiphertext`, `KeyNotUtf8` |
| `Env(String)` | `Env(ejson::env::EnvError)` |
| `Io(io::Error)` when the secrets file can't be read | `ReadFile { path, source }` |
| `From<serde_json::Error>` and the other parser conversions | removed |

```rust
use ejsonkms::{Error, KmsError};

fn describe(err: &Error) -> String {
    match err {
        Error::MissingPrivateKeyEnc => "not an ejsonkms file".to_string(),
        Error::Kms(KmsError::Decrypt(cause)) => format!("KMS refused: {cause}"),
        Error::ReadFile { path, .. } => format!("can't read {}", path.display()),
        other => other.to_string(),
    }
}
```

The AWS SDK's error behind a `KmsError::Decrypt` or `Encrypt` is the
`source()` of its payload.

## Coming from 1.x

Everything above applies, plus what 2.0 changed:

- ejsonkms 2.0 is built on ejson 2.0 and needs Rust 1.99.1 or later to build.
- Errors that come from ejson lost their internal prefixes. For example
  `Decryption failed: file format error: unsupported file extension: txt`
  became `Decryption failed: unsupported file extension: txt`. See the
  [ejson upgrade guide](https://github.com/runlevel5/ejson-rs/blob/main/UPGRADING.md)
  for the full list.
- `ejson::FileFormat` became non-exhaustive, and ejsonkms gained
  `UnsupportedFormat` for a format it does not know how to read
  `_private_key_enc` from.
