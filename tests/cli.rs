//! End-to-end tests that run the compiled `ejsonkms` binary against the mock
//! KMS: exit codes, what goes to stdout versus stderr, and the files written.

// Test helpers panic on failure by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{DENIED_KEY_ID, DENIED_PLAINTEXT, KMS_KEY_ID, MockKms};
use serde_json::json;

/// A mock KMS, a scratch directory and a keypair generated through the CLI.
struct Fixture {
    kms: MockKms,
    dir: tempfile::TempDir,
    public_key: String,
    private_key_enc: String,
}

impl Fixture {
    fn new() -> Self {
        let kms = MockKms::start();
        let document: serde_json::Value =
            serde_json::from_str(&kms.run_ok(&["keygen", "--kms-key-id", KMS_KEY_ID])).unwrap();
        Self {
            kms,
            dir: tempfile::TempDir::new().unwrap(),
            public_key: document["_public_key"].as_str().unwrap().to_string(),
            private_key_enc: document["_private_key_enc"].as_str().unwrap().to_string(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write `contents` to `name` in the scratch directory.
    fn write(&self, name: &str, contents: &str) -> String {
        let path = self.path(name);
        std::fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_string()
    }

    /// Write a JSON secrets file with this fixture's keys and encrypt it.
    fn encrypted_json(&self, name: &str, environment: serde_json::Value) -> String {
        let path = self.write(
            name,
            &json!({
                "_public_key": self.public_key,
                "_private_key_enc": self.private_key_enc,
                "environment": environment,
            })
            .to_string(),
        );
        self.kms.run_ok(&["encrypt", &path]);
        path
    }

    fn secrets(&self) -> String {
        self.encrypted_json("secrets.ejson", json!({ "my_secret": "secret123" }))
    }
}

fn read(path: impl AsRef<Path>) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[cfg(unix)]
fn mode(path: impl AsRef<Path>) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn encrypt_then_decrypt_roundtrips_in_every_format() {
    let fixture = Fixture::new();
    let (public_key, private_key_enc) = (&fixture.public_key, &fixture.private_key_enc);

    let documents = [
        (
            "secrets.ejson",
            format!(
                r#"{{"_public_key": "{public_key}", "_private_key_enc": "{private_key_enc}", "environment": {{"my_secret": "secret123"}}}}"#
            ),
        ),
        (
            "secrets.eyaml",
            format!(
                "_public_key: \"{public_key}\"\n_private_key_enc: \"{private_key_enc}\"\nenvironment:\n  my_secret: \"secret123\"\n"
            ),
        ),
        (
            "secrets.etoml",
            format!(
                "_public_key = \"{public_key}\"\n_private_key_enc = \"{private_key_enc}\"\n\n[environment]\nmy_secret = \"secret123\"\n"
            ),
        ),
    ];

    for (name, plaintext) in documents {
        let path = fixture.write(name, &plaintext);

        let stdout = fixture.kms.run_ok(&["encrypt", &path]);
        let encrypted = read(&path);
        assert_eq!(
            stdout,
            format!("Wrote {} bytes to {path}.\n", encrypted.len())
        );
        assert!(encrypted.contains("EJ["), "{name} should be encrypted");
        assert!(!encrypted.contains("secret123"), "{name}");

        let decrypted = fixture.kms.run_ok(&["decrypt", &path]);
        assert!(decrypted.contains("secret123"), "{name}: {decrypted}");
        assert!(!decrypted.contains("EJ["), "{name}: {decrypted}");

        assert_eq!(
            fixture.kms.run_ok(&["env", &path]),
            "export my_secret='secret123'\n",
            "{name}"
        );
    }
}

#[test]
fn encrypt_makes_no_kms_request() {
    let fixture = Fixture::new();
    let before = fixture.kms.requests().len();
    fixture.secrets();
    assert_eq!(fixture.kms.requests().len(), before);
}

#[test]
fn decrypt_o_writes_an_owner_only_file() {
    let fixture = Fixture::new();
    let secrets = fixture.secrets();

    let out = fixture.path("decrypted.json");
    let stdout = fixture
        .kms
        .run_ok(&["decrypt", "-o", out.to_str().unwrap(), &secrets]);
    assert_eq!(stdout, "", "decrypt -o should not print the plaintext");
    assert!(read(&out).contains("secret123"));
    #[cfg(unix)]
    assert_eq!(mode(&out), 0o600);
}

#[test]
fn decrypt_o_replaces_an_existing_file_without_reusing_its_permissions() {
    let fixture = Fixture::new();
    let secrets = fixture.secrets();

    let existing = fixture.write("existing.json", "stale");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    fixture.kms.run_ok(&["decrypt", "-o", &existing, &secrets]);
    assert!(read(&existing).contains("secret123"));
    #[cfg(unix)]
    assert_eq!(mode(&existing), 0o600);

    let leftovers: Vec<_> = std::fs::read_dir(fixture.dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
}

#[test]
fn decrypt_o_accepts_a_bare_file_name() {
    let fixture = Fixture::new();
    let secrets = fixture.secrets();

    // No directory component: the temporary file goes in the current directory.
    let output = fixture
        .kms
        .command()
        .current_dir(fixture.dir.path())
        .args(["decrypt", "-o", "plain.json", &secrets])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let out = fixture.path("plain.json");
    assert!(read(&out).contains("secret123"));
    #[cfg(unix)]
    assert_eq!(mode(&out), 0o600);
}

#[test]
fn env_prints_assignments() {
    let fixture = Fixture::new();
    let secrets = fixture.secrets();

    assert_eq!(
        fixture.kms.run_ok(&["env", &secrets]),
        "export my_secret='secret123'\n"
    );
    assert_eq!(
        fixture.kms.run_ok(&["env", "--quiet", &secrets]),
        "my_secret='secret123'\n"
    );
}

#[test]
fn env_shell_selects_the_syntax() {
    let fixture = Fixture::new();
    let secrets = fixture.secrets();

    assert_eq!(
        fixture.kms.run_ok(&["env", "--shell", "posix", &secrets]),
        "export my_secret='secret123'\n"
    );
    assert_eq!(
        fixture.kms.run_ok(&["env", "--shell", "fish", &secrets]),
        "set -gx my_secret 'secret123'\n"
    );

    // `auto` follows $FISH_VERSION; the default stays POSIX either way.
    let run_with_fish = |args: &[&str]| {
        let output = fixture
            .kms
            .command()
            .env("FISH_VERSION", "4.0")
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    };
    assert_eq!(
        run_with_fish(&["env", "--shell", "auto", &secrets]),
        "set -gx my_secret 'secret123'\n"
    );
    assert_eq!(
        run_with_fish(&["env", &secrets]),
        "export my_secret='secret123'\n"
    );
    let output = fixture
        .kms
        .command()
        .env_remove("FISH_VERSION")
        .args(["env", "--shell", "auto", &secrets])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "export my_secret='secret123'\n"
    );

    let output = fixture.kms.run(&["env", "--shell", "csh", &secrets]);
    assert_eq!(output.code, Some(2));
}

#[test]
fn env_trim_underscore_prefix_renames_variables() {
    let fixture = Fixture::new();
    let path = fixture.encrypted_json(
        "underscore.ejson",
        json!({ "_HOST": "db.internal", "PASSWORD": "secret123" }),
    );

    assert_eq!(
        fixture.kms.run_ok(&["env", &path]),
        "export PASSWORD='secret123'\nexport _HOST='db.internal'\n"
    );
    assert_eq!(
        fixture
            .kms
            .run_ok(&["env", "--trim-underscore-prefix", &path]),
        "export HOST='db.internal'\nexport PASSWORD='secret123'\n"
    );
}

#[test]
fn env_without_an_environment_section_prints_nothing() {
    let fixture = Fixture::new();
    let path = fixture.write(
        "no_env.ejson",
        &json!({
            "_public_key": fixture.public_key,
            "_private_key_enc": fixture.private_key_enc,
            "other": "value",
        })
        .to_string(),
    );
    assert_eq!(fixture.kms.run_ok(&["env", &path]), "");
}

#[test]
fn env_rejects_an_invalid_variable_name() {
    let fixture = Fixture::new();
    let path = fixture.encrypted_json("bad_env.ejson", json!({ "not valid": "x" }));

    let output = fixture.kms.run(&["env", &path]);
    assert_eq!(output.code, Some(1));
    assert_eq!(output.stdout, "");
    assert_eq!(
        output.stderr,
        "error: could not load environment from file: invalid identifier as key in environment: \"not valid\"\n"
    );
}

#[test]
fn keygen_prints_only_the_document_by_default() {
    let kms = MockKms::start();

    // stdout is just the document, so it can be redirected to a file.
    let stdout = kms.run_ok(&["keygen", "--kms-key-id", KMS_KEY_ID]);
    assert!(!stdout.contains("Private Key"), "{stdout}");
    let document: serde_json::Value =
        serde_json::from_str(&stdout).expect("keygen stdout should be the JSON document");
    assert_eq!(document["_public_key"].as_str().unwrap().len(), 64);

    let (private_key, _) = common::unwrap(document["_private_key_enc"].as_str().unwrap());
    let private_key = String::from_utf8(private_key).unwrap();
    assert_eq!(private_key.len(), 64);
    assert!(!stdout.contains(&private_key), "{stdout}");
}

#[test]
fn keygen_show_private_key_prints_the_key_first() {
    let kms = MockKms::start();

    let stdout = kms.run_ok(&["keygen", "--kms-key-id", KMS_KEY_ID, "--show-private-key"]);
    let mut lines = stdout.lines();
    let shown = lines
        .next()
        .and_then(|line| line.strip_prefix("Private Key: "))
        .expect("first line should be the private key");
    assert_eq!(lines.next(), Some("EJSON File:"));
    let document: serde_json::Value =
        serde_json::from_str(&lines.collect::<Vec<_>>().join("\n")).unwrap();

    // The key shown is the one KMS was asked to wrap.
    let (private_key, _) = common::unwrap(document["_private_key_enc"].as_str().unwrap());
    assert_eq!(private_key, shown.as_bytes());
}

#[test]
fn keygen_o_writes_the_format_of_the_extension_and_prints_nothing() {
    let fixture = Fixture::new();
    let keygen = |name: &str| {
        let path = fixture.path(name);
        let stdout = fixture.kms.run_ok(&[
            "keygen",
            "--kms-key-id",
            KMS_KEY_ID,
            "-o",
            path.to_str().unwrap(),
        ]);
        assert_eq!(stdout, "", "{name}");
        read(path)
    };

    let written: serde_json::Value = serde_json::from_str(&keygen("new.ejson")).unwrap();
    assert!(written["_public_key"].is_string());
    assert!(written["_private_key_enc"].is_string());

    let written: serde_json::Value = serde_norway::from_str(&keygen("new.eyaml")).unwrap();
    assert!(written["_public_key"].is_string());
    assert!(written["_private_key_enc"].is_string());

    let written: toml::Value = toml::from_str(&keygen("new.etoml")).unwrap();
    assert!(written["_public_key"].is_str());
    assert!(written["_private_key_enc"].is_str());
}

#[test]
fn keygen_v2_files_encrypt_and_decrypt() {
    let fixture = Fixture::new();

    for (name, flags) in [
        ("pqc.ejson", &["--pqc"][..]),
        ("v2.ejson", &["--scheme", "v2"]),
    ] {
        let path = fixture.path(name);
        let path = path.to_str().unwrap();
        let mut args = vec!["keygen", "--kms-key-id", KMS_KEY_ID, "-o", path];
        args.extend_from_slice(flags);
        fixture.kms.run_ok(&args);

        let mut document: serde_json::Value = serde_json::from_str(&read(path)).unwrap();
        assert_ne!(
            document["_public_key"].as_str().unwrap().len(),
            64,
            "{name}: expected a v2 public key"
        );
        document["environment"] = json!({ "my_secret": "secret123" });
        std::fs::write(path, document.to_string()).unwrap();

        fixture.kms.run_ok(&["encrypt", path]);
        let encrypted = read(path);
        assert!(encrypted.contains("EJ[2:"), "{name}: {encrypted}");
        assert!(!encrypted.contains("secret123"), "{name}");

        assert_eq!(
            fixture.kms.run_ok(&["env", path]),
            "export my_secret='secret123'\n",
            "{name}"
        );
    }

    let output = fixture
        .kms
        .run(&["keygen", "--kms-key-id", KMS_KEY_ID, "--scheme", "v9"]);
    assert_eq!(output.code, Some(2));
    assert_eq!(output.stdout, "");
}

/// `keygen --bind-public-key -o <name>`, then add a secret and encrypt.
fn bound_secrets(fixture: &Fixture, name: &str) -> (String, serde_json::Value) {
    let path = fixture.path(name);
    let path = path.to_str().unwrap().to_string();
    fixture.kms.run_ok(&[
        "keygen",
        "--kms-key-id",
        KMS_KEY_ID,
        "--bind-public-key",
        "-o",
        &path,
    ]);
    let mut document: serde_json::Value = serde_json::from_str(&read(&path)).unwrap();
    document["environment"] = json!({ "my_secret": "secret123" });
    std::fs::write(&path, document.to_string()).unwrap();
    fixture.kms.run_ok(&["encrypt", &path]);
    let document = serde_json::from_str(&read(&path)).unwrap();
    (path, document)
}

#[test]
fn keygen_bind_public_key_uses_a_kms_encryption_context() {
    let fixture = Fixture::new();
    let (path, document) = bound_secrets(&fixture, "bound.ejson");
    let public_key = document["_public_key"].as_str().unwrap();
    let context = json!({ "ejsonkms_public_key": public_key });

    // The file records the binding, in the clear, and encrypt leaves it alone.
    assert_eq!(document["_kms_encryption_context"], "public_key");

    // KMS was asked to encrypt under that context ...
    let (_, wrapped_context) = common::unwrap(document["_private_key_enc"].as_str().unwrap());
    assert_eq!(wrapped_context, context);

    // ... and decrypt presents the same one.
    assert_eq!(
        fixture.kms.run_ok(&["env", &path]),
        "export my_secret='secret123'\n"
    );
    let request = fixture.kms.requests().pop().unwrap();
    assert_eq!(request.operation, "Decrypt");
    assert_eq!(request.body["EncryptionContext"], context);
}

#[test]
fn files_without_the_marker_send_no_encryption_context() {
    let fixture = Fixture::new();
    let secrets = fixture.secrets();

    fixture.kms.run_ok(&["decrypt", &secrets]);
    let request = fixture.kms.requests().pop().unwrap();
    assert_eq!(request.operation, "Decrypt");
    assert!(
        request.body.get("EncryptionContext").is_none(),
        "{request:?}"
    );
}

#[test]
fn a_bound_key_cannot_be_used_from_another_file() {
    let fixture = Fixture::new();
    let (_, bound) = bound_secrets(&fixture, "bound.ejson");
    let (_, other) = bound_secrets(&fixture, "other.ejson");

    let expect_refused = |name: &str, document: &serde_json::Value| {
        let path = fixture.write(name, &document.to_string());
        let output = fixture.kms.run(&["decrypt", &path]);
        assert_eq!(output.code, Some(1), "{name}");
        assert_eq!(output.stdout, "", "{name}");
        assert!(
            output
                .stderr
                .starts_with("Decryption failed: unable to decrypt parameter: ")
                && output.stderr.contains("InvalidCiphertextException"),
            "{name}: {}",
            output.stderr
        );
    };

    // The wrapped key lifted into a file with a different public key.
    let mut lifted = other.clone();
    lifted["_private_key_enc"] = bound["_private_key_enc"].clone();
    expect_refused("lifted.ejson", &lifted);

    // The marker removed, so no context is presented.
    let mut stripped = bound.clone();
    stripped
        .as_object_mut()
        .unwrap()
        .remove("_kms_encryption_context");
    expect_refused("stripped.ejson", &stripped);

    // A marker added to a key that was not bound.
    let unbound = fixture.secrets();
    let mut marked: serde_json::Value = serde_json::from_str(&read(&unbound)).unwrap();
    marked["_kms_encryption_context"] = json!("public_key");
    expect_refused("marked.ejson", &marked);
}

#[test]
fn an_unknown_encryption_context_marker_is_rejected_without_calling_kms() {
    let fixture = Fixture::new();
    let secrets = fixture.secrets();
    let mut document: serde_json::Value = serde_json::from_str(&read(&secrets)).unwrap();
    document["_kms_encryption_context"] = json!("something_else");
    let path = fixture.write("unknown.ejson", &document.to_string());
    let requests = fixture.kms.requests().len();

    let output = fixture.kms.run(&["decrypt", &path]);
    assert_eq!(output.code, Some(1));
    assert_eq!(
        output.stderr,
        "Decryption failed: unsupported _kms_encryption_context: \"something_else\"\n"
    );
    assert_eq!(fixture.kms.requests().len(), requests);
}

#[test]
fn keygen_o_refuses_to_overwrite_an_existing_file() {
    let fixture = Fixture::new();
    let secrets = fixture.secrets();
    let before = read(&secrets);
    let requests = fixture.kms.requests().len();

    let output = fixture
        .kms
        .run(&["keygen", "--kms-key-id", KMS_KEY_ID, "-o", &secrets]);
    assert_eq!(output.code, Some(1));
    assert_eq!(output.stdout, "");
    assert_eq!(
        output.stderr,
        format!(
            "Key generation failed: io error: {secrets} already exists; refusing to overwrite it\n"
        )
    );
    assert_eq!(read(&secrets), before);
    // It fails before asking KMS for anything.
    assert_eq!(fixture.kms.requests().len(), requests);
}

#[test]
fn keygen_reports_a_kms_failure() {
    let fixture = Fixture::new();
    let out = fixture.path("new.ejson");

    let output = fixture.kms.run(&[
        "keygen",
        "--kms-key-id",
        DENIED_KEY_ID,
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(output.code, Some(1));
    assert_eq!(output.stdout, "");
    assert!(
        output
            .stderr
            .starts_with("Key generation failed: unable to encrypt parameter: ")
            && output.stderr.contains("AccessDeniedException"),
        "{}",
        output.stderr
    );
    assert!(!out.exists(), "no file should be written when KMS fails");
}

#[test]
fn decrypt_reports_a_kms_failure() {
    let fixture = Fixture::new();
    let path = fixture.write(
        "denied.ejson",
        &json!({
            "_public_key": fixture.public_key,
            "_private_key_enc": common::wrap(DENIED_PLAINTEXT, &json!({})),
        })
        .to_string(),
    );

    let output = fixture.kms.run(&["decrypt", &path]);
    assert_eq!(output.code, Some(1));
    assert_eq!(output.stdout, "");
    assert!(
        output
            .stderr
            .starts_with("Decryption failed: unable to decrypt parameter: ")
            && output.stderr.contains("AccessDeniedException"),
        "{}",
        output.stderr
    );
}

#[test]
fn decrypt_fails_when_the_wrapped_key_is_for_another_public_key() {
    let fixture = Fixture::new();
    let secrets = fixture.secrets();

    // Swap in the wrapped private key of a different keypair.
    let other = Fixture::new();
    let mut document: serde_json::Value = serde_json::from_str(&read(&secrets)).unwrap();
    document["_private_key_enc"] = json!(other.private_key_enc);
    let tampered = fixture.write("tampered.ejson", &document.to_string());

    let output = fixture.kms.run(&["decrypt", &tampered]);
    assert_eq!(output.code, Some(1));
    assert_eq!(output.stdout, "", "no plaintext on failure");
    assert!(
        output.stderr.starts_with("Decryption failed: "),
        "{}",
        output.stderr
    );
    assert!(!output.stderr.contains("secret123"));
}

#[test]
fn decrypt_rejects_files_it_cannot_use_without_calling_kms() {
    let fixture = Fixture::new();
    let requests = fixture.kms.requests().len();

    let cases = [
        (
            fixture.write(
                "no_key.ejson",
                &json!({ "_public_key": fixture.public_key }).to_string(),
            ),
            "Decryption failed: missing _private_key_enc field\n".to_string(),
        ),
        (
            fixture.write(
                "bad_base64.ejson",
                &json!({ "_public_key": fixture.public_key, "_private_key_enc": "!!!" })
                    .to_string(),
            ),
            "Decryption failed: base64 decode error: ".to_string(),
        ),
        (
            fixture.write("secrets.txt", "{}"),
            "Decryption failed: unsupported file extension: txt\n".to_string(),
        ),
        (
            fixture.write("broken.ejson", "{"),
            "Decryption failed: json error: ".to_string(),
        ),
    ];

    for (path, expected) in cases {
        let output = fixture.kms.run(&["decrypt", &path]);
        assert_eq!(output.code, Some(1), "{path}");
        assert_eq!(output.stdout, "", "{path}");
        assert!(
            output.stderr.starts_with(&expected),
            "{path}: {}",
            output.stderr
        );
    }

    let missing = fixture.path("missing.ejson");
    let output = fixture.kms.run(&["decrypt", missing.to_str().unwrap()]);
    assert_eq!(output.code, Some(1));
    assert!(
        output
            .stderr
            .starts_with(&format!("Decryption failed: {}: ", missing.display())),
        "{}",
        output.stderr
    );

    assert_eq!(fixture.kms.requests().len(), requests);
}

#[test]
fn rewrap_moves_a_file_to_another_kms_key() {
    let fixture = Fixture::new();
    let public_key = &fixture.public_key;
    let private_key_enc = &fixture.private_key_enc;
    let path = fixture.write(
        "secrets.eyaml",
        &format!(
            "# deploy secrets\n_public_key: \"{public_key}\"\n_private_key_enc: \"{private_key_enc}\" # wrapped by KMS\nenvironment:\n  my_secret: \"secret123\"\n"
        ),
    );
    fixture.kms.run_ok(&["encrypt", &path]);
    let before = read(&path);
    assert_eq!(common::key_id_of(private_key_enc), KMS_KEY_ID);

    let stdout = fixture
        .kms
        .run_ok(&["rewrap", "--kms-key-id", "alias/other", &path]);
    assert_eq!(stdout, format!("Rewrapped {path}.\n"));

    // Only the wrapped key changed: same private key, new KMS key.
    let after = read(&path);
    let document: serde_json::Value = serde_norway::from_str(&after).unwrap();
    let rewrapped = document["_private_key_enc"].as_str().unwrap();
    assert_eq!(after, before.replace(private_key_enc.as_str(), rewrapped));
    assert_eq!(common::key_id_of(rewrapped), "alias/other");
    assert_eq!(
        common::unwrap(rewrapped).0,
        common::unwrap(private_key_enc).0
    );

    assert_eq!(
        fixture.kms.run_ok(&["env", &path]),
        "export my_secret='secret123'\n"
    );
}

#[test]
fn rewrap_can_bind_an_existing_file_to_its_public_key() {
    let fixture = Fixture::new();
    let secrets = fixture.secrets();
    let before: serde_json::Value = serde_json::from_str(&read(&secrets)).unwrap();
    assert!(before.get("_kms_encryption_context").is_none());

    fixture.kms.run_ok(&[
        "rewrap",
        "--kms-key-id",
        KMS_KEY_ID,
        "--bind-public-key",
        &secrets,
    ]);

    let after: serde_json::Value = serde_json::from_str(&read(&secrets)).unwrap();
    assert_eq!(after["_kms_encryption_context"], "public_key");
    assert_eq!(after["_public_key"], before["_public_key"]);
    assert_eq!(after["environment"], before["environment"]);
    let (_, context) = common::unwrap(after["_private_key_enc"].as_str().unwrap());
    assert_eq!(
        context,
        json!({ "ejsonkms_public_key": fixture.public_key })
    );

    assert_eq!(
        fixture.kms.run_ok(&["env", &secrets]),
        "export my_secret='secret123'\n"
    );

    // A later rewrap without the flag keeps the binding.
    fixture
        .kms
        .run_ok(&["rewrap", "--kms-key-id", "alias/other", &secrets]);
    let again: serde_json::Value = serde_json::from_str(&read(&secrets)).unwrap();
    assert_eq!(again["_kms_encryption_context"], "public_key");
    let (_, context) = common::unwrap(again["_private_key_enc"].as_str().unwrap());
    assert_eq!(
        context,
        json!({ "ejsonkms_public_key": fixture.public_key })
    );
    assert_eq!(
        fixture.kms.run_ok(&["env", &secrets]),
        "export my_secret='secret123'\n"
    );
}

#[test]
fn rewrap_leaves_the_file_alone_when_kms_refuses() {
    let fixture = Fixture::new();
    let secrets = fixture.secrets();
    let before = read(&secrets);

    let output = fixture
        .kms
        .run(&["rewrap", "--kms-key-id", DENIED_KEY_ID, &secrets]);
    assert_eq!(output.code, Some(1));
    assert_eq!(output.stdout, "");
    assert!(
        output
            .stderr
            .starts_with("Rewrap failed: unable to encrypt parameter: "),
        "{}",
        output.stderr
    );
    assert_eq!(read(&secrets), before);

    let leftovers: Vec<_> = std::fs::read_dir(fixture.dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
}

#[test]
fn completions_and_man_page_are_generated() {
    let kms = MockKms::start();

    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let script = kms.run_ok(&["completions", shell]);
        assert!(script.contains("ejsonkms"), "{shell}");
        for command in ["encrypt", "decrypt", "keygen", "env", "rewrap"] {
            assert!(script.contains(command), "{shell}: no {command}");
        }
    }
    assert_eq!(kms.run(&["completions", "csh"]).code, Some(2));

    let man = kms.run_ok(&["man"]);
    assert!(man.contains(".TH ejsonkms 1"), "{man}");
    assert!(man.contains("rewrap"), "{man}");

    // Neither talks to KMS.
    assert!(kms.requests().is_empty());
}

#[test]
fn usage_errors_exit_with_2() {
    let kms = MockKms::start();

    for args in [&[][..], &["encrypt"], &["keygen"], &["frobnicate"]] {
        let output = kms.run(args);
        assert_eq!(output.code, Some(2), "{args:?}");
        assert_eq!(output.stdout, "", "{args:?}");
        assert!(!output.stderr.is_empty(), "{args:?}");
    }

    let version = kms.run_ok(&["--version"]);
    assert_eq!(version, format!("ejsonkms {}\n", env!("CARGO_PKG_VERSION")));
}
