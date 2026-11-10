//! Integration tests running against an in-process mock KMS server.
//!
//! The mock implements the two KMS operations used by ejsonkms (Encrypt and
//! Decrypt) as identity transforms: the ciphertext blob is the plaintext. This
//! mirrors what the Go project does with `nsmithuk/local-kms` in docker-compose,
//! but without requiring docker.

// Test helpers panic on failure by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

fn handle_connection(mut stream: TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    // Read headers
    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return,
        }
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let content_length: usize = headers
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);

    // Read body
    while buf.len() < header_end + content_length {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return,
        }
    }
    let body: serde_json::Value =
        serde_json::from_slice(&buf[header_end..header_end + content_length])
            .unwrap_or(serde_json::Value::Null);

    let target = headers
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("x-amz-target")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default();

    let key_id = "arn:aws:kms:us-east-1:111122223333:key/bc436485-5092-42b8-92a3-0aa8b93536dc";
    let response_body = match target.as_str() {
        "TrentService.Encrypt" => {
            let plaintext = body["Plaintext"].as_str().unwrap_or_default();
            serde_json::json!({ "CiphertextBlob": plaintext, "KeyId": key_id })
        }
        "TrentService.Decrypt" => {
            let ciphertext = body["CiphertextBlob"].as_str().unwrap_or_default();
            serde_json::json!({ "Plaintext": ciphertext, "KeyId": key_id })
        }
        _ => serde_json::json!({ "__type": "UnknownOperationException" }),
    }
    .to_string();

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Start the mock KMS server on an ephemeral port and return its URL.
fn start_mock_kms() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock KMS");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(|| handle_connection(stream));
        }
    });
    format!("http://{addr}")
}

/// Run the compiled `ejsonkms` binary.
fn cli(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_ejsonkms"))
        .args(args)
        .output()
        .expect("run ejsonkms")
}

/// Run the compiled `ejsonkms` binary, expecting success; returns stdout.
fn cli_ok(args: &[&str]) -> String {
    let output = cli(args);
    assert!(output.status.success(), "ejsonkms {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn full_roundtrip_with_mock_kms() {
    let url = start_mock_kms();
    std::env::set_var("FAKE_AWSKMS_URL", &url);
    std::env::set_var("AWS_ACCESS_KEY_ID", "123");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "xyz");

    let kms_key_id = "bc436485-5092-42b8-92a3-0aa8b93536dc";
    let aws_region = "us-east-1";

    // --- keygen ---
    let keys = ejsonkms::keygen(kms_key_id, aws_region)
        .await
        .expect("keygen should succeed");
    assert_eq!(keys.public_key.len(), 64);
    assert_eq!(keys.private_key.len(), 64);
    assert_ne!(keys.public_key, keys.private_key);
    // The mock KMS is an identity transform, so the encrypted private key
    // decodes back to the plaintext private key
    assert_eq!(
        BASE64.decode(&keys.private_key_enc).unwrap(),
        keys.private_key.as_bytes()
    );

    // --- write an EJSON file and encrypt it in place ---
    let temp_dir = tempfile::TempDir::new().unwrap();
    let ejson_path = temp_dir.path().join("secrets.ejson");
    let contents = serde_json::json!({
        "_public_key": keys.public_key,
        "_private_key_enc": keys.private_key_enc,
        "environment": { "my_secret": "secret123" }
    });
    std::fs::write(
        &ejson_path,
        serde_json::to_string_pretty(&contents).unwrap(),
    )
    .unwrap();

    let ejson_path_str = ejson_path.to_str().unwrap().to_string();
    cli_ok(&["encrypt", &ejson_path_str]);

    let encrypted = std::fs::read_to_string(&ejson_path).unwrap();
    assert!(encrypted.contains("EJ["), "secret should be encrypted");
    assert!(!encrypted.contains("secret123"));

    // --- decrypt ---
    let decrypted = ejsonkms::decrypt(&ejson_path_str, aws_region)
        .await
        .expect("decrypt should succeed");
    let decrypted = String::from_utf8(decrypted.to_vec()).unwrap();
    assert!(decrypted.contains(r#""my_secret": "secret123""#));

    assert_eq!(
        cli_ok(&["decrypt", "--aws-region", aws_region, &ejson_path_str]),
        decrypted
    );

    // --- decrypt -o writes the output file with 0600 permissions ---
    let out_path = temp_dir.path().join("decrypted.json");
    let stdout = cli_ok(&[
        "decrypt",
        "--aws-region",
        aws_region,
        "-o",
        out_path.to_str().unwrap(),
        &ejson_path_str,
    ]);
    assert_eq!(stdout, "", "decrypt -o should not print the plaintext");
    assert!(std::fs::read_to_string(&out_path)
        .unwrap()
        .contains("secret123"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "decrypted file should be 0600");
    }

    // --- decrypt -o over an existing world-readable file replaces it with
    // an owner-only one and leaves no temporary file behind ---
    let existing_path = temp_dir.path().join("existing.json");
    std::fs::write(&existing_path, "stale").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&existing_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    cli_ok(&[
        "decrypt",
        "--aws-region",
        aws_region,
        "-o",
        existing_path.to_str().unwrap(),
        &ejson_path_str,
    ]);
    assert!(std::fs::read_to_string(&existing_path)
        .unwrap()
        .contains("secret123"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&existing_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "replaced file should be 0600");
    }
    let leftovers: Vec<_> = std::fs::read_dir(temp_dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");

    // --- env ---
    assert_eq!(
        cli_ok(&["env", "--aws-region", aws_region, &ejson_path_str]),
        "export my_secret='secret123'\n"
    );

    // --- env --quiet ---
    assert_eq!(
        cli_ok(&[
            "env",
            "--quiet",
            "--aws-region",
            aws_region,
            &ejson_path_str
        ]),
        "my_secret='secret123'\n"
    );

    // --- env with no environment key: empty export, not an error ---
    let no_env_path = temp_dir.path().join("no_env.ejson");
    let contents = serde_json::json!({
        "_public_key": keys.public_key,
        "_private_key_enc": keys.private_key_enc,
        "other": "value"
    });
    std::fs::write(&no_env_path, serde_json::to_string(&contents).unwrap()).unwrap();
    assert_eq!(
        cli_ok(&[
            "env",
            "--aws-region",
            aws_region,
            no_env_path.to_str().unwrap()
        ]),
        ""
    );

    // --- decrypt a file with no _private_key_enc fails before touching KMS ---
    let err = ejsonkms::decrypt("testdata/test_no_private_key.ejson", aws_region)
        .await
        .expect_err("decrypt should fail without _private_key_enc");
    assert!(err.to_string().contains("missing _private_key_enc"));

    // --- YAML roundtrip ---
    let yaml_path = temp_dir.path().join("secrets.eyaml");
    let yaml_contents = format!(
        "_public_key: \"{}\"\n_private_key_enc: \"{}\"\nenvironment:\n  my_secret: \"secret123\"\n",
        keys.public_key, keys.private_key_enc
    );
    std::fs::write(&yaml_path, yaml_contents).unwrap();
    let yaml_path_str = yaml_path.to_str().unwrap().to_string();

    cli_ok(&["encrypt", &yaml_path_str]);
    let encrypted = std::fs::read_to_string(&yaml_path).unwrap();
    assert!(encrypted.contains("EJ["), "yaml secret should be encrypted");
    assert!(!encrypted.contains("secret123"));

    let decrypted = ejsonkms::decrypt(&yaml_path_str, aws_region)
        .await
        .expect("yaml decrypt should succeed");
    assert!(String::from_utf8(decrypted.to_vec())
        .unwrap()
        .contains("secret123"));

    assert_eq!(
        cli_ok(&["env", "--aws-region", aws_region, &yaml_path_str]),
        "export my_secret='secret123'\n"
    );

    // --- TOML roundtrip ---
    let toml_path = temp_dir.path().join("secrets.etoml");
    let toml_contents = format!(
        "_public_key = \"{}\"\n_private_key_enc = \"{}\"\n\n[environment]\nmy_secret = \"secret123\"\n",
        keys.public_key, keys.private_key_enc
    );
    std::fs::write(&toml_path, toml_contents).unwrap();
    let toml_path_str = toml_path.to_str().unwrap().to_string();

    cli_ok(&["encrypt", &toml_path_str]);
    let encrypted = std::fs::read_to_string(&toml_path).unwrap();
    assert!(encrypted.contains("EJ["), "toml secret should be encrypted");
    assert!(!encrypted.contains("secret123"));

    let decrypted = ejsonkms::decrypt(&toml_path_str, aws_region)
        .await
        .expect("toml decrypt should succeed");
    assert!(String::from_utf8(decrypted.to_vec())
        .unwrap()
        .contains("secret123"));

    assert_eq!(
        cli_ok(&["env", "--aws-region", aws_region, &toml_path_str]),
        "export my_secret='secret123'\n"
    );

    // --- keygen -o writes the format matching the file extension ---
    let keygen_yaml = temp_dir.path().join("keygen.eyaml");
    cli_ok(&[
        "keygen",
        "--kms-key-id",
        kms_key_id,
        "--aws-region",
        aws_region,
        "-o",
        keygen_yaml.to_str().unwrap(),
    ]);
    let written: serde_json::Value =
        serde_norway::from_slice::<serde_json::Value>(&std::fs::read(&keygen_yaml).unwrap())
            .expect("keygen output should be valid YAML");
    assert!(written["_public_key"].is_string());
    assert!(written["_private_key_enc"].is_string());

    let keygen_toml = temp_dir.path().join("keygen.etoml");
    cli_ok(&[
        "keygen",
        "--kms-key-id",
        kms_key_id,
        "--aws-region",
        aws_region,
        "-o",
        keygen_toml.to_str().unwrap(),
    ]);
    let written: toml::Value = toml::from_str(&std::fs::read_to_string(&keygen_toml).unwrap())
        .expect("keygen output should be valid TOML");
    assert!(written["_public_key"].is_str());
    assert!(written["_private_key_enc"].is_str());

    // --- keygen -o refuses to overwrite an existing file ---
    let before = std::fs::read(&ejson_path).unwrap();
    let output = cli(&[
        "keygen",
        "--kms-key-id",
        kms_key_id,
        "--aws-region",
        aws_region,
        "-o",
        &ejson_path_str,
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with("Key generation failed: ") && stderr.contains("already exists"),
        "unexpected stderr: {stderr}"
    );
    assert_eq!(std::fs::read(&ejson_path).unwrap(), before);

    // --- the keygen command prints the private key only when asked ---
    let run_keygen = |extra: &[&str]| {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_ejsonkms"))
            .args(["keygen", "--kms-key-id", kms_key_id])
            .args(["--aws-region", aws_region])
            .args(extra)
            .output()
            .expect("run ejsonkms keygen");
        assert!(output.status.success(), "keygen failed: {output:?}");
        String::from_utf8(output.stdout).unwrap()
    };

    // By default stdout is just the document, so it can be redirected to a file.
    let stdout = run_keygen(&[]);
    assert!(!stdout.contains("Private Key"), "{stdout}");
    let document: serde_json::Value =
        serde_json::from_str(&stdout).expect("keygen stdout should be the JSON document");
    assert!(document["_public_key"].is_string());
    let private_key = BASE64
        .decode(document["_private_key_enc"].as_str().unwrap())
        .unwrap();
    let private_key = String::from_utf8(private_key).unwrap();
    assert!(!stdout.contains(&private_key), "{stdout}");

    // -o prints nothing at all.
    let quiet_path = temp_dir.path().join("quiet.ejson");
    assert_eq!(run_keygen(&["-o", quiet_path.to_str().unwrap()]), "");
    assert!(quiet_path.exists());

    // --show-private-key keeps the previous output.
    let stdout = run_keygen(&["--show-private-key"]);
    let mut lines = stdout.lines();
    let shown = lines
        .next()
        .and_then(|line| line.strip_prefix("Private Key: "))
        .expect("first line should be the private key");
    assert_eq!(shown.len(), 64);
    assert_eq!(lines.next(), Some("EJSON File:"));
    let document: serde_json::Value =
        serde_json::from_str(&lines.collect::<Vec<_>>().join("\n")).unwrap();
    // The mock KMS is an identity transform, so the wrapped key is the key.
    assert_eq!(
        BASE64
            .decode(document["_private_key_enc"].as_str().unwrap())
            .unwrap(),
        shown.as_bytes()
    );
}
