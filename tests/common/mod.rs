//! An in-process mock of the two KMS operations ejsonkms uses.
//!
//! `Encrypt` wraps the plaintext and its encryption context in a JSON
//! envelope and returns that as the ciphertext; `Decrypt` opens the envelope
//! and, like KMS, refuses when the encryption context differs. This mirrors
//! what the Go project does with `nsmithuk/local-kms` in docker-compose, but
//! without requiring docker.
//!
//! A few inputs make it fail the way KMS does:
//! - `Encrypt` with [`DENIED_KEY_ID`] is refused with `AccessDeniedException`.
//! - `Decrypt` of a ciphertext wrapping [`DENIED_PLAINTEXT`] is refused with
//!   `AccessDeniedException`.
//! - `Decrypt` of a ciphertext that is not an envelope returns those bytes as
//!   the plaintext, so a test can make "KMS" return anything.

// Test helpers panic on failure by design; not every test file uses all of them.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};

pub const KMS_KEY_ID: &str = "bc436485-5092-42b8-92a3-0aa8b93536dc";
pub const AWS_REGION: &str = "us-east-1";

/// A key id the mock refuses to encrypt with.
pub const DENIED_KEY_ID: &str = "alias/denied";
/// A plaintext the mock refuses to decrypt to.
pub const DENIED_PLAINTEXT: &[u8] = b"denied";

const KEY_ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/bc436485-5092-42b8-92a3-0aa8b93536dc";

/// One request the mock received.
#[derive(Clone, Debug)]
pub struct Request {
    /// `Encrypt` or `Decrypt`.
    pub operation: String,
    pub body: Value,
}

/// A running mock KMS.
pub struct MockKms {
    pub url: String,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl MockKms {
    /// Start the mock on an ephemeral port.
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock KMS");
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let log = Arc::clone(&log);
                std::thread::spawn(move || handle_connection(stream, &log));
            }
        });
        Self {
            url: format!("http://{addr}"),
            requests,
        }
    }

    /// Every request received so far.
    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    /// A command running the compiled `ejsonkms` binary against this mock,
    /// with nothing inherited from the caller's AWS configuration.
    pub fn command(&self) -> std::process::Command {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_ejsonkms"));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("AWS_") {
                command.env_remove(name);
            }
        }
        command
            .env("AWS_ENDPOINT_URL_KMS", &self.url)
            .env("AWS_ACCESS_KEY_ID", "123")
            .env("AWS_SECRET_ACCESS_KEY", "xyz")
            .env("AWS_REGION", AWS_REGION)
            .env("AWS_EC2_METADATA_DISABLED", "true");
        command
    }

    /// Run `ejsonkms` with `args`.
    pub fn run(&self, args: &[&str]) -> Output {
        let output = self.command().args(args).output().expect("run ejsonkms");
        Output {
            code: output.status.code(),
            stdout: String::from_utf8(output.stdout).unwrap(),
            stderr: String::from_utf8(output.stderr).unwrap(),
        }
    }

    /// Run `ejsonkms` with `args`, expecting success; returns stdout.
    pub fn run_ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert_eq!(output.code, Some(0), "ejsonkms {args:?}: {output:?}");
        output.stdout
    }
}

/// What a run of the binary produced.
#[derive(Debug)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Build the `_private_key_enc` the mock would produce for `plaintext`
/// encrypted under `context`.
pub fn wrap(plaintext: &[u8], context: &Value) -> String {
    BASE64.encode(envelope(&BASE64.encode(plaintext), context))
}

/// Open a `_private_key_enc` produced by the mock: the plaintext and the
/// encryption context it was encrypted under.
pub fn unwrap(private_key_enc: &str) -> (Vec<u8>, Value) {
    let envelope: Value = serde_json::from_slice(&BASE64.decode(private_key_enc).unwrap())
        .expect("not a mock KMS ciphertext");
    let plaintext = BASE64
        .decode(envelope["plaintext"].as_str().unwrap())
        .unwrap();
    (plaintext, envelope["context"].clone())
}

fn envelope(plaintext_base64: &str, context: &Value) -> Vec<u8> {
    json!({ "plaintext": plaintext_base64, "context": context })
        .to_string()
        .into_bytes()
}

fn context_of(body: &Value) -> Value {
    match &body["EncryptionContext"] {
        Value::Null => json!({}),
        context => context.clone(),
    }
}

fn error(kind: &str, message: &str) -> (u16, Value) {
    (400, json!({ "__type": kind, "message": message }))
}

fn respond(operation: &str, body: &Value) -> (u16, Value) {
    match operation {
        "Encrypt" => {
            if body["KeyId"] == DENIED_KEY_ID {
                return error(
                    "AccessDeniedException",
                    "User is not authorized to perform: kms:Encrypt",
                );
            }
            let plaintext = body["Plaintext"].as_str().unwrap_or_default();
            let ciphertext = BASE64.encode(envelope(plaintext, &context_of(body)));
            (
                200,
                json!({ "CiphertextBlob": ciphertext, "KeyId": KEY_ARN }),
            )
        }
        "Decrypt" => {
            let blob = BASE64
                .decode(body["CiphertextBlob"].as_str().unwrap_or_default())
                .unwrap_or_default();
            let (plaintext, context) = match serde_json::from_slice::<Value>(&blob) {
                Ok(envelope) if envelope["plaintext"].is_string() => (
                    BASE64
                        .decode(envelope["plaintext"].as_str().unwrap_or_default())
                        .unwrap_or_default(),
                    envelope["context"].clone(),
                ),
                // Not an envelope: hand the bytes back as the plaintext.
                _ => (blob, json!({})),
            };
            if context != context_of(body) {
                return error("InvalidCiphertextException", "");
            }
            if plaintext == DENIED_PLAINTEXT {
                return error(
                    "AccessDeniedException",
                    "User is not authorized to perform: kms:Decrypt",
                );
            }
            (
                200,
                json!({ "Plaintext": BASE64.encode(plaintext), "KeyId": KEY_ARN }),
            )
        }
        _ => error("UnknownOperationException", ""),
    }
}

fn handle_connection(mut stream: TcpStream, log: &Mutex<Vec<Request>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    // Read headers
    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let header = |wanted: &str| {
        headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(wanted)
                .then(|| value.trim().to_string())
        })
    };
    let content_length: usize = header("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);

    // Read body
    while buf.len() < header_end + content_length {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return,
        }
    }
    let body: Value = buf
        .get(header_end..header_end + content_length)
        .and_then(|body| serde_json::from_slice(body).ok())
        .unwrap_or(Value::Null);

    let operation = header("x-amz-target")
        .and_then(|target| target.strip_prefix("TrentService.").map(str::to_string))
        .unwrap_or_default();

    let (status, response_body) = respond(&operation, &body);
    log.lock().unwrap().push(Request { operation, body });

    let response_body = response_body.to_string();
    let reason = if status == 200 { "OK" } else { "Bad Request" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
        response_body.len(),
    );
    let _ = stream.write_all(response.as_bytes());
}
