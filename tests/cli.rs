//! End-to-end tests of the `riegel` binary.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use riegel::PublicKey;

const PASSPHRASE_LINE: &str = "correct horse battery staple\n";
const NO_INPUT: &str = "";
/// Two payload chunks, so a decryption that fails in the last chunk has already written the
/// first one.
const TWO_CHUNK_MESSAGE_LEN: usize = 100_000;

/// A fresh, empty directory for one test.
fn scratch_dir(test_name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test_name);
    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs the tool with `input` on its standard input, which is where it takes a passphrase
/// from when it has no terminal.
fn riegel(input: &str, command: &str, arguments: &[&Path]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_riegel"))
        .arg(command)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The tool may exit without reading its input, which makes this write fail.
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    child.wait_with_output().unwrap()
}

fn message() -> Vec<u8> {
    (0..TWO_CHUNK_MESSAGE_LEN)
        .map(|i| (i % 251) as u8)
        .collect()
}

/// Generates a passphrase-protected key pair and encrypts `message()` in `dir`; returns the
/// secret key path and the container path.
fn keygen_and_encrypt(dir: &Path) -> (PathBuf, PathBuf) {
    let secret_key = dir.join("test.key");
    let public_key = dir.join("test.pub");
    let plain = dir.join("message.bin");
    let sealed = dir.join("message.riegel");
    fs::write(&plain, message()).unwrap();

    let keygen = riegel(PASSPHRASE_LINE, "keygen", &[&secret_key, &public_key]);
    assert!(keygen.status.success());
    let encrypt = riegel(NO_INPUT, "encrypt", &[&public_key, &plain, &sealed]);
    assert!(encrypt.status.success());
    (secret_key, sealed)
}

fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn encrypted_file_decrypts_to_the_original() {
    let dir = scratch_dir("encrypted_file_decrypts_to_the_original");
    let (secret_key, sealed) = keygen_and_encrypt(&dir);
    let opened = dir.join("opened.bin");

    let output = riegel(PASSPHRASE_LINE, "decrypt", &[&secret_key, &sealed, &opened]);

    assert!(output.status.success());
    assert_eq!(fs::read(&opened).unwrap(), message());
    assert_eq!(
        file_names(&dir),
        [
            "message.bin",
            "message.riegel",
            "opened.bin",
            "test.key",
            "test.pub"
        ]
    );
}

#[test]
fn secret_key_file_is_encrypted_with_the_passphrase() {
    let dir = scratch_dir("secret_key_file_is_encrypted_with_the_passphrase");
    let (secret_key, _) = keygen_and_encrypt(&dir);

    let key_file = fs::read_to_string(secret_key).unwrap();

    assert!(key_file.starts_with("riegel-sec-pw-1:"));
}

#[test]
fn decrypting_with_the_wrong_passphrase_fails_and_leaves_no_output() {
    let dir = scratch_dir("decrypting_with_the_wrong_passphrase_fails_and_leaves_no_output");
    let (secret_key, sealed) = keygen_and_encrypt(&dir);

    let output = riegel(
        "a different passphrase\n",
        "decrypt",
        &[&secret_key, &sealed, &dir.join("opened.bin")],
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("wrong passphrase"));
    assert_eq!(
        file_names(&dir),
        ["message.bin", "message.riegel", "test.key", "test.pub"]
    );
}

#[test]
fn decrypting_a_modified_file_fails_and_leaves_no_output() {
    let dir = scratch_dir("decrypting_a_modified_file_fails_and_leaves_no_output");
    let (secret_key, sealed) = keygen_and_encrypt(&dir);
    let mut container = fs::read(&sealed).unwrap();
    *container.last_mut().unwrap() ^= 1;
    fs::write(&sealed, container).unwrap();

    let output = riegel(
        PASSPHRASE_LINE,
        "decrypt",
        &[&secret_key, &sealed, &dir.join("opened.bin")],
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("decryption failed"));
    assert_eq!(
        file_names(&dir),
        ["message.bin", "message.riegel", "test.key", "test.pub"]
    );
}

#[test]
fn existing_output_file_is_not_overwritten() {
    let dir = scratch_dir("existing_output_file_is_not_overwritten");
    let (secret_key, sealed) = keygen_and_encrypt(&dir);
    let opened = dir.join("opened.bin");
    fs::write(&opened, "keep me").unwrap();

    let output = riegel(PASSPHRASE_LINE, "decrypt", &[&secret_key, &sealed, &opened]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&opened).unwrap(), b"keep me");
}

#[test]
fn keygen_does_not_overwrite_an_existing_secret_key() {
    let dir = scratch_dir("keygen_does_not_overwrite_an_existing_secret_key");
    let secret_key = dir.join("test.key");
    fs::write(&secret_key, "keep me").unwrap();

    let output = riegel(
        PASSPHRASE_LINE,
        "keygen",
        &[&secret_key, &dir.join("test.pub")],
    );

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&secret_key).unwrap(), b"keep me");
    assert_eq!(file_names(&dir), ["test.key"]);
}

#[test]
fn keygen_writes_nothing_when_the_public_key_file_exists() {
    let dir = scratch_dir("keygen_writes_nothing_when_the_public_key_file_exists");
    let public_key = dir.join("test.pub");
    fs::write(&public_key, "keep me").unwrap();

    let output = riegel(
        PASSPHRASE_LINE,
        "keygen",
        &[&dir.join("test.key"), &public_key],
    );

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&public_key).unwrap(), b"keep me");
    assert_eq!(file_names(&dir), ["test.pub"]);
}

#[test]
fn keygen_refuses_one_file_for_both_keys() {
    let dir = scratch_dir("keygen_refuses_one_file_for_both_keys");
    let key = dir.join("test.key");

    let output = riegel(PASSPHRASE_LINE, "keygen", &[&key, &key]);

    assert_eq!(output.status.code(), Some(1));
    assert!(file_names(&dir).is_empty());
}

#[test]
fn keygen_without_a_passphrase_writes_nothing() {
    let dir = scratch_dir("keygen_without_a_passphrase_writes_nothing");

    let output = riegel(
        NO_INPUT,
        "keygen",
        &[&dir.join("test.key"), &dir.join("test.pub")],
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("passphrase"));
    assert!(file_names(&dir).is_empty());
}

#[test]
fn key_made_with_no_passphrase_flag_decrypts_without_a_passphrase() {
    let dir = scratch_dir("key_made_with_no_passphrase_flag_decrypts_without_a_passphrase");
    let secret_key = dir.join("test.key");
    let public_key = dir.join("test.pub");
    let plain = dir.join("message.bin");
    let sealed = dir.join("message.riegel");
    let opened = dir.join("opened.bin");
    fs::write(&plain, "unattended").unwrap();

    let keygen = riegel(
        NO_INPUT,
        "keygen",
        &[Path::new("--no-passphrase"), &secret_key, &public_key],
    );
    let encrypt = riegel(NO_INPUT, "encrypt", &[&public_key, &plain, &sealed]);
    let decrypt = riegel(NO_INPUT, "decrypt", &[&secret_key, &sealed, &opened]);

    assert!(keygen.status.success());
    assert!(encrypt.status.success());
    assert!(decrypt.status.success());
    assert!(
        fs::read_to_string(&secret_key)
            .unwrap()
            .starts_with("riegel-sec-1:")
    );
    assert_eq!(fs::read(&opened).unwrap(), b"unattended");
}

#[test]
fn fingerprint_command_prints_the_fingerprint_of_the_key() {
    let dir = scratch_dir("fingerprint_command_prints_the_fingerprint_of_the_key");
    let public_key = dir.join("test.pub");
    let keygen = riegel(
        PASSPHRASE_LINE,
        "keygen",
        &[&dir.join("test.key"), &public_key],
    );
    assert!(keygen.status.success());
    let key: PublicKey = fs::read_to_string(&public_key).unwrap().parse().unwrap();

    let output = riegel(NO_INPUT, "fingerprint", &[&public_key]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{}\n", key.fingerprint())
    );
}

#[test]
fn wrong_number_of_arguments_prints_usage() {
    let output = riegel(NO_INPUT, "encrypt", &[Path::new("only-one-argument")]);

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).starts_with("Usage:"));
}

#[cfg(unix)]
#[test]
fn secret_key_file_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch_dir("secret_key_file_is_readable_by_its_owner_only");
    let (secret_key, _) = keygen_and_encrypt(&dir);

    let mode = fs::metadata(&secret_key).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}
