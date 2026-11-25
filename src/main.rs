//! The `riegel` command-line tool: key generation, file encryption and file decryption.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use riegel::{PublicKey, SecretKey};
use zeroize::Zeroizing;

const USAGE: &str = "\
Usage:
  riegel keygen [--no-passphrase] <SECRET_KEY_FILE> <PUBLIC_KEY_FILE>
  riegel fingerprint <PUBLIC_KEY_FILE>
  riegel encrypt <PUBLIC_KEY_FILE> <INPUT_FILE> <OUTPUT_FILE>
  riegel decrypt <SECRET_KEY_FILE> <INPUT_FILE> <OUTPUT_FILE>

The secret key file is encrypted with a passphrase, which is asked for on the
terminal. When standard input is not a terminal, its first line is the passphrase.
Existing files are never overwritten.";

/// Larger than any key file; stops a wrong path from being read into memory whole.
const MAX_KEY_FILE_LEN: u64 = 4096;
/// Longest passphrase line accepted from standard input, including its line ending.
const MAX_PASSPHRASE_LINE_LEN: usize = 4096;

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let paths: Vec<&Path> = args.iter().skip(1).map(Path::new).collect();
    let command = args.first().and_then(|command| command.to_str());

    let result = match (command, paths.as_slice()) {
        (Some("keygen"), [secret_key, public_key]) => {
            keygen(secret_key, public_key, Protection::Passphrase)
        }
        (Some("keygen"), [flag, secret_key, public_key])
            if flag.as_os_str() == "--no-passphrase" =>
        {
            keygen(secret_key, public_key, Protection::None)
        }
        (Some("fingerprint"), [public_key]) => fingerprint(public_key),
        (Some("encrypt"), [public_key, input, output]) => encrypt(public_key, input, output),
        (Some("decrypt"), [secret_key, input, output]) => decrypt(secret_key, input, output),
        (Some("--help" | "-h"), []) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("riegel: {message}");
            ExitCode::FAILURE
        }
    }
}

/// How a new secret key file is stored.
enum Protection {
    /// Encrypted under a passphrase.
    Passphrase,
    /// In the clear, for machines where nobody can type a passphrase.
    None,
}

fn keygen(
    secret_key_path: &Path,
    public_key_path: &Path,
    protection: Protection,
) -> Result<(), String> {
    // All checked before the passphrase is asked for and before anything is written, so that
    // no secret key is left behind without its public key.
    if secret_key_path == public_key_path {
        return Err("the secret key and the public key need two different files".to_owned());
    }
    refuse_existing(secret_key_path)?;
    refuse_existing(public_key_path)?;

    let secret_key = SecretKey::generate().map_err(|error| error.to_string())?;
    let secret_key_text = match protection {
        Protection::Passphrase => secret_key
            .to_protected_text(&new_passphrase()?)
            .map_err(|error| error.to_string())?,
        Protection::None => secret_key.to_text(),
    };
    let public_key = secret_key.public_key();

    create_file(secret_key_path, Access::OwnerOnly, |file| {
        writeln!(file, "{}", *secret_key_text).map_err(|error| error.to_string())
    })?;
    create_file(public_key_path, Access::Default, |file| {
        writeln!(file, "{public_key}").map_err(|error| error.to_string())
    })?;
    eprintln!(
        "riegel: public key fingerprint: {}",
        public_key.fingerprint()
    );
    Ok(())
}

fn fingerprint(public_key_path: &Path) -> Result<(), String> {
    println!("{}", read_public_key(public_key_path)?.fingerprint());
    Ok(())
}

fn encrypt(public_key_path: &Path, input_path: &Path, output_path: &Path) -> Result<(), String> {
    let recipient = read_public_key(public_key_path)?;
    let input = open(input_path)?;
    eprintln!(
        "riegel: encrypting to the key with fingerprint {}",
        recipient.fingerprint()
    );
    create_file(output_path, Access::Default, |output| {
        riegel::encrypt(&recipient, input, output)
            .map_err(|error| format!("cannot encrypt {}: {error}", input_path.display()))
    })
}

fn decrypt(secret_key_path: &Path, input_path: &Path, output_path: &Path) -> Result<(), String> {
    // The cheap checks come before the passphrase prompt.
    let input = open(input_path)?;
    refuse_existing(output_path)?;
    let key = read_secret_key(secret_key_path)?;
    create_file(output_path, Access::Default, |output| {
        riegel::decrypt(&key, input, output)
            .map_err(|error| format!("cannot decrypt {}: {error}", input_path.display()))
    })
}

fn open(path: &Path) -> Result<File, String> {
    File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))
}

fn read_key_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let mut text = Zeroizing::new(String::new());
    open(path)?
        .take(MAX_KEY_FILE_LEN)
        .read_to_string(&mut text)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(text)
}

fn read_public_key(path: &Path) -> Result<PublicKey, String> {
    read_key_file(path)?
        .parse()
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn read_secret_key(path: &Path) -> Result<SecretKey, String> {
    let text = read_key_file(path)?;
    let key = match text.parse::<SecretKey>() {
        Err(riegel::Error::PassphraseRequired) => {
            let passphrase = read_passphrase(&format!("Passphrase for {}: ", path.display()))?;
            SecretKey::from_protected_text(&text, &passphrase)
        }
        plain => plain,
    };
    key.map_err(|error| format!("{}: {error}", path.display()))
}

/// Asks for the passphrase of a new key. On a terminal it is typed blind, so it is asked for
/// twice.
fn new_passphrase() -> Result<Zeroizing<String>, String> {
    let passphrase = read_passphrase("Passphrase for the new secret key: ")?;
    if io::stdin().is_terminal() {
        let repeated = read_passphrase("Repeat the passphrase: ")?;
        if *repeated != *passphrase {
            return Err("the two passphrases differ".to_owned());
        }
    }
    Ok(passphrase)
}

/// Reads a passphrase from the terminal without showing it. When standard input is not a
/// terminal, its first line is the passphrase instead, so that a script can supply one.
/// It is never taken from the command line, where other users could see it.
fn read_passphrase(prompt: &str) -> Result<Zeroizing<String>, String> {
    if io::stdin().is_terminal() {
        return rpassword::prompt_password(prompt)
            .map(Zeroizing::new)
            .map_err(|error| format!("cannot read the passphrase from the terminal: {error}"));
    }

    // Allocated up front, so that reading never moves the passphrase and leaves a copy behind.
    let mut line = Zeroizing::new(String::with_capacity(MAX_PASSPHRASE_LINE_LEN));
    io::stdin()
        .lock()
        .take(MAX_PASSPHRASE_LINE_LEN as u64)
        .read_line(&mut line)
        .map_err(|error| format!("cannot read the passphrase from standard input: {error}"))?;
    if line.len() == MAX_PASSPHRASE_LINE_LEN && !line.ends_with('\n') {
        return Err("the passphrase on standard input is too long".to_owned());
    }
    let passphrase_len = line.trim_end_matches(['\r', '\n']).len();
    line.truncate(passphrase_len);
    Ok(line)
}

fn refuse_existing(path: &Path) -> Result<(), String> {
    match path.try_exists() {
        Ok(false) => Ok(()),
        Ok(true) => Err(format!(
            "{} already exists; not overwriting it",
            path.display()
        )),
        Err(error) => Err(format!("cannot check {}: {error}", path.display())),
    }
}

/// Who may read a newly created file.
enum Access {
    /// Whatever the system gives new files.
    Default,
    /// Only the owner, where the platform can say so at creation (Unix).
    OwnerOnly,
}

/// Creates `path` with the content written by `fill`. The content goes to a `.partial`
/// sibling that is renamed only after `fill` succeeded and the data reached the disk, so a
/// failed or interrupted run never leaves something that looks like a finished file.
fn create_file(
    path: &Path,
    access: Access,
    fill: impl FnOnce(&mut File) -> Result<(), String>,
) -> Result<(), String> {
    refuse_existing(path)?;

    let mut partial_name = path.as_os_str().to_owned();
    partial_name.push(".partial");
    let partial_path = PathBuf::from(partial_name);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    if matches!(access, Access::OwnerOnly) {
        restrict_to_owner(&mut options);
    }
    let mut file = options
        .open(&partial_path)
        .map_err(|error| format!("cannot create {}: {error}", partial_path.display()))?;

    let written = fill(&mut file).and_then(|()| {
        file.sync_all()
            .map_err(|error| format!("cannot write {}: {error}", partial_path.display()))
    });
    // Windows can neither rename nor remove a file that is still open.
    drop(file);

    let result = written.and_then(|()| {
        fs::rename(&partial_path, path)
            .map_err(|error| format!("cannot create {}: {error}", path.display()))
    });
    if result.is_err() {
        // Best effort: the original error is the one worth reporting.
        let _ = fs::remove_file(&partial_path);
    }
    result
}

#[cfg(unix)]
fn restrict_to_owner(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

/// Windows has no creation mode: the file gets the permissions of its folder.
#[cfg(not(unix))]
fn restrict_to_owner(_options: &mut OpenOptions) {}
