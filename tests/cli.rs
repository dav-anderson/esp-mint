//! The `esp-mint` binary, run as a process: what its commands print and what
//! status they exit with when they are given something they refuse.
//!
//! Each run clears the environment, so nothing of the machine's leaks in, and
//! gives the process a scratch `ESP_DATA_DIR` of its own. None of these runs
//! reaches a network or starts a listener: each is refused before it gets that
//! far (the one exception, `pay` with no `serve` running, tries the operator's
//! listener on a loopback port nothing listens on and is refused there), and each test checks the data folder is as it was (the files that are
//! there are the same bytes, and no file or folder was made). A run that has not
//! ended after a minute is killed and fails the test, so a command that should
//! have been refused cannot hang the suite by carrying on instead.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use esp_mint::queue::{Entry, Queue};
use sp_wire::ServiceDid;

const G_DID: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONE_USD: u128 = 1_000_000_000_000;
const DAY1: u64 = 20_735 * 86_400;

/// The first line of the usage text, and a line from its middle.
const USAGE_FIRST_LINE: &str = "esp-mint <command>\n";
const USAGE_DECLINE_LINE: &str = "  decline <entry id> --reason TEXT\n";

fn scratch(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "esp-mint-cli-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What a run printed and how it ended.
struct Ran {
    /// The exit status; `None` if the process was ended by a signal.
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run `esp-mint args` with an empty environment but `ESP_DATA_DIR=dir` and
/// the `env` given.
fn run(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Ran {
    let mut child = Command::new(env!("CARGO_BIN_EXE_esp-mint"))
        .args(args)
        .env_clear()
        .env("ESP_DATA_DIR", dir)
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let out = thread::spawn(move || {
        let mut text = String::new();
        out.read_to_string(&mut text).unwrap();
        text
    });
    let err = thread::spawn(move || {
        let mut text = String::new();
        err.read_to_string(&mut text).unwrap();
        text
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("esp-mint {args:?} did not end within a minute");
        }
        thread::sleep(Duration::from_millis(20));
    };
    Ran {
        code: status.code(),
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
    }
}

/// Every file and folder under `dir`, with the bytes of each file.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(dir: &Path, found: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                found.insert(path.clone(), None);
                walk(&path, found);
            } else {
                let bytes = std::fs::read(&path).unwrap();
                found.insert(path, Some(bytes));
            }
        }
    }
    let mut found = BTreeMap::new();
    walk(dir, &mut found);
    found
}

/// The line every command says first, on stderr: the network and its data folder.
fn banner(dir: &Path, network: &str) -> String {
    format!(
        "esp-mint on {network}: data in {}\n",
        dir.join(network).display()
    )
}

/// A queue file with two open entries at `dir/main/queue.json`, where the
/// commands look for it on the default network.
fn seed_queue(dir: &Path) {
    let net = dir.join("main");
    std::fs::create_dir_all(&net).unwrap();
    let service = ServiceDid::parse(G_DID).unwrap();
    let mut queue = Queue::open(&net.join("queue.json")).unwrap();
    queue
        .add(Entry::open("e1", service, 10 * ONE_USD, "btc:x", DAY1))
        .unwrap();
    queue
        .add(Entry::open("e2", service, 5 * ONE_USD, "btc:x", DAY1))
        .unwrap();
}

#[test]
fn no_command_or_an_unknown_one_is_usage_on_stderr_with_status_2_and_help_is_usage_on_stdout() {
    let dir = scratch("usage");
    let mut usage_on_stderr = Vec::new();
    let none: &[&str] = &[];
    for args in [none, &["frobnicate"]] {
        let ran = run(&dir, args, &[]);
        assert_eq!(ran.code, Some(2), "{args:?}");
        assert_eq!(ran.stdout, "", "{args:?}");
        assert!(ran.stderr.starts_with(USAGE_FIRST_LINE), "{}", ran.stderr);
        assert!(ran.stderr.contains(USAGE_DECLINE_LINE), "{}", ran.stderr);
        usage_on_stderr.push(ran.stderr);
    }
    assert_eq!(usage_on_stderr[0], usage_on_stderr[1]);

    let help = run(&dir, &["--help"], &[]);
    assert_eq!(help.code, Some(0));
    assert_eq!(help.stderr, "");
    assert!(help.stdout.starts_with(USAGE_FIRST_LINE), "{}", help.stdout);
    assert!(help.stdout.contains(USAGE_DECLINE_LINE), "{}", help.stdout);
    // It is the same text as the one an unknown command gets.
    assert_eq!(help.stdout, usage_on_stderr[0]);

    assert!(snapshot(&dir).is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn pay_without_a_reference_or_with_a_bad_service_is_refused_before_any_request_and_changes_nothing()
{
    let dir = scratch("pay");
    seed_queue(&dir);
    let before = snapshot(&dir);
    // A listener where the operator's listener would be: a command that got as
    // far as sending its request would have connected to it.
    let watch = TcpListener::bind("127.0.0.1:0").unwrap();
    watch.set_nonblocking(true).unwrap();
    let bind = watch.local_addr().unwrap().to_string();
    let env = [("ESP_ADMIN_BIND", bind.as_str())];
    let refusals: [(&[&str], &str); 2] = [
        (
            &["pay", G_DID, "wire-1"],
            "error: usage: esp-mint pay <service> <ref> <entry id>... [--mixed-memos]\n",
        ),
        (
            &["pay", "zz", "wire-1", "e1"],
            "error: `zz` is not a service ID: it must be hex\n",
        ),
    ];
    for (args, message) in refusals {
        let ran = run(&dir, args, &env);
        assert_eq!(ran.code, Some(1), "{args:?}");
        assert_eq!(ran.stdout, "", "{args:?}");
        assert_eq!(
            ran.stderr,
            format!("{}{message}", banner(&dir, "main")),
            "{args:?}"
        );
        assert_eq!(snapshot(&dir), before, "{args:?}");
    }
    assert_eq!(
        watch.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "a refused pay still connected to the operator's listener"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn pay_with_no_serve_running_says_so_and_does_not_write_the_queue_itself() {
    let dir = scratch("pay-no-serve");
    seed_queue(&dir);
    let before = snapshot(&dir);
    // An address nothing listens on: the port was free a moment ago.
    let bind = {
        let free = TcpListener::bind("127.0.0.1:0").unwrap();
        free.local_addr().unwrap().to_string()
    };
    let ran = run(
        &dir,
        &["pay", G_DID, "wire-1", "e1", "e2"],
        &[("ESP_ADMIN_BIND", bind.as_str())],
    );
    assert_eq!(ran.code, Some(1));
    assert_eq!(ran.stdout, "");
    let expected_start = format!(
        "{}error: could not reach the mint's admin listener at {bind}: ",
        banner(&dir, "main")
    );
    assert!(ran.stderr.starts_with(&expected_start), "{}", ran.stderr);
    assert!(
        ran.stderr.ends_with(". Is `esp-mint serve` running?\n"),
        "{}",
        ran.stderr
    );
    // The entries are still open: `pay` did not settle them by writing the file.
    assert_eq!(snapshot(&dir), before);
    let queue = Queue::open(&dir.join("main").join("queue.json")).unwrap();
    assert!(queue.entries().all(|e| e.payment_ref.is_none()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn version_names_the_program_and_the_libraries_and_reads_and_writes_nothing() {
    let dir = scratch("version");
    let long = run(&dir, &["--version"], &[]);
    let short = run(&dir, &["-V"], &[]);
    assert_eq!((long.code, short.code), (Some(0), Some(0)));
    assert_eq!(long.stdout, short.stdout);
    assert_eq!((long.stderr.as_str(), short.stderr.as_str()), ("", ""));
    let lines: Vec<&str> = long.stdout.lines().collect();
    assert_eq!(lines[0], format!("esp-mint {}", env!("CARGO_PKG_VERSION")));
    // Each other line is `name x.y.z`, and the two libraries every mint is built
    // on are there.
    for line in &lines[1..] {
        let (name, version) = line.split_once(' ').expect(line);
        assert!(
            !name.is_empty() && version.split('.').count() == 3,
            "{line}"
        );
    }
    for library in ["sp-wire ", "mint-core "] {
        assert!(
            lines.iter().any(|l| l.starts_with(library)),
            "{library}missing in {lines:?}"
        );
    }
    // Not even a settings file was read or the banner printed, and nothing made.
    assert!(snapshot(&dir).is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn payouts_with_an_argument_it_does_not_take_is_refused_naming_it() {
    let dir = scratch("payouts");
    seed_queue(&dir);
    let before = snapshot(&dir);
    for (args, message) in [
        (
            &["payouts", "--nope"][..],
            "error: unexpected argument `--nope`\n",
        ),
        (
            &["payouts", "--json", "extra"][..],
            "error: unexpected argument `extra`\n",
        ),
    ] {
        let ran = run(&dir, args, &[]);
        assert_eq!(ran.code, Some(1), "{args:?}");
        assert_eq!(ran.stdout, "", "{args:?}");
        assert_eq!(
            ran.stderr,
            format!("{}{message}", banner(&dir, "main")),
            "{args:?}"
        );
        assert_eq!(snapshot(&dir), before, "{args:?}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn decline_without_a_reason_with_an_unknown_option_or_with_two_entries_is_refused_before_any_request()
 {
    let dir = scratch("decline");
    seed_queue(&dir);
    let before = snapshot(&dir);
    // A listener where the operator's listener would be: a command that got as
    // far as sending its request would have connected to it.
    let watch = TcpListener::bind("127.0.0.1:0").unwrap();
    watch.set_nonblocking(true).unwrap();
    let bind = watch.local_addr().unwrap().to_string();
    let env = [("ESP_ADMIN_BIND", bind.as_str())];

    // (arguments, how the message starts); the usage text follows each message.
    let refusals: [(&[&str], &str); 4] = [
        (&["decline", "e1"], "error: esp-mint <command>\n"),
        (
            &["decline", "e1", "--reason", "x", "--verbose"],
            "error: unknown option --verbose\nesp-mint <command>\n",
        ),
        (
            &["decline", "e1", "e2", "--reason", "x"],
            "error: only one entry id can be declined at a time\nesp-mint <command>\n",
        ),
        (
            &["decline", "e1", "--reason"],
            "error: --reason needs the text of the reason\n",
        ),
    ];
    for (args, start) in refusals {
        let ran = run(&dir, args, &env);
        assert_eq!(ran.code, Some(1), "{args:?}");
        assert_eq!(ran.stdout, "", "{args:?}");
        assert!(
            ran.stderr
                .starts_with(&format!("{}{start}", banner(&dir, "main"))),
            "{args:?}: {}",
            ran.stderr
        );
        assert_eq!(snapshot(&dir), before, "{args:?}");
    }
    assert_eq!(
        watch.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "a refused decline still connected to the operator's listener"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn config_with_a_bad_file_names_the_setting_or_the_file_and_changes_nothing() {
    let dir = scratch("config");
    let file = dir.join("esp-mint.toml");

    // A value that is not a number: the message names the setting and the value.
    std::fs::write(&file, "[admin]\nmax_request_bytes = \"many\"\n").unwrap();
    let before = snapshot(&dir);
    let ran = run(&dir, &["config"], &[]);
    assert_eq!(ran.code, Some(1));
    assert_eq!(ran.stdout, "");
    assert_eq!(
        ran.stderr,
        format!(
            "error: the settings are not valid:\n  {}: admin.max_request_bytes = `many` is not a whole number (no sign, no decimals)\n",
            file.display()
        )
    );
    assert_eq!(snapshot(&dir), before);

    // A setting there is no such thing as.
    std::fs::write(&file, "[nope]\nx = 1\n").unwrap();
    let before = snapshot(&dir);
    let ran = run(&dir, &["config"], &[]);
    assert_eq!(ran.code, Some(1));
    assert_eq!(ran.stdout, "");
    assert_eq!(
        ran.stderr,
        format!(
            "error: the settings are not valid:\n  {}: unknown setting `nope.x`\n",
            file.display()
        )
    );
    assert_eq!(snapshot(&dir), before);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn serve_without_the_air_settings_or_with_an_empty_admin_token_is_refused_before_it_listens() {
    let dir = scratch("serve");

    // Neither AIR setting: both are named, with the variable that sets each.
    let ran = run(&dir, &["serve"], &[]);
    assert_eq!(ran.code, Some(1));
    assert!(
        ran.stderr.starts_with(&format!(
            "{}error: serve needs the AIR settings",
            banner(&dir, "main")
        )),
        "{}",
        ran.stderr
    );
    assert!(
        ran.stderr
            .contains("air.server (ESP_AIR_SERVER) and air.host (ESP_AIR_HOST) are not set"),
        "{}",
        ran.stderr
    );
    assert!(snapshot(&dir).is_empty());

    // Only one of them: only that one is named.
    let ran = run(&dir, &["serve"], &[("ESP_AIR_HOST", "127.0.0.1")]);
    assert_eq!(ran.code, Some(1));
    assert!(
        ran.stderr
            .contains("air.server (ESP_AIR_SERVER) is not set"),
        "{}",
        ran.stderr
    );
    assert!(!ran.stderr.contains("ESP_AIR_HOST"), "{}", ran.stderr);
    assert!(snapshot(&dir).is_empty());

    // Both set, and an admin token that is set but empty: refused for that.
    let ran = run(
        &dir,
        &["serve"],
        &[
            ("ESP_AIR_SERVER", G_DID),
            ("ESP_AIR_HOST", "127.0.0.1"),
            ("ESP_ADMIN_TOKEN", ""),
        ],
    );
    assert_eq!(ran.code, Some(1));
    assert_eq!(
        ran.stderr,
        format!(
            "{}error: ESP_ADMIN_TOKEN is set but empty\n",
            banner(&dir, "main")
        )
    );
    assert!(snapshot(&dir).is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn every_command_says_its_network_on_stderr_and_pubkey_prints_only_the_did_on_stdout() {
    let dir = scratch("banner");
    // Unlike the others, this one makes files (`pubkey` makes a key file), in its own scratch folder.

    // `pubkey` on the default network: mainnet is said, not assumed. stdout is
    // the DID alone, so `ESP_DID=$(esp-mint pubkey)` takes just that.
    let ran = run(&dir, &["pubkey"], &[]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    assert_eq!(ran.stderr, banner(&dir, "main"));
    assert_eq!(ran.stdout.len(), 66 + 1, "{}", ran.stdout);
    assert!(ran.stdout.ends_with('\n'));
    assert!(ran.stdout[..66].chars().all(|c| c.is_ascii_hexdigit()));
    let main_did = ran.stdout;

    // On regtest: the banner says regtest, and the DID is another one (the
    // network has its own key file).
    let ran = run(&dir, &["pubkey"], &[("ESP_NETWORK", "regtest")]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    assert_eq!(ran.stderr, banner(&dir, "regtest"));
    assert_ne!(ran.stdout, main_did);

    // `config` says it too, on stderr; its stdout is the settings as before.
    let ran = run(&dir, &["config"], &[("ESP_NETWORK", "regtest")]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    assert_eq!(ran.stderr, banner(&dir, "regtest"));
    assert!(ran.stdout.contains("server.network"), "{}", ran.stdout);
    std::fs::remove_dir_all(&dir).unwrap();
}
