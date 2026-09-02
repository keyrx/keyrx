use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct SecretDir(PathBuf);

impl SecretDir {
    fn new(label: &str) -> Self {
        let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "keyrx-security-{}-{}-{}",
            std::process::id(),
            label,
            nonce,
        ));
        std::fs::create_dir(&path).expect("create isolated test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("secure isolated test directory");
        }
        Self(path)
    }
}

impl Drop for SecretDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn output_with_deadline(mut command: Command) -> Output {
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    ChildGuard::new(command.spawn().expect("start bounded keyrx command"))
        .finish(std::time::Duration::from_secs(30))
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("child is still owned")
    }

    fn id(&self) -> u32 {
        self.0.as_ref().expect("child is still owned").id()
    }

    fn finish(mut self, timeout: std::time::Duration) -> Output {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self
                .child_mut()
                .try_wait()
                .expect("poll bounded child")
                .is_some()
            {
                return self
                    .0
                    .take()
                    .expect("child is still owned")
                    .wait_with_output()
                    .expect("collect bounded child output");
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.child_mut().kill();
                let _ = self.child_mut().wait();
                self.0.take();
                panic!("keyrx child exceeded its {timeout:?} test deadline");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn keyrx(dir: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_keyrx"));
    command
        .args(args)
        .env("NO_COLOR", "1")
        .env("KEYRX_NO_LINKS", "1")
        .env("XDG_DATA_HOME", dir);
    output_with_deadline(command)
}

fn keyrx_without_home(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_keyrx"));
    command
        .args(args)
        .env_clear()
        .env("NO_COLOR", "1")
        .env("KEYRX_NO_LINKS", "1");
    output_with_deadline(command)
}

fn grind_args(out: &str) -> Vec<&str> {
    vec![
        "grind",
        "--ends-with",
        "a",
        "--threads",
        "32",
        "--indices",
        "4",
        "--count",
        "1",
        "--out",
        out,
    ]
}

#[test]
fn zero_work_arguments_are_refused() {
    let dir = SecretDir::new("zero");
    for args in [
        vec!["estimate", "--ends-with", "a", "--threads", "0"],
        vec!["estimate", "--ends-with", "a", "--indices", "0"],
        vec!["estimate", "--ends-with", "a", "--count", "0"],
        vec!["bench", "--threads", "0", "--seconds", "1"],
        vec!["bench", "--threads", "1", "--seconds", "0"],
        vec!["grind", "--ends-with", "a", "--count", "0"],
    ] {
        let output = keyrx(&dir.0, &args);
        assert!(
            !output.status.success(),
            "accepted zero-valued arguments: {args:?}"
        );
    }
    let huge = usize::MAX.to_string();
    let output = keyrx(&dir.0, &["grind", "--ends-with", "a", "--threads", &huge]);
    assert!(
        !output.status.success(),
        "accepted an unbounded worker count"
    );
}

#[cfg(unix)]
#[test]
fn count_one_persists_exactly_one_complete_record_and_narrows_mode() {
    let dir = SecretDir::new("count");
    let out = dir.0.join("matches.txt");
    std::fs::write(&out, b"").expect("precreate output");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o644))
            .expect("make the precondition public");
    }
    let out_text = out.to_str().expect("UTF-8 temporary path");
    let output = keyrx(&dir.0, &grind_args(out_text));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let secret = std::fs::read_to_string(&out).expect("read result for structural test");
    assert_eq!(
        secret
            .lines()
            .filter(|line| line.starts_with("address "))
            .count(),
        1
    );
    assert_eq!(
        secret
            .lines()
            .filter(|line| line.starts_with("seed "))
            .count(),
        1
    );
    assert_eq!(
        secret
            .lines()
            .filter(|line| line.starts_with("privkey "))
            .count(),
        1
    );
    assert_eq!(
        secret
            .lines()
            .filter(|line| line.starts_with("keypair "))
            .count(),
        1
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn output_symlink_is_not_followed_and_recovery_file_is_private() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = SecretDir::new("out-symlink");
    let target = dir.0.join("target.txt");
    let out = dir.0.join("matches.txt");
    std::fs::write(&target, b"sentinel").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    symlink(&target, &out).unwrap();
    let output = keyrx(&dir.0, &grind_args(out.to_str().unwrap()));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"sentinel");
    let recovered = dir.0.join("matches.recovered.txt");
    let text = std::fs::read_to_string(&recovered).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("address "))
            .count(),
        1
    );
    assert_eq!(
        std::fs::metadata(recovered).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn marker_symlink_is_never_followed_or_removed() {
    use std::os::unix::fs::symlink;
    let dir = SecretDir::new("marker-symlink");
    let target = dir.0.join("target.txt");
    let out = dir.0.join("matches.txt");
    let marker = dir.0.join("matches.txt.grinding");
    std::fs::write(&target, b"sentinel").unwrap();
    symlink(&target, &marker).unwrap();
    let output = keyrx(&dir.0, &grind_args(out.to_str().unwrap()));
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&target).unwrap(), b"sentinel");
    assert!(std::fs::symlink_metadata(&marker)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[cfg(unix)]
#[test]
fn show_refuses_symlink_hardlink_and_public_secret_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = SecretDir::new("show-custody");
    let target = dir.0.join("target.txt");
    let symlinked = dir.0.join("symlinked.txt");
    let aliased = dir.0.join("aliased.txt");
    std::fs::write(
        &target,
        b"address A\npath    m/44'/501'/0'/0'\nseed    secret\nprivkey secret\nkeypair secret\n\n",
    )
    .unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &symlinked).unwrap();
    let out = keyrx(&dir.0, &["show", symlinked.to_str().unwrap(), "--keys"]);
    assert!(
        !out.status.success(),
        "show followed a secret-bearing symlink"
    );

    std::fs::hard_link(&target, &aliased).unwrap();
    let out = keyrx(&dir.0, &["show", target.to_str().unwrap(), "--keys"]);
    assert!(
        !out.status.success(),
        "show accepted a hard-linked secret file"
    );
    std::fs::remove_file(&aliased).unwrap();

    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = keyrx(&dir.0, &["show", target.to_str().unwrap(), "--keys"]);
    assert!(
        !out.status.success(),
        "show accepted a world-readable secret file"
    );
}

#[cfg(unix)]
#[test]
fn interrupt_returns_130_and_removes_only_its_marker() {
    let dir = SecretDir::new("interrupt");
    let out = dir.0.join("matches.txt");
    let marker = dir.0.join("matches.txt.grinding");
    let child = Command::new(env!("CARGO_BIN_EXE_keyrx"))
        .args([
            "grind",
            "--ends-with",
            "zzzzzzzzzzzzzzzz",
            "--threads",
            "1",
            "--indices",
            "1",
            "--out",
            out.to_str().unwrap(),
        ])
        .env("NO_COLOR", "1")
        .env("KEYRX_NO_LINKS", "1")
        .env("XDG_DATA_HOME", &dir.0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start interruptible grind");
    let child = ChildGuard::new(child);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if !marker.exists() {
        panic!("grind never acquired its marker");
    }
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let result = child.finish(std::time::Duration::from_secs(10));
    assert_eq!(result.status.code(), Some(130), "{:?}", result.status);
    assert!(!marker.exists(), "interrupted grind stranded its marker");
}

#[cfg(unix)]
#[test]
fn malformed_output_is_preserved_and_recovery_is_showable() {
    let dir = SecretDir::new("recovery");
    let out = dir.0.join("matches.txt");
    std::fs::write(&out, b"damaged\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let result = keyrx(&dir.0, &grind_args(out.to_str().unwrap()));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read(&out).unwrap(), b"damaged\n");
    let recovered = dir.0.join("matches.recovered.txt");
    assert!(recovered.is_file());
    let shown = keyrx(&dir.0, &["show", recovered.to_str().unwrap()]);
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(stdout.contains(recovered.to_str().unwrap()));
}

#[cfg(unix)]
#[test]
fn custom_evm_output_works_without_home_or_data_environment() {
    let dir = SecretDir::new("evm-no-home");
    let out = dir.0.join("evm.txt");
    let output = keyrx_without_home(&[
        "grind",
        "--chain",
        "evm",
        "--ends-with",
        "a",
        "--threads",
        "4",
        "--indices",
        "4",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.is_file());
    assert!(!dir.0.join("evm.txt.grinding").exists());
}

#[test]
fn estimate_without_home_uses_an_honest_theoretical_fallback() {
    let output = keyrx_without_home(&["estimate", "--ends-with", "a"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("THEORETICAL"));
}

#[cfg(unix)]
#[test]
fn estimate_never_trusts_symlink_or_fifo_rate_caches() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = SecretDir::new("rate-input");
    let cache_dir = dir.0.join("keyrx");
    std::fs::create_dir(&cache_dir).unwrap();
    std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let cache = cache_dir.join("bench-sol-phantom-12w.txt");
    let target = dir.0.join("attacker.txt");
    std::fs::write(
        &target,
        format!(
            "keyrx-rate-v2 {} linux x86_64 debug sol-phantom 12 1 1 999999.00000000000000000\n",
            env!("CARGO_PKG_VERSION")
        ),
    )
    .unwrap();
    symlink(&target, &cache).unwrap();
    let output = keyrx(&dir.0, &["estimate", "--ends-with", "a"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("THEORETICAL"));
    std::fs::remove_file(&cache).unwrap();

    let cache_bytes = std::ffi::CString::new(cache.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cache_bytes.as_ptr(), 0o600) }, 0);
    let started = std::time::Instant::now();
    let output = keyrx(&dir.0, &["estimate", "--ends-with", "a"]);
    assert!(output.status.success());
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert!(String::from_utf8_lossy(&output.stdout).contains("THEORETICAL"));
}

#[cfg(unix)]
#[test]
fn bench_holds_and_atomically_replaces_its_real_cache_stage() {
    use std::os::unix::fs::PermissionsExt;
    let dir = SecretDir::new("rate-output");
    for _ in 0..2 {
        let output = keyrx(
            &dir.0,
            &[
                "bench",
                "--threads",
                "1",
                "--indices",
                "1",
                "--seconds",
                "1",
            ],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let cache_dir = dir.0.join("keyrx");
    let cache = cache_dir.join("bench-sol-phantom-12w.txt");
    let receipt = cache_dir.join("bench-sol-phantom-12w.txt.valid");
    let ceremony = cache_dir.join("bench-sol-phantom-12w.txt.bench.lock");
    assert!(cache.is_file());
    assert!(receipt.is_file());
    assert!(!ceremony.exists());
    assert_eq!(
        std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        std::fs::read_dir(&cache_dir).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".stage.")),
        "benchmark left a hidden stage behind"
    );

    // A marker from a failed/crashed ceremony poisons an otherwise valid
    // cache. A later benchmark may reclaim it only after acquiring its inode.
    std::fs::write(&ceremony, b"keyrx-bench-lock-v1 stale\n").unwrap();
    std::fs::set_permissions(&ceremony, std::fs::Permissions::from_mode(0o600)).unwrap();
    let poisoned = keyrx(
        &dir.0,
        &[
            "estimate",
            "--ends-with",
            "zzzzz",
            "--threads",
            "1",
            "--indices",
            "1",
        ],
    );
    assert!(poisoned.status.success());
    assert!(String::from_utf8_lossy(&poisoned.stdout).contains("THEORETICAL"));
    let recovered = keyrx(
        &dir.0,
        &[
            "bench",
            "--threads",
            "1",
            "--indices",
            "1",
            "--seconds",
            "1",
        ],
    );
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(!ceremony.exists());
    assert!(receipt.exists());

    let exact = keyrx(
        &dir.0,
        &[
            "estimate",
            "--ends-with",
            "zzzzz",
            "--threads",
            "1",
            "--indices",
            "1",
        ],
    );
    let exact_text = String::from_utf8_lossy(&exact.stdout);
    assert!(exact.status.success(), "{}", exact_text);
    assert!(
        exact_text.contains("exact benchmark workload"),
        "{}",
        exact_text
    );

    let approximate = keyrx(
        &dir.0,
        &[
            "estimate",
            "--ends-with",
            "a",
            "--threads",
            "1",
            "--indices",
            "1",
        ],
    );
    let approximate_text = String::from_utf8_lossy(&approximate.stdout);
    assert!(approximate.status.success(), "{}", approximate_text);
    assert!(
        approximate_text.contains("APPROX MEASURED - matcher differs"),
        "{}",
        approximate_text
    );
    assert!(
        !approximate_text.contains("from this machine's exact benchmark workload"),
        "{}",
        approximate_text
    );

    std::fs::remove_file(&receipt).unwrap();
    let missing_receipt = keyrx(
        &dir.0,
        &[
            "estimate",
            "--ends-with",
            "zzzzz",
            "--threads",
            "1",
            "--indices",
            "1",
        ],
    );
    assert!(missing_receipt.status.success());
    assert!(
        String::from_utf8_lossy(&missing_receipt.stdout).contains("THEORETICAL"),
        "a cache without its validity receipt was accepted"
    );
}

#[cfg(unix)]
#[test]
fn concurrent_bench_on_the_same_lane_refuses_before_timing() {
    let dir = SecretDir::new("rate-concurrent");
    let cache_dir = dir.0.join("keyrx");
    let ceremony = cache_dir.join("bench-sol-phantom-12w.txt.bench.lock");
    let first = Command::new(env!("CARGO_BIN_EXE_keyrx"))
        .args([
            "bench",
            "--threads",
            "1",
            "--indices",
            "1",
            "--seconds",
            "3",
        ])
        .env("NO_COLOR", "1")
        .env("KEYRX_NO_LINKS", "1")
        .env("XDG_DATA_HOME", &dir.0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start first benchmark");
    let first = ChildGuard::new(first);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !ceremony.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(ceremony.exists(), "first benchmark never acquired its lane");

    let started = std::time::Instant::now();
    let second = keyrx(
        &dir.0,
        &[
            "bench",
            "--threads",
            "1",
            "--indices",
            "1",
            "--seconds",
            "1",
        ],
    );
    assert!(
        !second.status.success(),
        "concurrent benchmark was accepted"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("cache lane is in use"),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let first_result = first.finish(std::time::Duration::from_secs(10));
    assert!(
        first_result.status.success(),
        "{}",
        String::from_utf8_lossy(&first_result.stderr)
    );
    assert!(
        !ceremony.exists(),
        "successful benchmark left its lane locked"
    );
}

#[cfg(unix)]
#[test]
fn second_grind_on_same_output_refuses_before_touching_or_recovery() {
    let dir = SecretDir::new("two-grinds");
    let out = dir.0.join("matches.txt");
    let marker = dir.0.join("matches.txt.grinding");
    let first = Command::new(env!("CARGO_BIN_EXE_keyrx"))
        .args([
            "grind",
            "--ends-with",
            "zzzzzzzzzzzzzzzz",
            "--threads",
            "1",
            "--indices",
            "1",
            "--out",
            out.to_str().unwrap(),
        ])
        .env("NO_COLOR", "1")
        .env("KEYRX_NO_LINKS", "1")
        .env("XDG_DATA_HOME", &dir.0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let first = ChildGuard::new(first);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if !marker.exists() {
        panic!("first grind never acquired its marker");
    }
    let second = keyrx(&dir.0, &grind_args(out.to_str().unwrap()));
    assert!(
        !second.status.success(),
        "second grind acquired an owned output"
    );
    assert!(!dir.0.join("matches.recovered.txt").exists());
    assert_eq!(unsafe { libc::kill(first.id() as i32, libc::SIGINT) }, 0);
    let result = first.finish(std::time::Duration::from_secs(10));
    assert_eq!(result.status.code(), Some(130));
}

#[cfg(unix)]
#[test]
fn show_refuses_an_internally_contradictory_record() {
    let dir = SecretDir::new("contradiction");
    let out = dir.0.join("matches.txt");
    let made = keyrx(&dir.0, &grind_args(out.to_str().unwrap()));
    assert!(made.status.success());
    let text = std::fs::read_to_string(&out).unwrap();
    let address = text.lines().next().unwrap();
    let corrupted = text.replacen(address, "address 11111111111111111111111111111111", 1);
    std::fs::write(&out, corrupted).unwrap();
    let shown = keyrx(&dir.0, &["show", out.to_str().unwrap(), "--keys"]);
    assert!(!shown.status.success());
    assert!(!String::from_utf8_lossy(&shown.stdout).contains("privkey  base58"));
    let inventory = dir.0.join("keyrx/matches");
    std::fs::create_dir_all(&inventory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&inventory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::copy(&out, inventory.join("corrupt.txt")).unwrap();
    let listed = keyrx(&dir.0, &["show"]);
    assert!(!listed.status.success());
}

#[cfg(unix)]
#[test]
fn show_refuses_noncanonical_seed_path_and_keypair_spellings() {
    let dir = SecretDir::new("canonical-record");
    let out = dir.0.join("matches.txt");
    let made = keyrx(&dir.0, &grind_args(out.to_str().unwrap()));
    assert!(made.status.success());
    let original = std::fs::read_to_string(&out).unwrap();
    let seed_line = original
        .lines()
        .find(|line| line.starts_with("seed    "))
        .unwrap();
    let seed_words = seed_line.strip_prefix("seed    ").unwrap();
    let (first, rest) = seed_words.split_once(' ').unwrap();
    let mutations = [
        (
            "keypair plus",
            original.replacen("keypair [", "keypair [+", 1),
        ),
        (
            "leading-zero path",
            original.replacen("path    m/44'/501'/", "path    m/44'/501'/0", 1),
        ),
        (
            "double-space seed",
            original.replacen(seed_line, &format!("seed    {first}  {rest}"), 1),
        ),
    ];
    for (label, mutation) in mutations {
        assert_ne!(mutation, original, "test mutation did not apply: {label}");
        std::fs::write(&out, mutation).unwrap();
        let shown = keyrx(&dir.0, &["show", out.to_str().unwrap(), "--keys"]);
        assert!(
            !shown.status.success(),
            "show accepted a noncanonical writer-controlled record field: {label}"
        );
    }
}

#[cfg(unix)]
#[test]
fn show_refuses_non_utf8_inventory_names_without_terminal_bytes() {
    use std::os::unix::ffi::OsStringExt;
    let dir = SecretDir::new("raw-name");
    let matches = dir.0.join("keyrx/matches");
    std::fs::create_dir_all(&matches).unwrap();
    let raw = std::ffi::OsString::from_vec(vec![0x80, b'.', b't', b'x', b't']);
    std::fs::write(matches.join(raw), b"").unwrap();
    let output = keyrx(&dir.0, &["show"]);
    assert!(!output.status.success());
    assert!(!output.stdout.contains(&0x1b));
    assert!(!output.stderr.contains(&0x1b));
}

#[test]
fn direct_secret_paths_refuse_terminal_controls_without_echoing_them() {
    let dir = SecretDir::new("terminal-path");
    let hostile = dir
        .0
        .join("owned\u{1b}]8;;https://example.invalid\u{7}.txt");
    let hostile_text = hostile.to_str().unwrap();
    for args in [
        vec!["show", hostile_text, "--keys"],
        vec![
            "grind",
            "--ends-with",
            "a",
            "--threads",
            "1",
            "--indices",
            "1",
            "--out",
            hostile_text,
        ],
    ] {
        let output = keyrx(&dir.0, &args);
        assert!(!output.status.success(), "accepted hostile path: {args:?}");
        assert!(!output.stdout.contains(&0x1b));
        assert!(!output.stderr.contains(&0x1b));
        assert!(
            !hostile.exists(),
            "a refused output path must not reach filesystem custody"
        );
    }
}

#[test]
fn hostile_patterns_never_echo_terminal_control_bytes() {
    let dir = SecretDir::new("terminal-pattern");
    let hostile = "a\u{1b}]8;;https://example.invalid\u{7}";
    for args in [
        vec!["estimate", "--ends-with", hostile],
        vec!["estimate", "--chain", "evm", "--ends-with", hostile],
    ] {
        let output = keyrx(&dir.0, &args);
        assert!(
            !output.status.success(),
            "accepted hostile pattern: {args:?}"
        );
        assert!(!output.stdout.contains(&0x1b));
        assert!(!output.stderr.contains(&0x1b));
        assert!(!output.stdout.contains(&0x07));
        assert!(!output.stderr.contains(&0x07));
    }
}

#[test]
fn impossible_full_length_patterns_are_refused() {
    let dir = SecretDir::new("impossible");
    let sol = "z".repeat(44);
    let result = keyrx(&dir.0, &["estimate", "--starts-with", &sol]);
    assert!(!result.status.success());
    let result = keyrx(
        &dir.0,
        &["estimate", "--starts-with", &sol, "--ignore-case"],
    );
    assert!(!result.status.success());
    let too_many_zero_bytes = "1".repeat(33);
    let result = keyrx(&dir.0, &["estimate", "--starts-with", &too_many_zero_bytes]);
    assert!(!result.status.success());
    let split_impossible = "z".repeat(43);
    let result = keyrx(
        &dir.0,
        &[
            "estimate",
            "--starts-with",
            &split_impossible,
            "--ends-with",
            "z",
        ],
    );
    assert!(
        !result.status.success(),
        "canonical text still must contain a valid non-identity prime-order Ed25519 point"
    );
    let result = keyrx(
        &dir.0,
        &[
            "estimate",
            "--starts-with",
            &split_impossible,
            "--ends-with",
            "z",
            "--ignore-case",
        ],
    );
    assert!(!result.status.success());
    let impossible_partial = "1".repeat(31);
    let impossible_suffix = "z".repeat(12);
    let result = keyrx(
        &dir.0,
        &[
            "estimate",
            "--starts-with",
            &impossible_partial,
            "--ends-with",
            &impossible_suffix,
        ],
    );
    assert!(
        !result.status.success(),
        "a wildcard text digit did not make the 32-byte value feasible"
    );
    let wrong_checksum = "0x52908400098527886e0f7030069857d2e4169ee7";
    let result = keyrx(
        &dir.0,
        &[
            "estimate",
            "--chain",
            "evm",
            "--starts-with",
            wrong_checksum,
            "--checksum",
        ],
    );
    assert!(!result.status.success());
}

#[cfg(unix)]
#[test]
fn managed_output_refuses_non_utf8_data_root_without_redirecting_to_replacement_text() {
    use std::os::unix::ffi::OsStringExt;
    let dir = SecretDir::new("raw-data-root");
    let mut raw = dir.0.as_os_str().as_encoded_bytes().to_vec();
    raw.extend_from_slice(b"/xdg-\x80");
    let raw = std::ffi::OsString::from_vec(raw);
    let lossy = PathBuf::from(raw.to_string_lossy().into_owned())
        .join("keyrx")
        .join("matches")
        .join("a.txt");
    let output = output_with_deadline({
        let mut command = Command::new(env!("CARGO_BIN_EXE_keyrx"));
        command
            .args([
                "grind",
                "--ends-with",
                "a",
                "--threads",
                "1",
                "--indices",
                "1",
            ])
            .env("XDG_DATA_HOME", &raw)
            .env_remove("HOME");
        command
    });
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not valid UTF-8"));
    assert!(
        !lossy.exists(),
        "a lossy U+FFFD pathname was created instead of refusing before custody"
    );
}

#[cfg(unix)]
#[test]
fn required_terminal_copy_is_complete_and_dynamic_clipping_is_explicit() {
    use std::os::unix::fs::PermissionsExt;

    let dir = SecretDir::new("complete-copy");
    let start = keyrx(&dir.0, &[]);
    assert!(start.status.success());
    let start = String::from_utf8_lossy(&start.stdout);
    for sentence in [
        "slots are reserved before writing; hits cannot overshoot.",
        "Use it only where the wallet exposes key import.",
        "The keyRX seed + printed path (+ passphrase, if used)",
        "re-derive this key; an unrelated wallet seed does not.",
        "show lists files · show KEYRX / show evm/dead reads one",
        "account. Keep the keyRX match file or equivalent backup.",
    ] {
        assert!(start.contains(sentence), "start screen lost: {sentence}");
    }

    let verify = keyrx(&dir.0, &["verify"]);
    assert!(verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stdout)
        .contains("cast wallet address --mnemonic \"<seed>\" --mnemonic-index 0"));

    for chain in [None, Some("evm")] {
        let mut args = vec!["estimate"];
        if let Some(chain) = chain {
            args.extend(["--chain", chain]);
        }
        args.extend(["--ends-with", "a", "--indices", "8"]);
        let estimate = keyrx(&dir.0, &args);
        assert!(estimate.status.success());
        assert!(String::from_utf8_lossy(&estimate.stdout)
            .contains("match may land at a higher account index"));
    }

    let generated = dir.0.join("generated-evm.txt");
    let generated_text = generated.to_str().unwrap();
    let evm = keyrx(
        &dir.0,
        &[
            "grind",
            "--chain",
            "evm",
            "--ends-with",
            "a",
            "--threads",
            "4",
            "--indices",
            "4",
            "--out",
            generated_text,
        ],
    );
    assert!(
        evm.status.success(),
        "{}",
        String::from_utf8_lossy(&evm.stderr)
    );
    let evm_stdout = String::from_utf8_lossy(&evm.stdout);
    assert!(
        evm_stdout.contains("Seed:     use only in a wallet that supports the exact printed path")
    );
    assert!(evm_stdout.contains("(index "));
    assert!(evm_stdout.contains("verify the address before funding"));

    let evm_dir = dir.0.join("keyrx").join("matches").join("evm");
    std::fs::create_dir_all(&evm_dir).unwrap();
    std::fs::set_permissions(dir.0.join("keyrx"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(
        dir.0.join("keyrx").join("matches"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::set_permissions(&evm_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stem = "0123456789abcdef0123456789abcdef01234567";
    let listed = evm_dir.join(format!("{stem}.txt"));
    std::fs::copy(&generated, &listed).unwrap();
    std::fs::set_permissions(&listed, std::fs::Permissions::from_mode(0o600)).unwrap();
    let show = keyrx(&dir.0, &["show"]);
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    assert!(String::from_utf8_lossy(&show.stdout).contains(&format!("keyrx show -- 'evm/{stem}'")));

    let long_name = format!("{}.txt", "x".repeat(96));
    let long_out = dir.0.join(long_name);
    let long_out_text = long_out.to_str().unwrap();
    let sol = keyrx(
        &dir.0,
        &[
            "grind",
            "--ends-with",
            "a",
            "--threads",
            "4",
            "--indices",
            "4",
            "--out",
            long_out_text,
        ],
    );
    assert!(
        sol.status.success(),
        "{}",
        String::from_utf8_lossy(&sol.stderr)
    );
    let sol_stdout = String::from_utf8_lossy(&sol.stdout);
    assert!(
        sol_stdout.lines().any(|line| line.ends_with("...║")),
        "a bounded dynamic path was silently clipped"
    );
    assert!(
        sol_stdout.contains(long_out_text),
        "the complete path was not preserved in the plain receipt"
    );

    let unicode_name = "matches-界\u{301}.txt";
    let unicode_out = dir.0.join(unicode_name);
    std::fs::copy(&generated, &unicode_out).unwrap();
    std::fs::set_permissions(&unicode_out, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_keyrx"));
    command
        .args(["show", "--", unicode_name])
        .current_dir(&dir.0)
        .env("NO_COLOR", "1")
        .env("KEYRX_NO_LINKS", "1")
        .env("XDG_DATA_HOME", &dir.0);
    let shown = output_with_deadline(command);
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let shown = String::from_utf8_lossy(&shown.stdout);
    assert!(
        shown.contains("\\u{754c}\\u{301}"),
        "Unicode path was not rendered as complete width-safe escape tokens: {shown}"
    );
    for line in shown.lines().filter(|line| {
        let line = line.trim_start();
        line.starts_with('╔') || line.starts_with('║') || line.starts_with('╚')
    }) {
        assert_eq!(line.chars().count(), 78, "ragged Unicode frame: {line:?}");
    }
}

#[cfg(unix)]
#[test]
fn show_finds_a_unicode_path_marker_using_filesystem_bytes_not_rendered_text() {
    use std::os::unix::fs::PermissionsExt;
    let dir = SecretDir::new("unicode-marker");
    let data = dir.0.join("data-界");
    let keyrx_dir = data.join("keyrx");
    let matches = keyrx_dir.join("matches");
    std::fs::create_dir_all(&matches).unwrap();
    for path in [data.as_path(), keyrx_dir.as_path(), matches.as_path()] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let marker = matches.join("missing.txt.grinding");
    std::fs::write(&marker, b"test").unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_keyrx"));
    command
        .args(["show", "missing"])
        .env("NO_COLOR", "1")
        .env("KEYRX_NO_LINKS", "1")
        .env("XDG_DATA_HOME", &data);
    let shown = output_with_deadline(command);
    assert!(!shown.status.success());
    let stdout = String::from_utf8_lossy(&shown.stdout);
    assert!(stdout.contains("GRIND MARKER"), "{stdout}");
    assert!(!stdout.contains("NO MATCHES"), "{stdout}");
}
