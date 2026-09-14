import re
from pathlib import Path
import os
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
DOCS = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
SITE = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
LLMS = (ROOT / "site" / "llms.txt").read_text(encoding="utf-8")
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
SURFACES = (("README", README), ("docs", DOCS), ("site", SITE), ("llms", LLMS))
LINUX_TARGET = "x86_64-unknown-linux-musl"
UNSHIPPED_MAC_TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin")
LINUX_SECTION = README.split("### Linux x86-64 and Windows through WSL", 1)[1].split(
    "### macOS", 1
)[0]
LINUX_BLOCKS = re.findall(r"```sh\n(.*?)```", LINUX_SECTION, re.DOTALL)
LINUX_BLOCK = next((body for body in LINUX_BLOCKS if body.startswith("set -eu\n")), "")
assert LINUX_BLOCK
INSTALLER = ROOT / "site" / "install.sh"
SITE_RECEIPT = (ROOT / "ops" / "site_receipt.sh").read_text(encoding="utf-8")


class InstallGuidanceTests(unittest.TestCase):
    def test_only_supported_prebuilt_target_is_advertised(self):
        archive = f"keyrx-<version>-{LINUX_TARGET}.tar.gz"
        for name, text in SURFACES:
            with self.subTest(name=name):
                if name == "site":
                    self.assertIn("stem+'" + LINUX_TARGET + ".tar.gz", text)
                    self.assertIn(LINUX_TARGET, text)
                else:
                    self.assertIn(archive, text)
                for target in UNSHIPPED_MAC_TARGETS:
                    self.assertNotIn(f"keyrx-<version>-{target}.tar.gz", text)
                    self.assertNotIn("+stem+'" + target + ".tar.gz", text)
        self.assertIn(
            "https://github.com/keyrx/keyrx/releases/download/v$VERSION", README
        )
        self.assertIn(
            "https://github.com/keyrx/keyrx/releases/download/v'+VERSION+'/'", SITE
        )
        self.assertRegex(SITE, rf"var VERSION='{re.escape(VERSION)}';")
        self.assertIn("$ARCHIVE.sha256", README)
        self.assertIn("archive+'.sha256'", SITE)
        self.assertIn("keyrx-<version>.SHA256SUMS", README)

    def test_linux_install_block_is_shell_syntax_and_fails_closed_before_install(self):
        self.assertIn(f"VERSION={VERSION}", LINUX_BLOCK)
        self.assertNotIn("VERSION=<version>", LINUX_BLOCK)
        parsed = subprocess.run(
            ["/bin/sh", "-n", "-c", LINUX_BLOCK],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        ordered = (
            'set -eu',
            'curl --proto',
            'sha256sum -c "$ARCHIVE.sha256"',
            'gh attestation verify "$ARCHIVE" --repo keyrx/keyrx',
            'tar -xzf "$ARCHIVE"',
            'install -m 0755',
            'keyrx verify',
        )
        positions = [LINUX_BLOCK.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            work = root / "fresh"
            tools.mkdir()
            work.mkdir()
            log = root / "calls"
            scripts = {
                "mktemp": '#!/bin/sh\nprintf "%s\\n" "$KEYRX_TEST_WORK"\n',
                "curl": '#!/bin/sh\nprintf "curl\\n" >> "$KEYRX_TEST_LOG"\n',
                "sha256sum": '#!/bin/sh\nprintf "checksum\\n" >> "$KEYRX_TEST_LOG"\nexit 1\n',
                "tar": '#!/bin/sh\nprintf "tar\\n" >> "$KEYRX_TEST_LOG"\n',
                "install": '#!/bin/sh\nprintf "install\\n" >> "$KEYRX_TEST_LOG"\n',
            }
            for name, body in scripts.items():
                path = tools / name
                path.write_text(body, encoding="utf-8")
                path.chmod(0o700)
            env = {
                "PATH": str(tools),
                "HOME": str(root / "home"),
                "CARGO_HOME": str(root / "cargo"),
                "KEYRX_TEST_WORK": str(work),
                "KEYRX_TEST_LOG": str(log),
            }
            refused = subprocess.run(
                ["/bin/sh", "-c", LINUX_BLOCK],
                cwd=root,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["curl", "curl", "checksum"])

    def test_site_install_route_shows_every_material_step_in_order(self):
        install_route = SITE.split("C.install=function", 1)[1].split("C.match=function", 1)[0]
        self.assertIn("if(arg!=='manual')", install_route)
        self.assertIn("Type install manual", install_route)
        manual_route = install_route.split("note('OPTIONAL MANUAL PATH');", 1)[1]
        ordered = (
            "curl --proto",
            "archive+'.sha256'",
            "sha256sum -c ",
            "gh attestation verify ",
            "tar -xzf ",
            "install -m 0755 ",
            "keyrx verify",
        )
        positions = [manual_route.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("stop if it does not", manual_route)
        self.assertIn("stop if you choose the provenance check and it fails", manual_route)
        self.assertIn("complete fail-closed script", manual_route)

    def test_global_manifest_is_not_claimed_to_hash_itself(self):
        for name, text in (("README", README), ("llms", LLMS)):
            with self.subTest(name=name):
                self.assertIn("every other attached asset", text)
                self.assertNotIn("manifest for all assets", text)
                self.assertNotIn("inventories every attached asset", text)

    def test_source_build_is_locked_and_points_to_official_rustup(self):
        for name, text in SURFACES:
            with self.subTest(name=name):
                self.assertIn("cargo install --locked keyrx", text)
                self.assertIn("Rust 1.85", text)
                self.assertIn("rustup.rs", text)
                self.assertIn("rustup default stable", text)
                self.assertRegex(text, r"(?is)(?:Ubuntu|apt install cargo).{0,100}(?:old|below|Rust 1\.85)")
                self.assertNotRegex(text, r"cargo install (?!-[^\n]*locked\b)keyrx\b")

    def test_path_repair_does_not_assume_rustup_environment_file(self):
        remedy = 'export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"'
        for name, text in SURFACES:
            with self.subTest(name=name):
                self.assertIn(remedy, text)
        self.assertIn("no ~/.cargo/env assumption", SITE)
        self.assertIn("does not assume that `~/.cargo/env` exists", README)

    def test_bash_wsl_guidance_preserves_system_path_after_reopening(self):
        profile_line = 'export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"'
        for name, text in SURFACES:
            with self.subTest(name=name):
                self.assertIn(profile_line, text)
        self.assertIn("/usr/bin", INSTALLER.read_text(encoding="utf-8"))
        self.assertIn("/bin", INSTALLER.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            bin_dir = home / ".cargo" / "bin"
            bin_dir.mkdir(parents=True)
            binary = bin_dir / "keyrx"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o700)
            profile = home / ".bashrc"
            profile.write_text(profile_line + "\n", encoding="utf-8")
            env = os.environ.copy()
            env["HOME"] = str(home)
            env.pop("CARGO_HOME", None)
            env["PATH"] = "/usr/bin:/bin"
            check = subprocess.run(
                ["/bin/bash", "--noprofile", "--rcfile", str(profile), "-ic", "command -v keyrx; command -v id"],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(check.returncode, 0, check.stderr)
            self.assertEqual(check.stdout.splitlines(), [str(binary), "/usr/bin/id"])

    def test_one_command_installer_is_taught_only_for_linux_and_wsl(self):
        command = "bash -o pipefail -c 'curl --proto \"=https\" --tlsv1.2 -fsSL https://keyrx.tech/install.sh | sh'"
        for name, text in SURFACES:
            with self.subTest(name=name):
                self.assertRegex(text, r"(?is)Windows.{0,100}WSL")
                self.assertIn(command, text)
        self.assertNotIn("&& clear", README)
        self.assertNotIn("&& clear", DOCS)
        self.assertNotIn("&& clear", SITE)
        self.assertNotIn("&& clear", LLMS)
        self.assertIn("Rerunning the one-line command repairs or reinstalls", README)
        self.assertIn("does not promise a\nno-downgrade check", README)
        self.assertIn("without `sudo`", README)
        self.assertIn("without sudo", SITE)

    def test_one_command_refuses_a_failed_installer_download(self):
        command = "bash -o pipefail -c 'curl --proto \"=https\" --tlsv1.2 -fsSL https://keyrx.tech/install.sh | sh'"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            curl = tools / "curl"
            curl.write_text("#!/bin/sh\nexit 22\n", encoding="utf-8")
            curl.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = f"{tools}:/usr/bin:/bin"
            result = subprocess.run(
                ["/bin/sh", "-c", command], env=env, check=False,
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 22)
            unguarded = subprocess.run(
                ["/bin/sh", "-c", 'curl --proto "=https" --tlsv1.2 -fsSL https://keyrx.tech/install.sh | sh'],
                env=env, check=False, capture_output=True, text=True,
            )
            self.assertEqual(unguarded.returncode, 0)

    def test_macos_uses_source_build_until_signed_notarized_binaries_exist(self):
        for name, text in SURFACES:
            with self.subTest(name=name):
                self.assertIn("macOS", text)
                self.assertRegex(text, r"(?is)(?:signed and notarized|signed, notarized).{0,100}(?:macOS|Apple)")
                self.assertIn("cargo install --locked keyrx", text)

    def test_installer_is_versioned_executable_shell_and_fail_closed_by_order(self):
        body = INSTALLER.read_text(encoding="utf-8")
        self.assertTrue(INSTALLER.stat().st_mode & 0o100)
        self.assertIn('"https://github.com/$REPOSITORY/releases/latest"', body)
        self.assertIn('BASE_URL="https://github.com/$REPOSITORY/releases/download/v$VERSION"', body)
        self.assertEqual(
            subprocess.run(["/bin/sh", "-n", str(INSTALLER)], check=False).returncode,
            0,
        )
        ordered = (
            'test "$(uname -s',
            'case "$(uname -m',
            'curl --proto',
            'sha256sum --check --strict',
            'gh attestation verify',
            'tar -tzf',
            'tar -xzf',
            'install -m 0755',
            'keyrx verify',
        )
        positions = [body.index(value) for value in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('"$HOST/install.sh"', SITE_RECEIPT)
        self.assertIn('cmp -s "$tmp" "$ROOT/site/install.sh"', SITE_RECEIPT)

    def _installer_fixture(self, root: Path, *, system="Linux", machine="x86_64", checksum=0, gh=False):
        tools = root / "tools"
        home = root / "home"
        work = root / "work"
        tools.mkdir()
        home.mkdir()
        work.mkdir()
        log = root / "calls"

        def tool(name, body):
            path = tools / name
            path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
            path.chmod(0o700)

        tool("uname", f'[ "$1" = -s ] && printf "%s\\n" "{system}" || printf "%s\\n" "{machine}"\n')
        tool("mktemp", '''if [ "${1:-}" = -d ]; then
  printf "%s\\n" "$KEYRX_TEST_WORK"
else
  /usr/bin/mktemp "$@"
fi
''')
        tool(
            "curl",
            '''out=''; url=''
while [ "$#" -gt 0 ]; do
  case "$1" in --output) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac
done
printf 'curl %s\\n' "$url" >> "$KEYRX_TEST_LOG"
case "$url" in
  */releases/latest) printf 'https://github.com/keyrx/keyrx/releases/tag/v%s' "$KEYRX_TEST_VERSION"; exit 0 ;;
esac
case "$out" in
  *.sha256) printf '%064d  %s\\n' 0 "${out%.sha256}" > "$out" ;;
  *) printf 'archive\\n' > "$out" ;;
esac
''',
        )
        tool("sha256sum", f'printf "checksum\\n" >> "$KEYRX_TEST_LOG"\nexit {checksum}\n')
        tool(
            "tar",
            '''root="keyrx-$KEYRX_TEST_VERSION-x86_64-unknown-linux-musl"
case "$1" in
  -tzf) printf '%s\\n' "$root/" "$root/keyrx" "$root/LICENSE" "$root/README.md" "$root/SOURCE.json" ;;
  -xzf)
    shift 2
    [ "$1" = -C ]; destination="$2"
    mkdir -p "$destination/$root"
    printf '%s\\n' '#!/bin/sh' '[ "$1" = --version ] && { echo "keyrx '$KEYRX_TEST_VERSION'"; exit 0; }' '[ "$1" = verify ] && { echo verify >> "$KEYRX_TEST_LOG"; exit 0; }' 'exit 1' > "$destination/$root/keyrx"
    chmod 0755 "$destination/$root/keyrx" ;;
esac
''',
        )
        tool("install", 'printf "install\\n" >> "$KEYRX_TEST_LOG"\ncp "$3" "$4"\nchmod "$2" "$4"\n')
        for name in ("chmod", "cmp", "cp", "grep", "head", "id", "mkdir", "mv", "rm", "sed", "sort", "stat", "tail", "tr", "wc"):
            (tools / name).symlink_to(Path("/usr/bin") / name)
        if gh:
            tool(
                "gh",
                '''case "$1 $2 $3" in
  "attestation verify --help")
    printf "attest-help\\n" >> "$KEYRX_TEST_LOG"
    exit "${KEYRX_TEST_GH_HELP_STATUS:-0}" ;;
  attestation\\ verify\\ *)
    printf "attest\\n" >> "$KEYRX_TEST_LOG"
    exit "${KEYRX_TEST_GH_STATUS:-0}" ;;
  *) exit 99 ;;
esac
''',
            )
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{tools}:/usr/bin:/bin",
                "SHELL": "/bin/bash",
                "HOME": str(home),
                "KEYRX_TEST_WORK": str(work),
                "KEYRX_TEST_LOG": str(log),
                "KEYRX_TEST_VERSION": VERSION,
                "CARGO_HOME": str(root / "install-root"),
            }
        )
        return env, log

    def test_installer_refuses_unsupported_platform_before_network(self):
        for system, machine in (("Darwin", "x86_64"), ("Linux", "aarch64")):
            with self.subTest(system=system, machine=machine), tempfile.TemporaryDirectory() as directory:
                env, log = self._installer_fixture(Path(directory), system=system, machine=machine)
                result = subprocess.run(
                    ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("only", result.stderr)
                self.assertFalse(log.exists())

    def test_installer_refuses_noncanonical_latest_tag_before_archive_download(self):
        for version in ("0.4", "01.2.3", "1.02.3", "v1.2.3", "1.2.3/other"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                env, log = self._installer_fixture(Path(directory))
                env["KEYRX_TEST_VERSION"] = version
                result = subprocess.run(
                    ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("latest release version", result.stderr)
                self.assertEqual(
                    log.read_text(encoding="utf-8").splitlines(),
                    ["curl https://github.com/keyrx/keyrx/releases/latest"],
                )

    def test_installer_checksum_failure_cannot_extract_or_install(self):
        with tempfile.TemporaryDirectory() as directory:
            env, log = self._installer_fixture(Path(directory), checksum=1)
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            calls = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len([line for line in calls if line.startswith("curl ")]), 3)
            self.assertEqual(calls[-1], "checksum")
            self.assertNotIn("install", calls)

    def test_installer_executes_verified_archive_and_installed_self_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, log = self._installer_fixture(root, gh=True)
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(calls[-7:], ["checksum", "attest-help", "attest", "verify", "install", "verify", "verify"])
            expected_base = f"https://github.com/keyrx/keyrx/releases/download/v{VERSION}"
            self.assertEqual(
                [line for line in calls if line.startswith("curl ")],
                [
                    "curl https://github.com/keyrx/keyrx/releases/latest",
                    f"curl {expected_base}/keyrx-{VERSION}-{LINUX_TARGET}.tar.gz",
                    f"curl {expected_base}/keyrx-{VERSION}-{LINUX_TARGET}.tar.gz.sha256",
                ],
            )
            installed = root / "install-root" / "bin" / "keyrx"
            self.assertTrue(installed.is_file())
            self.assertIn(f"keyrx {VERSION} installed", result.stdout)

    def test_installer_names_root_account_before_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, _ = self._installer_fixture(root, gh=False)
            id_tool = root / "tools" / "id"
            id_tool.unlink()
            id_tool.write_text("#!/bin/sh\n[ \"$1\" = -u ] && printf '0\\n'\n", encoding="utf-8")
            id_tool.chmod(0o700)
            stat_tool = root / "tools" / "stat"
            stat_tool.unlink()
            stat_tool.write_text("#!/bin/sh\n[ \"$2\" = '%u' ] && { printf '0\\n'; exit 0; }\nexec /usr/bin/stat \"$@\"\n", encoding="utf-8")
            stat_tool.chmod(0o700)
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("root shell; the install belongs to root", result.stderr)
            self.assertTrue((root / "install-root" / "bin" / "keyrx").exists())

    def test_installer_repeat_run_replaces_only_the_same_users_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, _ = self._installer_fixture(root, gh=True)
            first = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            installed = root / "install-root" / "bin" / "keyrx"
            self.assertEqual(
                subprocess.run([str(installed), "--version"], capture_output=True, text=True).stdout.strip(),
                f"keyrx {VERSION}",
            )
            (root / "work").mkdir()
            env["KEYRX_TEST_VERSION"] = "0.4.22"
            second = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(
                subprocess.run([str(installed), "--version"], capture_output=True, text=True).stdout.strip(),
                "keyrx 0.4.22",
            )
            profile = root / "home" / ".bashrc"
            self.assertEqual(profile.read_text(encoding="utf-8").count("export PATH="), 1)

    def test_installer_recovers_exact_wsl_bashrc_clobber_in_fresh_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, _ = self._installer_fixture(root, gh=True)
            env.pop("CARGO_HOME")
            home = root / "home"
            profile = home / ".bashrc"
            original = 'export PATH="$HOME/.cargo/bin"\nexport PATH="$HOME/.cargo/bin"\n'
            profile.write_text(original, encoding="utf-8")
            first = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            updated = profile.read_text(encoding="utf-8")
            self.assertTrue(updated.startswith(original))
            self.assertEqual(updated.count("/usr/bin:/sbin:/bin:$PATH"), 1)
            fresh_env = os.environ.copy()
            fresh_env.update({"HOME": str(home), "PATH": "/usr/bin:/bin"})
            fresh_env.pop("CARGO_HOME", None)
            fresh = subprocess.run(
                ["/bin/bash", "--noprofile", "--rcfile", str(profile), "-ic",
                 "command -v id && command -v curl && command -v keyrx"],
                env=fresh_env, check=False, capture_output=True, text=True,
            )
            self.assertEqual(fresh.returncode, 0, fresh.stderr)
            found = fresh.stdout.splitlines()
            self.assertEqual([Path(path).name for path in found], ["id", "curl", "keyrx"])
            self.assertEqual(found[-1], str(home / ".cargo" / "bin" / "keyrx"))
            (root / "work").mkdir()
            second = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(profile.read_text(encoding="utf-8"), updated)

    def test_installer_refuses_unsafe_bashrc_before_network(self):
        for kind in ("symlink", "hardlink", "world_writable"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env, log = self._installer_fixture(root)
                profile = root / "home" / ".bashrc"
                target = root / "home" / "other"
                target.write_text("# user content\n", encoding="utf-8")
                if kind == "symlink":
                    profile.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, profile)
                else:
                    profile.write_text("# user content\n", encoding="utf-8")
                    profile.chmod(0o666)
                result = subprocess.run(
                    ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(".bashrc", result.stderr)
                self.assertFalse(log.exists())
                self.assertEqual(target.read_text(encoding="utf-8"), "# user content\n")
                self.assertFalse((root / "install-root" / "bin" / "keyrx").exists())

    def test_installer_refuses_malformed_path_before_network(self):
        for suffix in ("::/usr/bin:/bin", ":/usr/local/bin", ""):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env, log = self._installer_fixture(root)
                env["PATH"] = str(root / "tools") + suffix
                result = subprocess.run(
                    ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("PATH", result.stderr)
                self.assertFalse(log.exists())

    def test_installer_refuses_unset_path_with_repair_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, log = self._installer_fixture(root)
            result = subprocess.run(
                ["/bin/sh", "-c", 'unset PATH; . "$1"', "sh", str(INSTALLER)],
                env=env, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('export PATH="/usr/local/sbin:', result.stderr)
            self.assertFalse(log.exists())

    def test_installer_custom_cargo_home_is_literal_in_next_bash_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, _ = self._installer_fixture(root)
            custom = root / 'a $`"\\ custom cargo'
            env["CARGO_HOME"] = str(custom)
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            profile = root / "home" / ".bashrc"
            fresh_env = os.environ.copy()
            fresh_env.update({"HOME": str(root / "home"), "PATH": "/usr/bin:/bin"})
            fresh_env.pop("CARGO_HOME", None)
            fresh = subprocess.run(
                ["/bin/bash", "--noprofile", "--rcfile", str(profile), "-ic", "command -v keyrx"],
                env=fresh_env, check=False, capture_output=True, text=True,
            )
            self.assertEqual(fresh.returncode, 0, fresh.stderr)
            self.assertEqual(fresh.stdout.strip(), str(custom / "bin" / "keyrx"))

    def test_installer_refuses_control_character_in_cargo_home_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, log = self._installer_fixture(root)
            env["CARGO_HOME"] = str(root / "cargo\nother")
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("control character", result.stderr)
            self.assertFalse(log.exists())

    def test_installer_non_bash_shell_does_not_create_bashrc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, _ = self._installer_fixture(root)
            env["SHELL"] = "/bin/zsh"
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "home" / ".bashrc").exists())
            self.assertIn("no profile was changed", result.stdout)

    def test_installer_new_directories_ignore_permissive_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, _ = self._installer_fixture(root)
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True,
                preexec_fn=lambda: os.umask(0o002),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "install-root").stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "install-root" / "bin").stat().st_mode & 0o777, 0o700)

    def test_installer_refuses_unsafe_existing_install_directory_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, log = self._installer_fixture(root)
            install_root = root / "install-root"
            install_root.mkdir(mode=0o777)
            install_root.chmod(0o777)
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("group- or world-writable", result.stderr)
            self.assertFalse(log.exists())

    def test_installer_refuses_unsafe_home_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, log = self._installer_fixture(root)
            (root / "home").chmod(0o777)
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("HOME is group- or world-writable", result.stderr)
            self.assertFalse(log.exists())

    def test_installer_refuses_directory_mode_change_before_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, _ = self._installer_fixture(root, gh=True)
            first = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            installed = root / "install-root" / "bin" / "keyrx"
            install_tool = root / "tools" / "install"
            install_tool.write_text(install_tool.read_text(encoding="utf-8") +
                                    'chmod 0777 "$CARGO_HOME/bin"\n', encoding="utf-8")
            (root / "work").mkdir()
            env["KEYRX_TEST_VERSION"] = "0.4.22"
            second = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("changed before executable replacement", second.stderr)
            self.assertEqual(subprocess.run([str(installed), "--version"], capture_output=True,
                                            text=True).stdout.strip(), f"keyrx {VERSION}")

    def test_installer_refuses_a_release_downgrade_before_asset_download(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, log = self._installer_fixture(root, gh=True)
            env["KEYRX_TEST_VERSION"] = "0.4.22"
            first = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            installed = root / "install-root" / "bin" / "keyrx"
            env["KEYRX_TEST_VERSION"] = "0.4.21"
            env["KEYRX_TRUSTED_INSTALLED_VERSION"] = "0.4.22"
            log.unlink()
            second = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("refusing to downgrade", second.stderr)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(),
                             ["curl https://github.com/keyrx/keyrx/releases/latest"])
            self.assertEqual(subprocess.run([str(installed), "--version"], capture_output=True,
                                            text=True).stdout.strip(), "keyrx 0.4.22")

    def test_installer_never_executes_preexisting_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, _ = self._installer_fixture(root)
            bin_dir = root / "install-root" / "bin"
            bin_dir.mkdir(parents=True, mode=0o700)
            marker = root / "old-ran"
            old = bin_dir / "keyrx"
            old.write_text(f'#!/bin/sh\nprintf "ran\\n" >> "{marker}"\nexit 23\n', encoding="utf-8")
            old.chmod(0o700)
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(subprocess.run([str(old), "--version"], capture_output=True,
                                            text=True).stdout.strip(), f"keyrx {VERSION}")

    def test_installer_profile_publish_failure_preserves_existing_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, _ = self._installer_fixture(root)
            bin_dir = root / "install-root" / "bin"
            bin_dir.mkdir(parents=True, mode=0o700)
            old = bin_dir / "keyrx"
            old_bytes = b'#!/bin/sh\nexit 23\n'
            old.write_bytes(old_bytes)
            old.chmod(0o700)
            profile = root / "home" / ".bashrc"
            profile.write_text("# original profile\n", encoding="utf-8")
            mv_tool = root / "tools" / "mv"
            mv_tool.unlink()
            mv_tool.write_text('#!/bin/sh\n[ "${4:-}" = "$HOME/.bashrc" ] && exit 73\nexec /usr/bin/mv "$@"\n',
                               encoding="utf-8")
            mv_tool.chmod(0o700)
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(old.read_bytes(), old_bytes)
            self.assertEqual(profile.read_text(encoding="utf-8"), "# original profile\n")
            self.assertFalse(list(bin_dir.glob(".keyrx-install-*")))

    def test_embedded_update_mode_skips_profile_and_guidance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, _ = self._installer_fixture(root)
            env["KEYRX_INSTALL_NO_PROFILE"] = "1"
            profile = root / "home" / ".bashrc"
            target = root / "home" / "other"
            target.write_text("# untouched\n", encoding="utf-8")
            profile.symlink_to(target)
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(profile.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "# untouched\n")
            self.assertNotIn("profile", result.stdout)
            self.assertNotIn("If keyrx is not found", result.stdout)

    def test_installer_attestation_failure_cannot_install(self):
        with tempfile.TemporaryDirectory() as directory:
            env, log = self._installer_fixture(Path(directory), gh=True)
            env["KEYRX_TEST_GH_STATUS"] = "1"
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines()[-3:], ["checksum", "attest-help", "attest"])

    def test_installer_old_gh_uses_explicit_checksum_only_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, log = self._installer_fixture(root, gh=True)
            env["KEYRX_TEST_GH_HELP_STATUS"] = "1"
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text(encoding="utf-8").splitlines()
            self.assertIn("attest-help", calls)
            self.assertNotIn("attest", calls)
            self.assertIn("provenance verification skipped", result.stderr)
            self.assertTrue((root / "install-root" / "bin" / "keyrx").is_file())

    def test_installer_old_gh_refuses_if_attestation_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, log = self._installer_fixture(root, gh=True)
            env["KEYRX_TEST_GH_HELP_STATUS"] = "1"
            env["KEYRX_REQUIRE_ATTESTATION"] = "1"
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("gh attestation verify is required", result.stderr)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines()[-2:], ["checksum", "attest-help"])
            self.assertFalse((root / "install-root" / "bin" / "keyrx").exists())

    def test_installer_absent_gh_uses_explicit_checksum_only_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, log = self._installer_fixture(root, gh=False)
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("attest", log.read_text(encoding="utf-8"))
            self.assertIn("provenance verification skipped", result.stderr)
            self.assertTrue((root / "install-root" / "bin" / "keyrx").is_file())

    def test_installer_absent_gh_refuses_if_attestation_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, log = self._installer_fixture(root, gh=False)
            env["KEYRX_REQUIRE_ATTESTATION"] = "1"
            result = subprocess.run(
                ["/bin/sh", str(INSTALLER)], env=env, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("gh attestation verify is required", result.stderr)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines()[-1], "checksum")
            self.assertFalse((root / "install-root" / "bin" / "keyrx").exists())

    def test_distro_rustup_is_not_declared_universally_broken(self):
        for name, text in SURFACES:
            with self.subTest(name=name):
                self.assertNotRegex(text, r"(?is)(?:do not|never) use.{0,100}(?:apt install rustup|snap install rustup)")


if __name__ == "__main__":
    unittest.main()
