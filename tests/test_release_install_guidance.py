import re
from pathlib import Path
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
LINUX_BLOCK_MATCH = re.search(
    r"### Linux x86-64 and Windows through WSL.*?```sh\n(?P<body>.*?)```",
    README,
    re.DOTALL,
)
assert LINUX_BLOCK_MATCH is not None
LINUX_BLOCK = LINUX_BLOCK_MATCH.group("body")


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
        ordered = (
            "curl --proto",
            "archive+'.sha256'",
            "sha256sum -c ",
            "gh attestation verify ",
            "tar -xzf ",
            "install -m 0755 ",
            "keyrx verify",
        )
        positions = [install_route.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("stop if it does not", install_route)
        self.assertIn("stop if you choose the provenance check and it fails", install_route)
        self.assertIn("complete fail-closed script", install_route)

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

    def test_windows_is_wsl_only_and_no_keyrx_curl_pipe_installer_is_taught(self):
        for name, text in SURFACES:
            with self.subTest(name=name):
                self.assertRegex(text, r"(?is)Windows.{0,100}WSL")
                self.assertNotRegex(text, r"(?is)curl[^\n]*(?:keyrx\.tech|github\.com/keyrx)[^\n]*\|\s*(?:ba)?sh")
        self.assertNotIn("&& clear", README)
        self.assertNotIn("&& clear", DOCS)
        self.assertNotIn("&& clear", SITE)
        self.assertNotIn("&& clear", LLMS)

    def test_macos_uses_source_build_until_signed_notarized_binaries_exist(self):
        for name, text in SURFACES:
            with self.subTest(name=name):
                self.assertIn("macOS", text)
                self.assertRegex(text, r"(?is)(?:signed and notarized|signed, notarized).{0,100}(?:macOS|Apple)")
                self.assertIn("cargo install --locked keyrx", text)

    def test_distro_rustup_is_not_declared_universally_broken(self):
        for name, text in SURFACES:
            with self.subTest(name=name):
                self.assertNotRegex(text, r"(?is)(?:do not|never) use.{0,100}(?:apt install rustup|snap install rustup)")


if __name__ == "__main__":
    unittest.main()
