import gzip
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "ops" / "package_binary.py"
SPEC = importlib.util.spec_from_file_location("package_binary", SCRIPT)
package_binary = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(package_binary)


VERSION = "1.2.3"
SOURCE_SHA = "1" * 40
TARGET = "x86_64-unknown-linux-musl"
EPOCH = 1_725_000_000


def fake_elf() -> bytes:
    data = bytearray(64)
    data[:7] = b"\x7fELF\x02\x01\x01"
    data[16:18] = (2).to_bytes(2, "little")
    data[18:20] = (62).to_bytes(2, "little")
    return bytes(data)


class BinaryPackageTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, Path]:
        binary = root / "keyrx"
        binary.write_bytes(fake_elf())
        binary.chmod(0o755)
        license_path = root / "LICENSE"
        license_path.write_text("MIT fixture\n", encoding="utf-8")
        readme = root / "README.md"
        readme.write_text("# KeyRX fixture\n", encoding="utf-8")
        return binary, license_path, readme

    def create(self, root: Path, output_name: str | None = None) -> tuple[Path, Path, Path]:
        binary, license_path, readme = self.fixture(root)
        archive = root / (
            output_name or package_binary.archive_name(VERSION, TARGET)
        )
        package_binary.write_archive(
            version=VERSION,
            source_sha=SOURCE_SHA,
            target=TARGET,
            epoch=EPOCH,
            binary_path=binary,
            license_path=license_path,
            readme_path=readme,
            output=archive,
        )
        return archive, license_path, readme

    def test_same_inputs_produce_identical_canonical_archive(self):
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first, _, _ = self.create(Path(first_dir))
            second, license_path, readme = self.create(Path(second_dir))
            self.assertEqual(first.read_bytes(), second.read_bytes())

            root = f"keyrx-{VERSION}-{TARGET}"
            with tarfile.open(second, "r:gz") as archive:
                self.assertEqual(
                    archive.getnames(),
                    [
                        root,
                        f"{root}/keyrx",
                        f"{root}/LICENSE",
                        f"{root}/README.md",
                        f"{root}/SOURCE.json",
                    ],
                )
                members = archive.getmembers()
                self.assertEqual([member.mode for member in members], [0o755, 0o755, 0o644, 0o644, 0o644])
                self.assertEqual({member.uid for member in members}, {0})
                self.assertEqual({member.gid for member in members}, {0})
                self.assertEqual({member.uname for member in members}, {"root"})
                self.assertEqual({member.gname for member in members}, {"root"})
                self.assertEqual({member.mtime for member in members}, {EPOCH})
                source = archive.extractfile(f"{root}/SOURCE.json")
                self.assertIsNotNone(source)
                self.assertEqual(
                    source.read(),
                    (
                        '{"sourceSha":"' + SOURCE_SHA + '","target":"' + TARGET
                        + '","version":"' + VERSION + '"}\n'
                    ).encode("utf-8"),
                )

            sidecar = second.with_name(second.name + ".sha256")
            sidecar.write_text(
                hashlib.sha256(second.read_bytes()).hexdigest()
                + "  "
                + second.name
                + "\n",
                encoding="ascii",
            )
            package_binary.validate_archive(
                second,
                version=VERSION,
                source_sha=SOURCE_SHA,
                target=TARGET,
                epoch=EPOCH,
                license_path=license_path,
                readme_path=readme,
            )
            package_binary.validate_sidecar(sidecar, second)

    def test_non_linux_target_non_elf_or_non_executable_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, license_path, readme = self.fixture(root)
            output = root / package_binary.archive_name(VERSION, TARGET)
            cases = (
                ("target", "x86_64-pc-windows-msvc", fake_elf(), 0o755),
                ("format", TARGET, b"not an ELF", 0o755),
                ("mode", TARGET, fake_elf(), 0o644),
            )
            for label, target, data, mode in cases:
                with self.subTest(label=label):
                    output.unlink(missing_ok=True)
                    binary.write_bytes(data)
                    binary.chmod(mode)
                    with self.assertRaises(package_binary.PackageError):
                        package_binary.write_archive(
                            version=VERSION,
                            source_sha=SOURCE_SHA,
                            target=target,
                            epoch=EPOCH,
                            binary_path=binary,
                            license_path=license_path,
                            readme_path=readme,
                            output=output,
                        )

    def test_symlinked_input_and_existing_output_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, license_path, readme = self.fixture(root)
            link = root / "linked-keyrx"
            link.symlink_to(binary)
            output = root / package_binary.archive_name(VERSION, TARGET)
            with self.assertRaises(package_binary.PackageError):
                package_binary.write_archive(
                    version=VERSION,
                    source_sha=SOURCE_SHA,
                    target=TARGET,
                    epoch=EPOCH,
                    binary_path=link,
                    license_path=license_path,
                    readme_path=readme,
                    output=output,
                )
            output.write_bytes(b"do not overwrite")
            with self.assertRaises(package_binary.PackageError):
                package_binary.write_archive(
                    version=VERSION,
                    source_sha=SOURCE_SHA,
                    target=TARGET,
                    epoch=EPOCH,
                    binary_path=binary,
                    license_path=license_path,
                    readme_path=readme,
                    output=output,
                )
            self.assertEqual(output.read_bytes(), b"do not overwrite")

    def test_changed_content_metadata_or_checksum_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, license_path, readme = self.create(root)
            sidecar = root / (archive.name + ".sha256")
            sidecar.write_text("0" * 64 + "  " + archive.name + "\n", encoding="ascii")
            with self.assertRaisesRegex(package_binary.PackageError, "sidecar"):
                package_binary.validate_sidecar(sidecar, archive)

            with gzip.GzipFile(fileobj=io.BytesIO(archive.read_bytes()), mode="rb") as stream:
                raw = stream.read()
            source = io.BytesIO(raw)
            rewritten = io.BytesIO()
            with tarfile.open(fileobj=source, mode="r:") as existing, tarfile.open(
                fileobj=rewritten, mode="w", format=tarfile.USTAR_FORMAT
            ) as changed:
                for member in existing.getmembers():
                    data = existing.extractfile(member) if member.isfile() else None
                    if member.name.endswith("/README.md"):
                        member.mode = 0o600
                    changed.addfile(member, data)
            changed_archive = root / ("changed-" + archive.name)
            compressed = io.BytesIO()
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=compressed, mtime=EPOCH
            ) as stream:
                stream.write(rewritten.getvalue())
            changed_archive.write_bytes(compressed.getvalue())
            # Give it the required basename in a separate directory so validation
            # reaches the metadata check instead of stopping at the name.
            hostile_root = root / "hostile"
            hostile_root.mkdir()
            hostile = hostile_root / archive.name
            hostile.write_bytes(changed_archive.read_bytes())
            with self.assertRaisesRegex(package_binary.PackageError, "metadata differs"):
                package_binary.validate_archive(
                    hostile,
                    version=VERSION,
                    source_sha=SOURCE_SHA,
                    target=TARGET,
                    epoch=EPOCH,
                    license_path=license_path,
                    readme_path=readme,
                )

            trailing_root = root / "trailing"
            trailing_root.mkdir()
            trailing = trailing_root / archive.name
            trailing.write_bytes(archive.read_bytes() + b"ignored by permissive readers")
            with self.assertRaisesRegex(package_binary.PackageError, "canonical deterministic"):
                package_binary.validate_archive(
                    trailing,
                    version=VERSION,
                    source_sha=SOURCE_SHA,
                    target=TARGET,
                    epoch=EPOCH,
                    license_path=license_path,
                    readme_path=readme,
                )


if __name__ == "__main__":
    unittest.main()
