import copy
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "ops" / "crates_upload.py"
SPEC = importlib.util.spec_from_file_location("crates_upload", SCRIPT)
crates_upload = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(crates_upload)

VERSION = "0.4.13"


def cargo_metadata(root):
    return {
        "packages": [
            {
                "name": "keyrx",
                "version": VERSION,
                "source": None,
                "manifest_path": str(root / "Cargo.toml"),
                "publish": None,
                "license": "MIT",
                "license_file": None,
                "description": "test package",
                "dependencies": [
                    {
                        "name": "clap",
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                        "req": "^4.5",
                        "kind": None,
                        "rename": None,
                        "optional": False,
                        "uses_default_features": True,
                        "features": ["derive"],
                        "target": None,
                        "registry": None,
                    }
                ],
                "features": {},
                "authors": [],
                "categories": ["command-line-utilities"],
                "keywords": ["test"],
                "readme": "README.md",
                "repository": "https://example.invalid/repo",
                "homepage": "https://example.invalid",
                "documentation": None,
                "links": None,
                "rust_version": "1.85",
            }
        ]
    }


def make_crate(path, readme="# exact archive readme\n"):
    data = readme.encode("utf-8")
    member = tarfile.TarInfo(f"keyrx-{VERSION}/README.md")
    member.size = len(data)
    member.mtime = 0
    with tarfile.open(path, "w:gz") as archive:
        archive.addfile(member, io.BytesIO(data))


def split_body(body):
    metadata_size = struct.unpack("<I", body[:4])[0]
    metadata_end = 4 + metadata_size
    metadata = json.loads(body[4:metadata_end])
    crate_size = struct.unpack("<I", body[metadata_end : metadata_end + 4])[0]
    crate = body[metadata_end + 4 :]
    if len(crate) != crate_size:
        raise AssertionError("wrong embedded crate length")
    return metadata, crate


class ExactUploadBodyTests(unittest.TestCase):
    def test_documented_protocol_embeds_exact_preserved_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crate = root / f"keyrx-{VERSION}.crate"
            make_crate(crate)
            body = crates_upload.build_body(crate, cargo_metadata(root), VERSION)
            metadata, embedded = split_body(body)
            self.assertEqual(embedded, crate.read_bytes())
            self.assertEqual(metadata["name"], "keyrx")
            self.assertEqual(metadata["vers"], VERSION)
            self.assertEqual(metadata["readme"], "# exact archive readme\n")
            self.assertEqual(metadata["readme_file"], "README.md")
            self.assertEqual(
                metadata["deps"],
                [
                    {
                        "name": "clap",
                        "version_req": "^4.5",
                        "features": ["derive"],
                        "optional": False,
                        "default_features": True,
                        "target": None,
                        "kind": "normal",
                        "registry": None,
                        "explicit_name_in_toml": None,
                    }
                ],
            )

    def test_non_registry_dependency_and_alternate_registry_are_rejected(self):
        mutations = [
            {"source": "git+https://example.invalid/repo"},
            {"registry": "https://example.invalid/index"},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                crate = root / f"keyrx-{VERSION}.crate"
                make_crate(crate)
                metadata = cargo_metadata(root)
                metadata["packages"][0]["dependencies"][0].update(mutation)
                with self.assertRaises(crates_upload.UploadError):
                    crates_upload.build_body(crate, metadata, VERSION)

    def test_metadata_identity_filename_and_readme_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = cargo_metadata(root)
            cases = []
            wrong_version = copy.deepcopy(valid)
            wrong_version["packages"][0]["version"] = "0.4.12"
            cases.append((root / f"keyrx-{VERSION}.crate", wrong_version, False))
            cases.append((root / "other.crate", valid, True))
            missing_readme = copy.deepcopy(valid)
            missing_readme["packages"][0]["readme"] = "MISSING.md"
            cases.append((root / f"keyrx-{VERSION}.crate", missing_readme, False))
            for crate, metadata, create_readme in cases:
                with self.subTest(crate=crate.name, metadata=metadata):
                    make_crate(crate, "# readme\n")
                    if create_readme:
                        # The filename check must still win even with a valid archive.
                        pass
                    with self.assertRaises(crates_upload.UploadError):
                        crates_upload.build_body(crate, metadata, VERSION)

    def test_malformed_feature_and_boolean_metadata_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crate = root / f"keyrx-{VERSION}.crate"
            make_crate(crate)
            for field, value in (("features", "derive"), ("optional", "false")):
                metadata = cargo_metadata(root)
                metadata["packages"][0]["dependencies"][0][field] = value
                with self.subTest(field=field), self.assertRaises(
                    crates_upload.UploadError
                ):
                    crates_upload.build_body(crate, metadata, VERSION)


if __name__ == "__main__":
    unittest.main()
