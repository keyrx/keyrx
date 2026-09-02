import copy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "ops" / "release_contract.py"
POLICY_PATH = ROOT / "ops" / "release" / "0.4.13.json"
SPEC = importlib.util.spec_from_file_location("release_contract", SCRIPT)
release_contract = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(release_contract)

class ReleaseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = release_contract.load_policy(POLICY_PATH)

    def test_exact_reviewed_legacy_identity_is_loaded(self):
        self.assertEqual(
            self.policy["predecessorEvidence"]["checksum"],
            "dcf2ff724aa2d0ec43173a2d1a7f225ea39efa8c5d61e43b02c82b26a4f7854d",
        )
        self.assertEqual(
            self.policy["predecessorEvidence"]["sourceSha"],
            "9b4725a0e8b160ccacad0d7b858793ba8dee4a89",
        )

    def test_policy_cannot_broaden_yanks_without_changing_the_reviewed_live_set(self):
        hostile = copy.deepcopy(self.policy)
        hostile["yankTargets"].insert(0, "0.4.11")
        with self.assertRaisesRegex(release_contract.ContractError, "must equal"):
            release_contract.validate_policy(hostile)

    def test_legacy_predecessor_mode_is_one_exact_migration_only(self):
        mutations = []
        wrong_predecessor = copy.deepcopy(self.policy)
        wrong_predecessor["predecessorEvidence"]["version"] = "0.4.11"
        mutations.append(wrong_predecessor)
        wrong_source = copy.deepcopy(self.policy)
        wrong_source["predecessorEvidence"]["sourceSha"] = "3" * 40
        mutations.append(wrong_source)
        future_current = copy.deepcopy(self.policy)
        future_current["version"] = "0.4.14"
        future_current["tag"] = "v0.4.14"
        future_current["assets"] = [name.replace("0.4.13", "0.4.14") for name in future_current["assets"]]
        mutations.append(future_current)
        for hostile in mutations:
            with self.subTest(hostile=hostile), self.assertRaisesRegex(
                release_contract.ContractError, "legacy predecessor evidence"
            ):
                release_contract.validate_policy(hostile)

    def test_predecessor_archive_member_manifest_is_bounded_unique_and_safe(self):
        for member in ("../escape", "keyrx-0.4.12/../escape"):
            hostile = copy.deepcopy(self.policy)
            hostile["predecessorEvidence"]["archiveMembers"].append(member)
            with self.subTest(member=member), self.assertRaises(
                release_contract.ContractError
            ):
                release_contract.validate_policy(hostile)
        duplicate = copy.deepcopy(self.policy)
        duplicate["predecessorEvidence"]["archiveMembers"].append(
            duplicate["predecessorEvidence"]["archiveMembers"][0]
        )
        with self.assertRaises(release_contract.ContractError):
            release_contract.validate_policy(duplicate)

    def test_policy_rejects_unknown_fields_and_wrong_asset_order(self):
        for mutation in ("unknown", "assets"):
            hostile = copy.deepcopy(self.policy)
            if mutation == "unknown":
                hostile["surprise"] = True
            else:
                hostile["assets"] = list(reversed(hostile["assets"]))
            with self.subTest(mutation=mutation), self.assertRaises(
                release_contract.ContractError
            ):
                release_contract.validate_policy(hostile)


if __name__ == "__main__":
    unittest.main()
