import argparse
import base64
import importlib.util
import json
import pathlib
import sys
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("epic_sandbox_client.py")
SPEC = importlib.util.spec_from_file_location("epic_sandbox_client", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class EpicSandboxClientTests(unittest.TestCase):
    def test_document_reference_binds_patient_encounter_and_exact_receipt(self):
        receipt = {"receipt_type": "EP-RECEIPT-v1", "receipt_id": "ep_demo_1"}

        document = MODULE.build_document_reference(
            receipt_bytes=json.dumps(receipt, separators=(",", ":")).encode(),
            patient_id="patient-1",
            encounter_id="encounter-1",
        )

        self.assertEqual(document["resourceType"], "DocumentReference")
        self.assertEqual(document["subject"]["reference"], "Patient/patient-1")
        self.assertEqual(
            document["context"]["encounter"],
            [{"reference": "Encounter/encounter-1"}],
        )
        encoded = document["content"][0]["attachment"]["data"]
        note = base64.b64decode(encoded).decode()
        self.assertIn('"receipt_id":"ep_demo_1"', note)
        self.assertNotIn("patient-1", note)

    def test_write_command_requires_explicit_confirmation(self):
        args = argparse.Namespace(confirm_write=False)
        with self.assertRaisesRegex(ValueError, "--confirm-write"):
            MODULE.require_write_confirmation(args)

    def test_reference_validation_rejects_path_injection(self):
        for value in ("../Patient/other", "patient/1", " patient-1", ""):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    MODULE.validate_fhir_id(value, "patient_id")

    def test_safe_summary_never_returns_token_or_private_key(self):
        response = {
            "access_token": "secret-token",
            "scope": "system/Patient.read system/DocumentReference.write",
            "expires_in": 3600,
            "private_key": "secret-key",
        }
        summary = MODULE.token_summary(response)
        serialized = json.dumps(summary)
        self.assertNotIn("secret-token", serialized)
        self.assertNotIn("secret-key", serialized)
        self.assertEqual(summary["expires_in"], 3600)

    def test_document_id_falls_back_to_epic_location_header(self):
        response = {
            "_http_status": 201,
            "_location": "https://example.test/FHIR/R4/DocumentReference/doc-9/_history/1",
        }
        self.assertEqual(MODULE.document_id_from_response(response), "doc-9")


if __name__ == "__main__":
    unittest.main()
