# SPDX-License-Identifier: Apache-2.0
import json

from ep_verify.cli import main


def test_duplicate_receipt_members_are_refused(tmp_path, capsys):
    receipt = tmp_path / "receipt.json"
    keys = tmp_path / "keys.json"
    receipt.write_text('{"@version":"EP-RECEIPT-v1","@version":"attacker"}', encoding="utf-8")
    keys.write_text('[]', encoding="utf-8")
    assert main([str(receipt), "--keys", str(keys)]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "REFUSED"
    assert json.loads(lines[1])["reason"] == "receipt_unreadable_or_malformed"


def test_duplicate_key_members_are_refused(tmp_path, capsys):
    receipt = tmp_path / "receipt.json"
    keys = tmp_path / "keys.json"
    receipt.write_text('{}', encoding="utf-8")
    keys.write_text('{"keys":[],"keys":[]}', encoding="utf-8")
    assert main([str(receipt), "--keys", str(keys)]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "REFUSED"
    assert json.loads(lines[1])["reason"] == "keys_unreadable_or_malformed"
