# SPDX-License-Identifier: Apache-2.0
# Python conformance runner: emits [{id, valid}] for each vector. argv[1] = vectors path.
import sys, json, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "packages", "python-verify"))
from emilia_verify import verify_receipt
vectors = json.load(open(sys.argv[1]))["vectors"]
print(json.dumps([{"id": v["id"], "valid": verify_receipt(v["document"], v["public_key"]).valid} for v in vectors]))
