"""Schema provenance is not an editor-version gate."""

import copy
import hashlib
import json
import plistlib
import tempfile
import unittest
from pathlib import Path

from tools.extract_cursor_schema import (
    BUNDLE,
    OUTPUT,
    compatible,
    descriptor_array,
    extract,
    literal,
)


class CursorSchemaTests(unittest.TestCase):
    def test_descriptor_arrays_handle_options_empty_types_and_quoted_brackets(self):
        source = 'prefix[{no:1,name:"quoted]name",kind:"scalar",T:9}],{localName:"X"})'
        start = source.index("[") + 1
        result = literal(descriptor_array(source, start))
        self.assertEqual(result[0]["name"], "quoted]name")
        self.assertEqual(descriptor_array("[])", 1), "[]")
        with self.assertRaises(ValueError):
            descriptor_array('[{name:"unterminated"}', 1)

    def test_metadata_and_older_subsets_do_not_require_a_version_match(self):
        baseline = json.loads(OUTPUT.read_text(encoding="utf-8"))
        for version in ("3.25.0", "3.99.0", "4.0.0"):
            candidate = copy.deepcopy(baseline)
            candidate.update(cursor_version=version, bundle_sha256="f" * 64)
            with self.subTest(version=version):
                self.assertTrue(compatible(baseline, candidate))
        candidate = copy.deepcopy(baseline)
        candidate["messages"][candidate["root"]] = candidate["messages"][
            candidate["root"]
        ][:1]
        candidate["enums"] = {
            name: values[:1] for name, values in candidate["enums"].items()
        }
        self.assertTrue(compatible(baseline, candidate))

    def test_protocol_drift_requires_review(self):
        baseline = json.loads(OUTPUT.read_text(encoding="utf-8"))
        for change in ("new-field", "wire-type", "oneof", "enum", "root"):
            candidate = copy.deepcopy(baseline)
            fields = candidate["messages"][candidate["root"]]
            if change == "new-field":
                fields.append({"number": 999, "name": "new_content", "type": "bytes"})
            elif change == "wire-type":
                fields[0]["type"] = "bytes"
            elif change == "oneof":
                fields[0].pop("oneof")
            elif change == "enum":
                next(iter(candidate["enums"].values())).append(999)
            else:
                candidate["root"] = "other.Message"
            with self.subTest(change=change):
                self.assertFalse(compatible(baseline, candidate))

    def test_extraction_resolves_renamed_symbols_and_records_provenance(self):
        source = (
            'r=Z.makeMessageType("aiserver.v1.RunInferenceClientMessage",'
            '()=>[{no:2,name:"invoke_model",kind:"message",T:alias}]),'
            'alias=renamed,renamed.typeName="google.protobuf.Struct",'
            "renamed.fields=Z.util.newFieldList(()=>["
            '{no:1,name:"fields",kind:"map",K:9,V:{kind:"scalar",T:9}}])'
        )
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary)
            (app / BUNDLE).parent.mkdir(parents=True)
            (app / BUNDLE).write_text(source, encoding="utf-8")
            (app / "Contents/Info.plist").write_bytes(
                plistlib.dumps({"CFBundleShortVersionString": "4.2.1"})
            )
            result = json.loads(extract(app))
        self.assertEqual(result["cursor_version"], "4.2.1")
        self.assertEqual(
            result["bundle_sha256"], hashlib.sha256(source.encode()).hexdigest()
        )
        self.assertEqual(
            result["messages"][result["root"]][0]["type"], "google.protobuf.Struct"
        )
        self.assertEqual(
            result["messages"]["google.protobuf.Struct"][0]["map_key"], "string"
        )

    def test_absent_newer_auxiliary_roots_and_empty_generated_messages(self):
        root = "aiserver.v1.NameTabRequest"
        source = f'r=Z.makeMessageType("{root}",[],{{localName:"NameTab"}})'
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary)
            (app / BUNDLE).parent.mkdir(parents=True)
            (app / BUNDLE).write_text(source, encoding="utf-8")
            (app / "Contents/Info.plist").write_bytes(
                plistlib.dumps({"CFBundleShortVersionString": "3.20.0"})
            )
            result = json.loads(extract(app, (root, "agent.v1.NewerRPCRequest")))
        self.assertEqual(result["messages"], {root: []})


if __name__ == "__main__":
    unittest.main()
