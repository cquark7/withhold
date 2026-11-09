"""Keep repository and packaged documentation navigable without network access."""

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.check_docs import ROOT, anchors, check_links, public_documents


class DocumentationTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("WITHHOLD_TEST_NATIVE"), "native executable required"
    )
    def test_documented_configuration_examples_are_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("WITHHOLD_")
            }
            environment.update(
                HOME=str(root),
                USERPROFILE=str(root),
                APPDATA=str(root / "appdata"),
                XDG_CONFIG_HOME=str(root / "config"),
                WITHHOLD_DIR=str(root / "state"),
            )
            examples = [
                (document, example)
                for document in public_documents()
                for example in re.findall(
                    r"```toml\n(.*?)\n```",
                    document.read_text(encoding="utf-8"),
                    flags=re.DOTALL,
                )
            ]
            self.assertIn(
                ROOT / "docs" / "configuration.md", [doc for doc, _ in examples]
            )
            for document, example in examples:
                with self.subTest(document=document.relative_to(ROOT)):
                    path = root / "example.toml"
                    path.write_text(example, encoding="utf-8")
                    result = subprocess.run(
                        [
                            os.environ["WITHHOLD_TEST_NATIVE"],
                            "config",
                            "--json",
                            "--config",
                            str(path),
                        ],
                        env=environment,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout)["schema"], 1)
            self.assertEqual(list(root.iterdir()), [root / "example.toml"])

    def test_public_links_and_anchors(self):
        errors = [
            error for path in public_documents() for error in check_links(path, ROOT)
        ]
        self.assertEqual(errors, [])

    def test_heading_slugs_and_fenced_examples(self):
        self.assertEqual(
            anchors(
                "# Start and stop\n## `--pii` coverage\n## Start and stop\n"
                "```markdown\n# Not a heading\n```\n"
            ),
            {"start-and-stop", "--pii-coverage", "start-and-stop-1"},
        )

    def test_missing_paths_and_fragments_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "README.md"
            path.write_text(
                "# Example\n[OK](#example)\n[Bad anchor](#absent)\n"
                "[Bad file](missing.md)\n[Outside](../private.md)\n"
                "```text\n[Not a link](example.md)\n```\n"
                "[Remote](https://example.com/absent)\n",
                encoding="utf-8",
            )
            errors = check_links(path, root)
            self.assertEqual(len(errors), 3)
            self.assertIn("missing heading", errors[0])
            self.assertIn("missing local destination", errors[1])
