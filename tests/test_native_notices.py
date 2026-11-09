"""Dependency notices must cover the executable without exposing build paths."""

import tempfile
import unittest
from pathlib import Path

from tools.native_notices import json_objects, render_notices


class NativeNoticesTests(unittest.TestCase):
    def test_notices_preserve_terms_and_identify_exact_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            goroot = root / "go"
            goroot.mkdir()
            (goroot / "LICENSE").write_text("Synthetic Go license\n")
            vendored = goroot / "src" / "vendor" / "example.org" / "lib"
            vendored.mkdir(parents=True)
            (vendored / "LICENSE").write_text("Synthetic vendored Go terms\n")
            module = root / "module"
            module.mkdir()
            (module / "LICENSE").write_text("Synthetic module license\n")
            nested = module / "internal" / "part"
            nested.mkdir(parents=True)
            (nested / "NOTICE.txt").write_text("Synthetic component attribution\n")
            (module / "COPYING.extra").write_text("Additional synthetic terms\n")
            dep = {"Path": "example.org/Some/lib/v2", "Version": "v2.3.4-RC.1"}
            build = {"GoVersion": "go1.26.10", "Deps": [dep]}
            modules = {dep["Path"]: dict(dep, Dir=str(module))}
            text = render_notices(build, modules, goroot).decode()
            self.assertIn("Synthetic vendored Go terms", text)
            self.assertIn("Synthetic component attribution", text)
            self.assertIn("Additional synthetic terms", text)
            self.assertIn("internal/part/NOTICE.txt", text)
            self.assertIn(
                "https://proxy.golang.org/example.org/!some/lib/v2/@v/v2.3.4-!r!c.1.zip",
                text,
            )
            self.assertNotIn(temporary, text)
            self.assertEqual(text.encode(), render_notices(build, modules, goroot))

    def test_missing_mismatched_or_replaced_sources_refuse_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "LICENSE").write_text("Synthetic license\n")
            dep = {"Path": "example.org/lib", "Version": "v1.0.0"}
            for module in (
                {},
                dict(dep),
                dict(dep, Version="v2.0.0", Dir=temporary),
                dict(dep, Dir=temporary, Replace={"Path": "../local"}),
            ):
                with self.subTest(module=module), self.assertRaises(ValueError):
                    render_notices(
                        {"GoVersion": "go1.26.10", "Deps": [dep]},
                        {dep["Path"]: module},
                        root,
                    )
            with self.assertRaises(ValueError):
                render_notices(
                    {
                        "GoVersion": "go1.26.10",
                        "Deps": [dict(dep, Replace={"Path": "local"})],
                    },
                    {dep["Path"]: dict(dep, Dir=temporary)},
                    root,
                )

    def test_absent_empty_or_symlinked_license_refuses_packaging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            goroot = root / "go"
            goroot.mkdir()
            (goroot / "LICENSE").write_text("Synthetic Go license\n")
            module = root / "module"
            module.mkdir()
            dep = {"Path": "example.org/lib", "Version": "v1.0.0"}
            build = {"GoVersion": "go1.26.10", "Deps": [dep]}
            modules = {dep["Path"]: dict(dep, Dir=str(module))}
            with self.assertRaises(ValueError):
                render_notices(build, modules, goroot)
            license = module / "LICENSE"
            license.write_text("  \n")
            with self.assertRaises(ValueError):
                render_notices(build, modules, goroot)
            license.unlink()
            try:
                license.symlink_to(goroot / "LICENSE")
            except OSError:
                return  # Windows can prohibit symlink creation for this user.
            with self.assertRaises(ValueError):
                render_notices(build, modules, goroot)

    def test_go_list_stream_retains_each_object(self):
        self.assertEqual(
            list(json_objects(' {"Path":"a"}\n {"Path":"b"}\n')),
            [{"Path": "a"}, {"Path": "b"}],
        )
