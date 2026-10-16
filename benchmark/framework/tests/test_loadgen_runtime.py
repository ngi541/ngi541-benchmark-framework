import json
import unittest
from pathlib import Path
import sys

TEST_DIR = Path(__file__).resolve().parent
BENCHMARK_DIR = TEST_DIR.parents[1]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.io_utils import FrameworkError
from framework.loadgen_runtime import (
    definition_sha256,
    load_definition,
    render_build_script,
    validate_definition,
)

CONFIG = BENCHMARK_DIR / "configs" / "r6.5.4.2-pi-http3-loadgen.json"


class LoadgenRuntimeDefinitionTests(unittest.TestCase):
    def test_valid_definition(self):
        value = load_definition(CONFIG)
        self.assertEqual(value["runtime"]["kind"], "curl-h2load-http3-ngtcp2")
        self.assertEqual(value["sources"]["curl"]["version"], "8.22.0")
        self.assertEqual(value["sources"]["ngtcp2"]["version"], "1.25.0")
        self.assertEqual(value["sources"]["nghttp2"]["version"], "1.69.0")

    def test_definition_hash_is_semantic(self):
        value = load_definition(CONFIG)
        reordered = json.loads(json.dumps(value, sort_keys=True))
        self.assertEqual(
            definition_sha256(value),
            definition_sha256(reordered),
        )

    def test_absolute_install_root_rejected(self):
        value = load_definition(CONFIG)
        value["runtime"]["install_root"] = "/opt/ngi541"
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_invalid_source_sha_rejected(self):
        value = load_definition(CONFIG)
        value["sources"]["curl"]["sha256"] = "deadbeef"
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_h2load_source_is_required(self):
        value = load_definition(CONFIG)
        del value["sources"]["nghttp2"]
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_nghttp2_patch_is_pinned(self):
        value = load_definition(CONFIG)
        patch = value["patches"]["nghttp2"]
        self.assertEqual(
            patch["path"],
            "integration/patches/nghttp2-1.69.0/"
            "0001-h2load-main-phase-stream-accounting.patch",
        )
        self.assertEqual(
            patch["sha256"],
            "ee36b8c0ff3b6c2bf703dcb0ea5608b237a98857d2d164960a5bf1de769d08a5",
        )


class LoadgenBuildScriptTests(unittest.TestCase):
    def setUp(self):
        self.value = load_definition(CONFIG)
        self.script = render_build_script(self.value)

    def test_script_pins_versions_and_http3_capabilities(self):
        self.assertIn("openssl-3.6.4", self.script)
        self.assertIn("nghttp3-1.18.0", self.script)
        self.assertIn("ngtcp2-1.25.0", self.script)
        self.assertIn("curl-8.22.0", self.script)
        self.assertIn("nghttp2-1.69.0.tar.xz", self.script)
        self.assertIn("--with-ngtcp2", self.script)
        self.assertIn("--enable-app --enable-http3", self.script)
        self.assertIn("--h3", self.script)
        self.assertIn("--output-file", self.script)
        self.assertIn("--timing-script-file", self.script)
        self.assertIn("--rps", self.script)

    def test_script_verifies_every_source_sha(self):
        for source in self.value["sources"].values():
            self.assertIn(source["sha256"], self.script)

    def test_h2load_build_forces_cxx20_before_configure(self):
        probe_pos = self.script.index("c++ -std=c++20")
        build_flag_pos = self.script.index('export CXXFLAGS="-std=c++20"')
        configure_pos = self.script.index(
            './configure --prefix="$PREFIX/nghttp2" --enable-app --enable-http3'
        )
        self.assertLess(probe_pos, build_flag_pos)
        self.assertLess(build_flag_pos, configure_pos)

    def test_h2load_build_is_scoped_to_required_target(self):
        self.assertIn("make -j4 -C lib", self.script)
        self.assertIn("make -j4 -C third-party", self.script)
        self.assertIn("make -j4 -C src h2load", self.script)
        self.assertIn(
            "./libtool --mode=install /usr/bin/install -c src/h2load",
            self.script,
        )
        self.assertNotIn("make -C src install", self.script)
        self.assertIn("--disable-examples", self.script)

    def test_script_verifies_and_applies_pinned_patch(self):
        patch_sha = self.value["patches"]["nghttp2"]["sha256"]
        self.assertIn(patch_sha, self.script)
        self.assertIn("base64 -d", self.script)
        self.assertIn("patch --dry-run --batch --forward -p1", self.script)
        self.assertIn("patch --batch --forward -p1", self.script)
        self.assertIn("patch --dry-run --batch --reverse -p1", self.script)

        patch_pos = self.script.index(
            'echo "==> apply pinned nghttp2 patch"'
        )
        configure_pos = self.script.index(
            './configure --prefix="$PREFIX/nghttp2" --enable-app --enable-http3'
        )
        self.assertLess(patch_pos, configure_pos)

    def test_patch_sha_drift_is_rejected(self):
        value = load_definition(CONFIG)
        value["patches"]["nghttp2"]["sha256"] = "0" * 64
        with self.assertRaises(FrameworkError):
            render_build_script(value)


if __name__ == "__main__":
    unittest.main()
