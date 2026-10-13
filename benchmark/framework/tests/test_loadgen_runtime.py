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


CONFIG = BENCHMARK_DIR / "configs" / "r6.5.2-pi-http3-loadgen.json"
H2LOAD_CONFIG = BENCHMARK_DIR / "configs" / "r6.5.3b-pi-http3-loadgen.json"


class LoadgenRuntimeDefinitionTests(unittest.TestCase):
    def test_valid_definition(self):
        value = load_definition(CONFIG)
        self.assertEqual(value["sources"]["curl"]["version"], "8.22.0")
        self.assertEqual(value["sources"]["ngtcp2"]["version"], "1.25.0")

    def test_definition_hash_is_semantic(self):
        a = load_definition(CONFIG)
        b = json.loads(json.dumps(a, sort_keys=False))
        self.assertEqual(definition_sha256(a), definition_sha256(b))

    def test_absolute_install_root_rejected(self):
        value = load_definition(CONFIG)
        value["runtime"]["install_root"] = "/opt/ngi541"
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_invalid_sha_rejected(self):
        value = load_definition(CONFIG)
        value["sources"]["curl"]["sha256"] = "deadbeef"
        with self.assertRaises(FrameworkError):
            validate_definition(value)


class LoadgenBuildScriptTests(unittest.TestCase):
    def test_script_pins_versions_and_checks_http3(self):
        value = load_definition(CONFIG)
        script = render_build_script(value)
        self.assertIn("openssl-3.6.4", script)
        self.assertIn("nghttp3-1.18.0", script)
        self.assertIn("ngtcp2-1.25.0", script)
        self.assertIn("curl-8.22.0", script)
        self.assertIn("--with-ngtcp2", script)
        self.assertIn("grep -q 'HTTP3'", script)

    def test_script_verifies_every_source_sha(self):
        value = load_definition(CONFIG)
        script = render_build_script(value)
        for source in value["sources"].values():
            self.assertIn(source["sha256"], script)


class H2loadRuntimeDefinitionTests(unittest.TestCase):
    def test_h2load_definition_is_valid_and_pinned(self):
        value = load_definition(H2LOAD_CONFIG)
        self.assertEqual(value["runtime"]["kind"], "curl-h2load-http3-ngtcp2")
        self.assertEqual(value["sources"]["nghttp2"]["version"], "1.69.0")
        self.assertEqual(
            value["sources"]["nghttp2"]["sha256"],
            "1fb324b6ec2c56f6bde0658f4139ffd8209fa9e77ce98fd7a5f63af8d0e508ad",
        )

    def test_h2load_source_is_required_for_h2load_kind(self):
        value = load_definition(H2LOAD_CONFIG)
        del value["sources"]["nghttp2"]
        with self.assertRaises(FrameworkError):
            validate_definition(value)

    def test_original_r652_definition_remains_valid(self):
        value = load_definition(CONFIG)
        self.assertEqual(value["runtime"]["kind"], "curl-http3-ngtcp2")
        self.assertNotIn("nghttp2", value["sources"])


class H2loadBuildScriptTests(unittest.TestCase):
    def test_script_builds_http3_h2load_and_checks_capabilities(self):
        value = load_definition(H2LOAD_CONFIG)
        script = render_build_script(value)
        self.assertIn("nghttp2-1.69.0.tar.xz", script)
        self.assertIn("--enable-app --enable-http3", script)
        self.assertIn("--h3", script)
        self.assertIn("--output-file", script)
        self.assertIn("--timing-script-file", script)
        self.assertIn("--rps", script)
        self.assertIn("c++ -std=c++20", script)
        self.assertIn('export CXXFLAGS="-std=c++20"', script)

    def test_h2load_build_forces_cxx20_after_successful_probe(self):
        value = load_definition(H2LOAD_CONFIG)
        script = render_build_script(value)
        probe_pos = script.index('c++ -std=c++20')
        build_flag_pos = script.index('export CXXFLAGS="-std=c++20"')
        configure_pos = script.index('./configure --prefix="$PREFIX/nghttp2" --enable-app --enable-http3')
        self.assertLess(probe_pos, build_flag_pos)
        self.assertLess(build_flag_pos, configure_pos)


    def test_h2load_build_is_scoped_to_required_target(self):
        value = load_definition(H2LOAD_CONFIG)
        script = render_build_script(value)
        self.assertIn("make -j4 -C lib", script)
        self.assertIn("make -j4 -C third-party", script)
        self.assertIn("make -j4 -C src h2load", script)

    def test_h2load_install_does_not_build_other_nghttp2_apps(self):
        value = load_definition(H2LOAD_CONFIG)
        script = render_build_script(value)
        self.assertIn("./libtool --mode=install /usr/bin/install -c src/h2load", script)
        self.assertNotIn("make -C src install", script)
        self.assertIn("--disable-examples", script)

    def test_script_verifies_nghttp2_source_sha(self):
        value = load_definition(H2LOAD_CONFIG)
        script = render_build_script(value)
        self.assertIn(value["sources"]["nghttp2"]["sha256"], script)

    def test_h2load_definition_hash_differs_from_r652(self):
        self.assertNotEqual(
            definition_sha256(load_definition(CONFIG)),
            definition_sha256(load_definition(H2LOAD_CONFIG)),
        )


if __name__ == "__main__":
    unittest.main()
