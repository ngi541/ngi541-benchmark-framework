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


if __name__ == "__main__":
    unittest.main()
