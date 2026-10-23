"""B2 native profile and actual pinned-repository integration contracts."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from framework import cloudlab_artifacts
from framework.cloudlab_bootstrap_b2 import (
    REPO, _client_bootstrap, _load_nodes, _server_bootstrap, prepare,
)
from framework.loadgen_runtime import load_definition, render_build_script


class BootstrapB2Tests(unittest.TestCase):
    def setUp(self):
        self.definition = load_definition(REPO / 'benchmark/configs/r6.5.4.2-pi-http3-loadgen.json')

    def test_server_only_clones_pinned_ngi541(self):
        script = _server_bootstrap()
        self.assertIn('NGI541_BUILD_ENGINE=ON', script)
        self.assertIn('abc-linux-build.sh --build', script)
        self.assertIn('"$NGI541_COMMIT"', script)
        self.assertNotIn('ngi541-benchmark-framework', script)

    def test_client_script_is_role_specific(self):
        script = _client_bootstrap()
        self.assertNotIn('git clone', script)
        self.assertIn('HTTP2', script)
        self.assertIn('HTTP3', script)
        self.assertIn('verify-bundle.py', script)

    def test_native_http2_before_curl_and_libcurl_capability(self):
        script = render_build_script(
            self.definition, profile='cloudlab-http2-http3', runtime_identity='a'*64)
        self.assertLess(script.index('==> build nghttp2'), script.index('==> build curl'))
        self.assertIn('--with-nghttp2="$PREFIX/nghttp2"', script)
        self.assertIn('libnghttp2.so', script)
        self.assertIn('nghttp2-h2load.patch', script)
        self.assertNotIn('base64 -d', script)
        proc = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_historical_r6_renderer_is_byte_identical(self):
        script = render_build_script(self.definition)
        self.assertEqual(hashlib.sha256(script.encode()).hexdigest(),
                         '63b419bc234841037357b5ca7c68182676e50b3a2e9b6d7f4945447ae3fb9475')
        self.assertLess(script.index('==> build curl'), script.index('==> build nghttp2'))
        self.assertNotIn('--with-nghttp2=', script)

    def test_native_profile_requires_identity_and_pin(self):
        with self.assertRaises(Exception):
            render_build_script(self.definition, profile='cloudlab-http2-http3')
        changed = copy.deepcopy(self.definition)
        changed['patches']['nghttp2']['sha256'] = '0'*64
        with self.assertRaises(Exception):
            render_build_script(changed, profile='cloudlab-http2-http3', runtime_identity='a'*64)

    def test_nodes_are_explicit_and_can_repeat_communication_role(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / 'nodes.json'
            plan.write_text(json.dumps({'schema_version':1,'nodes':[
                {'node_id':'abc','communication_role':'client','stack_profile':'http-loadgen'},
                {'node_id':'def','communication_role':'client','stack_profile':'http-loadgen'}]}))
            self.assertEqual(len(_load_nodes(plan)), 2)

    def test_actual_pins_generate_two_self_contained_archives_and_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p1, p2 = root/'a', root/'b'
            a = prepare(REPO, p1, 'integration-test')
            b = prepare(REPO, p2, 'integration-test')
            self.assertEqual(a, b)
            self.assertEqual(len(a['nodes']), 2)
            self.assertEqual(len({x['sha256'] for x in a['nodes']}), 2)
            for node in a['nodes']:
                archive = p1 / node['archive']
                self.assertEqual(cloudlab_artifacts.digest(archive.read_bytes()), node['sha256'])
                self.assertEqual(cloudlab_artifacts.verify_archive(archive)['node_id'], node['node_id'])
                with tarfile.open(archive, 'r:gz') as tf:
                    members = set(tf.getnames())
                    self.assertIn('bootstrap.sh', members)
                    self.assertIn('build.lock.json', members)
                    self.assertIn('verify-bundle.py', members)
                    self.assertNotIn('.git', members)
                    lock = json.load(tf.extractfile('build.lock.json'))
                    self.assertEqual(set(lock['inputs_sha256']), members - {'bundle.manifest.json','build.lock.json'})
                    self.assertEqual(lock['publication_eligible'], all(lock['generator_sources_tracked'].values()))
                    if node['stack_profile'] == 'http-loadgen':
                        self.assertIn('benchmark/configs/r6.5.4.2-pi-http3-loadgen.json', members)
                        self.assertIn('client-build.sh', members)
                    else:
                        self.assertIn('scripts/abc-linux-build.sh', members)
                        self.assertIn('integration/versions/versions.env', members)
                    with tempfile.TemporaryDirectory() as extracted:
                        tf.extractall(extracted, filter='data')
                        for f in ('bootstrap.sh','client-build.sh'):
                            file = Path(extracted)/f
                            if file.is_file():
                                check = subprocess.run(['bash','-n',str(file)],capture_output=True,text=True)
                                self.assertEqual(check.returncode,0,check.stderr)
                        verified = subprocess.run(['python3',str(Path(extracted)/'verify-bundle.py'),extracted],capture_output=True,text=True)
                        self.assertEqual(verified.returncode,0,verified.stderr)
                        # Prevent accepting silently modified DUT bundle contents.
                        (Path(extracted)/'bootstrap.sh').write_text('#/bin/bash\nexit 0\n')
                        failed = subprocess.run(['python3',str(Path(extracted)/'verify-bundle.py'),extracted],capture_output=True,text=True)
                        self.assertNotEqual(failed.returncode,0)
            with self.assertRaises(FileExistsError):
                prepare(REPO,p1,'integration-test')


if __name__ == '__main__':
    unittest.main()
