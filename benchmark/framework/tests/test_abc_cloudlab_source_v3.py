"""Source-build controller contract tests; never use SSH/network."""
import json, pathlib, sys, tempfile, unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import abc_cloudlab_source_v3 as v3

CONF=pathlib.Path(__file__).resolve().parents[2]/'configs/abc-cloudlab-source.json'

class CloudlabSourceTests(unittest.TestCase):
    def setUp(self):
        self.cfg=json.loads(CONF.read_text())
    def test_schema(self):
        self.assertEqual(v3.check_config(self.cfg)['schema_version'],3)
    def test_no_private_identity_in_json(self):
        s=json.dumps(self.cfg)
        for word in ('identity_file','private_key','cloudlab_ngi541_ivan_ed25519','client_root','upload-prebuilt','build/abc-linux'):
            self.assertNotIn(word,s)
    def test_reject_other_schema(self):
        self.cfg['schema_version']=2
        with self.assertRaises(v3.SourceError):v3.check_config(self.cfg)
    def test_require_distinct_hosts(self):
        self.cfg['nodes']['client']=self.cfg['nodes']['server']
        with self.assertRaises(v3.SourceError):v3.check_config(self.cfg)
    def test_invalid_ssh_syntax(self):
        self.cfg['nodes']['server']='ssh ivanets@node0; echo oops'
        with self.assertRaises(v3.SourceError):v3.check_config(self.cfg)
    def test_reject_extra_fields(self):
        self.cfg['network']={'experiment_cidr':'10.10.1.0/24'}
        with self.assertRaises(v3.SourceError):v3.check_config(self.cfg)
    def test_reject_nonboolean_smoke(self):
        self.cfg['connection_smoke']='true'
        with self.assertRaises(v3.SourceError):v3.check_config(self.cfg)
    def test_reject_arbitrary_manifest(self):
        self.cfg['inputs']['server_build']='../../../etc/passwd'
        with self.assertRaises(v3.SourceError):v3.check_config(self.cfg)
    def test_version_env_exact(self):
        p=pathlib.Path(__file__).resolve().parents[3]/'integration/versions/versions.env'
        self.assertEqual(v3.version_env(p)['NGINX_VERSION'],'1.31.6')
    def test_server_builder_is_from_sources(self):
        env={'NGI541_COMMIT':'f'*40}
        s=v3.server_script('/users/u/.ngi541-cloudlab/20261022T230000Z-abcdef1234',env,'a'*40)
        for x in ('git clone','checkout -q --detach','cmake -S','abc-linux-build.sh --build','libngi541_engine.so','SOURCE_BUILD_SERVER_PASS'):
            self.assertIn(x,s)
        self.assertIn('-DNGI541_BUILD_ENGINE=ON',s)
        for x in ('upload-prebuilt','scp','darwin','Downloads/ngi541'):
            self.assertNotIn(x,s)
    def test_client_build_from_pins(self):
        s=v3.client_script_for_remote('/users/u/.ngi541-cloudlab/20261022T230000Z-abcdef1234','PREFIX="$HOME/.local/ngi541/loadgen/http3/demo"\necho demo')
        self.assertIn('PINNED_CLIENT_BUILD',s)
        self.assertIn('SOURCE_BUILD_CLIENT_PASS',s)
        self.assertNotIn('scp ',s)
    def test_client_rejects_unrecognized_prefix(self):
        with self.assertRaises(v3.SourceError):v3.client_script_for_remote('/tmp/a','echo hello')
    def test_missing_private_key(self):
        with self.assertRaises(v3.SourceError):v3.private_config(self.cfg,'/tmp/ngi541-absent-key')
    def test_sneaky_public_key(self):
        with tempfile.TemporaryDirectory() as t:
            k=pathlib.Path(t)/'key.pub';k.write_text('public')
            with self.assertRaises(v3.SourceError):v3.private_config(self.cfg,k)
    def test_private_config_maps_roles(self):
        with tempfile.TemporaryDirectory() as t:
            k=pathlib.Path(t)/'private';k.write_text('test fake')
            p=v3.private_config(self.cfg,k)
            self.assertEqual(p['nodes']['dut']['ssh'],self.cfg['nodes']['server'])
            self.assertEqual(p['network']['experiment_cidr'],None)
            self.assertEqual(p['smoke']['iperf3']['minimum_goodput_gbps'],0)
    def test_source_script_bash_syntax(self):
        import subprocess
        s=v3.server_script('/home/u/.ngi541-cloudlab/test',{'NGI541_COMMIT':'f'*40},'a'*40)
        self.assertEqual(subprocess.run(['bash','-n'],input=s,text=True,capture_output=True).returncode,0)
        c=v3.client_script_for_remote('/home/u/run','PREFIX="$HOME/test"\necho demo')
        self.assertEqual(subprocess.run(['bash','-n'],input=c,text=True,capture_output=True).returncode,0)

if __name__=='__main__':unittest.main()
