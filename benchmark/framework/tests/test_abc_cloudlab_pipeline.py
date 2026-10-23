import importlib.util
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[2]
THIS=pathlib.Path(__file__).resolve().parents[1]
if str(THIS) not in sys.path:sys.path.insert(0,str(THIS))
from abc_cloudlab_pipeline import (PipelineError, load_config, ensure_hash, sha256,
    remote_python, remote_prepare_dut, remote_write_ca, remote_check_binaries,
    run_arm, collect_remote_logs, start_nginx, validate_tar_name,
    create_archives, remote_root, PINNED_HASHES)

class PipelineTests(unittest.TestCase):
    def test_valid_archive_name(self):
        validate_tar_name('client/nghttp2/lib/libev.so.1')
    def test_bad_archive_paths(self):
        for n in ['/tmp/evil', '../escape', 'x/../y', '']:
            with self.subTest(n=n),self.assertRaises(PipelineError):validate_tar_name(n)
    def test_sha256(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t)/'a';p.write_bytes(b'abc')
            self.assertEqual(sha256(p),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
            with self.assertRaises(PipelineError):ensure_hash(p,'stock_nginx',PINNED_HASHES)
    def test_config_positive(self):
        src=pathlib.Path(__file__).parents[2]/'configs/abc-cloudlab-10g-pipeline.json'
        with tempfile.TemporaryDirectory() as td:
            conf=json.loads(src.read_text()); key=pathlib.Path(td)/'key';key.write_text('dummy')
            conf['ssh']['identity_file']=str(key)
            file=pathlib.Path(td)/'conf.json';file.write_text(json.dumps(conf))
            self.assertEqual(load_config(file,pathlib.Path(td))['pipeline']['https_port'],18443)
    def test_pinned_hashes_cannot_be_replaced(self):
        src=pathlib.Path(__file__).parents[2]/'configs/abc-cloudlab-10g-pipeline.json'
        with tempfile.TemporaryDirectory() as td:
            conf=json.loads(src.read_text()); key=pathlib.Path(td)/'key';key.write_text('dummy')
            conf['ssh']['identity_file']=str(key)
            conf['pipeline']['pinned_sha256']={'stock_nginx':'0'*64}
            file=pathlib.Path(td)/'conf.json';file.write_text(json.dumps(conf))
            with self.assertRaises(PipelineError):load_config(file,pathlib.Path(td))
    def test_wrong_port(self):
        src=pathlib.Path(__file__).parents[2]/'configs/abc-cloudlab-10g-pipeline.json'
        with tempfile.TemporaryDirectory() as td:
            conf=json.loads(src.read_text()); key=pathlib.Path(td)/'key';key.write_text('dummy')
            conf['ssh']['identity_file']=str(key)
            conf['pipeline']['https_port']=conf['smoke']['iperf3']['port']
            file=pathlib.Path(td)/'conf.json';file.write_text(json.dumps(conf))
            with self.assertRaises(PipelineError):load_config(file,pathlib.Path(td))
    def test_remote_python_compilable(self):
        seen=[]
        def fake(cfg,role,command,*,input_text=None,timeout_s=40):
            compile(input_text,'<remote-script>','exec')
            seen.append((role,input_text))
            return '{}'
        with patch('abc_cloudlab_pipeline.pf.ssh_run',side_effect=fake):
            remote_prepare_dut({},'/home/ivanets/.ngi541/run','10.10.1.1',18443)
            remote_write_ca({},'/home/ivanets/.ngi541/run',
                            '-----BEGIN CERTIFICATE-----\nGOOD\n-----END CERTIFICATE-----\n')
            remote_check_binaries({}, {'dut':'/tmp/dut','client':'/tmp/client'})
            with tempfile.TemporaryDirectory() as t:
                collect_remote_logs({}, {'dut':'/tmp/dut','client':'/tmp/client'},pathlib.Path(t))
        self.assertGreaterEqual(len(seen),6)
    def test_arm_remote_script_compilable(self):
        seen=[]
        def remote_py(cfg, role, body, payload, timeout_s=40):
            fake='import json\nP=json.loads('+repr(json.dumps(payload))+')\n'+body
            compile(fake,'<remote-run-arm>','exec')
            seen.append((role,fake))
            if role=='client':return {'http_version':'2','payload_sha256':'abc'}
            if payload.get('type'):return {'listener_found':True}
            return {'access_lines':['tls=TLSv1.3 cipher=TLS_AES_128_GCM_SHA256'], 'error_tail':''}
        with patch('abc_cloudlab_pipeline.start_nginx'),patch('abc_cloudlab_pipeline.stop_nginx'),\
             patch('abc_cloudlab_pipeline.remote_python',side_effect=remote_py),patch('abc_cloudlab_pipeline.time.sleep'):
            output=run_arm({}, {'dut':'/tmp/d','client':'/tmp/c'},'10.10.1.1',18443,'A','abc')
        self.assertEqual(output['http_version'],'2');self.assertEqual(len(seen),3)
    def test_upload_staging_archive_contains_expected_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            p={}
            for key in ('stock_nginx','candidate_nginx','ngi541_engine','client_curl','client_h2load'):
                x=root/key;x.write_bytes(key.encode());p[key]=x
            client=root/'prefix';p['client_prefix']=client
            for component in ('curl','openssl','ngtcp2','nghttp3','nghttp2'):
                d=client/component/'lib';d.mkdir(parents=True)
                (d/'libtest.so.1').write_bytes(b'x')
                (d/'libtest.so').symlink_to('libtest.so.1')
            files=create_archives(p,root)
            with tarfile.open(files['client']) as tf:
                names=tf.getnames()
                self.assertIn('client/curl/bin/curl',names)
                self.assertIn('client/openssl/lib/libtest.so.1',names)
            with tarfile.open(files['dut']) as tf:
                self.assertIn('bin/stock-nginx',tf.getnames())
                self.assertIn('lib/libngi541_engine.so.0.1',tf.getnames())
    def test_remote_root_id_validation(self):
        with self.assertRaises(PipelineError):remote_root({},'dut','unsafe-root')

if __name__=='__main__':unittest.main()

class ControlFlowTests(unittest.TestCase):
    def test_fail_closed_preflight_blocks_deployment(self):
        import abc_cloudlab_pipeline as m
        config={'pipeline': {'https_port':18443}}
        with tempfile.TemporaryDirectory() as td, patch.object(m.pf,'execute',return_value={'status':'FAIL'}), \
             patch.object(m,'checked_local_artifacts') as ar, patch.object(m,'collect_remote_logs'):
            result=m.execute(config,pathlib.Path(td),pathlib.Path(td)/'evidence')
            self.assertEqual(result['status'],'FAIL')
            self.assertIn('preflight',result['error'])
            ar.assert_not_called()
    def test_full_control_flow_marks_functional_only(self):
        import abc_cloudlab_pipeline as m
        config={'pipeline': {'https_port':18443}}
        with tempfile.TemporaryDirectory() as td:
            d=pathlib.Path(td)
            paths={k:d/k for k in ('stock_nginx','candidate_nginx','ngi541_engine','client_curl','client_h2load')}
            for p in paths.values():p.write_bytes(b'x')
            paths['client_prefix']=d
            preflight={'status':'PASS','path':{'dut':{'ip':'10.10.1.1'}}}
            archives={'dut':d/'dut.tar.gz','client':d/'client.tar.gz'}
            for p in archives.values():p.write_bytes(b'test')
            with patch.object(m.pf,'execute',return_value=preflight),\
                 patch.object(m,'checked_local_artifacts',return_value=(paths,{})),\
                 patch.object(m,'create_archives',return_value=archives),\
                 patch.object(m,'remote_root',side_effect=['/tmp/abc-dut','/tmp/abc-client']),\
                 patch.object(m,'upload_tar'),patch.object(m,'remote_check_binaries',return_value={}),\
                 patch.object(m,'remote_prepare_dut',return_value={'expected_sha256':'x'*64,'ca_pem':'pem'}),\
                 patch.object(m,'remote_write_ca'),\
                 patch.object(m,'run_arm',side_effect=[{'http_version':'2','payload_sha256':'x'*64},
                    {'http_version':'3','payload_sha256':'x'*64},
                    {'http_version':'3','payload_sha256':'x'*64}]),\
                 patch.object(m,'collect_remote_logs'):
                result=m.execute(config,d,d/'out')
            self.assertEqual(result['status'],'PASS_FUNCTIONAL_NOT_SCIENTIFIC')
            self.assertEqual(set(result['arms']),set('ABC'))
            self.assertEqual(result['scientific_measurement']['status'],'not_applicable')
