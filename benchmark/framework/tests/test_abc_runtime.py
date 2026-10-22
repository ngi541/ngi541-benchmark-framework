from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

BENCHMARK_DIR=Path(__file__).resolve().parents[2]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0,str(BENCHMARK_DIR))

from framework.abc_runtime import validate_build_receipt, validate_smoke_evidence, write_evidence
from framework.abc_smoke import smoke_curl_command, parse_writeout, extract_cipher_evidence
from framework.io_utils import FrameworkError

class ABCStage2Tests(unittest.TestCase):
    def setUp(self):
        self.receipt={
            'schema_version':1,'os':'linux','arch':'x86_64',
            'variant':'stock','nginx_version':'1.31.6','openssl_version':'3.5.9',
            'binary_sha256':'a'*64, 'ngi541_enabled':False,'ngi541_library_sha256':None,
            'configure_arguments':'--with-http_ssl_module --with-http_v2_module --with-http_v3_module'
        }
        self.smoke={
            'schema_version':1,'arm':'B','protocol_http_version':'3',
            'response_code':200,'ssl_verify_result':0,
            'expected_sha256':'a'*64,'received_sha256':'a'*64,'received_bytes':32768,
            'client_uses_ngi541':False,'client_binary_sha256':'b'*64,
            'cipher_evidence':{'state':'unavailable','value':None,'reason':'no negotiated cipher in stderr'},
        }

    def test_ab_reuse_stock_receipt(self):
        validate_build_receipt(self.receipt,arm='A')
        validate_build_receipt(self.receipt,arm='B')

    def test_candidate_requires_crypto_macro_and_hash(self):
        r=copy.deepcopy(self.receipt);r.update(variant='ngi541-direct',ngi541_enabled=True,
                                               ngi541_library_sha256='b'*64)
        with self.assertRaises(FrameworkError): validate_build_receipt(r,arm='C')
        r['configure_arguments']+=' -DNGX_QUIC_NGI541=1'
        validate_build_receipt(r,arm='C')
        with self.assertRaises(FrameworkError): validate_build_receipt(r,arm='A')

    def test_rejects_missing_nginx_modules(self):
        r=copy.deepcopy(self.receipt);r['configure_arguments']=r['configure_arguments'].replace('--with-http_v2_module','')
        with self.assertRaises(FrameworkError): validate_build_receipt(r,arm='B')

    def test_smoke_h3(self):
        validate_smoke_evidence(self.smoke)
        r=copy.deepcopy(self.smoke);r['arm']='A';r['protocol_http_version']='2'
        validate_smoke_evidence(r)

    def test_rejects_protocol_fallback(self):
        r=copy.deepcopy(self.smoke);r['arm']='A'
        with self.assertRaises(FrameworkError): validate_smoke_evidence(r)

    def test_rejects_bad_client_identity(self):
        r=copy.deepcopy(self.smoke);r['client_uses_ngi541']=True
        with self.assertRaises(FrameworkError): validate_smoke_evidence(r)

    def test_rejects_object_corruption(self):
        r=copy.deepcopy(self.smoke);r['received_sha256']='c'*64
        with self.assertRaises(FrameworkError): validate_smoke_evidence(r)

    def test_tls_cipher_does_not_get_invented(self):
        x=extract_cipher_evidence('TLSv1.3 (OUT)\n')
        self.assertEqual(x['state'],'unavailable')
        x=extract_cipher_evidence('* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256 / X25519')
        self.assertEqual(x['value'],'TLS_AES_128_GCM_SHA256')

    def test_curl_h2_explicit(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);(p/'curl').write_text('');(p/'ca').write_text('')
            cmd=smoke_curl_command(arm='A',binary=p/'curl',server_name='ngi541-dut.local',address='192.0.2.1',
              port=4433,ca_file=p/'ca',object_path='test.bin',output_path=p/'out',cipher='TLS_AES_128_GCM_SHA256')
            self.assertIn('--http2',cmd);self.assertNotIn('--insecure',cmd)
            self.assertNotIn('--http3-only',cmd)
            cmd=smoke_curl_command(arm='C',binary=p/'curl',server_name='ngi541-dut.local',address='192.0.2.1',
              port=4433,ca_file=p/'ca',object_path='test.bin',output_path=p/'out',cipher='TLS_AES_128_GCM_SHA256')
            self.assertIn('--http3-only',cmd)

    def test_curl_writeout_parser(self):
        self.assertEqual(parse_writeout('3\t200\t0\t32768\n'),('3',200,0,32768))
        with self.assertRaises(FrameworkError):parse_writeout('garbage')

    def test_evidence_no_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'proof.json'
            write_evidence(p,self.smoke)
            with self.assertRaises(FrameworkError): write_evidence(p,self.smoke)

if __name__=='__main__':
    unittest.main()
