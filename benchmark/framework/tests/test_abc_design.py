from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parents[2]
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from framework.abc_design import (load_abc_design, validate_abc_design,
                                  abc_design_sha256, build_abc_schedule)
from framework.abc_transport import (nginx_http2_config, abc_h2load_command,
                                     abc_curl_probe_command, validate_abc_protocol_proof)
from framework.abc_measurements import (validate_metric, validate_abc_observation)
from framework.io_utils import FrameworkError

PROTO = BENCHMARK_DIR / 'protocols' / 'abc-high-speed-design-draft.json'

class ABCDesignTests(unittest.TestCase):
    def setUp(self):
        self.value = load_abc_design(PROTO)

    def test_arm_contract(self):
        self.assertEqual([self.value['arms'][a]['protocol'] for a in 'ABC'], ['h2','h3','h3'])
        self.assertTrue(all(not v['client_uses_ngi541'] for v in self.value['arms'].values()))

    def test_reject_client_crypto(self):
        v=copy.deepcopy(self.value);v['arms']['C']['client_uses_ngi541']=True
        with self.assertRaises(FrameworkError): validate_abc_design(v)

    def test_reject_duplicate_condition(self):
        v=copy.deepcopy(self.value);v['conditions'][1]=v['conditions'][0]
        with self.assertRaises(FrameworkError): validate_abc_design(v)

    def test_semantic_hash_stable(self):
        self.assertEqual(abc_design_sha256(self.value), abc_design_sha256(copy.deepcopy(self.value)))

    def test_schedule_full_and_balanced(self):
        runs=build_abc_schedule(self.value)
        self.assertEqual(len(runs),108)
        for condition in self.value['conditions']:
            group=[r for r in runs if r['condition_id']==condition['condition_id']]
            self.assertEqual(len(group),12)
            self.assertEqual({a:sum(r['arm']==a for r in group) for a in 'ABC'}, dict(A=4,B=4,C=4))
            for rep in range(1,5):
                part=[r for r in group if r['repetition']==rep]
                bc=sorted(r['position'] for r in part if r['arm'] in 'BC')
                self.assertEqual(bc[1]-bc[0],1)
                self.assertEqual(len({r['pair_id'] for r in part if r['arm'] in 'BC'}),1)
                self.assertIsNone(next(r['pair_id'] for r in part if r['arm']=='A'))
            self.assertEqual(sum(group[i]['arm']=='B' and group[i]['position'] < next(r['position'] for r in group if r['repetition']==group[i]['repetition'] and r['arm']=='C') for i in range(len(group)) if group[i]['arm']=='B'),2)

    def test_h2_nginx_is_tls13_http2_only(self):
        conf=nginx_http2_config(host='192.0.2.1',port=8443,workers=4,worker_connections=4096,cipher_suite='TLS_AES_128_GCM_SHA256')
        self.assertIn('listen 192.0.2.1:8443 ssl;',conf)
        self.assertIn('http2 on;',conf)
        self.assertNotIn('http3 on;',conf)
        self.assertNotIn(' quic',conf)
        self.assertIn('ssl_early_data off;',conf)

    def test_h2_command_only_removes_h3_flag(self):
        opts=dict(h2load_binary='/bin/h2load',server_name='ngi541-dut.local',host='192.0.2.1',port=8443,
                  cipher_suite='TLS_AES_128_GCM_SHA256',ca_path='/tmp/ca.crt',connections=4,max_streams=4,
                  threads=4,warmup_seconds=3,measurement_seconds=5,target_goodput_mbps=100,
                  profile=dict(kind='fixed-object', objects=[dict(size_bytes=32768,relative_path='obj.bin')]),
                  result_path='/tmp/result.json',timing_script_path=None)
        b=abc_h2load_command(arm='B',**opts);c=abc_h2load_command(arm='C',**opts);a=abc_h2load_command(arm='A',**opts)
        self.assertEqual(b,c)
        self.assertEqual(a, [x for x in b if x!='--h3'])

    def test_h2_curl_requires_version_proof(self):
        opts=dict(curl_binary='/bin/curl',server_name='ngi541-dut.local',host='192.0.2.1',port=8443,
                  cipher_suite='TLS_AES_128_GCM_SHA256',ca_path='/tmp/ca.crt',object_path='obj.bin',
                  output_path='/tmp/out.bin',timeout_seconds=10)
        self.assertIn('--http2',abc_curl_probe_command(arm='A',**opts))
        self.assertIn('--http3-only',abc_curl_probe_command(arm='B',**opts))
        validate_abc_protocol_proof(arm='A',http_version='2',status=200,tls_verified=True,cipher_suite='TLS_AES_128_GCM_SHA256')
        with self.assertRaises(FrameworkError):
            validate_abc_protocol_proof(arm='A',http_version='1.1',status=200,tls_verified=True,cipher_suite='TLS_AES_128_GCM_SHA256')

    def test_metric_unavailable_distinct_from_zero(self):
        validate_metric(dict(state='unavailable',value=None,reason='PMU blocked'),'pmu_cycles')
        validate_metric(dict(state='measured',value=0,reason=None),'nic_drops')
        with self.assertRaises(FrameworkError):
            validate_metric(dict(state='unavailable',value=0,reason='missing'),'pmu_cycles')

    def test_observation_rejects_unavailable_primary(self):
        rec=dict(schema_version=1,arm='C',mode='performance',condition_id='clas12-event-stream-4',repetition=1,
                 protocol_proof=dict(negotiated='h3',verified=True,tls_version='TLSv1.3',cipher_suite='TLS_AES_128_GCM_SHA256'),
                 client=dict(ngi541_enabled=False,binary_sha256='0'*64),
                 metrics={k:dict(state='measured',value=1.0,reason=None) for k in ('application_goodput_mbps','dut_process_cpu_seconds_per_gib','dut_host_cpu_seconds_per_gib','loadgen_max_single_core_busy_percent')})
        validate_abc_observation(rec)
        rec['metrics']['dut_host_cpu_seconds_per_gib']=dict(state='unavailable',value=None,reason='not measured')
        with self.assertRaises(FrameworkError): validate_abc_observation(rec)

if __name__=='__main__': unittest.main()
