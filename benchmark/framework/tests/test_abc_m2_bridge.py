"""M2.1.1 negative gates: protect causality, byte integrity and window provenance."""
from __future__ import annotations
import copy
import json
import sys
import unittest
from pathlib import Path

B = Path(__file__).resolve().parents[2]
if str(B) not in sys.path: sys.path.insert(0,str(B))
from framework.abc_m2_coordination import (COORDINATION_REVISION, assess,
    assess_snapshot_enclosure,receipt,validate_receipt)
from framework.abc_m2_payload import extract_h2load_evidence
from framework.io_utils import FrameworkError


def mk(role,edge,s,e,host=None):
    return {'schema_version':1,'revision':COORDINATION_REVISION,'kind':'linux-host-marker',
            'run_id':'r','attempt_id':'a','window_id':'w','host_role':role,'edge':edge,
            'boot_id':f'boot-{role}', 'hostname':host or role,
            'monotonic_ns_before':s,'monotonic_ns_after':e,
            'utc_advisory_only':'2026-10-22T00:00:00Z'}


def rec(role,edge,s,e,ms,me,transport='ssh'):
    return receipt(host_marker=mk(role,edge,ms,me),controller_boot_id='ctrl-boot',
                   controller_hostname='ctrl',send_before_ns=s,receive_after_ns=e,
                   transport=transport)


def rounds(transport='ssh'):
    start={'dut':rec('dut','start',100_000_000,102_000_000,1000,1010,transport),
           'client':rec('client','start',101_000_000,104_000_000,4_000,4_010,transport)}
    end={'dut':rec('dut','end',2_100_000_000,2_103_000_000,2_000,2_010,transport),
         'client':rec('client','end',2_101_000_000,2_104_000_000,6_000,6_010,transport)}
    return start,end


def loadgen(*,data=32768,done=1,started=1,fail=0,success=1,timeout=0,stat=1):
    return json.dumps({'measurements':{'traffic':{'data':data,'total':data+123},
            'requests':{'started':started,'done':done,'succeeded':success,
                        'failed':fail,'errored':0,'timeout':timeout},
            'status_codes':{'2xx':stat,'3xx':0,'4xx':0,'5xx':0}}}).encode()


class ControllerTests(unittest.TestCase):
    def test_bound_is_conservative_and_no_qualification(self):
        a,b=rounds()
        x=assess(start_receipts=a,end_receipts=b,max_boundary_uncertainty_ms=5.0)
        self.assertEqual(x['quality'],'within-provisional-threshold')
        self.assertAlmostEqual(x['start_skew_upper_bound_ms'],4.0)
        self.assertAlmostEqual(x['end_skew_upper_bound_ms'],4.0)
        self.assertFalse(x['qualified_primary_result'])
        self.assertFalse(x['loadgen_main_phase_bound'])

    def test_explicit_quality_failure_not_silent_pass(self):
        a,b=rounds()
        x=assess(start_receipts=a,end_receipts=b,max_boundary_uncertainty_ms=1)
        self.assertEqual(x['quality'],'exceeds-provisional-threshold')

    def test_local_two_roles_not_remote_evidence(self):
        a,b=rounds('local-test')
        self.assertEqual(assess(start_receipts=a,end_receipts=b,
                         max_boundary_uncertainty_ms=100)['quality'],'functional-local-only')

    def test_same_kernel_ssh_does_not_qualify_separate_hosts(self):
        a,b=rounds()
        for group in (a,b):
            group['client']['host_marker']['boot_id']='boot-dut'
        self.assertEqual(assess(start_receipts=a,end_receipts=b,
            max_boundary_uncertainty_ms=50)['quality'],'same-linux-kernel-unqualified')

    def test_controller_boot_change_rejected(self):
        a,b=rounds()
        b['dut']['controller']['boot_id']='other'
        with self.assertRaises(FrameworkError):
            assess(start_receipts=a,end_receipts=b,max_boundary_uncertainty_ms=50)

    def test_host_boot_change_rejected(self):
        a,b=rounds()
        b['dut']['host_marker']['boot_id']='other'
        with self.assertRaises(FrameworkError):
            assess(start_receipts=a,end_receipts=b,max_boundary_uncertainty_ms=50)

    def test_host_monotonic_not_cross_compared(self):
        a,b=rounds()
        a['client']['host_marker']['monotonic_ns_before']=10**14
        a['client']['host_marker']['monotonic_ns_after']=10**14+1
        b['client']['host_marker']['monotonic_ns_before']=10**14+5000
        b['client']['host_marker']['monotonic_ns_after']=10**14+5100
        self.assertGreater(assess(start_receipts=a,end_receipts=b,
                    max_boundary_uncertainty_ms=50)['max_skew_upper_bound_ms'],0)

    def test_controller_round_overlap_rejected(self):
        a,b=rounds()
        b['dut']['controller_before_ns']=102_000_000
        with self.assertRaises(FrameworkError):
            assess(start_receipts=a,end_receipts=b,max_boundary_uncertainty_ms=50)

    def test_non_monotonic_local_marker_rejected(self):
        a,b=rounds()
        a['dut']['host_marker']['monotonic_ns_after']=999
        with self.assertRaises(FrameworkError):
            assess(start_receipts=a,end_receipts=b,max_boundary_uncertainty_ms=50)

    def test_receipt_has_no_cross_host_time_sync_assertion(self):
        a,_=rounds()
        validate_receipt(a['dut'],role='dut',edge='start')
        a['dut']['qualified_time_sync']=True
        with self.assertRaises(FrameworkError):validate_receipt(a['dut'])

    def test_snapshot_enclosure_detects_padding(self):
        a,b=rounds()
        # Snapshots deliberately bracket same-host markers, but not MAIN boundaries.
        s={'run_id':'r','attempt_id':'a','window_id':'w','host_role':'dut',
           'identity':{'boot_id':'boot-dut'},
           'capture':{'monotonic_ns_before':990,'monotonic_ns_after':998}}
        e={'run_id':'r','attempt_id':'a','window_id':'w','host_role':'dut',
           'identity':{'boot_id':'boot-dut'},
           'capture':{'monotonic_ns_before':2011,'monotonic_ns_after':2020}}
        x=assess_snapshot_enclosure(start=s,end=e,start_marker=a['dut']['host_marker'],
                                     end_marker=b['dut']['host_marker'])
        self.assertTrue(x['counters_enclose_markers'])
        self.assertFalse(x['exact_main_phase_bound'])
        self.assertAlmostEqual(x['pre_window_padding_upper_bound_ms'],20/1e6)
        e['capture']['monotonic_ns_before']=2009
        with self.assertRaises(FrameworkError):
            assess_snapshot_enclosure(start=s,end=e,start_marker=a['dut']['host_marker'],
                                      end_marker=b['dut']['host_marker'])


class PayloadTests(unittest.TestCase):
    def extract(self,src=None,**kw):
        return extract_h2load_evidence(source=src or loadgen(),arm='C',run_id='r',
                attempt_id='a',window_id='w',**kw)

    def test_main_data_not_valid_bytes(self):
        x=self.extract(declared_main_seconds=2.)
        self.assertEqual(x['main_phase_data_bytes_reported'],32768)
        self.assertEqual(x['scientific_byte_accounting'],'h2load-main-phase-body-bytes')
        self.assertAlmostEqual(x['reported_data_rate_mbps_diagnostic'],0.131072)
        self.assertEqual(x['valid_application_payload_bytes']['state'],'unavailable')
        self.assertFalse(x['qualified_primary_result'])
        self.assertEqual(x['client_identity_state'],'unverified')

    def test_anomaly_and_partial_download_remain_unqualified(self):
        x=self.extract(src=loadgen(data=1234,done=0,started=1,success=0,stat=0))
        self.assertIn('inflight_at_cutoff',x['diagnostic_flags'])
        self.assertIsNone(x['reported_data_rate_mbps_diagnostic'])

    def test_failure_never_zeroed(self):
        x=self.extract(src=loadgen(fail=1,timeout=1))
        self.assertIn('request_failure_reported',x['diagnostic_flags'])

    def test_invalid_bytes_and_bool_rejected(self):
        for data in (-1,True,'42'):
            src=loadgen()
            j=json.loads(src)
            j['measurements']['traffic']['data']=data
            with self.assertRaises(FrameworkError):self.extract(src=json.dumps(j).encode())

    def test_schema_missing_rejected(self):
        with self.assertRaises(ValueError):self.extract(src=b'{}')

    def test_client_identity_match_is_recorded(self):
        x=self.extract(expected_client_sha256='abcd',actual_client_sha256='abcd')
        self.assertEqual(x['client_identity_state'],'pinned-match')

    def test_client_identity_mismatch_rejected(self):
        with self.assertRaises(FrameworkError):
            self.extract(expected_client_sha256='sha1',actual_client_sha256='sha2')

    def test_goodput_duration_must_be_positive(self):
        with self.assertRaises(FrameworkError):self.extract(declared_main_seconds=0)

    def test_measurement_source_sha256_is_exact(self):
        import hashlib
        src=loadgen()
        self.assertEqual(self.extract(src=src)['source_sha256'],hashlib.sha256(src).hexdigest())

if __name__=='__main__':unittest.main()
