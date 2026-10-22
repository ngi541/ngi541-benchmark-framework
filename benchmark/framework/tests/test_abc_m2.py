"""M2.0+M2.1 additive contract and Linux counter fixture tests."""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

BENCHMARK = Path(__file__).resolve().parents[2]
if str(BENCHMARK) not in sys.path:
    sys.path.insert(0, str(BENCHMARK))

from framework.abc_m2_contract import (REVISION, load_registry, metric_record,
    validate_metric_v2, validate_observation_v2, validate_complete_primary_claim)
from framework.abc_m2_linux import (CPU_NAMES, parse_cpu_set, parse_net_protocols,
    parse_proc_stat, counter_deltas, derive)
from framework.io_utils import FrameworkError


def sample(phase, role='dut', *, reset=False):
    offset = 0 if phase == 'start' else 100
    if reset:
        offset = -5
    cpu = {'user':100+offset, 'nice':0,'system':50+offset,'idle':200+offset,
           'iowait':10, 'irq':10+offset,'softirq':10+offset,
           'steal':0,'guest':0,'guest_nice':0}
    return {'schema_version':2, 'contract_revision':REVISION, 'kind':'linux-primary-snapshot',
            'run_id':'abc-001','attempt_id':'attempt-001','window_id':'main-01',
            'phase':phase,'host_role':role,
            'capture':{'utc_started':'2026-10-22T04:00:00+00:00',
              'monotonic_ns_before':10_000_000_000 if phase=='start' else 12_000_000_000,
              'monotonic_ns_after':10_002_000_000 if phase=='start' else 12_002_000_000,
              'read_duration_ns':2_000_000},
            'identity':{'boot_id':'boot-id','hostname':'server', 'kernel':'6.1.0',
                 'cpu_tick_hz':100,'cpus':[0], 'interface':'eth1',
                 'network_scope':'current-network-namespace'},
            'counters':{'cpu_ticks':{'cpu0':cpu},'netdev':{
              'tx_bytes':4000+offset, 'rx_bytes':2000+offset,
              'tx_packets':400+offset,'rx_packets':300+offset,
              'tx_dropped':0,'rx_dropped':0,'tx_errors':0,'rx_errors':0},
              'cgroup':{'state':'measured','reason':None,
                        'values':{'usage_usec':10000+offset,'user_usec':5000+offset,
                                  'system_usec':5000+offset, 'nr_throttled':0, 'throttled_usec':0},
                        'identity':{'path':'/sys/fs/cgroup/dut','st_dev':1,'st_ino':99}},
              'protocols':{'snmp':{'Tcp.RetransSegs':3 if phase=='start' else 4},
                           'netstat':{}},'protocol_read_errors':{}}}


class M2ContractTests(unittest.TestCase):
    def setUp(self):
        self.registry = load_registry()
        self.defs = {x['name']:x for x in self.registry['metrics']}

    def test_registry_keeps_26_metrics_and_modes(self):
        self.assertEqual(len(self.defs),26)
        self.assertEqual(set(self.registry['states']),{'measured','unavailable','not_applicable','invalid'})
        self.assertEqual(set(self.registry['measurement_modes']),{'P','C','K'})

    def test_registered_metrics_include_attribution_and_protocol(self):
        for name in ('ngi541_prepared_encrypt_calls','ngi541_hp_calls','openssl_quic_fallback_calls',
                     'quic_loss_events','tcp_retransmits','cpu_cycles','udp_send_syscalls',
                     'valid_application_payload_bytes'):
            self.assertIn(name,self.defs)

    def test_states_not_confused_with_zero(self):
        for state in ('unavailable','not_applicable','invalid'):
            x=metric_record(name='nic_rx_drops',state=state,value=None,reason='not measured',
                    source='sysfs',host_role='dut',window_id='w')
            self.assertIsNone(x['value'])
        x=metric_record(name='nic_rx_drops',state='measured',value=0,reason=None,
                source='sysfs',host_role='dut',window_id='w')
        self.assertEqual(x['value'],0)

    def test_reject_nonmeasured_numeric_value(self):
        with self.assertRaises(FrameworkError):
            metric_record(name='nic_rx_drops',state='unavailable',value=0,reason='unknown',
                source='sysfs',host_role='dut',window_id='w')

    def test_reject_wrong_unit(self):
        x=metric_record(name='nic_tx_bytes',state='measured',value=1,reason=None,
                source='sysfs',host_role='dut',window_id='w')
        x['unit']='Mbit/s'
        with self.assertRaises(FrameworkError): validate_metric_v2(x,'nic_tx_bytes',self.defs['nic_tx_bytes'])

    def test_reject_wrong_mode(self):
        with self.assertRaises(FrameworkError):
            metric_record(name='ngi541_hp_calls',state='measured',value=2,reason=None,
                source='instrumentation',host_role='dut',window_id='w',collection_mode='P')

    def test_nonapplicable_protocol_must_not_be_zero(self):
        r=derive(sample('start'),sample('end'),arm='B')
        self.assertEqual(r['metrics']['tcp_retransmits']['state'],'not_applicable')
        v=copy.deepcopy(r)
        v['metrics']['tcp_retransmits'].update(state='measured',value=0,reason=None)
        with self.assertRaises(FrameworkError): validate_observation_v2(v)

    def test_primary_claim_cannot_be_inferred(self):
        r=derive(sample('start'),sample('end'),arm='C')
        with self.assertRaises(FrameworkError): validate_complete_primary_claim(r)


class LinuxM2Tests(unittest.TestCase):
    def test_cpu_set_parser(self):
        self.assertEqual(parse_cpu_set('0-2,4,5-6'),[0,1,2,4,5,6])
        for invalid in ('','4-1','1,x','1,,2','0-900000'):
            with self.assertRaises(FrameworkError): parse_cpu_set(invalid)

    def test_stat_parser_ignores_aggregate(self):
        text='cpu 1 2 3 4 5 6 7 8 9 10\ncpu0 1 2 3 4 5 6 7 8 9 10\n'
        self.assertEqual(parse_proc_stat(text,[0])['cpu0']['guest'],9)
        with self.assertRaises(FrameworkError):parse_proc_stat(text,[1])

    def test_net_snmp_parser(self):
        self.assertEqual(parse_net_protocols('Tcp: RtoAlgorithm RetransSegs\nTcp: 1 5\n'),
                         {'Tcp.RtoAlgorithm':1,'Tcp.RetransSegs':5})
        self.assertEqual(parse_net_protocols('Tcp: MaxConn RetransSegs\nTcp: -1 7\n'),
                         {'Tcp.MaxConn':-1,'Tcp.RetransSegs':7})
        with self.assertRaises(FrameworkError):parse_net_protocols('Tcp: A B\nUdp: 1 2\n')

    def test_reject_counter_reset(self):
        with self.assertRaises(FrameworkError):counter_deltas({'a':100},{'a':50})

    def test_derive_dut_raw_no_fabricated_cpu_per_gib(self):
        r=derive(sample('start'),sample('end'),arm='A')
        self.assertEqual(r['qualification_status'],'evidence-only-not-qualified')
        self.assertEqual(r['metrics']['nic_tx_bytes']['value'],100)
        self.assertEqual(r['metrics']['tcp_retransmits']['value'],1)
        self.assertEqual(r['metrics']['application_goodput_mbps']['state'],'unavailable')
        self.assertEqual(r['metrics']['dut_process_cpu_seconds_per_gib']['state'],'unavailable')
        self.assertGreater(r['raw_counter_evidence']['host_cpu_busy_seconds'],0)
        self.assertGreater(r['raw_counter_evidence']['elapsed_seconds_range']['minimum'],0)
        validate_observation_v2(r)

    def test_derive_client_peak_not_claimed(self):
        r=derive(sample('start',role='client'),sample('end',role='client'),arm='B')
        self.assertEqual(r['metrics']['client_total_busy_percent']['state'],'measured')
        self.assertEqual(r['metrics']['client_max_single_core_busy_percent']['state'],'unavailable')
        self.assertFalse(r['metrics']['client_max_single_core_busy_percent']['detail']['is_instantaneous_peak'])
        self.assertEqual(r['metrics']['dut_host_cpu_seconds_per_gib']['state'],'not_applicable')

    def test_snmp_gauge_may_decrease_without_counter_reset(self):
        a,b=sample('start'),sample('end')
        a['counters']['protocols']['snmp']['Tcp.CurrEstab']=7
        b['counters']['protocols']['snmp']['Tcp.CurrEstab']=2
        r=derive(a,b,arm='A')
        self.assertNotIn('Tcp.CurrEstab',r['raw_counter_evidence']['protocol_counter_deltas']['snmp'])
        self.assertEqual(r['raw_counter_evidence']['protocol_gauges_before_after']['snmp']['Tcp.CurrEstab'],
                         {'before':7,'after':2})

    def test_cgroup_absent_explicit(self):
        a,b=sample('start'),sample('end')
        for s in (a,b):s['counters']['cgroup']={'state':'unavailable','reason':'not configured','values':None,'identity':None}
        r=derive(a,b,arm='C')
        self.assertIsNone(r['raw_counter_evidence']['cgroup_cpu_stat_deltas'])
        self.assertIn('not configured',r['raw_counter_evidence']['cgroup_unavailable_reason'])

    def test_refuse_mismatched_boot_and_cgroup(self):
        a,b=sample('start'),sample('end')
        b['identity']['boot_id']='second'
        with self.assertRaises(FrameworkError):derive(a,b,arm='A')
        b=sample('end')
        b['counters']['cgroup']['identity']['st_ino']=100
        with self.assertRaises(FrameworkError):derive(a,b,arm='A')

    def test_refuse_reset_and_mismatched_window(self):
        a,b=sample('start'),sample('end',reset=True)
        with self.assertRaises(FrameworkError):derive(a,b,arm='A')
        b=sample('end')
        b['window_id']='other-window'
        with self.assertRaises(FrameworkError):derive(a,b,arm='A')

    def test_refuse_overlapping_samples(self):
        a,b=sample('start'),sample('end')
        b['capture']['monotonic_ns_before']=a['capture']['monotonic_ns_before']
        with self.assertRaises(FrameworkError):derive(a,b,arm='A')

    def test_legacy_schema_v1_is_unmodified(self):
        # Legacy v1 has 2 states and a performance/attribution mode, not P/C/K.
        from framework.abc_measurements import validate_metric
        validate_metric({'state':'unavailable','value':None,'reason':'not sampled'},'pmu_cycles')
        with self.assertRaises(FrameworkError):
            validate_metric({'state':'not_applicable','value':None,'reason':'not QUIC'},'pmu_cycles')

if __name__ == '__main__': unittest.main()
