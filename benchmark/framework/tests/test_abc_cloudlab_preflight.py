"""Controller-only unit tests; no CloudLab SSH connection is attempted."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('abc_cloudlab_preflight', ROOT / 'abc_cloudlab_preflight.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def inventory(name='dut', ip='10.10.1.1', speed=10000, dev='eno2', management='eno1'):
    return {
        'inventory_schema': 'ngi541-cloudlab-inventory-v1', 'hostname': name,
        'default_route_devices': [management], 'cpu_model': 'Intel Xeon',
        'tools': {'iperf3': True, 'ss': True},
        'interfaces': [
            {'name': management, 'operstate': 'UP', 'speed_mbps': 1000,
             'ipv4': [{'address': '130.127.133.189', 'prefixlen': 22}]},
            {'name': dev, 'operstate': 'UP', 'speed_mbps': speed,
             'ipv4': [{'address': ip, 'prefixlen': 24}], 'mtu': 1500,
             'numa_node': '1'},
        ]
    }


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = pathlib.Path(self.tmp.name) / 'id_ed25519'
        self.key.write_text('a mocked key, not a real private key')
        self.cfg = {
            'schema': P.SCHEMA,
            'nodes': {'dut': {'ssh': 'ivanets@clnode180.clemson.cloudlab.us'},
                      'client': {'ssh': 'ivanets@clnode148.clemson.cloudlab.us'}},
            'ssh': {'identity_file': str(self.key)},
            'network': {'min_link_mbps': 10000, 'experiment_cidr': None},
            'smoke': {'ping_packets': 4, 'iperf3': {
                'port': 52103, 'parallel_streams': 4, 'duration_s': 12,
                'omit_s': 3, 'minimum_goodput_gbps': 8.0}},
        }

    def parse(self):
        path = pathlib.Path(self.tmp.name) / 'config.json'
        path.write_text(json.dumps(self.cfg))
        return P.load_config(path)

    def test_valid(self):
        self.assertEqual(self.parse()['nodes']['dut']['ssh'], self.cfg['nodes']['dut']['ssh'])

    def test_private_key_missing(self):
        self.key.unlink()
        with self.assertRaisesRegex(P.PreflightError, 'not found'):
            self.parse()

    def test_public_key_rejected(self):
        path = pathlib.Path(self.tmp.name) / 'id.pub'
        path.write_text('pub')
        self.cfg['ssh']['identity_file'] = str(path)
        with self.assertRaises(P.PreflightError):
            self.parse()

    def test_injection_hostname_rejected(self):
        self.cfg['nodes']['dut']['ssh'] = 'ivanets@host;touch /tmp/test'
        with self.assertRaises(P.PreflightError):
            self.parse()

    def test_same_node_rejected(self):
        self.cfg['nodes']['dut'] = self.cfg['nodes']['client']
        with self.assertRaises(P.PreflightError):
            self.parse()

    def test_port_rejected(self):
        self.cfg['smoke']['iperf3']['port'] = 90
        with self.assertRaises(P.PreflightError):
            self.parse()

    def test_duration_omit_rejected(self):
        self.cfg['smoke']['iperf3']['duration_s'] = 3
        self.cfg['smoke']['iperf3']['omit_s'] = 3
        with self.assertRaises(P.PreflightError):
            self.parse()

    def test_network_cidr_invalid(self):
        self.cfg['network']['experiment_cidr'] = 'bad'
        with self.assertRaises(P.PreflightError):
            self.parse()

    def test_ssh_flags_no_insecure_host_check(self):
        command = P.ssh_base(self.cfg, 'dut')
        self.assertIn('StrictHostKeyChecking=accept-new', command)
        self.assertIn('BatchMode=yes', command)
        self.assertIn('IdentitiesOnly=yes', command)
        self.assertNotIn('StrictHostKeyChecking=no', command)


class SelectionTests(unittest.TestCase):
    def test_dedicated_interface_selected(self):
        result = P.select_experiment_path(inventory(), inventory('client', '10.10.1.2'), 10000)
        self.assertEqual(result['dut']['interface'], 'eno2')
        self.assertEqual(result['client']['ip'], '10.10.1.2')
        self.assertEqual(result['common_link_mbps'], 10000)

    def test_management_interface_never_used(self):
        with self.assertRaisesRegex(P.PreflightError, 'refusing to use management'):
            P.select_experiment_path(inventory(speed=1000), inventory('client', '10.10.1.2', speed=1000), 10000)

    def test_mismatch_subnets_rejected(self):
        with self.assertRaises(P.PreflightError):
            P.select_experiment_path(inventory(), inventory('client', '10.10.2.2'), 10000)

    def test_different_nodes_same_ip_rejected(self):
        with self.assertRaises(P.PreflightError):
            P.select_experiment_path(inventory(), inventory('client', '10.10.1.1'), 10000)

    def test_100g_filter(self):
        with self.assertRaises(P.PreflightError):
            P.select_experiment_path(inventory(), inventory('client','10.10.1.2'), 100000)

    def test_cidr_filter(self):
        with self.assertRaises(P.PreflightError):
            P.select_experiment_path(inventory(), inventory('client','10.10.1.2'), 10000, '10.10.2.0/24')

    def test_ambiguous_equal_speed_fail_closed(self):
        a = inventory()
        b = inventory('client', '10.10.1.2')
        a['interfaces'].append({'name':'eno3', 'operstate':'UP', 'speed_mbps':10000,
                                'ipv4':[{'address':'10.10.9.1','prefixlen':24}]})
        b['interfaces'].append({'name':'eno3', 'operstate':'UP', 'speed_mbps':10000,
                                'ipv4':[{'address':'10.10.9.2','prefixlen':24}]})
        with self.assertRaisesRegex(P.PreflightError, 'equally fast'):
            P.select_experiment_path(a, b, 10000)
        picked = P.select_experiment_path(a, b, 10000, '10.10.1.0/24')
        self.assertEqual(picked['subnet'], '10.10.1.0/24')


class EvidenceTests(unittest.TestCase):
    def test_ping_success(self):
        text = '4 packets transmitted, 4 received, 0% packet loss\nrtt min/avg/max/mdev = 0.054/0.092/0.176/0.048 ms'
        self.assertEqual(P.parse_ping(text)['rtt_avg_ms'], 0.092)

    def test_ping_loss_rejected(self):
        with self.assertRaises(P.PreflightError):
            P.parse_ping('4 packets transmitted, 3 received, 25% packet loss')

    def test_iperf_summary(self):
        info = {'end': {'sum_sent': {'bits_per_second': 9419000000, 'retransmits': 48},
                        'sum_received': {'bits_per_second': 9410000000, 'bytes': 14100000000}}}
        result = P.iperf_summary(info, 'client-to-dut')
        self.assertEqual(result['receiver_gbps'], 9.41)
        self.assertEqual(result['retransmissions'], 48)

    def test_iperf_error_rejected(self):
        with self.assertRaises(P.PreflightError):
            P.iperf_summary({'error': 'connection refused'}, 'dut-to-client')

    def test_missing_receiver_metric_rejected(self):
        with self.assertRaises(P.PreflightError):
            P.iperf_summary({'end': {'sum_sent': {'bits_per_second': 4e9}}}, 'dut-to-client')

    def test_route_validation(self):
        with mock.patch.object(P, 'ssh_run', return_value='[{"dev":"eno2","prefsrc":"10.10.1.1"}]'):
            data = P.verify_peer_route({}, 'dut', {'interface':'eno2','ip':'10.10.1.1'}, '10.10.1.2')
        self.assertEqual(data['dev'], 'eno2')

    def test_route_via_management_rejected(self):
        with mock.patch.object(P, 'ssh_run', return_value='[{"dev":"eno1","gateway":"130.127.132.1"}]'):
            with self.assertRaises(P.PreflightError):
                P.verify_peer_route({}, 'dut', {'interface':'eno2','ip':'10.10.1.1'}, '10.10.1.2')

    def test_execution_fails_closed_on_ping_loss(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = {'schema':P.SCHEMA, 'nodes': {'dut':{'ssh':'u@dut'}, 'client':{'ssh':'u@client'}},
                   'network':{'min_link_mbps':10000}, 'smoke':{'ping_packets':4, 'iperf3':{}}}
            with mock.patch.object(P, 'fetch_inventory', side_effect=[inventory(),inventory('client','10.10.1.2')]), \
                 mock.patch.object(P, 'ssh_run', side_effect=['[{"dev":"eno2"}]','[{"dev":"eno2"}]',
                                                           '4 packets transmitted, 3 received, 25% packet loss']), \
                 mock.patch.object(P, 'run_iperf_direction') as run:
                report = P.execute(cfg, pathlib.Path(d))
            self.assertEqual(report['status'], 'FAIL')
            run.assert_not_called()
            self.assertTrue((pathlib.Path(d)/'report.json').exists())

    def test_execution_success_with_iperf_mock(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = {'schema':P.SCHEMA, 'nodes': {'dut':{'ssh':'u@dut'}, 'client':{'ssh':'u@client'}},
                   'network':{'min_link_mbps':10000}, 'smoke':{'ping_packets':4, 'iperf3':{}}}
            ping = '4 packets transmitted, 4 received, 0% packet loss\nrtt min/avg/max/mdev = 0.01/0.02/0.03/0.01 ms'
            sample = {'receiver_gbps':9.41, 'direction':'mock'}
            with mock.patch.object(P, 'fetch_inventory', side_effect=[inventory(),inventory('client','10.10.1.2')]), \
                 mock.patch.object(P, 'ssh_run', side_effect=['[{"dev":"eno2"}]','[{"dev":"eno2"}]', ping]), \
                 mock.patch.object(P, 'run_iperf_direction', return_value=sample) as run:
                report = P.execute(cfg, pathlib.Path(d))
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual(run.call_count, 2)
            self.assertTrue((pathlib.Path(d)/'path.json').exists())


if __name__ == '__main__':
    unittest.main()
