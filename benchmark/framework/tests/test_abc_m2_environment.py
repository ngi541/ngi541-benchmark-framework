"""M2.1.2a inventory contract and scientific fail-closed gates."""
import copy
import hashlib
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock
from framework import abc_m2_environment as m
from framework.abc_m2_environment_cli import save_new


class FakeReader:
    def __init__(self, root):
        self.root=pathlib.Path(root)
        self.commands={}
    def read(self,p):
        f=self.root/p.lstrip('/')
        return f.read_text().strip() if f.exists() else None
    def at(self,p):return self.root/p.lstrip('/')
    def cmd(self,key,args):
        content={
          'lscpu': 'Socket(s): 1\nCore(s) per socket: 4\nThread(s) per core: 2\nNUMA node(s): 1\n',
          'ethtool_info':'driver: ixgbe\nfirmware-version: 0x80001001\n',
          'ethtool_features':'tcp-segmentation-offload: on\ntx-udp-segmentation: off\ngeneric-receive-offload: off\n',
          'ethtool_channels':'Current hardware settings:\nCombined: 4',
          'ethtool_speed':'Speed: 25000Mb/s',
          'ethtool_rss':'RSS indirection table for eth0',
          'ip_link':'eth0: mtu 1500',
          'numactl_show':'policy: default',
          'ldd_nginx':'libz.so.1 => /lib/libz.so.1',
          'ldd_client':'libssl.so.3 => /usr/lib/libssl.so.3',
          'nginx_version':'nginx version: nginx/1.31.6',
          'client_version':'h2load nghttp2/1.69.0',
        }.get(key)
        self.commands[key]={'argv':args,'state':'measured' if content else 'unavailable',
                            'reason':None if content else 'fixture has no command','stdout':content}
        return content


def make_tree(root):
    fs={
     '/proc/cpuinfo':'processor : 0\nvendor_id : GenuineIntel\ncpu family : 6\nmodel : 106\nmodel name : Fake Intel\nstepping : 6\nmicrocode : 0xffffffff\nflags : aes vaes avx2 avx512f\n\n',
     '/proc/meminfo':'MemTotal: 32768000 kB\n',
     '/proc/sys/kernel/random/boot_id':'boot-fixed',
     '/sys/fs/cgroup/cpuset.cpus.effective':'0-3',
     '/sys/devices/system/cpu/online':'0-7',
     '/sys/devices/system/node/online':'0',
     '/sys/devices/system/cpu/cpufreq/policy0/scaling_governor':'performance',
     '/sys/devices/system/cpu/cpufreq/policy0/affected_cpus':'0-3',
     '/sys/devices/system/cpu/cpufreq/policy0/scaling_driver':'intel_pstate',
     '/sys/devices/system/cpu/intel_pstate/no_turbo':'0',
     '/sys/class/net/eth0/mtu':'1500',
     '/sys/class/net/eth0/carrier':'1',
     '/sys/class/net/eth0/address':'aa:bb:cc:dd:ee:ff',
     '/sys/class/net/eth0/device/vendor':'0x8086',
     '/sys/class/net/eth0/device/device':'0x1528',
     '/sys/class/net/eth0/device/subsystem_device':'0x0001',
     '/sys/class/net/eth0/device/current_link_speed':'8.0 GT/s PCIe',
     '/sys/class/net/eth0/device/current_link_width':'8',
     '/etc/os-release':'ID=test-os\nPRETTY_NAME="Test OS"\n',
     '/proc/interrupts':'0: 1 2 3 4 timer',
     '/proc/sys/net/core/rmem_max':'2097152',
    }
    for rel,data in fs.items():
        dest=pathlib.Path(root)/rel.lstrip('/')
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(data)


class TestM2Environment(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        make_tree(self.tmp.name)
        self.assets={'profile_id':'LCLS-pilot','cache_policy':'warm-cache-declared',
                     'object_identifiers':['object-001'],'quic_gso':False,
                     'nginx_source_revision':'nginx-1.31.6',
                     'nginx_configure_flags':'--with-http_v3_module',
                     'nginx_worker_affinity':'0-3',
                     'openssl_revision':'3.5.9',
                     'ngi541_revision':'0.1.1',
                     'dispatch_isa_path':'pending-M2.2-verification',
                     'tls_provider':'OpenSSL 3.6.4',
                     'h2_h3_capability':{'h2':True,'h3':True}}
        for key in ['nginx_binary','nginx_patch','nginx_config','openssl_library',
                    'ngi541_library','openssl_source_archive','corpus_manifest','stream_schedule','client_binary']:
            path=pathlib.Path(self.tmp.name)/(key+'.bin')
            path.write_bytes(('fixture:'+key).encode())
            self.assets[key]=str(path)

    def capture(self,role='dut',assets=None,arm='B'):
        with mock.patch.object(m.platform,'system',return_value='Linux'), mock.patch.object(m.os,'sched_getaffinity',create=True,return_value={0,1,2,3}):
            return m.collect(host_role=role,arm=arm,interface='eth0',run_id='run-a',attempt_id='attempt-1',
                             assets=assets if assets is not None else self.assets,
                             reader=FakeReader(self.tmp.name))

    def test_01_eleven_groups(self):
        obj=self.capture()
        self.assertEqual(tuple(obj['categories']),m.GROUPS)
    def test_02_all_fields_present(self):
        obj=self.capture()
        for g in m.GROUPS:self.assertEqual(tuple(obj['categories'][g]),m.FIELD_SPEC[g])
    def test_03_client_role(self):
        obj=self.capture('client');self.assertEqual(obj['categories']['nginx']['binary_sha256']['state'],'not_applicable')
    def test_04_client_no_engine(self):
        self.assertIs(self.capture('client')['categories']['client']['client_ngi541_dependency']['value'],False)
    def test_05_client_actual_ngi541_dynamic_link(self):
        class Altered(FakeReader):
            def cmd(self,key,args):
                if key=='ldd_client':return 'libngi541_engine.so.0.1 => /opt/libngi541_engine.so.0.1'
                return super().cmd(key,args)
        with mock.patch.object(m.platform,'system',return_value='Linux'), mock.patch.object(m.os,'sched_getaffinity',create=True,return_value={0}):
            obj=m.collect(host_role='client',arm='B',interface='eth0',run_id='r',attempt_id='a',assets=self.assets,reader=Altered(self.tmp.name))
        self.assertIs(obj['categories']['client']['client_ngi541_dependency']['value'],True)
    def test_06_no_false_path_ngi541(self):
        self.assertNotIn('libngi541_engine.so','/work/.local/ngi541/loadgen/http3/libssl.so.3')
    def test_07_cannot_fake_qualified(self):
        obj=self.capture();obj['qualified_primary_result']=True
        with self.assertRaises(ValueError):m.validate(obj)
    def test_08_measured_requires_value(self):
        with self.assertRaises(ValueError):m.field(None,source='x',state='measured')
    def test_09_unavailable_requires_reason(self):
        with self.assertRaises(ValueError):m.field(source='x',state='unavailable')
    def test_10_measured_zero_and_false_valid(self):
        self.assertEqual(m.field(0,source='x')['state'],'measured')
        self.assertEqual(m.field(False,source='x')['state'],'measured')
    def test_11_no_status_override(self):
        obj=self.capture();obj['categories']['cpu']['model']['state']='pass'
        with self.assertRaises(ValueError):m.validate(obj)
    def test_12_role_inapplicable_not_zero(self):
        obj=self.capture('dut');self.assertIsNone(obj['categories']['client']['binary_sha256']['value'])
    def test_13_required_missing_not_pass(self):
        obj=self.capture();assessment=m.completeness(obj)
        self.assertFalse(assessment['bare_metal_qualified'])
        self.assertFalse(assessment['identity_fields_complete'])
    def test_14_container_never_qualified(self):
        obj=self.capture();obj['context']['environment_class']='container'
        self.assertFalse(m.completeness(obj)['bare_metal_qualified'])
    def test_15_same_same_no_drift(self):
        obj=self.capture()
        report=m.compare(obj,copy.deepcopy(obj))
        self.assertFalse(report['changed'])
        self.assertEqual(report['status'],'unqualified')
    def test_16_cpu_model_drift(self):
        a=self.capture();b=copy.deepcopy(a)
        b['categories']['cpu']['model']['value']='different'
        report=m.compare(a,b)
        self.assertEqual(report['status'],'fail')
        self.assertIn('cpu.model',[x['field'] for x in report['changed']])
    def test_17_boot_id_gate(self):
        a=self.capture();b=copy.deepcopy(a);b['context']['boot_id']='newboot'
        self.assertEqual(m.compare(a,b)['status'],'fail')
    def test_18_no_blanket_bc_difference(self):
        a=self.capture();b=copy.deepcopy(a)
        b['arm']='C'
        b['categories']['nginx']['binary_sha256']['value']='f'*64
        report=m.compare(a,b,mode='bc-pair')
        self.assertIn('nginx.binary_sha256',[x['field'] for x in report['changed']])
        approval={'nginx.binary_sha256':{'before':a['categories']['nginx']['binary_sha256']['value'],
                                         'after':'f'*64}}
        approved=m.compare(a,b,mode='bc-pair',approved_differences=approval)
        self.assertNotIn('nginx.binary_sha256',[x['field'] for x in approved['changed']])
        self.assertEqual(approved['approved'][0]['field'],'nginx.binary_sha256')
    def test_18a_approved_hash_must_match_exact(self):
        a=self.capture();b=copy.deepcopy(a)
        b['arm']='C'
        b['categories']['nginx']['binary_sha256']['value']='f'*64
        with self.assertRaises(ValueError):m.compare(a,b,mode='bc-pair',approved_differences={
          'nginx.binary_sha256':{'before':'0'*64,'after':'f'*64}})
    def test_18b_must_not_approve_cpu_mismatch(self):
        a=self.capture();b=copy.deepcopy(a);b['arm']='C';b['categories']['cpu']['model']['value']='other'
        with self.assertRaises(ValueError):m.compare(a,b,mode='bc-pair',approved_differences={
          'cpu.model':{'before':'106','after':'other'}})
    def test_19_different_corpa_not_allowed(self):
        a=self.capture();b=copy.deepcopy(a);b['arm']='C'
        b['categories']['workload']['corpus_sha256']['value']='f'*64
        self.assertIn('workload.corpus_sha256',[x['field'] for x in m.compare(a,b,mode='bc-pair')['changed']])
    def test_20_different_host_roles_not_comparable(self):
        with self.assertRaises(ValueError):m.compare(self.capture(),self.capture('client'))
    def test_21_variant_mode_rejected(self):
        with self.assertRaises(ValueError):m.compare(self.capture(),self.capture(),mode='ignore-all')
    def test_22_path_traversal_iface_rejected(self):
        with self.assertRaises(ValueError):m.collect(host_role='dut',arm='B',interface='../dev',run_id='r',attempt_id='a',assets={},reader=FakeReader(self.tmp.name))
    def test_23_untrusted_run_id_rejected(self):
        with self.assertRaises(ValueError):m.collect(host_role='dut',arm='B',interface='eth0',run_id='a/b',attempt_id='a',assets={},reader=FakeReader(self.tmp.name))
    def test_24_explicit_hash_matches(self):
        obj=self.capture();data=pathlib.Path(self.assets['nginx_binary']).read_bytes()
        self.assertEqual(obj['categories']['nginx']['binary_sha256']['value'],hashlib.sha256(data).hexdigest())
    def test_25_missing_file_not_silently_zero(self):
        obj=self.capture(assets={})
        f=obj['categories']['nginx']['binary_sha256'];self.assertEqual(f['state'],'unavailable');self.assertIsNone(f['value'])
    def test_26_schema_group_deletion_rejected(self):
        obj=self.capture();del obj['categories']['nic']
        with self.assertRaises(ValueError):m.validate(obj)
    def test_27_duplicate_evidence_rejected(self):
        p=pathlib.Path(self.tmp.name)/'new.json';save_new(p,{'hello':1})
        with self.assertRaises(FileExistsError):save_new(p,{'hello':1})
    def test_28_list_cpu_ranges(self):
        self.assertEqual(m._list_from_range('1-3,6,10-11'),[1,2,3,6,10,11])
        self.assertIsNone(m._list_from_range('1-0'))
    def test_29_canonical_stable(self):
        self.assertEqual(m.digest(m.canonical({'z':1,'a':2})),m.digest(m.canonical({'a':2,'z':1})))
    def test_29a_stock_engine_not_applicable(self):
        obj=self.capture(arm='B')
        self.assertEqual(obj['categories']['crypto']['ngi541_binary_sha256']['state'],'not_applicable')
        self.assertEqual(obj['categories']['nginx']['patch_sha256']['state'],'not_applicable')
    def test_29b_candidate_engine_required(self):
        obj=self.capture(arm='C')
        self.assertEqual(obj['categories']['crypto']['ngi541_binary_sha256']['state'],'measured')
        self.assertEqual(obj['categories']['nginx']['patch_sha256']['state'],'measured')
    def test_29c_stock_absence_not_missing(self):
        obj=self.capture(arm='B')
        missing={item['field'] for item in m.completeness(obj)['missing_mandatory']}
        self.assertNotIn('crypto.ngi541_binary_sha256',missing)
        self.assertNotIn('nginx.patch_sha256',missing)
    def test_29d_bc_status_difference_exact_approval(self):
        a=self.capture(arm='B');b=self.capture(arm='C')
        f='crypto.ngi541_binary_sha256'
        pre=a['categories']['crypto']['ngi541_binary_sha256']
        post=b['categories']['crypto']['ngi541_binary_sha256']
        app={f:{'before':{'state':pre['state'],'value':pre['value']},
                'after':{'state':post['state'],'value':post['value']}}}
        result=m.compare(a,b,mode='bc-pair',approved_differences=app)
        self.assertIn(f,[item['field'] for item in result['approved']])
    def test_29e_bc_must_be_ordered(self):
        with self.assertRaises(ValueError):m.compare(self.capture(arm='C'),self.capture(arm='B'),mode='bc-pair')
    def test_29f_same_role_requires_same_arm(self):
        with self.assertRaises(ValueError):m.compare(self.capture(arm='B'),self.capture(arm='C'),mode='same-role')
    def test_29g_b_stock_dep_false(self):
        self.assertIs(self.capture(arm='B')['categories']['nginx']['ngi541_dynamic_dependency']['value'],False)
    def test_29h_c_candidate_dep_true_required(self):
        # Fixture has stock ldd, so candidate completeness is intentionally incomplete.
        obj=self.capture(arm='C')
        self.assertIn('nginx.ngi541_dynamic_dependency',
            {x['field'] for x in m.completeness(obj)['missing_mandatory']})
    def test_29i_client_link_dependency_blocks_qualification(self):
        obj=self.capture('client')
        obj['categories']['client']['client_ngi541_dependency']['value']=True
        self.assertIn('client.client_ngi541_dependency',
            {x['field'] for x in m.completeness(obj)['missing_mandatory']})
    def test_30_four_states(self):
        self.assertEqual(m.STATES,{'measured','unavailable','not_applicable','invalid'})

if __name__=='__main__':unittest.main()
