"""Portable M2.1.2b negative gates; fixtures explicitly not an actual h2load run."""
import copy, hashlib, json, tempfile, unittest
from pathlib import Path
from framework.abc_m2_main_validity import evaluate, REVISION, read_corpus
from framework.abc_m2_payload import extract_h2load_evidence
from framework.io_utils import FrameworkError


class MainValidityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.data=b'ABC-instrumented-checksum-fixture'*100
        (self.root/'s-1.bin').write_bytes(self.data)
        self.obj_sha=hashlib.sha256(self.data).hexdigest()
        self.corpus=json.dumps({'kind':'abc-m2-corpus-manifest-v1','objects':[
            {'object_id':'obj-1','sha256':self.obj_sha,'size_bytes':len(self.data)}]},sort_keys=True).encode()
        self.corpus_sha=hashlib.sha256(self.corpus).hexdigest()
        self.client_hash='a'*64
        self.ids=dict(run_id='r',attempt_id='a',window_id='w')
        self.phase={'revision':REVISION,'kind':'main-phase-boundary-evidence',**self.ids,
                    'arm':'B','client_sha256':self.client_hash,'boot_id':'boot-client',
                    'source':'external-wrapper','warmup_traffic_included':False,
                    'main_start_monotonic_ns':1000,'main_end_monotonic_ns':2000001000}
        self.ledger={'revision':REVISION,'kind':'stream-completion-ledger',**self.ids,
                     'arm':'B','client_sha256':self.client_hash,'boot_id':'boot-client',
                     'streams':[{'stream_id':'s-1','object_id':'obj-1','status_code':200,
                       'complete':True,'integrity_checked':True,'http_version':'3',
                       'started_monotonic_ns':1100,'completed_monotonic_ns':1900,
                       'response_file':'s-1.bin','received_bytes':len(self.data),
                       'sha256':self.obj_sha}]}
        raw=json.dumps({'measurements':{'requests':{'started':1,'done':1,'succeeded':1,
                'failed':0,'errored':0,'timeout':0},
                'status_codes':{'2xx':1,'3xx':0,'4xx':0,'5xx':0},
                'traffic':{'data':len(self.data),'total':len(self.data)+40}}}).encode()
        self.h2=extract_h2load_evidence(source=raw,arm='B',**self.ids,
                                        expected_client_sha256=self.client_hash,
                                        actual_client_sha256=self.client_hash)
    def ev(self,**kwargs):
        return evaluate(corpus_source=self.corpus,expected_corpus_sha256=self.corpus_sha,
                        ledger=self.ledger,phase=self.phase,h2load=self.h2,
                        response_dir=self.root,**kwargs)
    def test_a_demo_verified_not_qualified(self):
        r=self.ev()
        self.assertEqual(r['integrity_verified_file_bytes'],len(self.data))
        self.assertFalse(r['qualified_primary_result'])
        self.assertEqual(r['valid_application_payload_bytes']['state'],'unavailable')
        self.assertEqual(r['application_goodput_mbps']['state'],'unavailable')
    def test_b_reject_corrupt_body(self):
        (self.root/'s-1.bin').write_bytes(self.data[:-1]+b'0')
        with self.assertRaises(FrameworkError):self.ev()
    def test_c_reject_missing_corpus_pin(self):
        with self.assertRaises(FrameworkError):evaluate(corpus_source=self.corpus,
            expected_corpus_sha256='f'*64,ledger=self.ledger,phase=self.phase,
            h2load=self.h2,response_dir=self.root)
    def test_d_reject_bad_payload_digest(self):
        self.ledger['streams'][0]['sha256']='0'*64
        with self.assertRaises(FrameworkError):self.ev()
    def test_e_reject_mismatch_h2load_bytes(self):
        self.h2['main_phase_data_bytes_reported']+=1
        with self.assertRaises(FrameworkError):self.ev()
    def test_f_reject_failed_requests(self):
        self.h2['request_counters']['failed']=1
        with self.assertRaises(FrameworkError):self.ev()
    def test_g_reject_inflight(self):
        self.h2['request_counters']['started']=2
        with self.assertRaises(FrameworkError):self.ev()
    def test_h_reject_http_error(self):
        self.ledger['streams'][0]['status_code']=404
        with self.assertRaises(FrameworkError):self.ev()
    def test_i_reject_bad_arm_proto(self):
        self.ledger['streams'][0]['http_version']='2'
        with self.assertRaises(FrameworkError):self.ev()
    def test_j_reject_nonmain_start(self):
        self.ledger['streams'][0]['started_monotonic_ns']=999
        with self.assertRaises(FrameworkError):self.ev()
    def test_k_reject_nonmain_end(self):
        self.ledger['streams'][0]['completed_monotonic_ns']=2000001001
        with self.assertRaises(FrameworkError):self.ev()
    def test_l_reject_mismatched_boot(self):
        self.ledger['boot_id']='other'
        with self.assertRaises(FrameworkError):self.ev()
    def test_m_reject_mismatched_attempt(self):
        self.ledger['attempt_id']='other'
        with self.assertRaises(FrameworkError):self.ev()
    def test_n_reject_unpinned_client(self):
        self.h2['client_identity_state']='unverified'
        with self.assertRaises(FrameworkError):self.ev()
    def test_o_reject_symlink(self):
        (self.root/'s-1.bin').unlink()
        (self.root/'original.bin').write_bytes(self.data)
        (self.root/'s-1.bin').symlink_to(self.root/'original.bin')
        with self.assertRaises(FrameworkError):self.ev()
    def test_p_reject_relative_traversal(self):
        self.ledger['streams'][0]['response_file']='../s-1.bin'
        with self.assertRaises(FrameworkError):self.ev()
    def test_q_reject_zero_main_duration(self):
        self.phase['main_end_monotonic_ns']=1000
        with self.assertRaises(FrameworkError):self.ev()
    def test_r_reject_warmup_included(self):
        self.phase['warmup_traffic_included']=True
        with self.assertRaises(FrameworkError):self.ev()
    def test_s_reject_duplicate_corpus(self):
        doc=json.loads(self.corpus);doc['objects'].append(copy.deepcopy(doc['objects'][0]))
        encoded=json.dumps(doc).encode()
        with self.assertRaises(FrameworkError):read_corpus(source=encoded,
            expected_sha256=hashlib.sha256(encoded).hexdigest())
    def test_t_correct_client_snapshot_enclosure(self):
        a={'host_role':'client','phase':'start',**self.ids,
            'identity':{'boot_id':'boot-client'},'capture':{'monotonic_ns_after':999}}
        b={'host_role':'client','phase':'end',**self.ids,
            'identity':{'boot_id':'boot-client'},'capture':{'monotonic_ns_before':2000001001}}
        result=self.ev(client_start_snapshot=a,client_end_snapshot=b)
        self.assertIn('enclose',result['client_counter_enclosure'])
        self.assertFalse(result['qualified_primary_result'])
    def test_u_reject_client_window_disjoint(self):
        a={'host_role':'client','phase':'start',**self.ids,
            'identity':{'boot_id':'boot-client'},'capture':{'monotonic_ns_after':1001}}
        b={'host_role':'client','phase':'end',**self.ids,
            'identity':{'boot_id':'boot-client'},'capture':{'monotonic_ns_before':2000001001}}
        with self.assertRaises(FrameworkError):self.ev(client_start_snapshot=a,client_end_snapshot=b)
    def test_v_reject_one_sided_snapshot(self):
        with self.assertRaises(ValueError):self.ev(client_start_snapshot={'x':1})
    def test_w_reject_false_controller_claim(self):
        coord={**self.ids,'quality':'within-provisional-threshold','loadgen_main_phase_bound':True}
        with self.assertRaises(FrameworkError):self.ev(controller_coordination=coord)
    def test_x_valid_h2load_flags_only(self):
        self.h2['diagnostic_flags']=['status_mismatch']
        with self.assertRaises(FrameworkError):self.ev()
    def test_y_empty_ledger(self):
        self.ledger['streams']=[]
        with self.assertRaises(FrameworkError):self.ev()
    def test_z_schema_must_be_pinned(self):
        self.phase['revision']='other'
        with self.assertRaises(FrameworkError):self.ev()

if __name__=='__main__':unittest.main()
