import json
from pathlib import Path
import tempfile
import unittest

from framework import cloudlab_artifacts as mod


class PackagingTests(unittest.TestCase):
    def make_plan(self, root, same_role=False):
        nodes = []
        for nid, role, profile in [('node0', 'server', 'nginx-ngi541'),
                                   ('node1', 'server' if same_role else 'client', 'http-loadgen')]:
            folder = root/nid
            folder.mkdir()
            (folder/'bootstrap.sh').write_text('#!/bin/sh\nexit 0\n')
            (folder/'build.lock.json').write_text(json.dumps({'schema_version':1,'stack_profile':profile}))
            nodes.append({'node_id':nid,'communication_role':role,'stack_profile':profile,
                          'files':{'bootstrap.sh':f'{nid}/bootstrap.sh',
                                   'build.lock.json':f'{nid}/build.lock.json'}})
        path = root/'plan.json'
        path.write_text(json.dumps({'schema_version':1,'revision':'r1','nodes':nodes}))
        return path

    def test_repeatable_two_duts(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            p = self.make_plan(r)
            first = mod.package(p,r/'out1')
            second = mod.package(p,r/'out2')
            self.assertEqual(first,second)
            self.assertEqual(len(first['nodes']),2)
            for record in first['nodes']:
                self.assertEqual(mod.verify_archive(r/'out1'/record['archive'])['node_id'],record['node_id'])

    def test_two_duts_same_role_no_collisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            p = self.make_plan(r, same_role=True)
            index = mod.package(p,r/'out')
            self.assertEqual(len(set(x['archive'] for x in index['nodes'])),2)

    def test_invalid_payload_does_not_publish_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = self.make_plan(root)
            lock = root/'node1/build.lock.json'
            lock.write_text(json.dumps({'schema_version':1,'stack_profile':'http-loadgen',
                                        'inputs_sha256':{'missing.patch':'0'*64}}))
            with self.assertRaises(ValueError):
                mod.package(p,root/'out')
            self.assertFalse((root/'out').exists())
            self.assertEqual(list(root.glob('.ngi541-bootstrap-stage-*')),[])

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            p = self.make_plan(r)
            out = r/'out'
            out.mkdir()
            (out/'sentinel.txt').write_text('untouched')
            with self.assertRaises(FileExistsError):
                mod.package(p,out)
            self.assertEqual((out/'sentinel.txt').read_text(),'untouched')

    def test_path_traversal_denied(self):
        self.assertFalse(mod.valid_name('../bad'))
        self.assertFalse(mod.valid_name('/absolute'))
        self.assertFalse(mod.valid_name('a\\b'))


if __name__ == '__main__':
    unittest.main()
