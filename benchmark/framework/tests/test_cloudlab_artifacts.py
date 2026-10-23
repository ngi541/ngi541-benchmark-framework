import json
from pathlib import Path
import tempfile
import unittest

from framework import cloudlab_artifacts as mod

class PackagingTests(unittest.TestCase):
    def test_repeatable_two_duts(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            nodes=[]
            for nid, role, profile in [('node0','server','nginx-ngi541'),('node1','client','http-loadgen')]:
                folder=r/nid; folder.mkdir()
                (folder/'bootstrap.sh').write_text('#!/bin/sh\nexit 0\n')
                (folder/'build.lock.json').write_text(json.dumps({'schema_version':1,'stack_profile':profile}))
                nodes.append({'node_id':nid,'communication_role':role,'stack_profile':profile,'files':{
                    'bootstrap.sh':f'{nid}/bootstrap.sh','build.lock.json':f'{nid}/build.lock.json'}})
            p=r/'plan.json';p.write_text(json.dumps({'schema_version':1,'revision':'r1','nodes':nodes}))
            first=mod.package(p,r/'out1')
            second=mod.package(p,r/'out2')
            self.assertEqual(first,second)
            self.assertEqual(len(first['nodes']),2)
    def test_path_traversal_denied(self):
        self.assertFalse(mod.valid_name('../bad'))
        self.assertFalse(mod.valid_name('/absolute'))

if __name__=='__main__':unittest.main()
