"""Shell contract tests use test doubles; they do not certify Snapcraft packaging."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ('aegis-gateway', 'aegis-radius', 'aegis-portal', 'aegis-session',
            'aegis-policy', 'aegis-admin-api', 'aegis-telemetry', 'aegis-ai-lite')


class SnapRecipeTests(unittest.TestCase):
    def test_all_recipe_overrides_use_repository_compiler_helper(self):
        version = re.search(r'^go (\d+\.\d+)\.\d+$', (ROOT/'go.mod').read_text(), re.M)[1]
        for service in SERVICES:
            with self.subTest(service=service):
                recipe = (ROOT/'snaps'/service/'snapcraft.yaml').read_text(encoding='utf-8')
                self.assertIn('    plugin: nil\n', recipe)
                self.assertIn('      - go/'+version+'/stable\n', recipe)
                self.assertIn('      cd "$CRAFT_PART_SRC"\n', recipe)
                self.assertIn('      bash scripts/build-snap-service.sh '+service+' "$CRAFT_PART_INSTALL"\n', recipe)


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux Bash build contract')
class SnapBuildContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aegis snap build ')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.fakebin = self.base/'fakebin'; self.fakebin.mkdir()
        self.log = self.base/'calls.jsonl'
        self.environment = {**os.environ, 'PATH':str(self.fakebin)+os.pathsep+os.environ['PATH'],
                            'TEST_CALLS':str(self.log), 'CRAFT_ARCH_BUILD_FOR':'arm64'}
        self.install = self.base/'install'; self.install.mkdir()

    def stub(self, name, body):
        path = self.fakebin/name
        path.write_text('#!/usr/bin/env python3\n'+body)
        path.chmod(0o700)

    def run_script(self, path, *arguments):
        return subprocess.run(['bash', str(ROOT/path), *map(str, arguments)], cwd=self.base,
            env=self.environment, capture_output=True, text=True, timeout=30)

    def fake_go(self, no_binary=False, wrong_version=False):
        self.stub('go', '''import json,os,pathlib,sys
with open(os.environ['TEST_CALLS'],'a') as f:
 f.write(json.dumps({'cwd':os.getcwd(),'args':sys.argv[1:], 'env':{k:os.environ.get(k) for k in ('GOOS','GOARCH','CGO_ENABLED','GOTOOLCHAIN','GOWORK')}})+'\\n')
if sys.argv[1:]==['env','GOVERSION']: print('WRONG' if WRONG_VERSION else os.environ['GOTOOLCHAIN'])
elif sys.argv[1:]==['env','GOARCH']: print('amd64')
elif sys.argv[1]=='build' and not NO_BINARY: pathlib.Path(sys.argv[sys.argv.index('-o')+1]).write_bytes(b'fake compiler output')
'''.replace('WRONG_VERSION', repr(wrong_version)).replace('NO_BINARY',repr(no_binary)))

    def fake_snapcraft(self, fail=None, empty=False):
        self.stub('snapcraft','''import json,os,pathlib,sys
service=pathlib.Path.cwd().name
with open(os.environ['TEST_CALLS'],'a') as f: f.write(json.dumps({'service':service,'args':sys.argv[1:]})+'\\n')
if service==FAIL: sys.exit(7)
if not EMPTY: pathlib.Path(sys.argv[sys.argv.index('--output')+1]).write_bytes(service.encode())
'''.replace('FAIL',repr(fail)).replace('EMPTY',repr(empty)))

    def test_compiler_matches_go_mod_and_cross_target_without_changing_cwd(self):
        self.fake_go()
        result = self.run_script('scripts/build-snap-service.sh','aegis-radius',self.install)
        self.assertEqual(result.returncode,0,result.stderr)
        call=json.loads(self.log.read_text().splitlines()[-1])
        version=re.search(r'^go ([0-9.]+)$',(ROOT/'go.mod').read_text(),re.M)[1]
        self.assertEqual(call['env'],{'GOOS':'linux','GOARCH':'arm64','CGO_ENABLED':'0',
                         'GOTOOLCHAIN':'go'+version,'GOWORK':str(ROOT/'go.work')})
        self.assertEqual(call['cwd'],str(ROOT))
        self.assertIn('-mod=readonly',call['args'])
        self.assertEqual(call['args'][-1],'./cmd/aegis-radius')

    def test_unknown_service_unsupported_arch_and_missing_install_rejected(self):
        self.fake_go()
        self.assertNotEqual(self.run_script('scripts/build-snap-service.sh','../../unknown',self.install).returncode,0)
        self.assertNotEqual(self.run_script('scripts/build-snap-service.sh','aegis-radius',self.base/'missing').returncode,0)
        self.environment['CRAFT_ARCH_BUILD_FOR']='s390x'
        self.assertNotEqual(self.run_script('scripts/build-snap-service.sh','aegis-radius',self.install).returncode,0)

    def test_wrong_compiler_version_rejected_before_build(self):
        self.fake_go(wrong_version=True)
        self.assertNotEqual(self.run_script('scripts/build-snap-service.sh','aegis-radius',self.install).returncode,0)
        self.assertFalse((self.install/'bin/aegis-radius').exists())

    def test_missing_compiler_output_rejected(self):
        self.fake_go(no_binary=True)
        self.assertNotEqual(self.run_script('scripts/build-snap-service.sh','aegis-radius',self.install).returncode,0)

    def test_builder_visits_all_eight_projects_and_preserves_prior_outputs(self):
        self.fake_snapcraft()
        output=self.base/'snap artifacts'
        result=self.run_script('snaps/build-all.sh',output)
        self.assertEqual(result.returncode,0,result.stderr)
        calls=[json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([call['service'] for call in calls],list(SERVICES))
        self.assertTrue(all(call['args'][0]=='pack' for call in calls))
        self.assertEqual(len((output/'SHA256SUMS').read_text().splitlines()),8)
        self.assertNotEqual(self.run_script('snaps/build-all.sh',output).returncode,0)
        self.assertEqual(len(self.log.read_text().splitlines()),8)

    def test_builder_stops_on_failure_and_keeps_partial_evidence(self):
        self.fake_snapcraft(fail='aegis-radius')
        output=self.base/'failed build'
        self.assertEqual(self.run_script('snaps/build-all.sh',output).returncode,7)
        self.assertTrue((output/'aegis-gateway.snap').exists())
        self.assertFalse((output/'SHA256SUMS').exists())
        self.assertEqual(len(self.log.read_text().splitlines()),2)

    def test_builder_rejects_success_without_artifact(self):
        self.fake_snapcraft(empty=True)
        result=self.run_script('snaps/build-all.sh',self.base/'empty artifacts')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(len(self.log.read_text().splitlines()),1)


if __name__ == '__main__':
    unittest.main()
