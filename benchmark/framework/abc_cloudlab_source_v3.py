"""Source-first CloudLab ABC deployment, reuses preflight and A/B/C functional gates.

All pinned sources fetched/compiled on assigned bare-metal nodes. Neither local
.so files nor local NGINX/loadgen executables are transferred. External network
and root package-manager prerequisites are explicit, with fail-closed receipts.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

import abc_cloudlab_preflight as pf
import abc_cloudlab_pipeline as functional

SCHEMA_VERSION=3
INPUT_PATHS={
  'server_build':'integration/versions/versions.env',
  'client_build':'benchmark/configs/r6.5.4.2-pi-http3-loadgen.json',
  'corpus':'benchmark/configs/r6.5.3d-scientific-corpus.json',
}
NGI541_URL='https://github.com/NGI541/ngi541.git'
FRAMEWORK_URL='https://github.com/NGI541/ngi541-benchmark-framework.git'
SERVER_PACKAGES=('git','cmake','build-essential','perl','curl','ca-certificates',
                 'pkg-config','patch','libpcre2-dev','zlib1g-dev','libssl-dev')
CLIENT_PACKAGES=('git','build-essential','perl','curl','ca-certificates','pkg-config',
                 'patch','libev-dev','zlib1g-dev','libc-ares-dev','libtool','autoconf',
                 'automake','xz-utils','libssl-dev')

class SourceError(RuntimeError): pass

def check_config(config):
    if not isinstance(config,dict) or set(config)!={'schema_version','experiment','nodes','inputs','connection_smoke'}:
        raise SourceError('config requires exactly schema_version, experiment, nodes, inputs, connection_smoke')
    if config['schema_version']!=3 or not isinstance(config['experiment'],str) or not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_-]{2,100}',config['experiment']):
        raise SourceError('invalid schema_version or experiment name')
    nodes=config['nodes']
    if not isinstance(nodes,dict) or set(nodes)!={'server','client'}:
        raise SourceError('nodes must contain exactly server and client')
    if any(not isinstance(nodes[x],str) or not pf.SSH_DEST_RE.fullmatch(nodes[x]) for x in nodes):
        raise SourceError('invalid SSH destination')
    if nodes['server']==nodes['client']:raise SourceError('server and client must differ')
    if config.get('inputs')!=INPUT_PATHS:raise SourceError('inputs must reference pinned source manifests; no arbitrary substitutions')
    if type(config['connection_smoke']) is not bool:raise SourceError('connection_smoke must be boolean')
    return config

def sha(path:Path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for c in iter(lambda:f.read(1<<20),b''):h.update(c)
    return h.hexdigest()

def version_env(path):
    values={}
    for line in path.read_text().splitlines():
        if not line or line.startswith('#'):continue
        if not re.fullmatch(r'[A-Z0-9_]+=[0-9A-Za-z:/.+_-]+',line):raise SourceError('unsupported versions.env line: '+line)
        k,v=line.split('=',1);values[k]=v
    for key in ('NGINX_VERSION','NGINX_SHA256','OPENSSL_VERSION','OPENSSL_SHA256','NGI541_COMMIT','NGI541_VERSION'):
        if key not in values:raise SourceError('version pin missing: '+key)
    if not re.fullmatch('[a-f0-9]{40}',values['NGI541_COMMIT']):raise SourceError('invalid NGI541 git pin')
    return values

def check_sources(repo, config):
    src={}
    for k,rel in config['inputs'].items():
        path=(repo/rel).resolve()
        if not path.is_file() or not path.is_relative_to(repo):raise SourceError('missing pinned input: '+rel)
        src[k]={'path':rel,'sha256':sha(path)}
    pins=version_env(repo/INPUT_PATHS['server_build'])
    patch=repo/f'integration/patches/nginx-{pins["NGINX_VERSION"]}/0001-ngi541-quic-crypto.patch'
    if not patch.is_file():raise SourceError('NGINX integration patch missing')
    src['nginx_patch']={'path':str(patch.relative_to(repo)),'sha256':sha(patch)}
    sys.path.insert(0,str(repo/'benchmark'))
    from framework import loadgen_runtime,scientific_corpus
    ldef=loadgen_runtime.load_definition(repo/INPUT_PATHS['client_build'])
    if ldef['runtime']['kind']!='curl-h2load-http3-ngtcp2':raise SourceError('pinned runtime lacks h2load')
    # render_build_script validates the pinned h2load patch SHA-256
    client_script=loadgen_runtime.render_build_script(ldef)
    cdef=scientific_corpus.load_definition(repo/INPUT_PATHS['corpus'])
    src['scientific_corpus_definition_sha256']=hashlib.sha256(json.dumps(cdef,sort_keys=True).encode()).hexdigest()
    commit=subprocess.run(['git','rev-parse','HEAD'],cwd=repo,check=True,capture_output=True,text=True).stdout.strip()
    if not re.fullmatch('[0-9a-f]{40}',commit):raise SourceError('invalid Git HEAD')
    # The build scripts and patches must match the immutable public checkout.
    if subprocess.run(['git','diff','--quiet','HEAD','--','scripts/abc-linux-build.sh','integration/versions/versions.env',str(patch.relative_to(repo)),INPUT_PATHS['client_build'],INPUT_PATHS['corpus'],'integration/patches/nghttp2-1.69.0/0001-h2load-main-phase-stream-accounting.patch'],cwd=repo).returncode:
        raise SourceError('build recipes/pins modified since Git HEAD; commit/push first')
    if subprocess.run(['git','ls-files','--error-unmatch','scripts/abc-linux-build.sh'],cwd=repo,capture_output=True).returncode:
        raise SourceError('server build recipe not tracked in Git')
    return pins,ldef,client_script,src,commit

def private_config(config,key):
    key=Path(key).expanduser().resolve()
    if not key.is_file() or key.suffix=='.pub':raise SourceError('invalid private SSH key path')
    return {'schema':pf.SCHEMA,
      'nodes':{'dut':{'ssh':config['nodes']['server']},'client':{'ssh':config['nodes']['client']}},
      'ssh':{'identity_file':str(key),'connect_timeout_s':10},
      'network':{'min_link_mbps':1000,'experiment_cidr':None},
      'smoke':{'ping_packets':4,'iperf3':{'port':52103,'parallel_streams':4,
                        'duration_s':12,'omit_s':3,'minimum_goodput_gbps':0.0}}}

def q(v):return shlex.quote(str(v))

def remote(config,role,script,timeout=2700):
    return pf.ssh_run(config,role,'bash -s',input_text=script,timeout_s=timeout)

def apt_install(packages):
    # Packages are pinned by OS image provenance but apt metadata is not frozen;
    # software package versions are recorded rather than claiming a hermetic build.
    return 'sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update -qq\n' + \
           'sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq '+ ' '.join(packages)+'\n'

def server_script(root,pins,commit):
    # Do not interpolate user-controlled shell strings; hashes, versions and Git SHA validated.
    return f'''set -euo pipefail
ROOT={q(root)}
mkdir -p "$ROOT"/bin "$ROOT"/lib "$ROOT"/source
exec > >(tee -a "$ROOT/server-build.log") 2>&1
printf 'source-build server start: %s\n' "$(date -u +%FT%TZ)"
{apt_install(SERVER_PACKAGES)}
git clone -q {q(FRAMEWORK_URL)} "$ROOT/source/framework"
git -C "$ROOT/source/framework" checkout -q --detach {q(commit)}
test "$(git -C "$ROOT/source/framework" rev-parse HEAD)" = {q(commit)}
git clone -q {q(NGI541_URL)} "$ROOT/source/ngi541"
git -C "$ROOT/source/ngi541" checkout -q --detach {q(pins['NGI541_COMMIT'])}
test "$(git -C "$ROOT/source/ngi541" rev-parse HEAD)" = {q(pins['NGI541_COMMIT'])}
cmake -S "$ROOT/source/ngi541" -B "$ROOT/ngi541-build" \
  -DCMAKE_BUILD_TYPE=Release -DNGI541_BUILD_ENGINE=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="$ROOT/ngi541-install"
cmake --build "$ROOT/ngi541-build" -j4
cmake --install "$ROOT/ngi541-build"
NGI541_PREFIX="$ROOT/ngi541-install"
test -f "$NGI541_PREFIX/include/ngi541/engine.h"
test -f "$NGI541_PREFIX/lib/libngi541_engine.so"
(cd "$ROOT/source/framework" && NGI541_PREFIX="$NGI541_PREFIX" ABC_BUILD_JOBS=4 \
  bash scripts/abc-linux-build.sh --build)
ln -s "$ROOT/source/framework/build/abc-linux/stock/sbin/nginx" "$ROOT/bin/stock-nginx"
ln -s "$ROOT/source/framework/build/abc-linux/ngi541-direct/sbin/nginx" "$ROOT/bin/candidate-nginx"
ln -s "$NGI541_PREFIX/lib/libngi541_engine.so" "$ROOT/lib/libngi541_engine.so.0.1"
ldd "$ROOT/bin/stock-nginx" | tee "$ROOT/stock-ldd.txt"
ldd "$ROOT/bin/candidate-nginx" | tee "$ROOT/candidate-ldd.txt"
! grep -q 'not found' "$ROOT/stock-ldd.txt"
! grep -q 'not found' "$ROOT/candidate-ldd.txt"
! grep -q 'libngi541_engine.so' "$ROOT/stock-ldd.txt"
grep -q 'libngi541_engine.so' "$ROOT/candidate-ldd.txt"
sha256sum "$ROOT/bin/stock-nginx" "$ROOT/bin/candidate-nginx" "$ROOT/lib/libngi541_engine.so.0.1"
echo 'SOURCE_BUILD_SERVER_PASS'
'''

def client_script_for_remote(root,build_script):
    # Rendered pinned client builder installs under $HOME/.local/ngi541/loadgen/http3/hash;
    # symlinks only, not binary uploads. Uses per-host source download SHA checks.
    link = '''
mkdir -p "$RUN_ROOT/client"
for comp in curl openssl ngtcp2 nghttp3 nghttp2; do
  test -d "$PREFIX/$comp"
  ln -s "$PREFIX/$comp" "$RUN_ROOT/client/$comp"
done
test -x "$RUN_ROOT/client/curl/bin/curl"
test -x "$RUN_ROOT/client/nghttp2/bin/h2load"
ldd "$RUN_ROOT/client/curl/bin/curl" | tee "$RUN_ROOT/curl-ldd.txt"
ldd "$RUN_ROOT/client/nghttp2/bin/h2load" | tee "$RUN_ROOT/h2load-ldd.txt"
! grep -q 'not found' "$RUN_ROOT/curl-ldd.txt"
! grep -q 'not found' "$RUN_ROOT/h2load-ldd.txt"
! grep -qi ngi541 "$RUN_ROOT/curl-ldd.txt"
! grep -qi ngi541 "$RUN_ROOT/h2load-ldd.txt"
sha256sum "$RUN_ROOT/client/curl/bin/curl" "$RUN_ROOT/client/nghttp2/bin/h2load"
echo SOURCE_BUILD_CLIENT_PASS
'''
    # The source builder emits last line 'runtime-ready: PREFIX' only when freshly built;
    # derive PREFIX from builder definition rather than terminal output.
    match=re.search(r'^PREFIX=(.+)$',build_script,re.MULTILINE)
    if not match:raise SourceError('pinned loadgen script PREFIX not found')
    prefix=match.group(1)
    return f'''set -euo pipefail
RUN_ROOT={q(root)}
mkdir -p "$RUN_ROOT"
exec > >(tee -a "$RUN_ROOT/client-build.log") 2>&1
{apt_install(CLIENT_PACKAGES)}
bash -s <<'PINNED_CLIENT_BUILD'
{build_script}
PINNED_CLIENT_BUILD
PREFIX={prefix}
{link}'''

def attest(config,roots,commit,pins):
    body='''
from pathlib import Path
import hashlib,subprocess
r=Path(P['root']); files=P['files']; hashes={}
for key,rel in files.items():
 f=r/rel
 if not f.is_file():raise RuntimeError('built artifact missing: '+str(f))
 hashes[key]=hashlib.sha256(f.read_bytes()).hexdigest()
for s in P['bins']:
 cp=subprocess.run(['ldd',str(r/s)],capture_output=True,text=True)
 if cp.returncode or 'not found' in cp.stdout+cp.stderr:
  raise RuntimeError('unresolved ELF dependency: '+str(r/s))
print(json.dumps({'binary_sha256':hashes,'build_method':'from-pinned-source',
 'source_git_commit':P.get('commit'), 'ngi541_git_commit':P.get('ngi541_commit')}))
'''
    data={}
    roles={'dut':{'files':{'stock_nginx':'bin/stock-nginx','candidate_nginx':'bin/candidate-nginx','ngi541_engine':'lib/libngi541_engine.so.0.1'},
                  'bins':['bin/stock-nginx','bin/candidate-nginx']},
           'client':{'files':{'curl':'client/curl/bin/curl','h2load':'client/nghttp2/bin/h2load'},
                     'bins':['client/curl/bin/curl','client/nghttp2/bin/h2load']}}
    for role in roles:
        payload=dict(roles[role],root=roots[role],commit=commit,ngi541_commit=pins['NGI541_COMMIT'])
        data[role]=functional.remote_python(config,role,body,payload,timeout_s=60)
    return data

def run(config_path,ssh_key,output,repo):
    repo=Path(repo).resolve()
    obj=check_config(json.loads(Path(config_path).read_text()))
    pins,ldef,build_client,source_receipts,commit=check_sources(repo,obj)
    priv=private_config(obj,ssh_key)
    out=Path(output).expanduser().resolve()
    out.mkdir(parents=True,exist_ok=False)
    pf.save_json(out/'config.json',obj)
    pf.save_json(out/'source-inputs.json',source_receipts)
    report={'status':'FAIL','scope':'functional-only; not publication-qualified','steps':{},'arms':{}}
    roots={}
    try:
        print('===== 1. SSH / NETWORK QUALIFICATION =====',flush=True)
        result=pf.execute(priv,out/'preflight',skip_iperf=not obj['connection_smoke'])
        if result['status'] != ('PASS' if obj['connection_smoke'] else 'CONNECTIVITY_ONLY_PASS'):
            raise SourceError('preflight failed: '+str(result.get('error')))
        report['steps']['preflight']='PASS'
        run_id=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+os.urandom(5).hex()
        for role in ('dut','client'):roots[role]=functional.remote_root(priv,role,run_id)
        pf.save_json(out/'remote-roots.json',roots)
        print('===== 2. SOURCE BUILD: SERVER =====',flush=True)
        try:
            remote(priv,'dut',server_script(roots['dut'],pins,commit))
        except Exception as exc:
            raise SourceError('server source build failed; remote log: '+roots['dut']+'/server-build.log; '+str(exc)) from exc
        report['steps']['server_source_build']='PASS'
        print('===== 3. SOURCE BUILD: CLIENT =====',flush=True)
        try:
            remote(priv,'client',client_script_for_remote(roots['client'],build_client))
        except Exception as exc:
            raise SourceError('client source build failed; remote log: '+roots['client']+'/client-build.log; '+str(exc)) from exc
        report['steps']['client_source_build']='PASS'
        pf.save_json(out/'built-binaries.json',attest(priv,roots,commit,pins))
        report['steps']['remote_identity']='PASS'
        path=result['path']; ip=path['dut']['ip']; port=18443
        print('===== 4. CORPUS + TLS =====',flush=True)
        prepared=functional.remote_prepare_dut(priv,roots['dut'],ip,port)
        functional.remote_write_ca(priv,roots['client'],prepared['ca_pem'])
        report['functional_smoke_corpus_sha256']=prepared['expected_sha256']
        report['functional_smoke_corpus_bytes']=prepared['payload_bytes']
        print('===== 5. A/B/C FUNCTIONAL VALIDATION =====',flush=True)
        for arm in 'ABC':
            report['arms'][arm]=functional.run_arm(priv,roots,ip,port,arm,prepared['expected_sha256'])
            print(f'PASS {arm}: HTTP/{report["arms"][arm]["http_version"]}',flush=True)
        report['status']='PASS_FUNCTIONAL_NOT_SCIENTIFIC'
        report['scientific_measurement']={'status':'unavailable','reason':'No genuine h2load MAIN ledger/CPU alignment/measurement overhead'}
    except Exception as exc:
        report['error']=str(exc)
        print('FAIL:',exc,file=sys.stderr,flush=True)
    finally:
        # Save bounded build-log tails even when building fails before A/B/C.
        for role,name in (('dut','server-build.log'),('client','client-build.log')):
            if role not in roots:continue
            try:
                logs=pf.ssh_run(priv,role,"tail -n 120 "+q(roots[role]+'/'+name)+" 2>/dev/null || true",timeout_s=20)
                (out/(name+'.tail.txt')).write_text(logs[-48000:])
            except Exception:pass
        report['remote_roots']=roots
        report['finished_utc']=dt.datetime.now(dt.timezone.utc).isoformat()
        pf.save_json(out/'report.json',report)
        if roots:
            functional.collect_remote_logs(priv,roots,out)
        print('EVIDENCE:',out,flush=True)
    return 0 if report['status']=='PASS_FUNCTIONAL_NOT_SCIENTIFIC' else 1

def main(argv=None):
    parser=argparse.ArgumentParser(description='CloudLab source build + SSH preflight + ABC functional runner')
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--ssh-key',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=None)
    parser.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[2])
    args=parser.parse_args(argv)
    try:
        if args.output is None:
            suffix=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+os.urandom(3).hex()
            args.output=Path.home()/'Downloads'/('ngi541-cloudlab-abc-'+suffix)
        return run(args.config,args.ssh_key,args.output,args.repo)
    except (SourceError,OSError,subprocess.SubprocessError,ValueError) as exc:
        print('ERROR:',exc,file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
