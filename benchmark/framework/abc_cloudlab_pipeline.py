"""Additive NGI541 SSH CloudLab deployment + ABC functional qualification.

Uses existing abc_cloudlab_preflight contract and ephemeral per-run directories.
Not a scientific performance experiment (MAIN ledger/overhead unqualified).
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any

import abc_cloudlab_preflight as pf

SCHEMA = 'ngi541-cloudlab-abc-pipeline-v1'
PINNED_HASHES = {
    'stock_nginx': '4f1d1a4a8ed0146d4c3f9b4395238eab0e90f83a235efd2878d263de8ca19b9d',
    'candidate_nginx': '43addf6a20fdea56318d1b91699a98438e62a79c26bc7ae5453cea73feef4880',
    'ngi541_engine': '8c375b7b68f76cbe305ef123e38a81221cf889c22749272ebc2b9715e8d553ed',
    'client_curl': 'd17620eebdb3b6cf8ebe96232c467c403b5a93a05a509280c17945613a9410a3',
    'client_h2load': 'dcd0dfe45c76fd6afe249bfd8d2d0f1a01437d07ed56c31f349bc26ce2d65924',
}
SERVER_NAME = 'ngi541-dut.local'
CIPHER = 'TLS_AES_128_GCM_SHA256'
VALID_ARMS = ('A', 'B', 'C')
CLIENT_COMPONENTS = ('curl', 'openssl', 'ngtcp2', 'nghttp3', 'nghttp2')

class PipelineError(RuntimeError):
    pass


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as fp:
        for block in iter(lambda: fp.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def resolve_local_path(value: str, root: pathlib.Path) -> pathlib.Path:
    p = pathlib.Path(value).expanduser()
    return p if p.is_absolute() else root / p


def ensure_hash(path: pathlib.Path, name: str, expected: dict[str, str]) -> dict:
    if not path.is_file():
        raise PipelineError(f'missing local binary {name}: {path}')
    actual = sha256(path)
    if actual != expected[name]:
        raise PipelineError(f'PINNED SHA mismatch for {name}: actual={actual}, expected={expected[name]}')
    return {'name': name, 'sha256': actual, 'size_bytes': path.stat().st_size, 'local_path': str(path)}


def load_config(path: pathlib.Path, repo: pathlib.Path) -> dict:
    config = json.loads(path.read_text())
    pf.load_config(path)  # enforce original schema and baseline constraints
    cfg = config.get('pipeline')
    if not isinstance(cfg, dict) or cfg.get('schema') != SCHEMA:
        raise PipelineError('pipeline.schema must be ngi541-cloudlab-abc-pipeline-v1')
    artifacts = cfg.get('artifacts', {})
    if not isinstance(artifacts, dict):
        raise PipelineError('pipeline.artifacts must be a JSON object')
    for name in ('stock_nginx', 'candidate_nginx', 'ngi541_engine', 'client_root'):
        if not isinstance(artifacts.get(name), str) or not artifacts[name].strip():
            raise PipelineError(f'pipeline.artifacts.{name} required')
    if not isinstance(artifacts.get('client_prefix_file'), str):
        raise PipelineError('pipeline.artifacts.client_prefix_file required')
    port = cfg.get('https_port', 18443)
    if type(port) is not int or not 1024 <= port <= 65535:
        raise PipelineError('pipeline.https_port must be 1024..65535')
    if port == config['smoke']['iperf3']['port']:
        raise PipelineError('pipeline.https_port must differ from iperf3 port')
    if cfg.get('server_name', SERVER_NAME) != SERVER_NAME:
        raise PipelineError('server_name is pinned to ngi541-dut.local for this functional smoke')
    hashes = cfg.get('pinned_sha256', PINNED_HASHES)
    if hashes != PINNED_HASHES:
        raise PipelineError('pinned_sha256 must match verified Stage 3.4 identities; no silent substitution')
    if cfg.get('deployment_mode', 'upload-prebuilt') != 'upload-prebuilt':
        raise PipelineError('only upload-prebuilt deployment mode supported')
    return config


def checked_local_artifacts(config: dict, repo: pathlib.Path) -> tuple[dict, dict]:
    a = config['pipeline']['artifacts']
    paths = {name:resolve_local_path(a[name], repo) for name in
             ('stock_nginx', 'candidate_nginx', 'ngi541_engine')}
    prefix_file = resolve_local_path(a['client_prefix_file'], repo)
    root = resolve_local_path(a['client_root'], repo)
    if not prefix_file.is_file() or not root.is_dir():
        raise PipelineError('pinned Linux client artifacts absent; see Stage 3.3')
    prefix_literal = prefix_file.read_text().strip()
    if not prefix_literal.startswith('/work/.local/ngi541/loadgen/http3/'):
        raise PipelineError('unexpected pinned client prefix; expected /work/.local/...')
    relative = pathlib.PurePosixPath(prefix_literal).relative_to('/work')
    prefix = root.joinpath(*relative.parts)
    if not prefix.is_dir() or not prefix.resolve().is_relative_to(root.resolve()):
        raise PipelineError('client prefix not contained under client_root')
    paths['client_curl'] = prefix / 'curl/bin/curl'
    paths['client_h2load'] = prefix / 'nghttp2/bin/h2load'
    receipts = {name: ensure_hash(path,name,PINNED_HASHES) for name,path in paths.items()}
    for component in CLIENT_COMPONENTS:
        if not (prefix / component / 'lib').is_dir():
            raise PipelineError(f'missing pinned client library directory: {prefix}/{component}/lib')
    return paths | {'client_prefix':prefix}, receipts


def validate_tar_name(name: str) -> None:
    p=pathlib.PurePosixPath(name)
    if p.is_absolute() or not name or '..' in p.parts:
        raise PipelineError(f'unsafe archive member name: {name}')


def add_tree(tar: tarfile.TarFile, path: pathlib.Path, arc: str) -> None:
    validate_tar_name(arc)
    if path.is_symlink():
        target = path.readlink()
        if target.is_absolute() or '..' in target.parts:
            raise PipelineError(f'unsafe client library symlink: {path} -> {target}')
        tar.add(path, arcname=arc, recursive=False)
    elif path.is_dir():
        for child in sorted(path.iterdir()):
            add_tree(tar, child, f'{arc}/{child.name}')
    elif path.is_file():
        tar.add(path, arcname=arc, recursive=False)


def create_archives(paths: dict, temp: pathlib.Path) -> dict[str,pathlib.Path]:
    output={}
    dut=temp/'dut-artifacts.tar.gz'
    with tarfile.open(dut,'w:gz') as tar:
        tar.add(paths['stock_nginx'],arcname='bin/stock-nginx',recursive=False)
        tar.add(paths['candidate_nginx'],arcname='bin/candidate-nginx',recursive=False)
        engine=paths['ngi541_engine']
        tar.add(engine,arcname='lib/libngi541_engine.so.0.1',recursive=False)
    output['dut']=dut
    client=temp/'client-artifacts.tar.gz'
    with tarfile.open(client,'w:gz') as tar:
        tar.add(paths['client_curl'],arcname='client/curl/bin/curl',recursive=False)
        tar.add(paths['client_h2load'],arcname='client/nghttp2/bin/h2load',recursive=False)
        for component in CLIENT_COMPONENTS:
            add_tree(tar, paths['client_prefix']/component/'lib', f'client/{component}/lib')
    output['client']=client
    return output


def shell_quote(value: str) -> str:
    return shlex.quote(str(value))


def remote_cmd(config: dict, role: str, command: str, timeout_s: int = 40) -> str:
    return pf.ssh_run(config, role, command, timeout_s=timeout_s)


def remote_python(config: dict, role: str, body: str, payload: dict, timeout_s: int = 40) -> Any:
    program='import json\nP=json.loads('+repr(json.dumps(payload,sort_keys=True))+')\n'+body
    raw=pf.ssh_run(config,role,'python3 -',input_text=program,timeout_s=timeout_s)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PipelineError(f'{role}: remote Python returned invalid JSON: {raw[-600:]}') from exc


def remote_root(config: dict, role: str, run_id: str) -> str:
    # Do not permit host-specific, user-supplied arbitrary remote paths.
    if not re.fullmatch(r'[0-9TZ-]+-[a-f0-9]{10}',run_id):
        raise PipelineError(f'bad run id {run_id}')
    out=remote_python(config,role,"""
from pathlib import Path
root=Path.home()/'.ngi541-cloudlab'/P['run_id']
root.parent.mkdir(mode=0o700,exist_ok=True)
root.mkdir(mode=0o700,exist_ok=False)
print(json.dumps({'root':str(root)}))
""", {'run_id':run_id})
    return out['root']


def upload_tar(config: dict, role: str, tar_path: pathlib.Path, dest: str, timeout_s: int = 300) -> None:
    cmd='tar -xzf - -C '+shell_quote(dest)
    with tar_path.open('rb') as inp:
        proc=subprocess.Popen(pf.ssh_base(config,role)+[cmd],stdin=inp,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            stdout,stderr=proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill();proc.communicate();raise PipelineError(f'{role}: artifact upload timed out')
    if proc.returncode:
        raise PipelineError(f'{role}: upload tar failed ({proc.returncode}): {stderr[-1000:].decode(errors="replace")}')


def remote_check_binaries(config: dict, roots: dict[str,str]) -> dict:
    body="""
from pathlib import Path
import hashlib,os,subprocess
r=Path(P['root'])
hashes={}
for name,rel in P['binaries'].items():
    f=r/rel
    if not f.is_file(): raise RuntimeError('missing deployed file: '+str(f))
    hashes[name]=hashlib.sha256(f.read_bytes()).hexdigest()
    if hashes[name]!=P['hashes'][name]: raise RuntimeError('remote sha mismatch: '+name)
if P['role']=='dut':
    lib=r/'lib/libngi541_engine.so.0.1'
    for symlink in ('libngi541_engine.so','libngi541_engine.so.0'):
        p=r/'lib'/symlink
        p.symlink_to(lib.name)
    target_names=['bin/stock-nginx','bin/candidate-nginx']
    env=dict(os.environ,LD_LIBRARY_PATH=str(r/'lib'))
else:
    target_names=['client/curl/bin/curl','client/nghttp2/bin/h2load']
    env=dict(os.environ,LD_LIBRARY_PATH=':'.join(str(r/'client'/c/'lib') for c in P['components']))
linkage={}
for t in target_names:
    proc=subprocess.run(['ldd',str(r/t)],env=env,capture_output=True,text=True)
    linkage[t]=proc.stdout+proc.stderr
    if proc.returncode or 'not found' in linkage[t]:
        raise RuntimeError('dynamic libraries unresolved for '+t+': '+linkage[t][-1400:])
if P['role']=='dut':
    if 'libngi541_engine.so' in linkage['bin/stock-nginx']:
        raise RuntimeError('stock nginx unexpectedly linked to NGI541')
    if 'libngi541_engine.so' not in linkage['bin/candidate-nginx']:
        raise RuntimeError('candidate nginx not linked to NGI541')
else:
    if any('ngi541' in text.lower() for text in linkage.values()):
        raise RuntimeError('client linked NGI541: forbidden')
print(json.dumps({'hashes':hashes,'linkage':linkage}))
"""
    result={}
    for role in ('dut','client'):
        binaries = ({'stock_nginx':'bin/stock-nginx','candidate_nginx':'bin/candidate-nginx',
                     'ngi541_engine':'lib/libngi541_engine.so.0.1'} if role=='dut' else
                    {'client_curl':'client/curl/bin/curl','client_h2load':'client/nghttp2/bin/h2load'})
        result[role]=remote_python(config,role,body,{'root':roots[role], 'role':role,
                       'binaries':binaries,'hashes':PINNED_HASHES,'components':CLIENT_COMPONENTS})
    return result


def remote_prepare_dut(config: dict, root: str, ip: str, port: int) -> dict:
    script="""
from pathlib import Path
import hashlib,subprocess
r=Path(P['root']); cert=r/'cert'; cert.mkdir(mode=0o700)
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
  '-keyout',str(cert/'ca.key'),'-out',str(cert/'ca.crt'),'-days','1','-sha256',
  '-subj','/CN=NGI541 CloudLab Smoke CA','-addext','basicConstraints=critical,CA:TRUE',
  '-addext','keyUsage=critical,keyCertSign,cRLSign'],capture_output=True,check=True)
subprocess.run(['openssl','req','-new','-newkey','rsa:2048','-nodes',
  '-keyout',str(cert/'server.key'),'-out',str(cert/'server.csr'),
  '-subj','/CN=ngi541-dut.local'],capture_output=True,check=True)
(cert/'server.ext').write_text('subjectAltName=DNS:ngi541-dut.local\\n'
  'basicConstraints=critical,CA:FALSE\\n'
  'keyUsage=critical,digitalSignature,keyEncipherment\\n'
  'extendedKeyUsage=serverAuth\\n')
subprocess.run(['openssl','x509','-req','-in',str(cert/'server.csr'),
  '-CA',str(cert/'ca.crt'),'-CAkey',str(cert/'ca.key'),
  '-CAcreateserial','-out',str(cert/'server.crt'),'-days','1','-sha256',
  '-extfile',str(cert/'server.ext')],capture_output=True,check=True)
for f in (cert/'ca.key',cert/'server.key'): f.chmod(0o600)
corpus=r/'corpus';corpus.mkdir()
raw=b'NGI541-ABC-HTTP-SMOKE-v1\\x00\\x01\\xff\\n'*1300
payload=(raw+bytes(range(256))*200)[:32768]
(corpus/'smoke.bin').write_bytes(payload)
expected=hashlib.sha256(payload).hexdigest()
for arm in 'ABC':
    d=r/arm;d.mkdir()
    listener=(f'listen {P["ip"]}:{P["port"]} ssl;\\nhttp2 on;' if arm=='A'
      else f'listen {P["ip"]}:{P["port"]} quic reuseport;\\nhttp3 on;')
    conf=f'''worker_processes 1;
pid {d}/nginx.pid;
error_log {d}/error.log info;
events {{ worker_connections 1024; }}
http {{
 log_format abc 'tls=$ssl_protocol cipher=$ssl_cipher proto=$server_protocol http3=$http3';
 access_log {d}/access.log abc;
 server {{
 {listener}
 server_name ngi541-dut.local;
 ssl_protocols TLSv1.3;
 ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256;
 ssl_certificate {cert}/server.crt;
 ssl_certificate_key {cert}/server.key;
 ssl_early_data off;
 root {corpus};
 location = /smoke.bin {{ default_type application/octet-stream; }}
 }}
}}
'''
    (d/'nginx.conf').write_text(conf)
print(json.dumps({'expected_sha256':expected,'payload_bytes':len(payload),
                  'ca_pem':(cert/'ca.crt').read_text()}))
"""
    out=remote_python(config,'dut',script,{'root':root,'ip':ip,'port':port},timeout_s=65)
    # CA is PUBLIC material; root CA private key remains only on DUT.
    return out


def remote_write_ca(config: dict, root: str, pem: str) -> None:
    if not pem.startswith('-----BEGIN CERTIFICATE-----') or len(pem)>10000:
        raise PipelineError('unexpected CA certificate data')
    script="""
from pathlib import Path
r=Path(P['root']);p=r/'ca.crt';p.write_text(P['pem']);p.chmod(0o600)
print(json.dumps({'path':str(p)}))
"""
    remote_python(config,'client',script,{'root':root,'pem':pem})


def start_nginx(config: dict, root: str, arm: str) -> None:
    bin_name = 'candidate-nginx' if arm=='C' else 'stock-nginx'
    directory=f'{root}/{arm}'
    env=f'LD_LIBRARY_PATH={shell_quote(root+"/lib")}'
    conf=f'{directory}/nginx.conf'
    nginx=f'{root}/bin/{bin_name}'
    remote_cmd(config,'dut',f'{env} {shell_quote(nginx)} -t -p {shell_quote(directory+"/")} -c {shell_quote(conf)}',timeout_s=25)
    # Explicit logfile redirection and bounded start. No unrelated NGINX touched.
    inner=(f'cd {shell_quote(directory)}; '
       f'nohup timeout -s TERM -k 5s 105s env {env} {shell_quote(nginx)} -p {shell_quote(directory+"/")} '
       f'-c {shell_quote(conf)} -g {shell_quote("daemon off;")} '
       f'> {shell_quote(directory+"/stdout.log")} 2>&1 < /dev/null & '
       f'pid=$!; echo $pid > {shell_quote(directory+"/controller.pid")}; '
       f'sleep 0.2; kill -0 $pid')
    remote_cmd(config,'dut','sh -c '+shell_quote(inner),timeout_s=20)


def stop_nginx(config: dict, root: str, arm: str) -> None:
    directory=f'{root}/{arm}'
    cmd=(f'if [ -f {shell_quote(directory+"/controller.pid")} ]; then '
         f'kill "$(cat {shell_quote(directory+"/controller.pid")})" 2>/dev/null || true; fi')
    try: remote_cmd(config,'dut',cmd,timeout_s=10)
    except (pf.PreflightError,subprocess.TimeoutExpired): pass


def run_arm(config: dict, roots: dict, ip: str, port: int, arm: str,
            expected_hash: str) -> dict:
    if arm not in VALID_ARMS: raise PipelineError('unknown arm')
    start_nginx(config,roots['dut'],arm)
    try:
        time.sleep(1.0)
        directory=roots['dut']+'/'+arm
        # Validate process stays up and listener really bound to experiment IP.
        expected_type='tcp' if arm=='A' else 'udp'
        status=remote_python(config,'dut',"""
import subprocess
cp=subprocess.run(['ss','-H','-lntu'],capture_output=True,text=True,check=True)
needle=P['ip']+':'+str(P['port'])
lines=[x for x in cp.stdout.splitlines() if needle in x and x.startswith(P['type'])]
print(json.dumps({'listener_found':bool(lines),'lines':lines}))
""",{'ip':ip,'port':port,'type':expected_type})
        if not status['listener_found']:
            raise PipelineError(f'{arm} {expected_type} listener absent: {status}')
        result=remote_python(config,'client',"""
from pathlib import Path
import hashlib,os,subprocess
r=Path(P['root']);d=r/P['arm'];d.mkdir(exist_ok=False)
curl=r/'client/curl/bin/curl'
env=dict(os.environ, LD_LIBRARY_PATH=':'.join(str(r/'client'/x/'lib') for x in P['components']),
         NO_PROXY='*',no_proxy='*')
cmd=[str(curl),'--noproxy','*','--http2' if P['arm']=='A' else '--http3-only',
 '--tlsv1.3','--tls-max','1.3','--tls13-ciphers','TLS_AES_128_GCM_SHA256',
 '--cacert',str(r/'ca.crt'),'--resolve','ngi541-dut.local:'+str(P['port'])+':'+P['ip'],
 '--silent','--show-error','--fail','--verbose','--connect-timeout','10',
 '--max-time','40','--output',str(d/'download.bin'),
 '--write-out','%{http_version}\\t%{response_code}\\t%{ssl_verify_result}\\t%{size_download}\\n',
 'https://ngi541-dut.local:'+str(P['port'])+'/smoke.bin']
cp=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=50)
(d/'curl-stdout.txt').write_text(cp.stdout)
(d/'curl-stderr.txt').write_text(cp.stderr)
if cp.returncode: raise RuntimeError('curl exit='+str(cp.returncode)+': '+cp.stderr[-1300:])
parts=cp.stdout.strip().split('\\t')
if len(parts)!=4: raise RuntimeError('unexpected curl writeout: '+repr(cp.stdout))
version,status,verify,size=parts
body=d/'download.bin'
actual=hashlib.sha256(body.read_bytes()).hexdigest() if body.exists() else None
if (version!=('2' if P['arm']=='A' else '3') or status!='200' or verify!='0' or
    int(float(size))!=32768 or actual!=P['hash']):
    raise RuntimeError('HTTP/CA/payload proof invalid: '+repr(parts)+' sha='+str(actual))
print(json.dumps({'arm':P['arm'],'http_version':version,'http_status':int(status),
 'verified_ca':True,'payload_bytes':body.stat().st_size,'payload_sha256':actual,
 'curl_writeout':cp.stdout.strip()}))
""", {'root':roots['client'],'arm':arm,'ip':ip,'port':port,
        'hash':expected_hash,'components':CLIENT_COMPONENTS},timeout_s=75)
        server=remote_python(config,'dut',"""
from pathlib import Path
r=Path(P['root']);d=r/P['arm'];p=d/'access.log'
if not p.is_file():raise RuntimeError('NGINX access log missing')
lines=[x.strip() for x in p.read_text().splitlines() if x.strip()]
print(json.dumps({'access_lines':lines,'error_tail':(d/'error.log').read_text()[-3000:]}))
""",{'root':roots['dut'],'arm':arm})
        lines=server['access_lines']
        if len(lines)!=1 or 'tls=TLSv1.3' not in lines[0] or 'cipher='+CIPHER not in lines[0]:
            raise PipelineError(f'{arm}: server-side negotiated TLS cipher proof failed: {lines}')
        result.update({'tls_version':'TLSv1.3','cipher':CIPHER,
                       'nginx_access_line':lines[0],
                       'server_variant':'ngi541-direct' if arm=='C' else 'stock',
                       'actual_ngi541_crypto_call_trace':'unavailable; not claimed',
                       'scope':'functional only, not high-rate measurement'})
        return result
    finally:
        stop_nginx(config,roots['dut'],arm)


def collect_remote_logs(config: dict, roots: dict, outdir: pathlib.Path) -> None:
    for role in ('dut','client'):
        remote=roots.get(role)
        if not remote:continue
        # No CA private key, TLS private key, or downloaded payload exported.
        body="""
from pathlib import Path
r=Path(P['root']);out={}
for arm in 'ABC':
 d=r/arm
 for name in ('access.log','error.log','stdout.log','curl-stdout.txt','curl-stderr.txt'):
  p=d/name
  if p.is_file():out[arm+'/'+name]=p.read_text(errors='replace')[-100000:]
print(json.dumps(out))
"""
        try:
            logs=remote_python(config,role,body,{'root':remote},timeout_s=20)
            pf.save_json(outdir/f'{role}-abc-logs.json',logs)
        except Exception as exc:
            pf.save_json(outdir/f'{role}-logs-unavailable.json',{'error':str(exc)})


def execute(config: dict, repo: pathlib.Path, outdir: pathlib.Path, skip_iperf=False) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    run_id=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+os.urandom(5).hex()
    report={'schema':SCHEMA,'run_id':run_id,'status':'FAIL',
            'qualification':'exploratory-functional-only; not publication-qualified',
            'steps':{},'arms':{},'remote_roots':{},
            'scientific_measurement':{'status':'not_applicable',
                'reason':'No genuine h2load MAIN window / complete payload ledger / DUT-client CPU alignment / measurement overhead calibration'}}
    roots={}
    try:
        print('===== 1. SSH / HARDWARE / NETWORK / IPERF3 =====',flush=True)
        preflight=pf.execute(config,outdir/'preflight',skip_iperf=skip_iperf)
        allowed_status = 'CONNECTIVITY_ONLY_PASS' if skip_iperf else 'PASS'
        if preflight['status'] != allowed_status:
            raise PipelineError(f'preflight status {preflight["status"]!r}; expected {allowed_status!r}; refusing deployment')
        report['steps']['preflight']='PASS'
        path=preflight['path']; ip=path['dut']['ip']
        print('===== 2. VERIFY LOCAL PINNED LINUX ARTIFACTS =====',flush=True)
        artifacts,receipts=checked_local_artifacts(config,repo)
        pf.save_json(outdir/'local-artifact-hashes.json',receipts)
        report['steps']['local_binaries']='PASS'
        print('===== 3. DEPLOY EXACT BINARIES VIA SSH =====',flush=True)
        with tempfile.TemporaryDirectory(prefix='ngi541-abc-archive-') as tdir:
            packages=create_archives(artifacts,pathlib.Path(tdir))
            for role in ('dut','client'):
                roots[role]=remote_root(config,role,run_id)
                report['remote_roots'][role]=roots[role]
                upload_tar(config,role,packages[role],roots[role])
        linkage=remote_check_binaries(config,roots)
        pf.save_json(outdir/'remote-artifact-identity.json',linkage)
        report['steps']['deployment']='PASS'
        print('===== 4. PREPARE CERTIFICATE + 32KiB CORPUS =====',flush=True)
        port=config['pipeline'].get('https_port',18443)
        prep=remote_prepare_dut(config,roots['dut'],ip,port)
        remote_write_ca(config,roots['client'],prep['ca_pem'])
        report['payload_sha256']=prep['expected_sha256']
        report['steps']['corpus_tls']='PASS'
        print('===== 5. A/B/C FUNCTIONAL EXECUTION =====',flush=True)
        for arm in VALID_ARMS:
            result=run_arm(config,roots,ip,port,arm,prep['expected_sha256'])
            report['arms'][arm]=result
            print(f"PASS {arm}: HTTP/{result['http_version']} TLS1.3 {CIPHER} 32768 bytes SHA256={result['payload_sha256']}",flush=True)
        report['steps']['abc_functional']='PASS'
        report['status']='PASS_FUNCTIONAL_NOT_SCIENTIFIC'
    except (pf.PreflightError,PipelineError,OSError,ValueError,KeyError,subprocess.TimeoutExpired,
            RuntimeError,subprocess.CalledProcessError) as exc:
        report['error']=str(exc)
        print(f'FAIL: {exc}',file=sys.stderr,flush=True)
    finally:
        collect_remote_logs(config,roots,outdir)
        report['finished_utc']=pf.utcnow()
        pf.save_json(outdir/'report.json',report)
        print('EVIDENCE: '+str(outdir),flush=True)
    return report


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description='CloudLab SSH -> preflight -> pinned artifact upload -> ABC functional smoke')
    parser.add_argument('--config',required=True,type=pathlib.Path)
    parser.add_argument('--output',type=pathlib.Path)
    parser.add_argument('--repo',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[2])
    parser.add_argument('--validate-local',action='store_true',
                        help='validate JSON and exact local pinned binaries without SSH')
    args=parser.parse_args(argv)
    try:
        cfg=load_config(args.config,args.repo)
        if args.validate_local:
            _,receipt=checked_local_artifacts(cfg,args.repo.resolve())
            print('PASS: config + local binary hashes valid; no SSH executed')
            for name,item in sorted(receipt.items()):
                print(name,item['sha256'])
            return 0
        if args.output is None:
            parser.error('--output required unless --validate-local')
        outdir=args.output.expanduser().resolve()
        if outdir.exists() and any(outdir.iterdir()):
            parser.error('output directory must be empty: '+str(outdir))
        result=execute(cfg,args.repo.resolve(),outdir)
        return 0 if result['status']=='PASS_FUNCTIONAL_NOT_SCIENTIFIC' else 1
    except (pf.PreflightError,PipelineError,ValueError,OSError,json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2

if __name__=='__main__':raise SystemExit(main())
