"""Read-only CloudLab SSH environment preflight + explicitly scoped iperf3 smoke.

Only the iperf3 server (bounded by coreutils timeout) is transiently launched
remotely. Run from the local controller, not inside either CloudLab node.
No third-party Python dependencies.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import time
from typing import Any

SCHEMA = "ngi541-cloudlab-ssh-preflight-v1"
SSH_DEST_RE = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9_.-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*$")

# Executed with `ssh ... 'python3 -'`; no local or remote files are modified.
REMOTE_INVENTORY = r'''
import json, os, platform, pathlib, re, socket, subprocess

def call(args):
    cp = subprocess.run(args, text=True, capture_output=True, check=True, timeout=12)
    return cp.stdout

def rd(p):
    try:
        return pathlib.Path(p).read_text().strip()
    except (OSError, UnicodeError):
        return None

addresses = json.loads(call(['ip', '-j', '-4', 'address', 'show']))
routes = json.loads(call(['ip', '-j', '-4', 'route', 'show', 'default']))
interfaces = []
for link in addresses:
    name = link.get('ifname', '')
    if not name or name == 'lo':
        continue
    speed = rd('/sys/class/net/' + name + '/speed')
    try:
        speed = int(speed)
    except (TypeError, ValueError):
        speed = None
    if speed is not None and speed <= 0:
        speed = None
    interfaces.append({
      'name': name,
      'operstate': link.get('operstate'),
      'mtu': link.get('mtu'),
      'mac': rd('/sys/class/net/' + name + '/address'),
      'speed_mbps': speed,
      'numa_node': rd('/sys/class/net/' + name + '/device/numa_node'),
      'pci_device': os.path.basename(os.path.realpath('/sys/class/net/' + name + '/device')),
      'pci_vendor_id': rd('/sys/class/net/' + name + '/device/vendor'),
      'pci_device_id': rd('/sys/class/net/' + name + '/device/device'),
      'driver': os.path.basename(os.path.realpath('/sys/class/net/' + name + '/device/driver')),
      'ipv4': [
        {'address': a['local'], 'prefixlen': a['prefixlen']}
        for a in link.get('addr_info', [])
        if a.get('family') == 'inet' and 'local' in a and 'prefixlen' in a
      ],
    })
flags = set()
try:
    for line in pathlib.Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith('flags') or line.startswith('Features'):
            flags = set(line.partition(':')[2].split())
            break
except OSError:
    pass
model = None
try:
    for line in pathlib.Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith('model name'):
            model = line.partition(':')[2].strip()
            break
except OSError:
    pass
mem_total_kib = None
try:
    for line in pathlib.Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemTotal:'):
            mem_total_kib = int(line.split()[1])
            break
except (OSError, ValueError):
    pass
try:
    cpu_topology = {x['field'].strip().rstrip(':'): x.get('data')
                    for x in json.loads(call(['lscpu','-J']))['lscpu']}
except (OSError, ValueError, KeyError, subprocess.SubprocessError):
    cpu_topology = {}
os_pretty = None
for line in (rd('/etc/os-release') or '').splitlines():
    if line.startswith('PRETTY_NAME='):
        os_pretty = line.split('=',1)[1].strip('"')
result = {
 'inventory_schema': 'ngi541-cloudlab-inventory-v1',
 'hostname': socket.gethostname(),
 'os_pretty': os_pretty,
 'kernel': platform.release(),
 'architecture': platform.machine(),
 'cpu_model': model,
 'logical_cpus': os.cpu_count(),
 'cpu_topology': cpu_topology,
 'mem_total_kib': mem_total_kib,
 'crypto_flags': sorted(flags.intersection({'aes','avx','avx2','avx512f','pclmulqdq','vaes','vpclmulqdq'})),
 'default_route_devices': sorted({r['dev'] for r in routes if 'dev' in r}),
 'interfaces': interfaces,
 'tools': {name: bool(subprocess.run(['which',name], capture_output=True).returncode == 0)
           for name in ('ip','ss','iperf3','ping','ethtool','perf','git','python3')},
}
print(json.dumps(result, sort_keys=True, separators=(',', ':')))
'''


class PreflightError(RuntimeError):
    pass


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def save_json(path: pathlib.Path, item: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(item, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    tmp.replace(path)


def positive_int(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise PreflightError(f'{name} must be integer between {low} and {high}')
    return value


def load_config(path: pathlib.Path) -> dict:
    config = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(config, dict) or config.get('schema') != SCHEMA:
        raise PreflightError(f'config must have schema={SCHEMA}')
    nodes = config.get('nodes')
    if not isinstance(nodes, dict) or set(nodes) != {'dut', 'client'}:
        raise PreflightError('nodes must contain exactly dut and client')
    for role in ('dut', 'client'):
        item = nodes[role]
        if not isinstance(item, dict) or not isinstance(item.get('ssh'), str) or not SSH_DEST_RE.fullmatch(item['ssh']):
            raise PreflightError(f'invalid nodes.{role}.ssh (expected user@hostname)')
    if nodes['dut']['ssh'] == nodes['client']['ssh']:
        raise PreflightError('DUT and client must be different SSH destinations')
    auth = config.get('ssh', {})
    if not isinstance(auth, dict) or not isinstance(auth.get('identity_file'), str):
        raise PreflightError('ssh.identity_file must be a private-key path')
    key = pathlib.Path(auth['identity_file']).expanduser()
    if not key.is_file() or key.suffix == '.pub':
        raise PreflightError(f'SSH private-key file not found: {key}')
    positive_int(auth.get('connect_timeout_s', 10), 'ssh.connect_timeout_s', 1, 30)
    network = config.get('network', {})
    if not isinstance(network, dict):
        raise PreflightError('network must be an object')
    positive_int(network.get('min_link_mbps', 10000), 'network.min_link_mbps', 1000, 400000)
    if network.get('experiment_cidr') is not None:
        try:
            ipaddress.IPv4Network(network['experiment_cidr'], strict=True)
        except (TypeError, ValueError, ipaddress.AddressValueError) as exc:
            raise PreflightError('network.experiment_cidr must be valid IPv4 CIDR') from exc
    smoke = config.get('smoke', {})
    if not isinstance(smoke, dict) or not isinstance(smoke.get('iperf3'), dict):
        raise PreflightError('smoke.iperf3 must be an object')
    positive_int(smoke.get('ping_packets', 4), 'smoke.ping_packets', 1, 20)
    iperf = smoke['iperf3']
    positive_int(iperf.get('port', 52103), 'smoke.iperf3.port', 1024, 65535)
    positive_int(iperf.get('parallel_streams', 4), 'smoke.iperf3.parallel_streams', 1, 32)
    duration = positive_int(iperf.get('duration_s', 12), 'smoke.iperf3.duration_s', 3, 60)
    omitted = positive_int(iperf.get('omit_s', 3), 'smoke.iperf3.omit_s', 0, 10)
    if duration <= omitted:
        raise PreflightError('iperf duration_s must exceed omit_s')
    threshold = iperf.get('minimum_goodput_gbps', 0.0)
    if type(threshold) not in (int, float) or not 0 <= threshold < 400:
        raise PreflightError('smoke.iperf3.minimum_goodput_gbps invalid')
    return config


def ssh_base(config: dict, role: str) -> list[str]:
    key = str(pathlib.Path(config['ssh']['identity_file']).expanduser())
    delay = config['ssh'].get('connect_timeout_s', 10)
    return [
        'ssh', '-T', '-i', key, '-o', 'IdentitiesOnly=yes',
        '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new',
        '-o', f'ConnectTimeout={delay}', '-o', 'ServerAliveInterval=10',
        '-o', 'ServerAliveCountMax=2', '-o', 'LogLevel=ERROR',
        config['nodes'][role]['ssh'],
    ]


def ssh_run(config: dict, role: str, remote_command: str, *, input_text: str | None = None,
            timeout_s: int = 35) -> str:
    result = subprocess.run(ssh_base(config, role) + [remote_command], input=input_text,
                            text=True, capture_output=True, timeout=timeout_s)
    if result.returncode != 0:
        raise PreflightError(f'SSH {role} [{remote_command.split()[0]}] exited {result.returncode}: '
                             f'{result.stderr[-1600:].strip()}')
    return result.stdout


def fetch_inventory(config: dict, role: str) -> dict:
    raw = ssh_run(config, role, 'python3 -', input_text=REMOTE_INVENTORY, timeout_s=40)
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PreflightError(f'{role}: inventory not valid JSON (unexpected SSH/banner output)') from exc
    if obj.get('inventory_schema') != 'ngi541-cloudlab-inventory-v1':
        raise PreflightError(f'{role}: unknown inventory schema')
    if not obj.get('tools', {}).get('iperf3') or not obj.get('tools', {}).get('ss'):
        raise PreflightError(f'{role}: iperf3 and ss must be installed')
    return obj


def candidates(inv: dict, min_mbps: int, network_filter: str | None) -> list[dict]:
    default = set(inv['default_route_devices'])
    want = ipaddress.IPv4Network(network_filter) if network_filter else None
    result = []
    for iface in inv['interfaces']:
        if iface['name'] in default or iface.get('operstate') != 'UP':
            continue
        speed = iface.get('speed_mbps')
        if type(speed) is not int or speed < min_mbps:
            continue
        for ipv4 in iface.get('ipv4', []):
            try:
                addr = ipaddress.IPv4Address(ipv4['address'])
                subnet = ipaddress.IPv4Interface(f"{addr}/{ipv4['prefixlen']}").network
            except (ValueError, KeyError):
                continue
            if not addr.is_private or not subnet.is_private:
                continue
            if want is not None and subnet != want:
                continue
            result.append({'interface': iface['name'], 'ip': str(addr),
                           'subnet': str(subnet), 'speed_mbps': speed,
                           'numa_node': iface.get('numa_node'),
                           'mtu': iface.get('mtu')})
    return result


def select_experiment_path(dut: dict, client: dict, min_link_mbps: int,
                           experiment_cidr: str | None = None) -> dict:
    ds = candidates(dut, min_link_mbps, experiment_cidr)
    cs = candidates(client, min_link_mbps, experiment_cidr)
    matches = [
       (d, c) for d in ds for c in cs
       if d['subnet'] == c['subnet'] and d['ip'] != c['ip']
    ]
    if not matches:
        raise PreflightError('no matching dedicated experiment interfaces with same private IPv4 subnet; '
                             'refusing to use management network')
    # Select the fastest common network; ambiguity at that speed is unsafe.
    best = max(min(d['speed_mbps'], c['speed_mbps']) for d, c in matches)
    fastest = [(d, c) for d, c in matches if min(d['speed_mbps'], c['speed_mbps']) == best]
    if len(fastest) != 1:
        raise PreflightError(f'{len(fastest)} equally fast experiment paths; set network.experiment_cidr')
    d, c = fastest[0]
    return {'dut': d, 'client': c, 'common_link_mbps': best,
            'subnet': d['subnet'], 'origin': 'auto-discovered; verify with ip route get'}


def verify_peer_route(config: dict, role: str, own: dict, peer_ip: str) -> dict:
    ipaddress.IPv4Address(peer_ip)
    out = ssh_run(config, role, f'ip -j -4 route get {peer_ip}', timeout_s=20)
    try:
        routes = json.loads(out)
    except json.JSONDecodeError as exc:
        raise PreflightError(f'{role}: route get not JSON') from exc
    if not routes or not isinstance(routes, list):
        raise PreflightError(f'{role}: route get returned no route')
    r = routes[0]
    if r.get('dev') != own['interface'] or r.get('gateway') or r.get('via'):
        raise PreflightError(f'{role}: peer route not direct experiment interface: {r}')
    src = r.get('prefsrc') or r.get('src')
    if src is not None and src != own['ip']:
        raise PreflightError(f'{role}: source IP {src} != selected {own["ip"]}')
    return r


def parse_ping(raw: str) -> dict:
    match = re.search(r'(\d+) packets transmitted,\s*(\d+) received,\s*([\d.]+)% packet loss', raw)
    if not match:
        raise PreflightError('ping summary missing / unknown format')
    sent, received, loss = int(match[1]), int(match[2]), float(match[3])
    if sent < 1 or received != sent or loss != 0:
        raise PreflightError(f'ping packets lost: {received}/{sent} received, {loss}% loss')
    timing = re.search(r'rtt min/avg/max/(?:mdev|stddev)\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms', raw)
    return {'sent': sent, 'received': received, 'loss_pct': loss,
            'rtt_min_ms': float(timing[1]) if timing else None,
            'rtt_avg_ms': float(timing[2]) if timing else None,
            'rtt_max_ms': float(timing[3]) if timing else None}


def iperf_summary(data: dict, direction: str) -> dict:
    if data.get('error'):
        raise PreflightError(f'iperf3 {direction}: {data["error"]}')
    end = data.get('end') or {}
    sent = end.get('sum_sent')
    received = end.get('sum_received')
    if not isinstance(sent, dict) or not isinstance(received, dict):
        raise PreflightError(f'iperf3 {direction}: missing sender or receiver aggregate')
    speed = received.get('bits_per_second')
    if type(speed) not in (int, float) or speed <= 0:
        raise PreflightError(f'iperf3 {direction}: invalid receiver goodput')
    return {
       'direction': direction,
       'sender_gbps': round(sent.get('bits_per_second', 0) / 1e9, 6),
       'receiver_gbps': round(speed / 1e9, 6),
       'retransmissions': sent.get('retransmits'),
       'received_bytes': received.get('bytes'),
       'measurement_kind': 'iperf3 TCP receiver throughput; NOT HTTP/3 application goodput',
    }


def wait_server_listening(config: dict, ip: str, port: int, proc: subprocess.Popen,
                          attempts: int = 9) -> None:
    needle = f'{ip}:{port}'
    for _ in range(attempts):
        if proc.poll() is not None:
            raise PreflightError(f'iperf3 server exited before listen: ssh status {proc.returncode}')
        try:
            lines = ssh_run(config, 'dut', 'ss -H -ltn', timeout_s=15)
            if any(needle in line for line in lines.splitlines()):
                return
        except PreflightError:
            pass
        time.sleep(0.25)
    raise PreflightError(f'iperf3 server not confirmed listening on {needle}')


def run_iperf_direction(config: dict, path: dict, outdir: pathlib.Path, reverse: bool) -> dict:
    p = config['smoke']['iperf3']
    port = p.get('port', 52103)
    dur = p.get('duration_s', 12)
    omit = p.get('omit_s', 3)
    parallel = p.get('parallel_streams', 4)
    direction = 'dut-to-client' if reverse else 'client-to-dut'
    dut_ip, client_ip = path['dut']['ip'], path['client']['ip']
    # Timeout on the remote DUT guarantees server cleanup even if SSH disconnects.
    server_limit = dur + omit + 35
    server_cmd = (f'exec timeout {server_limit}s iperf3 -s -1 -B {dut_ip} '
                  f'-p {port} -J')
    server_stdout = outdir / f'iperf-server-{direction}.stdout.json'
    server_stderr = outdir / f'iperf-server-{direction}.stderr.txt'
    with server_stdout.open('w') as f_out, server_stderr.open('w') as f_err:
        server = subprocess.Popen(ssh_base(config, 'dut') + [server_cmd],
                                  stdout=f_out, stderr=f_err, text=True)
        try:
            wait_server_listening(config, dut_ip, port, server)
            client_cmd = (f'iperf3 -c {dut_ip} -B {client_ip} -p {port} '
                          f'-P {parallel} -t {dur} -O {omit} -J')
            if reverse:
                client_cmd += ' -R'
            raw = ssh_run(config, 'client', client_cmd, timeout_s=dur + omit + 35)
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise PreflightError(f'iperf3 {direction}: invalid client JSON') from exc
            save_json(outdir / f'iperf-{direction}.json', data)
            summary = iperf_summary(data, direction)
            try:
                server.wait(timeout=12)
            except subprocess.TimeoutExpired as exc:
                raise PreflightError(f'iperf3 server {direction} did not exit after test') from exc
            if server.returncode != 0:
                raise PreflightError(f'iperf3 server {direction} exited {server.returncode}; see stderr')
            threshold = p.get('minimum_goodput_gbps', 0)
            if summary['receiver_gbps'] < threshold:
                raise PreflightError(f'iperf3 {direction}: {summary["receiver_gbps"]} Gb/s '
                                     f'< required smoke threshold {threshold} Gb/s')
            return summary
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=3)


def collect_identity(config: dict, role: str, outdir: pathlib.Path) -> dict:
    inv = fetch_inventory(config, role)
    save_json(outdir / f'{role}-inventory.json', inv)
    return inv


def safe_config_for_report(config: dict) -> dict:
    # Keep only nonsecret parameters; never copy SSH private key bytes.
    return {'schema': config['schema'], 'nodes': config['nodes'],
            'network': config.get('network'), 'smoke': config.get('smoke'),
            'ssh_auth': 'explicit identity file, IdentitiesOnly=yes, BatchMode=yes'}


def execute(config: dict, outdir: pathlib.Path, *, skip_iperf: bool = False) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    report = {'schema': SCHEMA, 'created_utc': utcnow(), 'status': 'FAIL',
              'qualification': 'infrastructure-smoke-only; not publication-qualified',
              'controller': socket.gethostname(), 'config': safe_config_for_report(config),
              'checks': {}, 'iperf3': {}}
    try:
        print('===== 1. SSH + HOST INVENTORY =====', flush=True)
        dut = collect_identity(config, 'dut', outdir)
        client = collect_identity(config, 'client', outdir)
        report['checks']['ssh'] = 'PASS'
        print(f"PASS: DUT={dut['hostname']}, client={client['hostname']}", flush=True)
        print('===== 2. AUTO-DISCOVER EXPERIMENT INTERFACE =====', flush=True)
        network = config.get('network', {})
        path = select_experiment_path(dut, client, network.get('min_link_mbps', 10000),
                                      network.get('experiment_cidr'))
        report['path'] = path
        save_json(outdir / 'path.json', path)
        print(f"PASS: {path['dut']['interface']} {path['dut']['ip']} <-> "
              f"{path['client']['interface']} {path['client']['ip']} "
              f"({path['common_link_mbps']} Mb/s)", flush=True)
        print('===== 3. VERIFY BOTH PEER ROUTES =====', flush=True)
        r_dut = verify_peer_route(config, 'dut', path['dut'], path['client']['ip'])
        r_client = verify_peer_route(config, 'client', path['client'], path['dut']['ip'])
        save_json(outdir / 'routes.json', {'dut': r_dut, 'client': r_client})
        report['checks']['direct_routes'] = 'PASS'
        print('PASS: direct bidirectional routes use experiment interface', flush=True)
        print('===== 4. ICMP CONNECTIVITY =====', flush=True)
        packet_count = config['smoke'].get('ping_packets', 4)
        raw = ssh_run(config, 'client',
                      f"ping -n -I {path['client']['interface']} -c {packet_count} -W 2 "
                      f"{path['dut']['ip']}", timeout_s=packet_count * 3 + 15)
        (outdir / 'ping-client-to-dut.txt').write_text(raw, encoding='utf-8')
        ping_result = parse_ping(raw)
        report['ping'] = ping_result
        report['checks']['icmp'] = 'PASS'
        print(f"PASS: {ping_result['received']}/{ping_result['sent']} ICMP; "
              f"avg RTT {ping_result['rtt_avg_ms']} ms", flush=True)
        if not skip_iperf:
            print('===== 5. IPERF3 CLIENT -> DUT =====', flush=True)
            fwd = run_iperf_direction(config, path, outdir, reverse=False)
            report['iperf3']['client_to_dut'] = fwd
            print(f"PASS: {fwd['receiver_gbps']} Gb/s", flush=True)
            print('===== 6. IPERF3 DUT -> CLIENT =====', flush=True)
            rev = run_iperf_direction(config, path, outdir, reverse=True)
            report['iperf3']['dut_to_client'] = rev
            print(f"PASS: {rev['receiver_gbps']} Gb/s", flush=True)
            report['checks']['iperf3_both_directions'] = 'PASS'
        else:
            report['checks']['iperf3_both_directions'] = 'NOT_RUN'
        report['status'] = 'PASS' if not skip_iperf else 'CONNECTIVITY_ONLY_PASS'
    except (PreflightError, OSError, subprocess.TimeoutExpired, ValueError, KeyError) as exc:
        report['error'] = str(exc)
        print(f'FAIL: {exc}', file=sys.stderr, flush=True)
    finally:
        report['completed_utc'] = utcnow()
        save_json(outdir / 'report.json', report)
        print(f"EVIDENCE: {outdir}", flush=True)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='NGI541 CloudLab remote SSH hardware/network/iperf3 preflight')
    parser.add_argument('--config', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--skip-iperf', action='store_true', help='SSH, inventory, routes and ping only')
    args = parser.parse_args(argv)
    if shutil.which('ssh') is None:
        parser.error('OpenSSH client required')
    try:
        config = load_config(args.config)
        outdir = args.output.expanduser().resolve()
        if outdir.exists() and any(outdir.iterdir()):
            parser.error(f'output directory must be empty: {outdir}')
        result = execute(config, outdir, skip_iperf=args.skip_iperf)
        return 0 if result['status'] in ('PASS', 'CONNECTIVITY_ONLY_PASS') else 1
    except (PreflightError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
