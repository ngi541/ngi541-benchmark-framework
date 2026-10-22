"""M2.1.2a: read-only Linux environment inventory, evidence and drift gates.

Evidence gathering is not bare-metal qualification. Missing measurements remain
explicitly unavailable; command failure is not equivalent to disabled features.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

REVISION = 'ngi541-abc-m2.1.2a-environment-r1'
GROUPS = ('cpu', 'cpu_topology', 'cpu_execution', 'memory', 'nic', 'packet_io',
          'os', 'nginx', 'crypto', 'client', 'workload')
STATES = frozenset(('measured', 'unavailable', 'not_applicable', 'invalid'))
ROLES = frozenset(('dut', 'client'))
SHA_RE = re.compile(r'^[0-9a-f]{64}$')
ID_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')
# Distinguish factual fields, experimental controls and dynamic observations.
# NOT every recorded field can act as a hard scientific gate; see documentation.
FIELD_SPEC = {
 'cpu': ('vendor','family','model','model_name','stepping','microcode','isa_flags','aes_ni','vaes','avx2','avx512'),
 'cpu_topology': ('sockets','cores_per_socket','threads_per_core','numa_nodes','effective_cpuset','online_cpus'),
 'cpu_execution': ('cpufreq_policies','governor','turbo_state','affinity','cpu_throttling','frequency_stability'),
 'memory': ('ram_kib','numa_memory_nodes','numa_policy','page_cache_policy','memory_pressure'),
 'nic': ('interface','mac_identity','pci_id','model','driver','firmware','link_speed_mbps','link_carrier','pcie_link'),
 'packet_io': ('mtu','tcp_offloads','udp_gso_gro','nic_channels','rss_queues','irq_affinity','quic_gso','socket_buffers'),
 'os': ('kernel','distribution','boot_id','sysctl','interrupts','irqbalance','bios','virtualization'),
 'nginx': ('binary_sha256','source_revision','patch_sha256','configure_flags','runtime_config_sha256','worker_affinity','ngi541_dynamic_dependency'),
 'crypto': ('openssl_revision','openssl_source_sha256','openssl_binary_sha256','openssl_linkage_mode','ngi541_revision','ngi541_binary_sha256','dispatch_isa_path'),
 'client': ('binary_sha256','client_version','tls_provider','h2_h3_capability','client_ngi541_dependency'),
 'workload': ('corpus_sha256','object_identifiers','stream_schedule_sha256','profile_id','cache_policy'),
}
assert tuple(FIELD_SPEC) == GROUPS
# Required for *complete identity* on physical hosts. A missing value makes
# completeness UNQUALIFIED; it does not necessarily constitute measured drift.
REQUIRED_BY_ROLE = {
 'dut': {
  'cpu': ('vendor','family','model','stepping','microcode','isa_flags'),
  'cpu_topology': ('effective_cpuset','online_cpus','sockets','numa_nodes'),
  'cpu_execution': ('governor','turbo_state','affinity'),
  'memory': ('ram_kib','numa_memory_nodes','page_cache_policy'),
  'nic': ('pci_id','driver','firmware','link_speed_mbps'),
  'packet_io': ('mtu','tcp_offloads','udp_gso_gro','irq_affinity','quic_gso'),
  'os': ('kernel','distribution','boot_id','sysctl','virtualization'),
  'nginx': ('binary_sha256','source_revision','patch_sha256','configure_flags','runtime_config_sha256','ngi541_dynamic_dependency'),
  'crypto': ('openssl_revision','openssl_source_sha256','openssl_binary_sha256','openssl_linkage_mode','ngi541_revision','ngi541_binary_sha256','dispatch_isa_path'),
  'workload': ('corpus_sha256','object_identifiers','stream_schedule_sha256','profile_id','cache_policy'),
 },
 'client': {
  'cpu': ('vendor','family','model','stepping','microcode','isa_flags'),
  'cpu_topology': ('effective_cpuset','online_cpus','sockets','numa_nodes'),
  'cpu_execution': ('governor','turbo_state','affinity'),
  'memory': ('ram_kib','numa_memory_nodes','page_cache_policy'),
  'nic': ('pci_id','driver','firmware','link_speed_mbps'),
  'packet_io': ('mtu','tcp_offloads','udp_gso_gro','irq_affinity'),
  'os': ('kernel','distribution','boot_id','sysctl','virtualization'),
  'client': ('binary_sha256','client_version','tls_provider','h2_h3_capability','client_ngi541_dependency'),
  'workload': ('corpus_sha256','object_identifiers','stream_schedule_sha256','profile_id','cache_policy'),
 }
}
# B/C variants legitimately differ in their NGINX binary, source patch and NGI541
# library. A/B/C must NEVER have a different client/corpus without predeclaration.
VARIANT_DIFFERENCES = frozenset({'nginx.binary_sha256', 'nginx.patch_sha256',
 'nginx.configure_flags', 'nginx.source_revision', 'nginx.ngi541_dynamic_dependency', 'crypto.ngi541_binary_sha256',
 'crypto.ngi541_revision', 'crypto.dispatch_isa_path'})
# A large set of dynamic/sampling fields must not become false cross-run drift.
DYNAMIC_FIELDS = frozenset({'cpu_execution.cpu_throttling','cpu_execution.frequency_stability',
 'memory.memory_pressure','nic.link_carrier','os.interrupts'})
# Important caveat: IRQ affinity requires comparison, when stable capture possible;
# the dynamic field is recorded separately and must later be gated during a run.


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def field(value: Any = None, *, source: str, reason: str | None = None,
          state: str | None = None, scope: str = 'host-or-current-namespace') -> dict:
    if state is None:
        state = 'measured' if value is not None else 'unavailable'
    if state not in STATES or not source or not scope:
        raise ValueError('bad environment field state/source/scope')
    if state == 'measured' and (value is None or reason is not None):
        raise ValueError('measured requires value and no reason')
    if state != 'measured' and (value is not None or not reason):
        raise ValueError('unmeasured requires null and explanation')
    return {'state':state,'value':value,'source':source,'scope':scope,'reason':reason}


def unavailable(why: str, source: str = 'unobserved') -> dict:
    return field(source=source, reason=why)


def _read(path: Path) -> str | None:
    try:
        text = path.read_text(encoding='utf-8', errors='replace').strip()
        return text or None
    except (OSError, UnicodeError):
        return None


def _parse_kv(raw: str | None, separator: str = ':') -> dict[str,str]:
    result = {}
    for line in (raw or '').splitlines():
        if separator in line:
            key,value = line.split(separator,1)
            result[key.strip()] = value.strip()
    return result


def _raw_bool(value: str | None, *, invert: bool = False) -> bool | None:
    if value not in ('0','1'): return None
    return (value == '0') if invert else (value == '1')


def _single_cpu_info(raw: str | None) -> dict:
    # microcode from the first stanza alone is not proof all CPUs agree.
    blocks = (raw or '').split('\n\n')
    main = _parse_kv(blocks[0]) if blocks else {}
    keys = {'vendor':'vendor_id','family':'cpu family','model':'model',
            'model_name':'model name','stepping':'stepping','microcode':'microcode'}
    result = {key: main.get(v) for key,v in keys.items()}
    flags = sorted(set(main.get('flags','').split()))
    result['isa_flags'] = flags if flags else None
    for key, name in [('aes_ni','aes'),('vaes','vaes'),('avx2','avx2')]:
        result[key] = (name in flags) if flags else None
    result['avx512'] = (any(v.startswith('avx512') for v in flags)) if flags else None
    all_stanzas = [_parse_kv(b) for b in blocks if 'processor' in b]
    values = {b.get('microcode') for b in all_stanzas}
    if len(values) > 1: result['microcode'] = None
    return result


def _bool_or_unknown(value: bool | None, source: str) -> dict:
    return field(value,source=source,reason=None if value is not None else 'not reported')


def _list_from_range(raw: str | None) -> list[int] | None:
    if not raw or not re.fullmatch(r'[\d,-]+',raw): return None
    values:set[int]=set()
    for part in raw.split(','):
        m=re.fullmatch(r'(\d+)(?:-(\d+))?',part)
        if not m:return None
        lo=int(m[1]); hi=int(m[2] or m[1])
        if lo>hi or hi-lo>8192:return None
        values.update(range(lo,hi+1))
    return sorted(values) if values else None


class Reader:
    def __init__(self, root: Path = Path('/'), command_timeout: float = 6.0):
        self.root = Path(root)
        self.timeout = command_timeout
        self.commands:dict[str,dict]={}

    def at(self, relative: str) -> Path:
        return self.root / relative.lstrip('/')

    def read(self, relative: str) -> str | None:
        return _read(self.at(relative))

    def cmd(self, key: str, args: list[str]) -> str | None:
        if key in self.commands: raise ValueError(f'duplicate command capture {key}')
        if not shutil.which(args[0]) and not (Path(args[0]).is_absolute() and Path(args[0]).is_file()):
            self.commands[key]={'argv':args,'state':'unavailable', 'reason':'executable missing', 'stdout':None}
            return None
        try:
            p=subprocess.run(args, capture_output=True, text=True, timeout=self.timeout, check=False)
            ok=p.returncode==0
            output=(p.stdout + (p.stderr if key=='nginx_version' else ''))[:65536] if ok else None
            self.commands[key]={'argv':args,'state':'measured' if ok else 'unavailable',
                                'reason':None if ok else f'exit={p.returncode}: {p.stderr[:512]}',
                                'stdout':output}
            return output
        except (OSError,subprocess.TimeoutExpired) as exc:
            self.commands[key]={'argv':args,'state':'unavailable',
                                'reason':type(exc).__name__,'stdout':None}
            return None


def _asset_field(asset: dict, key: str) -> dict:
    value = asset.get(key)
    if value is None:return unavailable('file not declared in approved asset manifest',f'assets.{key}')
    if not isinstance(value,str) or not Path(value).is_absolute():
        return field(source=f'assets.{key}',state='invalid',reason='asset path must be absolute')
    p=Path(value)
    try:
        if not p.is_file():return unavailable('declared file absent on this host', f'assets.{key}')
        h=hashlib.sha256()
        with p.open('rb') as f:
            for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
        return field(h.hexdigest(),source=f'sha256:{key}',scope='declared-file-content')
    except OSError as exc:return unavailable(f'could not read: {type(exc).__name__}',f'assets.{key}')


def _declared(asset: dict, key: str, *, guard: bool = False) -> dict:
    v=asset.get(key)
    if v is None: return unavailable('not independently declared/verified',f'assets.{key}')
    if not isinstance(v,(str,int,bool,list,dict)):
        return field(source=f'assets.{key}',state='invalid',reason='invalid declaration type')
    if guard and isinstance(v,str) and not v.strip():
        return field(source=f'assets.{key}',state='invalid',reason='empty declaration')
    return field(v,source=f'operator-declared:{key}',scope='declaration-not-automatically-proven')


def collect(*, host_role:str, interface:str, run_id:str, attempt_id:str, arm:str, assets:dict,
            reader:Reader|None=None) -> dict:
    if platform.system()!='Linux': raise ValueError('Linux-only inventory')
    if host_role not in ROLES: raise ValueError('bad host role')
    if arm not in ('A','B','C'):raise ValueError('arm must be A, B, or C')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}',interface):raise ValueError('unsafe iface')
    if not all(isinstance(s,str) and ID_RE.fullmatch(s) for s in (run_id,attempt_id)):
        raise ValueError('bad run/attempt identifiers')
    if not isinstance(assets,dict):raise ValueError('assets must be object')
    r=reader or Reader()
    started=time.monotonic_ns()
    pinfo=_single_cpu_info(r.read('/proc/cpuinfo'))
    lscpu=r.cmd('lscpu',['lscpu'])
    lfields=_parse_kv(lscpu)
    osrel=_parse_kv(r.read('/etc/os-release'),'=')
    aff=sorted(os.sched_getaffinity(0))
    cpuset=r.read('/sys/fs/cgroup/cpuset.cpus.effective')
    effective=_list_from_range(cpuset) or aff
    online=_list_from_range(r.read('/sys/devices/system/cpu/online'))
    cpu_sys=r.at('/sys/devices/system/cpu')
    policies=[]
    for directory in sorted((cpu_sys/'cpufreq').glob('policy[0-9]*')) if (cpu_sys/'cpufreq').is_dir() else []:
        vals={name:_read(directory/name) for name in ('affected_cpus','scaling_driver','scaling_governor',
             'scaling_min_freq','scaling_max_freq','scaling_cur_freq','cpuinfo_cur_freq','cpuinfo_max_freq')}
        policies.append({'policy':directory.name,'values':vals})
    govs={p['values']['scaling_governor'] for p in policies}
    gov=sorted(govs) if policies and None not in govs else None
    turbo_intel=_raw_bool(r.read('/sys/devices/system/cpu/intel_pstate/no_turbo'),invert=True)
    turbo_amd=_raw_bool(r.read('/sys/devices/system/cpu/cpufreq/boost'))
    turbo=turbo_intel if turbo_intel is not None else turbo_amd
    cpu_values={
      **{k:field(v,source='/proc/cpuinfo',reason=None if v is not None else 'missing or heterogeneous CPUinfo') for k,v in pinfo.items()},
    }
    topo={'sockets':lfields.get('Socket(s)'), 'cores_per_socket':lfields.get('Core(s) per socket'),
          'threads_per_core':lfields.get('Thread(s) per core'), 'numa_nodes':lfields.get('NUMA node(s)'),
          'effective_cpuset':effective,'online_cpus':online}
    m=_parse_kv(r.read('/proc/meminfo'))
    iface_root=r.at(f'/sys/class/net/{interface}')
    if not iface_root.is_dir():raise ValueError(f'network interface absent: {interface}')
    dev=iface_root/'device'
    pci_vendor=_read(dev/'vendor');pci_device=_read(dev/'device');pci_subsystem=_read(dev/'subsystem_device')
    pci_id={'vendor':pci_vendor,'device':pci_device,'subsystem':pci_subsystem} if pci_vendor and pci_device else None
    pci_slot=dev.resolve().name if dev.exists() else None
    lspci=r.cmd('lspci_device',['lspci','-nn','-s',pci_slot]) if pci_slot and re.fullmatch(r'[0-9a-fA-F:.]+',pci_slot) else None
    eth_info=r.cmd('ethtool_info',['ethtool','-i',interface]); eth_k=r.cmd('ethtool_features',['ethtool','-k',interface]);eth_l=r.cmd('ethtool_channels',['ethtool','-l',interface]);
    eth_speed=r.cmd('ethtool_speed',['ethtool',interface]);eth_rss=r.cmd('ethtool_rss',['ethtool','-x',interface]);
    eth_kv=_parse_kv(eth_info)
    speed=_parse_kv(eth_speed).get('Speed')
    speed_mbps=int(speed[:-4]) if speed and re.fullmatch(r'\d+Mb/s',speed) else None
    offloads={k:v for k,v in _parse_kv(eth_k).items() if k in (
      'tcp-segmentation-offload','generic-segmentation-offload','generic-receive-offload',
      'udp-fragmentation-offload','tx-udp-segmentation','rx-udp-gro-forwarding',
      'rx-gro-list','tx-checksumming','rx-checksumming')}
    ip_link=r.cmd('ip_link',['ip','-details','link','show','dev',interface])
    irq_raw=r.read('/proc/interrupts')
    # Map MSI-X IRQs from THIS PCI NIC to Linux effective affinities. Avoid
    # attributing all /proc/interrupts to the experiment interface.
    irq_dir=dev/'msi_irqs'
    irq_affinity={}
    if irq_dir.is_dir():
        for item in sorted(irq_dir.iterdir(),key=lambda p:p.name):
            if not item.name.isdecimal():continue
            target=r.read('/proc/irq/'+item.name+'/effective_affinity_list')
            if target is None:target=r.read('/proc/irq/'+item.name+'/smp_affinity_list')
            irq_affinity[item.name]=target
    if not irq_affinity or any(v is None for v in irq_affinity.values()):
        irq_affinity=None
    sysctl_keys=('net.core.rmem_max','net.core.wmem_max','net.ipv4.tcp_congestion_control',
                 'net.ipv4.tcp_rmem','net.ipv4.tcp_wmem','net.ipv4.udp_rmem_min','net.ipv4.udp_wmem_min')
    sysctl={k:r.read('/proc/sys/'+k.replace('.','/')) for k in sysctl_keys}
    mem_node=r.read('/sys/devices/system/node/online')
    mem_policy=r.cmd('numactl_show',['numactl','--show'])
    ldd_nginx=r.cmd('ldd_nginx',['ldd',assets['nginx_binary']]) if host_role=='dut' and isinstance(assets.get('nginx_binary'),str) and Path(assets['nginx_binary']).is_file() else None
    ldd_client=r.cmd('ldd_client',['ldd',assets['client_binary']]) if host_role=='client' and isinstance(assets.get('client_binary'),str) and Path(assets['client_binary']).is_file() else None
    nginxv=r.cmd('nginx_version',[assets['nginx_binary'],'-V']) if host_role=='dut' and isinstance(assets.get('nginx_binary'),str) and Path(assets['nginx_binary']).is_file() else None
    # nginx -V normally writes to stderr: configured flags must be sourced from
    # a separately declared build receipt unless command evidence supports it.
    clientv=r.cmd('client_version',[assets['client_binary'],'--version']) if host_role=='client' and isinstance(assets.get('client_binary'),str) and Path(assets['client_binary']).is_file() else None
    categories={g:{k:unavailable('not observed at inventory stage') for k in FIELD_SPEC[g]} for g in GROUPS}
    def put(g,k,v,source):
        categories[g][k]=field(v,source=source,reason=None if v is not None else 'not available on this environment')
    for k,v in cpu_values.items():categories['cpu'][k]=v
    for k,v in topo.items():put('cpu_topology',k,v,'lscpu+/sys+/proc' if k not in ('effective_cpuset','online_cpus') else '/sys+affinity')
    for k,v,src in [
      ('cpufreq_policies',policies if policies else None,'/sys/devices/system/cpu/cpufreq'),
      ('governor',gov,'cpufreq policy'),('turbo_state',turbo,'cpufreq boost/no_turbo'),
      ('affinity',aff,'sched_getaffinity')]: put('cpu_execution',k,v,src)
    put('memory','ram_kib',int(m['MemTotal'].split()[0]) if 'MemTotal' in m and m['MemTotal'].split()[0].isdigit() else None,'/proc/meminfo')
    put('memory','numa_memory_nodes',_list_from_range(mem_node),'/sys/devices/system/node/online')
    put('memory','numa_policy',mem_policy,'numactl --show')
    for k,v,src in [('interface',interface,'operator'),('mac_identity',_read(iface_root/'address'),'/sys/class/net'),
       ('pci_id',pci_id,'/sys/class/net/IF/device'),('model',lspci.strip() if lspci else None,'lspci -nn -s PCI'),
       ('driver',eth_kv.get('driver'), 'ethtool -i'),('firmware',eth_kv.get('firmware-version'),'ethtool -i'),
       ('link_speed_mbps',speed_mbps,'ethtool IF'),('link_carrier',_raw_bool(_read(iface_root/'carrier')),'/sys/class/net/IF/carrier'),
       ('pcie_link',{'speed':_read(dev/'current_link_speed'),'width':_read(dev/'current_link_width')}
          if _read(dev/'current_link_speed') and _read(dev/'current_link_width') else None,'/sys/class/net/IF/device')]: put('nic',k,v,src)
    put('packet_io','mtu',int(_read(iface_root/'mtu')) if (_read(iface_root/'mtu') or '').isdigit() else None,'/sys/class/net/IF/mtu')
    put('packet_io','tcp_offloads',({k:v for k,v in offloads.items() if 'udp' not in k} if eth_k is not None else None),'ethtool -k')
    put('packet_io','udp_gso_gro',({k:v for k,v in offloads.items() if 'udp' in k or 'gro' in k} if eth_k is not None else None),'ethtool -k')
    put('packet_io','nic_channels',eth_l,'ethtool -l')
    put('packet_io','rss_queues',eth_rss,'ethtool -x')
    put('packet_io','irq_affinity',irq_affinity,'/proc/irq/*/smp_affinity_list')
    categories['packet_io']['quic_gso']=_declared(assets,'quic_gso') if host_role=='dut' else field(source='protocol',state='not_applicable',reason='client is not NGINX QUIC server')
    put('packet_io','socket_buffers',({k:sysctl[k] for k in sysctl_keys if 'mem' in k} if all(sysctl[k] is not None for k in sysctl_keys if 'mem' in k) else None),'/proc/sys/net')
    for k,v,src in [ ('kernel',platform.release(),'uname'),('distribution',osrel.get('PRETTY_NAME') or osrel.get('ID'),'/etc/os-release'),
       ('boot_id',r.read('/proc/sys/kernel/random/boot_id'),'/proc/sys/kernel/random/boot_id'),('sysctl',sysctl if all(v is not None for v in sysctl.values()) else None,'/proc/sys/net'),
       ('interrupts',digest(irq_raw.encode()) if irq_raw else None,'/proc/interrupts hash'),
       ('irqbalance',None,'service status not probed'),('bios',r.read('/sys/class/dmi/id/bios_version'),'/sys/class/dmi/id/bios_version'),
       ('virtualization','container' if r.at('/.dockerenv').exists() or r.at('/run/.containerenv').exists() else 'unverified-physical-or-vm','container marker')]:put('os',k,v,src)
    if host_role=='dut':
        for k,src_key in [('binary_sha256','nginx_binary'),('patch_sha256','nginx_patch'),('runtime_config_sha256','nginx_config')]: categories['nginx'][k]=_asset_field(assets,src_key)
        if arm in ('A','B'):
            categories['nginx']['patch_sha256']=field(source='arm',state='not_applicable',reason='stock NGINX without NGI541 patch')
        for k in ('source_revision','worker_affinity'):categories['nginx'][k]=_declared(assets,'nginx_'+k)
        if ldd_nginx is None or 'not found' in ldd_nginx:
            categories['nginx']['ngi541_dynamic_dependency']=unavailable(
                'NGINX dependency resolution failed or unresolved','ldd nginx')
        else:
            has_engine=bool(re.search(r'(?m)^\s*libngi541_engine\.so(?:\.[^\s]+)?\s+=>',ldd_nginx))
            categories['nginx']['ngi541_dynamic_dependency']=field(has_engine,source='ldd nginx')
        categories['nginx']['configure_flags']=field(
            nginxv.split('configure arguments:',1)[1].strip() if nginxv and 'configure arguments:' in nginxv else None,
            source='nginx -V',reason=None if nginxv and 'configure arguments:' in nginxv else 'nginx -V configure arguments not available')
        if categories['nginx']['configure_flags']['state']!='measured':
            categories['nginx']['configure_flags']=_declared(assets,'nginx_configure_flags')
        for k,src in [('openssl_source_sha256','openssl_source_archive'),
                      ('openssl_binary_sha256','openssl_library'),
                      ('ngi541_binary_sha256','ngi541_library')]:categories['crypto'][k]=_asset_field(assets,src)
        link_mode=('shared' if ldd_nginx and re.search(r'(?m)^\s*lib(?:ssl|crypto)\.so(?:\.[^\s]+)?\s+=>',ldd_nginx)
                   else 'static-or-embedded' if ldd_nginx and nginxv and 'OpenSSL' in nginxv
                   else None)
        put('crypto','openssl_linkage_mode',link_mode,'nginx -V + ldd nginx')
        if link_mode=='static-or-embedded':
            categories['crypto']['openssl_binary_sha256']=field(source='nginx-linkage',state='not_applicable',
                reason='no external OpenSSL shared library; use source archive hash and complete NGINX binary hash')
        for k in ('openssl_revision','ngi541_revision','dispatch_isa_path'): categories['crypto'][k]=_declared(assets,k)
        if arm in ('A','B'):
            for k in ('ngi541_revision','ngi541_binary_sha256'):
                categories['crypto'][k]=field(source='arm',state='not_applicable',reason='NGI541 is not linked to stock NGINX')
    else:
        categories['client']['binary_sha256']=_asset_field(assets,'client_binary')
        categories['client']['client_version']=field(clientv.splitlines()[0] if clientv else None,
            source='client --version',reason=None if clientv else 'client executable not runnable')
        for k in ('tls_provider','h2_h3_capability'):categories['client'][k]=_declared(assets,k)
        if ldd_client is None or 'not found' in ldd_client:categories['client']['client_ngi541_dependency']=unavailable('ELF dependencies not fully resolved','ldd client')
        else:categories['client']['client_ngi541_dependency']=field(bool(re.search(r'(?m)^\s*libngi541_engine\.so(?:\.[^\s]+)?\s+=>',ldd_client)),source='ldd client')
    categories['workload']['corpus_sha256']=_asset_field(assets,'corpus_manifest')
    categories['workload']['stream_schedule_sha256']=_asset_field(assets,'stream_schedule')
    for k in ('object_identifiers','profile_id','cache_policy'):categories['workload'][k]=_declared(assets,k)
    # Fill with explicit role-inapplicable status. Never represent as zero.
    for irrelevant in ('client',) if host_role=='dut' else ('nginx','crypto'):
        for k in FIELD_SPEC[irrelevant]:categories[irrelevant][k]=field(source='role',state='not_applicable',reason=f'{irrelevant} is not measured on role={host_role}')
    ended=time.monotonic_ns()
    evidence={
      'schema_version':1,'revision':REVISION,'kind':'linux-environment-evidence',
      'run_id':run_id,'attempt_id':attempt_id,'host_role':host_role,'arm':arm,
      'context':{'kernel_hostname':socket.gethostname(),'interface':interface,
                 'boot_id':r.read('/proc/sys/kernel/random/boot_id'),
                 'observation_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 'capture_monotonic_ns_before':started,'capture_monotonic_ns_after':ended,
                 'environment_class':'container' if r.at('/.dockerenv').exists() or r.at('/run/.containerenv').exists() else 'unverified',
                 'authoritative_bare_metal_attestation':False},
      'categories':categories,
      'command_evidence':r.commands,
      'evidence_policy':'evidence-only; no automatic scientific qualification',
      'qualified_primary_result':False,
    }
    validate(evidence)
    return evidence


def validate(obj:dict)->None:
    if not isinstance(obj,dict) or obj.get('revision')!=REVISION or obj.get('kind')!='linux-environment-evidence':
        raise ValueError('invalid environment revision/kind')
    if obj.get('host_role') not in ROLES or obj.get('arm') not in ('A','B','C') or obj.get('qualified_primary_result') is not False:
        raise ValueError('role/qualification misrepresentation')
    if any(not isinstance(obj.get(k),str) or not ID_RE.fullmatch(obj[k]) for k in ('run_id','attempt_id')):
        raise ValueError('bad provenance identifiers')
    ctx=obj.get('context')
    if not isinstance(ctx,dict) or not ctx.get('boot_id') or ctx.get('authoritative_bare_metal_attestation') is not False:
        raise ValueError('missing boot identity or unauthorized bare-metal assertion')
    cats=obj.get('categories')
    if not isinstance(cats,dict) or set(cats)!=set(GROUPS):raise ValueError('11 DoD categories required')
    for g,fields in FIELD_SPEC.items():
        group=cats[g]
        if not isinstance(group,dict) or set(group)!=set(fields):raise ValueError(f'{g}: field coverage mismatch')
        for k,rec in group.items():
            if not isinstance(rec,dict) or set(rec)!=set(('state','value','source','scope','reason')):
                raise ValueError(f'{g}.{k}: evidence shape')
            state=rec['state']
            if state not in STATES or not isinstance(rec['source'],str) or not rec['source'] or not isinstance(rec['scope'],str) or not rec['scope']:
                raise ValueError(f'{g}.{k}: invalid state/provenance')
            if state=='measured':
                if rec['value'] is None or rec['reason'] is not None:raise ValueError(f'{g}.{k}: false measurement')
            elif rec['value'] is not None or not isinstance(rec['reason'],str) or not rec['reason']:
                raise ValueError(f'{g}.{k}: missing reason or invented value')
    if not isinstance(obj.get('command_evidence'),dict):raise ValueError('command provenance missing')


def _focus(obj:dict, *, paired:bool=False)->dict:
    out={}
    for g in GROUPS:
        for name,rec in obj['categories'][g].items():
            path=f'{g}.{name}'
            if path in DYNAMIC_FIELDS:continue
            # Only values from the expected role are included.
            if rec['state']=='not_applicable' and not (paired and path in VARIANT_DIFFERENCES):continue
            # Exclude purely diagnostic/sampled inventory values from frozen ID.
            if path in ('memory.numa_policy','nic.mac_identity',
                        'nic.link_carrier','nic.pcie_link','nic.model',
                        'packet_io.nic_channels','packet_io.rss_queues','os.irqbalance','os.bios',
                        'os.interrupts','cpu_execution.frequency_stability','memory.memory_pressure'):
                continue
            val=rec['value']
            if path=='cpu_execution.cpufreq_policies' and isinstance(val,list):
                val=[{'policy':v['policy'],'settings':{k:x for k,x in v['values'].items()
                      if k not in ('scaling_cur_freq','cpuinfo_cur_freq')}} for v in val]
            out[path]={'state':rec['state'],'value':val}
    return out


def completeness(obj:dict)->dict:
    validate(obj)
    missing=[]
    unverified=[]
    for group,keys in REQUIRED_BY_ROLE[obj['host_role']].items():
        for key in keys:
            rec=obj['categories'][group][key]
            if obj['host_role']=='dut' and obj['arm'] in ('A','B') and (group,key) in (
               ('nginx','patch_sha256'),('crypto','ngi541_revision'),('crypto','ngi541_binary_sha256')):
                if rec['state']!='not_applicable':missing.append({'field':group+'.'+key,'state':rec['state'],'reason':'expected not_applicable on stock arm'})
                continue
            if (group,key)==('crypto','openssl_binary_sha256') and obj['host_role']=='dut' and (
                obj['categories']['crypto']['openssl_linkage_mode']['value']=='static-or-embedded'):
                continue
            if rec['state']!='measured':missing.append({'field':group+'.'+key,'state':rec['state'],'reason':rec['reason']})
            elif rec['scope']=='declaration-not-automatically-proven':
                unverified.append(group+'.'+key)
    if obj['host_role']=='dut':
        engine_link=obj['categories']['nginx']['ngi541_dynamic_dependency']
        expected=obj['arm']=='C'
        if engine_link['state']!='measured' or engine_link['value'] is not expected:
            missing.append({'field':'nginx.ngi541_dynamic_dependency',
                'state':engine_link['state'],'reason':f'expected NGI541 shared linkage={expected}; actual={engine_link["value"]}'})
    else:
        engine_link=obj['categories']['client']['client_ngi541_dependency']
        if engine_link['state']!='measured' or engine_link['value'] is not False:
            missing.append({'field':'client.client_ngi541_dependency',
                'state':engine_link['state'],'reason':'client requires resolved ELF dependencies without NGI541'})
    class_state=obj['context']['environment_class']
    return {'identity_fields_complete':not missing and not unverified, 'missing_mandatory':missing,
            'unverified_declarations':unverified,
            'environment_class':class_state,
            'status':'evidence-complete-not-qualified' if not missing and not unverified else 'incomplete-not-qualified',
            'bare_metal_qualified':False,
            'note':'physical CloudLab attestation, drift and main-window gates are separate'}


def compare(a:dict,b:dict, *,mode:str='same-role',
            approved_differences:dict|None=None)->dict:
    """Do not auto-ignore variant differences: require exact before/after approval.

    Approved exceptions use {"nginx.binary_sha256": {"before": "...", "after": "..."}}
    and may only cover VARIANT_DIFFERENCES. Other mismatches invalidate B/C.
    """
    if mode not in ('same-role','bc-pair'):raise ValueError('invalid drift comparison mode')
    validate(a);validate(b)
    if a['host_role']!=b['host_role']:raise ValueError('cannot compare different host roles')
    if mode=='bc-pair' and (a['arm'],b['arm'])!=('B','C'):
        raise ValueError('B/C pairing requires ordered B -> C evidence')
    if mode=='same-role' and a['arm']!=b['arm']:
        raise ValueError('same-role drift requires same experimental arm')
    approved=approved_differences or {}
    if not isinstance(approved,dict) or (approved and mode!='bc-pair'):
        raise ValueError('approved differences permitted only for B/C pairing')
    if set(approved)-VARIANT_DIFFERENCES:
        raise ValueError('approval attempts to exempt non-variant control')
    if any(not isinstance(v,dict) or set(v)!=set(('before','after'))
           for v in approved.values()):
        raise ValueError('each difference approval needs exact before and after values')
    if a['context']['boot_id']!=b['context']['boot_id']:
        return {'kind':'m2-environment-drift','revision':REVISION,'mode':mode,
                'status':'fail','changed':[{'field':'context.boot_id','before':a['context']['boot_id'],
                             'after':b['context']['boot_id']}],
                'unresolved':[],'approved':[],'qualified_primary_result':False}
    before=_focus(a,paired=(mode=='bc-pair'));after=_focus(b,paired=(mode=='bc-pair'))
    changed=[]; unresolved=[]; accepted=[]
    for k in sorted(before.keys()|after.keys()):
        left=before.get(k);right=after.get(k)
        if left is None or right is None:unresolved.append(k);continue
        candidate={'before':left['value'],'after':right['value']}
        if left['state']!='measured' or right['state']!='measured':
            # A stock-side NOT_APPLICABLE is a legitimate B/C difference only
            # with a precise operator-reviewed exception, not blanket skipping.
            state_candidate={'before':{'state':left['state'],'value':left['value']},
                             'after':{'state':right['state'],'value':right['value']}}
            if (mode=='bc-pair' and k in approved and k in VARIANT_DIFFERENCES
                and approved[k]==state_candidate and left['state'] in ('measured','not_applicable')
                and right['state'] in ('measured','not_applicable')):
                accepted.append({'field':k,**state_candidate})
            else:unresolved.append(k)
            continue
        if left!=right:
            if mode=='bc-pair' and k in approved and approved[k]==candidate:
                accepted.append({'field':k,**candidate})
            else:changed.append({'field':k,**candidate})
    # Prevent bogus approval of fields that did not differ or were unavailable.
    if set(approved) != {x['field'] for x in accepted}:
        raise ValueError('approved difference not matched by exact observed values')
    status='fail' if changed else 'unqualified' if unresolved else 'identity-match-only'
    return {'kind':'m2-environment-drift','revision':REVISION,'mode':mode,
            'status':status,'changed':changed,'unresolved':unresolved,'approved':accepted,
            'before_fingerprint_sha256':digest(canonical(before)),
            'after_fingerprint_sha256':digest(canonical(after)),
            'qualified_primary_result':False}
