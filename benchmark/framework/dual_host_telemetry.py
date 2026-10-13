from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from framework.io_utils import FrameworkError, atomic_write_json, atomic_write_text
from framework.host_state import _darwin_thermal
from framework.loadgen_runtime import definition_sha256 as loadgen_definition_sha256
from framework.loadgen_runtime import load_definition as load_loadgen_definition
from framework.network_evidence import definition_sha256 as network_evidence_definition_sha256
from framework.network_evidence import load_definition as load_network_evidence_definition
from framework.network_qualification import SSHSession
from framework.transport_security import definition_sha256 as transport_security_definition_sha256
from framework.transport_security import load_definition as load_transport_security_definition

SCHEMA_VERSION = 1


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _semantic_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_id_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _slug(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not value:
        raise FrameworkError("qualification.name must contain an alphanumeric character")
    return value


def definition_sha256(definition: dict[str, Any]) -> str:
    return _semantic_sha256(definition)


def load_definition(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FrameworkError(f"dual-host telemetry config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FrameworkError(
            f"invalid dual-host telemetry JSON: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise FrameworkError("dual-host telemetry definition must be a JSON object")
    validate_definition(value)
    return value


def _relative_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FrameworkError(f"{field} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise FrameworkError(f"{field} must be a portable repository-relative path")
    return value


def validate_definition(definition: dict[str, Any]) -> None:
    if definition.get("schema_version") != SCHEMA_VERSION:
        raise FrameworkError("dual-host telemetry schema_version must be 1")
    qualification = definition.get("qualification")
    if not isinstance(qualification, dict) or not isinstance(qualification.get("name"), str) or not qualification["name"].strip():
        raise FrameworkError("qualification.name must be a non-empty string")

    inputs = definition.get("inputs")
    if not isinstance(inputs, dict):
        raise FrameworkError("inputs must be an object")
    for key in ("network_evidence_config", "loadgen_runtime_config", "transport_security_config"):
        _relative_path(inputs.get(key), f"inputs.{key}")

    sampling = definition.get("sampling")
    if not isinstance(sampling, dict):
        raise FrameworkError("sampling must be an object")
    count = sampling.get("sample_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 4:
        raise FrameworkError("sampling.sample_count must be an integer >= 4")
    interval = sampling.get("interval_seconds")
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 0.25 <= float(interval) <= 10:
        raise FrameworkError("sampling.interval_seconds must be in [0.25, 10]")
    probes = sampling.get("clock_alignment_probes")
    if not isinstance(probes, int) or isinstance(probes, bool) or probes < 3:
        raise FrameworkError("sampling.clock_alignment_probes must be an integer >= 3")

    dut = definition.get("dut")
    remote = definition.get("loadgen")
    if not isinstance(dut, dict) or dut.get("provider") != "darwin-local":
        raise FrameworkError("dut.provider must be 'darwin-local'")
    if not isinstance(remote, dict) or remote.get("provider") != "linux-ssh":
        raise FrameworkError("loadgen.provider must be 'linux-ssh'")
    if dut.get("require_ac_power") is not True:
        raise FrameworkError("dut.require_ac_power must be true for controlled telemetry qualification")
    if dut.get("require_no_throttling") is not True:
        raise FrameworkError("dut.require_no_throttling must be true for controlled telemetry qualification")
    power = dut.get("power")
    if not isinstance(power, dict) or power.get("mode") != "optional-estimated-package":
        raise FrameworkError("dut.power.mode must be 'optional-estimated-package'")
    if power.get("comparison_scope") != "same-host-paired-only":
        raise FrameworkError("dut.power.comparison_scope must be 'same-host-paired-only'")
    remote_power = remote.get("power")
    if not isinstance(remote_power, dict) or remote_power.get("mode") != "unavailable-without-external-sensor":
        raise FrameworkError("loadgen.power.mode must be 'unavailable-without-external-sensor'")


def parse_powermetrics_line(line: str) -> dict[str, float | str]:
    out: dict[str, float | str] = {}
    match = re.search(r"Intel energy model derived package power .*?:\s*([0-9]+(?:\.[0-9]+)?)\s*W", line, re.I)
    if match:
        out["package_power_w_estimate"] = float(match.group(1))
        out["package_power_source"] = "powermetrics-intel-energy-model"
    match = re.search(r"^\s*Package Power:\s*([0-9]+(?:\.[0-9]+)?)\s*(mW|W)\s*$", line, re.I)
    if match:
        value = float(match.group(1))
        if match.group(2).lower() == "mw":
            value /= 1000.0
        out["package_power_w_estimate"] = value
        out["package_power_source"] = "powermetrics-package-estimate"
    match = re.search(r"^\s*CPU Power:\s*([0-9]+(?:\.[0-9]+)?)\s*(mW|W)\s*$", line, re.I)
    if match:
        value = float(match.group(1))
        if match.group(2).lower() == "mw":
            value /= 1000.0
        out["cpu_power_w_estimate"] = value
    match = re.search(r"CPU die temperature:\s*([0-9]+(?:\.[0-9]+)?)\s*C", line, re.I)
    if match:
        out["temperature_c"] = float(match.group(1))
    match = re.search(r"Current pressure level:\s*([A-Za-z]+)", line, re.I)
    if match:
        out["thermal_pressure"] = match.group(1).lower()
    match = re.search(r"System Average frequency.*?\(([0-9]+(?:\.[0-9]+)?)\s*Mhz\)", line, re.I)
    if match:
        out["average_frequency_mhz"] = float(match.group(1))
    match = re.search(r"^\s*Fan:\s*([0-9]+(?:\.[0-9]+)?)\s*rpm", line, re.I)
    if match:
        out["fan_rpm"] = float(match.group(1))
    return out


def parse_darwin_netstat(text: str, interface: str) -> dict[str, int] | None:
    header: list[str] | None = None
    candidates: list[dict[str, int]] = []
    for raw in text.splitlines():
        parts = raw.split()
        if not parts:
            continue
        if parts[0] == "Name" and "Ipkts" in parts and "Ibytes" in parts and "Opkts" in parts and "Obytes" in parts:
            header = parts
            continue
        if header is None or parts[0] != interface or len(parts) < len(header):
            continue
        row = dict(zip(header, parts))
        try:
            candidates.append({
                "rx_packets": int(row["Ipkts"]),
                "rx_errors": int(row.get("Ierrs", "0")),
                "rx_bytes": int(row["Ibytes"]),
                "tx_packets": int(row["Opkts"]),
                "tx_errors": int(row.get("Oerrs", "0")),
                "tx_bytes": int(row["Obytes"]),
            })
        except (KeyError, ValueError):
            continue
    if not candidates:
        return None
    return max(candidates, key=lambda item: item["rx_bytes"] + item["tx_bytes"])


def parse_cpu_time(text: str) -> float:
    """Parse BSD/Linux ``ps`` cumulative CPU time.

    Darwin's BSD ``ps`` prints TIME with fractional seconds (for example
    ``0:00.00``), while Linux commonly prints integral ``MM:SS`` or
    ``HH:MM:SS``.  Preserve the fractional component so a short-lived
    process remains a valid telemetry root instead of being discarded.
    """
    value = text.strip()
    days = 0
    if "-" in value:
        day_text, value = value.split("-", 1)
        days = int(day_text)
    parts = value.split(":")
    if len(parts) == 2:
        hours = 0
        minutes = int(parts[0])
        seconds = float(parts[1])
    elif len(parts) == 3:
        hours = int(parts[0])
        minutes = int(parts[1])
        seconds = float(parts[2])
    else:
        raise ValueError(f"unsupported CPU time: {text!r}")
    return float(days * 86400 + hours * 3600 + minutes * 60 + seconds)


def parse_ps_process_tree(text: str, root_pid: int) -> dict[str, Any] | None:
    rows: dict[int, dict[str, Any]] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 4)
        if len(parts) < 5:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
            cpu_seconds = parse_cpu_time(parts[2])
            rss_bytes = int(parts[3]) * 1024
        except (ValueError, IndexError):
            continue
        rows[pid] = {"pid": pid, "ppid": ppid, "cpu_seconds": cpu_seconds, "rss_bytes": rss_bytes, "command": parts[4]}
    if root_pid not in rows:
        return None
    selected = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, row in rows.items():
            if pid not in selected and row["ppid"] in selected:
                selected.add(pid)
                changed = True
    chosen = [rows[pid] for pid in sorted(selected)]
    return {
        "root_pid": root_pid,
        "process_count": len(chosen),
        "cpu_seconds": sum(float(row["cpu_seconds"]) for row in chosen),
        "rss_bytes": sum(int(row["rss_bytes"]) for row in chosen),
        "pids": [row["pid"] for row in chosen],
    }


def integrate_power_energy_j(samples: list[dict[str, Any]]) -> float | None:
    points: list[tuple[int, float]] = []
    for sample in samples:
        value = sample.get("power", {}).get("package_power_w_estimate")
        stamp = sample.get("monotonic_ns")
        if isinstance(value, (int, float)) and not isinstance(value, bool) and isinstance(stamp, int):
            points.append((stamp, float(value)))
    if len(points) < 2:
        return None
    points.sort()
    energy = 0.0
    for (t0, p0), (t1, p1) in zip(points, points[1:]):
        if t1 <= t0:
            continue
        energy += ((p0 + p1) / 2.0) * ((t1 - t0) / 1e9)
    return energy


class DarwinPowermetricsTelemetry:
    def __init__(self, interval_seconds: float, raw_path: Path):
        self.interval_seconds = interval_seconds
        self.raw_path = raw_path
        self.process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._latest: dict[str, Any] = {}
        self._sample_monotonic_ns: int | None = None
        self._stderr: list[str] = []
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        sudo = shutil.which("sudo") or "/usr/bin/sudo"
        powermetrics = shutil.which("powermetrics") or "/usr/bin/powermetrics"
        if subprocess.run([sudo, "-v"], check=False).returncode != 0:
            raise FrameworkError("unable to establish sudo credentials for powermetrics telemetry")
        verify = subprocess.run([sudo, "-n", "-v"], check=False, capture_output=True, text=True)
        if verify.returncode != 0:
            raise FrameworkError("powermetrics sudo credentials are not reusable non-interactively")
        interval_ms = max(250, int(round(self.interval_seconds * 1000)))
        command = [sudo, "-n", powermetrics, "--samplers", "cpu_power,smc,thermal", "-i", str(interval_ms)]
        self.raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_handle = self.raw_path.open("w", encoding="utf-8", newline="\n")
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        except OSError as exc:
            raw_handle.close()
            raise FrameworkError(f"unable to start powermetrics telemetry: {exc}") from exc
        assert self.process.stdout is not None and self.process.stderr is not None
        self._threads = [
            threading.Thread(target=self._consume_stdout, args=(self.process.stdout, raw_handle), daemon=True),
            threading.Thread(target=self._consume_stderr, args=(self.process.stderr,), daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise FrameworkError("powermetrics telemetry exited before first usable sample: " + " | ".join(self._stderr[-10:]))
            if self.snapshot().get("temperature_c") is not None:
                return
            time.sleep(0.1)
        raise FrameworkError("powermetrics telemetry did not provide temperature within 15 seconds")

    def _consume_stdout(self, stream, raw_handle) -> None:
        try:
            for line in stream:
                raw_handle.write(line)
                raw_handle.flush()
                parsed = parse_powermetrics_line(line)
                if not parsed:
                    continue
                with self._lock:
                    self._latest.update(parsed)
                    self._sample_monotonic_ns = time.monotonic_ns()
        finally:
            raw_handle.close()

    def _consume_stderr(self, stream) -> None:
        for line in stream:
            text = line.strip()
            if text:
                with self._lock:
                    self._stderr.append(text)
                    del self._stderr[:-20]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            result = dict(self._latest)
            sampled = self._sample_monotonic_ns
        result["sample_age_seconds"] = None if sampled is None else max(0.0, (time.monotonic_ns() - sampled) / 1e9)
        return result

    def stop(self) -> None:
        process = self.process
        self.process = None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for thread in self._threads:
            thread.join(timeout=0.5)
        self._threads = []

    def __enter__(self) -> "DarwinPowermetricsTelemetry":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


def _darwin_cpu_busy_percent() -> float | None:
    top = shutil.which("top") or "/usr/bin/top"
    try:
        result = subprocess.run([top, "-l", "1", "-n", "0"], check=False, text=True, capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"CPU usage:.*?([0-9]+(?:\.[0-9]+)?)%\s*idle", result.stdout)
    return None if not match else max(0.0, min(100.0, 100.0 - float(match.group(1))))


def _darwin_power_source() -> str:
    pmset = shutil.which("pmset") or "/usr/bin/pmset"
    try:
        result = subprocess.run([pmset, "-g", "batt"], check=False, text=True, capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    match = re.search(r"Now drawing from '([^']+)'", result.stdout)
    if not match:
        return "unknown"
    text = match.group(1).lower()
    return "ac" if "ac" in text else "battery" if "battery" in text else text


def _darwin_interface(interface: str) -> dict[str, Any] | None:
    binary = "/usr/sbin/netstat" if Path("/usr/sbin/netstat").exists() else shutil.which("netstat")
    if not binary:
        return None
    try:
        result = subprocess.run([binary, "-ibn", "-I", interface], check=False, text=True, capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    parsed = parse_darwin_netstat(result.stdout, interface)
    if parsed is not None:
        parsed["interface"] = interface
    return parsed


def _darwin_process_tree(pid: int) -> dict[str, Any] | None:
    ps = shutil.which("ps") or "/bin/ps"
    try:
        result = subprocess.run([ps, "-axo", "pid=,ppid=,time=,rss=,comm="], check=False, text=True, capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_ps_process_tree(result.stdout, pid) if result.returncode == 0 else None


REMOTE_SAMPLER = r'''import glob, json, os, re, shutil, subprocess, sys, time
iface=sys.argv[1]; pid=int(sys.argv[2]); count=int(sys.argv[3]); interval=float(sys.argv[4])
clk=os.sysconf(os.sysconf_names['SC_CLK_TCK'])
def cpu_stat():
    out={}
    with open('/proc/stat') as f:
        for line in f:
            p=line.split()
            if not p or not re.fullmatch(r'cpu\d*', p[0]):
                if out: break
                continue
            vals=[int(x) for x in p[1:]]
            idle=vals[3]+(vals[4] if len(vals)>4 else 0)
            out[p[0]]=(sum(vals),idle)
    return out
def busy(prev, cur):
    if prev is None: return None
    dt=cur[0]-prev[0]; di=cur[1]-prev[1]
    return None if dt<=0 else max(0.0,min(100.0,(1.0-di/dt)*100.0))
def freqs():
    out=[]
    for n in range(os.cpu_count() or 1):
        p=f'/sys/devices/system/cpu/cpu{n}/cpufreq/scaling_cur_freq'
        try: out.append(int(open(p).read().strip())/1000.0)
        except Exception: out.append(None)
    return out
def temp():
    # /sys/class/thermal/thermal_zone* entries are sysfs symlinks on Raspberry Pi.
    # os.walk(..., followlinks=False) therefore misses their temp files. Prefer
    # explicit thermal-zone paths, then hwmon, then vcgencmd as a firmware fallback.
    candidates=[]
    try:
        candidates.extend(sorted(glob.glob('/sys/class/thermal/thermal_zone*/temp')))
        candidates.extend(sorted(glob.glob('/sys/class/hwmon/hwmon*/temp*_input')))
    except Exception:
        pass
    for path in candidates:
        try:
            value=float(open(path).read().strip())
            # Linux thermal/hwmon values are normally millidegrees Celsius.
            if value > 1000.0:
                value /= 1000.0
            if -20.0 <= value <= 150.0:
                return value
        except Exception:
            pass
    v=vcgencmd()
    if v:
        try:
            s=subprocess.check_output([v,'measure_temp'],text=True,timeout=2).strip()
            m=re.search(r'([0-9]+(?:\.[0-9]+)?)',s)
            if m:
                return float(m.group(1))
        except Exception:
            pass
    return None
def vcgencmd():
    for p in ('/usr/bin/vcgencmd','/opt/vc/bin/vcgencmd'):
        if os.path.isfile(p): return p
    return shutil.which('vcgencmd')
def throttled():
    v=vcgencmd()
    if not v:return (None,None)
    try:
        s=subprocess.check_output([v,'get_throttled'],text=True,timeout=2).strip()
        raw=s.split('=',1)[1]; value=int(raw,16)
        return (raw, bool(value & 0xF))
    except Exception:return (None,None)
def pmic_temp():
    v=vcgencmd()
    if not v:return None
    try:
        s=subprocess.check_output([v,'measure_temp','pmic'],text=True,timeout=2).strip()
        m=re.search(r'([0-9]+(?:\.[0-9]+)?)',s); return float(m.group(1)) if m else None
    except Exception:return None
def net():
    base=f'/sys/class/net/{iface}/statistics'; names=('rx_bytes','tx_bytes','rx_packets','tx_packets','rx_errors','tx_errors','rx_dropped','tx_dropped')
    out={'interface':iface}
    for name in names:
        try: out[name]=int(open(f'{base}/{name}').read().strip())
        except Exception: out[name]=None
    return out
def udp_errors():
    try:
        lines=open('/proc/net/snmp').read().splitlines()
        for i in range(len(lines)-1):
            if lines[i].startswith('Udp:') and lines[i+1].startswith('Udp:'):
                keys=lines[i].split()[1:]; vals=lines[i+1].split()[1:]; d=dict(zip(keys,vals)); return int(d.get('InErrors','0'))
    except Exception: pass
    return None
def proc():
    try:
        p=open(f'/proc/{pid}/stat').read().split(); cpu=(int(p[13])+int(p[14]))/clk
        rss=None
        for line in open(f'/proc/{pid}/status'):
            if line.startswith('VmRSS:'): rss=int(line.split()[1])*1024; break
        return {'root_pid':pid,'process_count':1,'cpu_seconds':cpu,'rss_bytes':rss,'pids':[pid]}
    except Exception:return None
prev=None
for idx in range(count):
    cur=cpu_stat(); total=busy(prev.get('cpu') if prev else None,cur.get('cpu'))
    cores=[]
    for key in sorted((k for k in cur if k!='cpu'),key=lambda x:int(x[3:])):
        cores.append(busy(prev.get(key) if prev else None,cur[key]))
    raw,active=throttled(); load=os.getloadavg()
    rec={'schema_version':1,'host_role':'loadgen','sample_index':idx,'wall_time_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns(),
         'cpu':{'busy_percent':total,'per_core_busy_percent':cores,'frequency_mhz':freqs()},
         'thermal':{'temperature_c':temp(),'pmic_temperature_c':pmic_temp(),'firmware_throttled_raw':raw,'throttling_active':active},
         'power':{'package_power_w_estimate':None,'source':'unavailable-no-onboard-current-sensor'},
         'load':{'load_1m':load[0],'load_5m':load[1],'load_15m':load[2]},'network':net(),'udp':{'in_errors':udp_errors()},'process':proc()}
    print(json.dumps(rec,separators=(',',':')),flush=True); prev=cur
    if idx+1<count: time.sleep(interval)
'''


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise FrameworkError(f"unable to read {label}: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise FrameworkError(f"{label} must be a JSON object")
    return value


def _discover_latest(root: Path, definition_sha: str, id_field: str) -> tuple[Path, dict[str, Any]]:
    matches=[]
    if not root.is_dir():
        raise FrameworkError(f"qualification root not found: {root}")
    for child in sorted(p for p in root.iterdir() if p.is_dir()):
        path=child/'processed'/'summary.json'
        if not path.is_file(): continue
        summary=_read_json(path,'qualification summary')
        if summary.get('status')=='COMPLETE' and summary.get('definition_sha256')==definition_sha and summary.get(id_field)==child.name:
            matches.append((child,summary))
    if not matches:
        raise FrameworkError(f"no COMPLETE qualification with definition SHA {definition_sha} in {root}")
    return matches[-1]


def _resolve_inputs(definition: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    def rp(value: str) -> Path:
        p=(repo_root/value).resolve()
        try:p.relative_to(repo_root.resolve())
        except ValueError as exc: raise FrameworkError(f"input path escapes repository: {value}") from exc
        return p
    net_def=load_network_evidence_definition(rp(definition['inputs']['network_evidence_config']))
    net_root,net_summary=_discover_latest(repo_root/'qualifications'/'network-evidence',network_evidence_definition_sha256(net_def),'evidence_id')
    envelope=_read_json(net_root/'processed'/'network-envelope.json','network envelope')
    load_def=load_loadgen_definition(rp(definition['inputs']['loadgen_runtime_config']))
    load_root,load_summary=_discover_latest(repo_root/'qualifications'/'loadgen-runtime',loadgen_definition_sha256(load_def),'runtime_id')
    sec_def=load_transport_security_definition(rp(definition['inputs']['transport_security_config']))
    sec_root,sec_summary=_discover_latest(repo_root/'qualifications'/'transport-security',transport_security_definition_sha256(sec_def),'qualification_id')
    topology=envelope.get('topology',{})
    local=topology.get('local',{}); remote=topology.get('remote',{})
    if local.get('system')!='Darwin' or remote.get('system')!='Linux':
        raise FrameworkError('R6.5.3f expects Darwin DUT and Linux loadgen topology')
    if not local.get('interface') or not remote.get('interface'):
        raise FrameworkError('network evidence is missing telemetry interfaces')
    if load_summary.get('remote',{}).get('ssh_target') != load_def['remote']['ssh_target']:
        raise FrameworkError('loadgen runtime SSH target mismatch')
    return {'network_root':net_root,'network_summary':net_summary,'envelope':envelope,'loadgen_root':load_root,'loadgen_summary':load_summary,'loadgen_definition':load_def,'security_root':sec_root,'security_summary':sec_summary,
            'dut_interface':local['interface'],'loadgen_interface':remote['interface'],'ssh_target':load_def['remote']['ssh_target']}


def _clock_alignment(ssh: SSHSession, probes: int) -> dict[str, Any]:
    rows=[]
    for _ in range(probes):
        t0=time.time_ns()
        result=ssh.run(['python3','-c','import time; print(time.time_ns())'],check=True,timeout=5)
        t1=time.time_ns()
        try: remote=int(result.stdout.strip().splitlines()[-1])
        except (ValueError,IndexError) as exc: raise FrameworkError('unable to parse remote clock probe') from exc
        midpoint=(t0+t1)//2
        rows.append({'rtt_ns':t1-t0,'remote_minus_local_ns':remote-midpoint})
    best=min(rows,key=lambda r:r['rtt_ns'])
    offsets=sorted(r['remote_minus_local_ns'] for r in rows)
    median=offsets[len(offsets)//2]
    return {'probes':rows,'best_rtt_ms':best['rtt_ns']/1e6,'median_remote_minus_local_ms':median/1e6,'method':'ssh-midpoint-wall-clock-v1'}


def _local_sample(index: int, interface: str, pid: int, pm: DarwinPowermetricsTelemetry) -> dict[str, Any]:
    p=pm.snapshot(); load=os.getloadavg()
    thermal_limits = _darwin_thermal(os.cpu_count() or 1, p.get('thermal_pressure'))
    return {'schema_version':1,'host_role':'dut','sample_index':index,'wall_time_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns(),
            'cpu':{'busy_percent':_darwin_cpu_busy_percent(),'per_core_busy_percent':None,'average_frequency_mhz':p.get('average_frequency_mhz')},
            'thermal':{'temperature_c':p.get('temperature_c'),'thermal_pressure':p.get('thermal_pressure'),'fan_rpm':p.get('fan_rpm'),'throttling_active':thermal_limits.get('throttling_active'),'performance_limit_active':thermal_limits.get('performance_limit_active'),'cpu_speed_limit_percent':thermal_limits.get('cpu_speed_limit_percent'),'sample_age_seconds':p.get('sample_age_seconds')},
            'power':{'package_power_w_estimate':p.get('package_power_w_estimate'),'cpu_power_w_estimate':p.get('cpu_power_w_estimate'),'source':p.get('package_power_source'),'estimated':p.get('package_power_w_estimate') is not None,'sample_age_seconds':p.get('sample_age_seconds')},
            'load':{'load_1m':load[0],'load_5m':load[1],'load_15m':load[2]},'network':_darwin_interface(interface),'udp':{'in_errors':None},'process':_darwin_process_tree(pid)}


def _validate_samples(local: list[dict[str, Any]], remote: list[dict[str, Any]], *, require_ac: bool, power_source: str) -> dict[str, Any]:
    if require_ac and power_source!='ac': raise FrameworkError(f'DUT must be on AC power; current source={power_source}')
    if not local or not remote: raise FrameworkError('telemetry sampling produced no samples')
    if any(s.get('thermal',{}).get('temperature_c') is None for s in local): raise FrameworkError('DUT temperature telemetry is unavailable')
    if any(s.get('network') is None for s in local): raise FrameworkError('DUT interface counters are unavailable')
    if any(s.get('process') is None for s in local): raise FrameworkError('DUT process-tree telemetry is unavailable')
    if any(s.get('thermal',{}).get('throttling_active') is None for s in local): raise FrameworkError('DUT throttling telemetry is unavailable')
    if any(s.get('thermal',{}).get('throttling_active') is True for s in local): raise FrameworkError('DUT throttling/performance limit became active during telemetry qualification')
    valid_remote_cpu=[s for s in remote if isinstance(s.get('cpu',{}).get('busy_percent'),(int,float))]
    if len(valid_remote_cpu) < max(1,len(remote)-1): raise FrameworkError('loadgen CPU telemetry is incomplete')
    if any(not isinstance(s.get('cpu',{}).get('per_core_busy_percent'),list) for s in remote): raise FrameworkError('loadgen per-core CPU telemetry is unavailable')
    valid_per_core=[s for s in remote if any(isinstance(x,(int,float)) for x in s.get('cpu',{}).get('per_core_busy_percent',[]))]
    if len(valid_per_core) < max(1,len(remote)-1): raise FrameworkError('loadgen per-core CPU telemetry is incomplete')
    if any(not any(isinstance(x,(int,float)) for x in s.get('cpu',{}).get('frequency_mhz',[])) for s in remote): raise FrameworkError('loadgen CPU frequency telemetry is unavailable')
    if any(s.get('thermal',{}).get('temperature_c') is None for s in remote): raise FrameworkError('loadgen temperature telemetry is unavailable')
    if any(s.get('thermal',{}).get('throttling_active') is None for s in remote): raise FrameworkError('loadgen firmware throttling telemetry is unavailable')
    if any(s.get('network') is None for s in remote): raise FrameworkError('loadgen interface telemetry is unavailable')
    if any(s.get('udp',{}).get('in_errors') is None for s in remote): raise FrameworkError('loadgen UDP error telemetry is unavailable')
    if any(s.get('process') is None for s in remote): raise FrameworkError('loadgen process telemetry is unavailable')
    local_power=[float(s['power']['package_power_w_estimate']) for s in local if isinstance(s.get('power',{}).get('package_power_w_estimate'),(int,float))]
    return {'dut':{'temperature':True,'system_cpu':True,'process_tree':True,'interface_counters':True,'estimated_package_power':bool(local_power)},
            'loadgen':{'temperature':True,'system_cpu':True,'per_core_cpu':True,'frequency':True,'firmware_throttling':True,'process':True,'interface_counters':True,'udp_errors':True,'power_watts':False}}


def _artifact_hashes(root: Path) -> str:
    rows=[]
    for p in sorted(x for x in root.rglob('*') if x.is_file() and x.name!='artifacts.sha256'):
        rows.append(f"{_sha256_file(p)}  {p.relative_to(root).as_posix()}")
    content='\n'.join(rows)+'\n'; atomic_write_text(root/'artifacts.sha256',content); return hashlib.sha256(content.encode()).hexdigest()


def run_dual_host_telemetry(definition: dict[str, Any], *, repo_root: Path, output_root: Path) -> dict[str, Any]:
    validate_definition(definition)
    resolved=_resolve_inputs(definition,repo_root)
    def_sha=definition_sha256(definition)
    qid=f"{_slug(definition['qualification']['name'])}-{_utc_id_timestamp()}-{def_sha[:6]}"
    root=output_root/qid
    if root.exists(): raise FrameworkError(f'telemetry qualification already exists: {root}')
    (root/'raw').mkdir(parents=True,exist_ok=False); (root/'processed').mkdir(parents=True); (root/'inputs').mkdir(parents=True)
    atomic_write_json(root/'config.json',definition)
    atomic_write_json(root/'inputs'/'resolved.json',{
        'network_evidence_id':resolved['network_summary']['evidence_id'],'network_envelope_sha256':_sha256_file(resolved['network_root']/'processed'/'network-envelope.json'),
        'loadgen_runtime_id':resolved['loadgen_summary']['runtime_id'],'loadgen_summary_sha256':_sha256_file(resolved['loadgen_root']/'processed'/'summary.json'),
        'transport_security_id':resolved['security_summary']['qualification_id'],'transport_security_summary_sha256':_sha256_file(resolved['security_root']/'processed'/'summary.json'),
        'dut_interface':resolved['dut_interface'],'loadgen_interface':resolved['loadgen_interface'],'ssh_target':resolved['ssh_target']})
    count=definition['sampling']['sample_count']; interval=float(definition['sampling']['interval_seconds'])
    local_proc=subprocess.Popen(['/bin/sleep','60'])
    local_samples=[]; remote_samples=[]
    try:
        with SSHSession(resolved['ssh_target']) as ssh:
            alignment=_clock_alignment(ssh,definition['sampling']['clock_alignment_probes'])
            remote_pid_result=ssh.run(['sh','-lc','sleep 60 >/dev/null 2>&1 & echo $!'],check=True,timeout=5)
            remote_pid=int(remote_pid_result.stdout.strip().splitlines()[-1])
            with DarwinPowermetricsTelemetry(interval,root/'raw'/'dut-powermetrics.txt') as pm:
                def collect_remote():
                    return ssh.run(['python3','-u','-c',REMOTE_SAMPLER,resolved['loadgen_interface'],str(remote_pid),str(count),str(interval)],check=True,timeout=count*interval+20)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future=pool.submit(collect_remote)
                    start=time.monotonic()
                    for idx in range(count):
                        local_samples.append(_local_sample(idx,resolved['dut_interface'],local_proc.pid,pm))
                        target=start+(idx+1)*interval
                        if idx+1<count and target>time.monotonic(): time.sleep(target-time.monotonic())
                    remote_result=future.result()
                atomic_write_text(root/'raw'/'loadgen-sampler.stdout',remote_result.stdout)
                atomic_write_text(root/'raw'/'loadgen-sampler.stderr',remote_result.stderr)
                for line in remote_result.stdout.splitlines():
                    if line.strip(): remote_samples.append(json.loads(line))
            ssh.run(['sh','-lc',f'kill {remote_pid} >/dev/null 2>&1 || true'],check=False,timeout=5)
    finally:
        if local_proc.poll() is None:
            local_proc.terminate()
            try: local_proc.wait(timeout=2)
            except subprocess.TimeoutExpired: local_proc.kill(); local_proc.wait(timeout=2)
    if len(remote_samples)!=count: raise FrameworkError(f'loadgen telemetry sample count mismatch: expected {count}, got {len(remote_samples)}')
    power_source=_darwin_power_source()
    capabilities=_validate_samples(local_samples,remote_samples,require_ac=definition['dut']['require_ac_power'],power_source=power_source)
    local_power=[float(s['power']['package_power_w_estimate']) for s in local_samples if isinstance(s.get('power',{}).get('package_power_w_estimate'),(int,float))]
    energy=integrate_power_energy_j(local_samples)
    for name,samples in [('dut',local_samples),('loadgen',remote_samples)]:
        atomic_write_text(root/'processed'/f'{name}.jsonl',''.join(json.dumps(s,sort_keys=True,separators=(',',':'))+'\n' for s in samples))
    summary={'schema_version':1,'qualification_id':qid,'definition_sha256':def_sha,'status':'COMPLETE','claim_scope':definition['qualification'].get('claim_scope'),
             'network_evidence_id':resolved['network_summary']['evidence_id'],'loadgen_runtime_id':resolved['loadgen_summary']['runtime_id'],'transport_security_id':resolved['security_summary']['qualification_id'],
             'samples_per_host':count,'interval_seconds':interval,'clock_alignment':alignment,'dut_power_source':power_source,'capabilities':capabilities,
             'dut_estimated_power':{'available':bool(local_power),'comparison_scope':'same-host-paired-only','average_package_power_w':sum(local_power)/len(local_power) if local_power else None,'min_package_power_w':min(local_power) if local_power else None,'max_package_power_w':max(local_power) if local_power else None,'sample_window_energy_j_estimate':energy,'measurement_kind':'estimated-not-external-wall-power'},
             'loadgen_power':{'available':False,'reason':'Raspberry Pi platform exposes voltage/thermal/throttle telemetry but no canonical onboard current sensor for total watts; external sensor required'}}
    summary['telemetry_contract_sha256']=_semantic_sha256({'capabilities':capabilities,'sampling':definition['sampling'],'power_policy':{'dut':definition['dut']['power'],'loadgen':definition['loadgen']['power']}})
    atomic_write_json(root/'processed'/'capabilities.json',capabilities); atomic_write_json(root/'processed'/'summary.json',summary)
    atomic_write_text(root/'processed'/'SUMMARY.md',f"# R6.5.3f dual-host telemetry\n\n- Qualification: `{qid}`\n- DUT samples: {count}\n- Loadgen samples: {count}\n- Interval: {interval:g} s\n- DUT estimated package power available: {'yes' if local_power else 'no'}\n- Loadgen total watts: unavailable without an external current/power sensor\n- Status: COMPLETE\n")
    _artifact_hashes(root)
    return {'root':root,'summary':summary}
