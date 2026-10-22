from __future__ import annotations

import math
import re
from typing import Any

from framework.io_utils import FrameworkError

METRICS = {
    "application_goodput_mbps", "dut_process_cpu_seconds_per_gib",
    "dut_host_cpu_seconds_per_gib", "loadgen_max_single_core_busy_percent",
    "crypto_aead_encrypt_calls", "crypto_aead_decrypt_calls",
    "crypto_header_protection_calls", "crypto_aead_input_bytes",
    "crypto_cycles", "packet_io_syscalls", "nic_tx_packets", "nic_rx_packets",
    "nic_drops", "kernel_softirq_cpu_seconds", "pmu_cycles", "pmu_instructions",
}
PRIMARY = {
    "application_goodput_mbps", "dut_process_cpu_seconds_per_gib",
    "dut_host_cpu_seconds_per_gib", "loadgen_max_single_core_busy_percent",
}


def validate_metric(value: Any, name: str) -> None:
    if not isinstance(value, dict) or value.get("state") not in ("measured", "unavailable"):
        raise FrameworkError(f"metric {name} requires state=measured/unavailable")
    if value["state"] == "measured":
        number = value.get("value")
        if isinstance(number, bool) or not isinstance(number, (int, float)) or \
                not math.isfinite(number) or number < 0:
            raise FrameworkError(f"metric {name} has invalid measured value")
        if value.get("reason") is not None:
            raise FrameworkError(f"metric {name} measured state cannot have reason")
    else:
        if value.get("value") is not None or not isinstance(value.get("reason"), str) or not value["reason"].strip():
            raise FrameworkError(f"metric {name}: unavailable requires null and reason")


def validate_abc_observation(record: dict[str, Any]) -> None:
    if not isinstance(record, dict) or record.get("schema_version") != 1:
        raise FrameworkError("ABC observation schema_version must be 1")
    if record.get("arm") not in ("A", "B", "C"):
        raise FrameworkError("ABC observation requires arm")
    if record.get("mode") not in ("performance", "attribution"):
        raise FrameworkError("ABC observation requires performance/attribution mode")
    if not isinstance(record.get("condition_id"), str) or not record["condition_id"]:
        raise FrameworkError("ABC observation requires condition_id")
    if type(record.get("repetition")) is not int or record["repetition"] < 1:
        raise FrameworkError("ABC observation requires positive repetition")
    proof = record.get("protocol_proof")
    if not isinstance(proof, dict) or proof.get("verified") is not True or \
            proof.get("negotiated") != ("h2" if record["arm"] == "A" else "h3"):
        raise FrameworkError("ABC ALPN/HTTP protocol proof invalid")
    if proof.get("tls_version") != "TLSv1.3" or \
            proof.get("cipher_suite") not in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"):
        raise FrameworkError("ABC TLS proof invalid")
    client = record.get("client")
    if not isinstance(client, dict) or client.get("ngi541_enabled") is not False or \
            not isinstance(client.get("binary_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", client["binary_sha256"]):
        raise FrameworkError("ABC client independence/binary provenance absent")
    metrics = record.get("metrics")
    if not isinstance(metrics, dict) or not PRIMARY <= set(metrics) or (set(metrics) - METRICS):
        raise FrameworkError("ABC required or unknown metrics")
    for name, datum in metrics.items():
        validate_metric(datum, name)
    if record["mode"] == "performance":
        for name in PRIMARY:
            if metrics[name]["state"] != "measured":
                raise FrameworkError(f"ABC performance metric {name} unavailable")
    # Attribution counters may be missing but never silently interpreted as zero.
    # Different host-counter and crypto measurements are not simply additive.
