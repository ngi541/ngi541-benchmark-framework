from __future__ import annotations

from typing import Any

from framework.io_utils import FrameworkError
from framework.transport_security import curl_smoke_command
from framework.workload_planner import _build_h2load_command


def nginx_http2_config(*, host: str, port: int, workers: int,
                        worker_connections: int, cipher_suite: str) -> str:
    """New A-only configuration; does not alter frozen R6 HTTP/3 renderer."""
    if workers < 1 or worker_connections < 1 or not (1 <= port <= 65535):
        raise FrameworkError("invalid HTTP/2 NGINX worker/port configuration")
    if cipher_suite not in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"):
        raise FrameworkError("unsupported ABC TLS 1.3 cipher suite")
    # host is a configuration input; reject NGINX directive injection.
    if not host or not all(c.isalnum() or c in '.:-[]' for c in host):
        raise FrameworkError("invalid ABC listener host")
    return f"""worker_processes {workers};
pid logs/nginx.pid;
error_log stderr notice;
events {{ worker_connections {worker_connections}; }}
http {{
    access_log off;
    server {{
        listen {host}:{port} ssl;
        http2 on;
        server_name ngi541-dut.local;
        ssl_protocols TLSv1.3;
        ssl_certificate server.crt;
        ssl_certificate_key server.key;
        ssl_conf_command Ciphersuites {cipher_suite};
        ssl_early_data off;
        root html;
    }}
}}
"""


def abc_h2load_command(*, arm: str, **kwargs: Any) -> list[str]:
    """Same pinned h2load and arguments; A selects default h2 over TLS.

    Final ALPN negotiation MUST be independently verified before a run is valid.
    """
    if arm not in ("A", "B", "C"):
        raise FrameworkError("ABC arm must be A, B or C")
    command = _build_h2load_command(**kwargs)
    if arm == "A":
        command.remove("--h3")
    return command


def abc_curl_probe_command(*, arm: str, **kwargs: Any) -> list[str]:
    if arm not in ("A", "B", "C"):
        raise FrameworkError("ABC arm must be A, B or C")
    command = curl_smoke_command(**kwargs)
    if arm == "A":
        command[command.index("--http3-only")] = "--http2"
    # --http2 can fall back; parse returned http_version and reject != "2".
    return command


def validate_abc_protocol_proof(*, arm: str, http_version: str,
                                status: int, tls_verified: bool,
                                cipher_suite: str) -> None:
    if arm not in ("A", "B", "C"):
        raise FrameworkError("unknown ABC arm")
    expected = "2" if arm == "A" else "3"
    if str(http_version) != expected or status != 200 or tls_verified is not True:
        raise FrameworkError(f"ABC {arm}: negotiated protocol/status/TLS verification invalid")
    if cipher_suite not in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"):
        raise FrameworkError("ABC negotiated TLS cipher is missing or unsupported")
