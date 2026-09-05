from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path


@lru_cache
def ensure_hacktheweb_import_path() -> Path:
    backend_root = Path(__file__).resolve().parents[2]
    hacktheweb_root = backend_root.parent / "hacktheweb-main"
    if str(hacktheweb_root) not in sys.path:
        sys.path.insert(0, str(hacktheweb_root))
    return hacktheweb_root


def load_hacktheweb_components():
    ensure_hacktheweb_import_path()
    from hacktheweb.core.ai_engine import AIEngine
    from hacktheweb.core.config import Config
    from hacktheweb.recon.recon_engine import ReconEngine
    from hacktheweb.scanners.csrf_scanner import CSRFScanner
    from hacktheweb.scanners.cors_scanner import CORSScanner
    from hacktheweb.scanners.idor_scanner import IDORScanner
    from hacktheweb.scanners.lfi_scanner import LFIScanner
    from hacktheweb.scanners.ldapi_scanner import LDAPIScanner
    from hacktheweb.scanners.nosqli_scanner import NoSQLiScanner
    from hacktheweb.scanners.open_redirect_scanner import OpenRedirectScanner
    from hacktheweb.scanners.path_traversal_scanner import PathTraversalScanner
    from hacktheweb.scanners.rce_scanner import RCEScanner
    from hacktheweb.scanners.security_headers_scanner import SecurityHeadersScanner
    from hacktheweb.scanners.sqli_scanner import SQLiScanner
    from hacktheweb.scanners.ssrf_scanner import SSRFScanner
    from hacktheweb.scanners.ssti_scanner import SSTIScanner
    from hacktheweb.scanners.xss_scanner import XSSScanner
    from hacktheweb.scanners.xxe_scanner import XXEScanner
    from hacktheweb.utils.data_loader import data_loader
    from hacktheweb.utils.logger import EnterpriseLogger

    return {
        "AIEngine": AIEngine,
        "Config": Config,
        "ReconEngine": ReconEngine,
        "CSRFScanner": CSRFScanner,
        "CORSScanner": CORSScanner,
        "IDORScanner": IDORScanner,
        "LFIScanner": LFIScanner,
        "LDAPIScanner": LDAPIScanner,
        "NoSQLiScanner": NoSQLiScanner,
        "OpenRedirectScanner": OpenRedirectScanner,
        "PathTraversalScanner": PathTraversalScanner,
        "RCEScanner": RCEScanner,
        "SecurityHeadersScanner": SecurityHeadersScanner,
        "SQLiScanner": SQLiScanner,
        "SSRFScanner": SSRFScanner,
        "SSTIScanner": SSTIScanner,
        "XSSScanner": XSSScanner,
        "XXEScanner": XXEScanner,
        "data_loader": data_loader,
        "EnterpriseLogger": EnterpriseLogger,
    }
