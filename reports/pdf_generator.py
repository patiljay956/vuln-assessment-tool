"""
SSL/TLS Scanner Module
======================
Passive scanner — checks SSL/TLS configuration without sending attack payloads.

Checks for:
    - Certificate validity and expiry
    - Weak protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    - Self-signed certificates
    - Hostname mismatch
    - HSTS header presence
    - Certificate chain issues

Usage:
    from scanner.modules.ssl_scanner import SSLScanner
    scanner = SSLScanner()
    result = scanner.run_scan("https://example.com")
"""

import uuid
import ssl
import socket
import logging
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SSL] %(message)s")
logger = logging.getLogger(__name__)


class SSLScanner:
    """
    Passive SSL/TLS configuration scanner.

    Args:
        timeout: Socket connection timeout in seconds
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def _get_certificate_info(self, hostname: str, port: int = 443) -> dict:
        """Fetch SSL certificate details from the target host."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    return {
                        "cert":     cert,
                        "protocol": protocol,
                        "cipher":   cipher,
                        "error":    None,
                    }
        except ssl.SSLCertVerificationError as e:
            return {"cert": None, "protocol": None, "cipher": None, "error": f"SSL verification failed: {e}"}
        except ssl.SSLError as e:
            return {"cert": None, "protocol": None, "cipher": None, "error": f"SSL error: {e}"}
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return {"cert": None, "protocol": None, "cipher": None, "error": f"Connection failed: {e}"}

    def _check_weak_protocols(self, hostname: str, port: int = 443) -> list:
        """Test whether weak TLS protocol versions are accepted."""
        weak_protocols = []
        protocols_to_test = [
            (ssl.PROTOCOL_TLS_CLIENT, "TLSv1"),
            (ssl.PROTOCOL_TLS_CLIENT, "TLSv1.1"),
        ]
        for proto_const, proto_name in protocols_to_test:
            try:
                context = ssl.SSLContext(proto_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ssl.TLSVersion.TLSv1
                context.maximum_version = ssl.TLSVersion.TLSv1 if "1.0" in proto_name else ssl.TLSVersion.TLSv1_1
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        weak_protocols.append(proto_name)
                        logger.warning(f"Weak protocol accepted: {proto_name}")
            except Exception:
                pass
        return weak_protocols

    def _check_cipher_suites(self, hostname: str, port: int = 443) -> dict:
        """
        Probe the server with restrictive OpenSSL cipher strings to see whether
        it will negotiate a connection using a weak/legacy cipher family.

        Returns a dict of {cipher_family: bool_accepted}.
        """
        weak_cipher_families = {
            "RC4":    "RC4",
            "DES":    "DES-CBC3-SHA:DES-CBC-SHA",
            "3DES":   "DES-CBC3-SHA",
            "NULL":   "eNULL:aNULL",
            "EXPORT": "EXPORT",
        }
        # Substring(s) expected in the negotiated cipher name for a hit to
        # count as a genuine match — set_ciphers() only constrains TLS<=1.2
        # suites (TLS 1.3 ciphersuites are negotiated independently), so we
        # must both cap the handshake at TLSv1.2 AND verify what actually
        # came back, or a TLS 1.3 connection falsely reads as "weak cipher accepted".
        match_tokens = {
            "RC4":    ("RC4",),
            "DES":    ("DES-CBC-SHA",),
            "3DES":   ("3DES", "DES-CBC3"),
            "NULL":   ("NULL",),
            "EXPORT": ("EXP-",),
        }

        accepted = {}
        for family, cipher_string in weak_cipher_families.items():
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                # Cap at TLSv1.2 — the legacy cipher families being tested
                # (RC4/DES/3DES/NULL/EXPORT) don't exist as TLS 1.3 suites,
                # so leaving 1.3 enabled would let the handshake silently
                # succeed on a modern cipher and produce a false positive.
                context.minimum_version = ssl.TLSVersion.TLSv1
                context.maximum_version = ssl.TLSVersion.TLSv1_2
                # Lower the security level so legacy ciphers aren't blocked
                # by OpenSSL's default policy before we even get to test them.
                context.set_ciphers(f"{cipher_string}:@SECLEVEL=0")
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        negotiated = ssock.cipher()
                        negotiated_name = negotiated[0] if negotiated else ""
                        is_match = any(tok in negotiated_name for tok in match_tokens[family])
                        accepted[family] = is_match
                        if is_match:
                            logger.warning(f"Weak cipher family accepted: {family} ({negotiated_name})")
            except (ssl.SSLError, OSError):
                # Either OpenSSL refused to even offer the cipher string, or
                # the server rejected the handshake — both mean "not weakly configured".
                accepted[family] = False
            except Exception:
                accepted[family] = False
        return accepted

    def _check_protocol_support(self, hostname: str, port: int = 443) -> dict:
        """
        Explicitly check whether the server supports the modern, recommended
        TLS versions (1.2 and 1.3), independent of the weak-protocol probe.

        Returns a dict of {"TLSv1.2": bool, "TLSv1.3": bool}.
        """
        support = {"TLSv1.2": False, "TLSv1.3": False}
        version_map = {
            "TLSv1.2": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
            "TLSv1.3": (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        }
        for proto_name, (min_v, max_v) in version_map.items():
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = min_v
                context.maximum_version = max_v
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        support[proto_name] = True
            except Exception:
                support[proto_name] = False
        return support

    def _extract_cert_details(self, cert: dict, protocol: str, cipher: tuple) -> dict:
        """
        Pull the human-readable issuer, subject, validity window, negotiated
        protocol, and negotiated cipher out of the raw certificate dict
        returned by ssl.SSLSocket.getpeercert().
        """
        def _flatten(name_field):
            # name_field looks like (((‘countryName’, ‘US’),), ((‘organizationName’, ‘Foo’),), ...)
            flat = {}
            if not name_field:
                return flat
            for rdn in name_field:
                for key, value in rdn:
                    flat[key] = value
            return flat

        if not cert:
            return {
                "issuer": None, "subject": None,
                "not_before": None, "not_after": None,
                "negotiated_protocol": protocol, "negotiated_cipher": cipher[0] if cipher else None,
            }

        return {
            "issuer":              _flatten(cert.get("issuer")),
            "subject":             _flatten(cert.get("subject")),
            "not_before":          cert.get("notBefore"),
            "not_after":           cert.get("notAfter"),
            "negotiated_protocol": protocol,
            "negotiated_cipher":   cipher[0] if cipher else None,
        }

    def _calculate_tls_grade(
        self,
        cert_error: bool,
        cert_expired: bool,
        cert_expiring_soon: bool,
        weak_protocols: list,
        weak_ciphers: dict,
        protocol_support: dict,
        hsts_missing: bool,
    ) -> str:
        """
        Derive an A-F letter grade from the individual check results.
        This is a local heuristic, not the SSL Labs algorithm.
        """
        # Hard failures short-circuit straight to F
        if cert_error or cert_expired:
            return "F"

        score = 100
        if weak_protocols:
            score -= 30 * len(weak_protocols)
        if any(weak_ciphers.values()):
            score -= 25
        if not protocol_support.get("TLSv1.2") and not protocol_support.get("TLSv1.3"):
            score -= 40  # server doesn't speak any modern TLS version
        elif not protocol_support.get("TLSv1.3"):
            score -= 5  # TLS 1.2 only — acceptable but not best practice
        if cert_expiring_soon:
            score -= 10
        if hsts_missing:
            score -= 10

        score = max(score, 0)

        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def _normalize_finding(
        self,
        scan_id: str,
        vuln_type: str,
        owasp_category: str,
        cvss_score: float,
        severity: str,
        description: str,
        solution: str,
        affected_url: str,
        evidence: str = "",
        plugin_id: str = "",
    ) -> dict:
        """Build a normalized finding dict matching the standard schema."""
        return {
            "vuln_id":         str(uuid.uuid4()),
            "scan_id":         scan_id,
            "tool":            "ssl_scanner",
            "plugin_id":       plugin_id or f"ssl_{vuln_type.lower().replace(' ', '_')}",
            "vuln_type":       vuln_type,
            "owasp_category":  owasp_category,
            "cvss_score":      cvss_score,
            "severity":        severity,
            "confidence":      "High",
            "evidence":        evidence,
            "affected_url":    affected_url,
            "method":          "GET",
            "param":           "",
            "attack":          "",
            "description":     description,
            "solution":        solution,
            "cwe_id":          "326",
            "recommendation":  solution,
            "business_impact": "",
        }

    def run_scan(self, target_url: str, scan_id: str = None) -> dict:
        """
        Run SSL/TLS security scan against the target URL.

        Args:
            target_url: URL to scan (must be https:// for full SSL checks)
            scan_id:    Optional parent scan ID

        Returns:
            Standard result dict with findings and summary
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())

        logger.info(f"=== Starting SSL scan | scan_id={scan_id} | target={target_url} ===")

        result = {
            "scan_id":  scan_id,
            "target":   target_url,
            "status":   "failed",
            "findings": [],
            "summary":  {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }

        parsed = urlparse(target_url)
        hostname = parsed.hostname
        findings = []

        # ── HTTP-only check ──────────────────────────────
        if parsed.scheme == "http":
            findings.append(self._normalize_finding(
                scan_id=scan_id,
                vuln_type="HTTP Only Site",
                owasp_category="A02:2021 - Cryptographic Failures",
                cvss_score=5.9,
                severity="Medium",
                description="The site is served over HTTP without SSL/TLS encryption. All data transmitted between the browser and server is in plaintext and can be intercepted.",
                solution="Configure your server to use HTTPS. Obtain a free TLS certificate from Let's Encrypt (certbot) and redirect all HTTP traffic to HTTPS.",
                affected_url=target_url,
                evidence="URL scheme is http://",
                plugin_id="ssl_http_only",
            ))
            logger.info("Site uses HTTP only — no SSL/TLS")

            # Still check HSTS header even on HTTP
            try:
                resp = requests.get(target_url, timeout=self.timeout, verify=False)
                if "strict-transport-security" not in {k.lower() for k in resp.headers}:
                    findings.append(self._normalize_finding(
                        scan_id=scan_id,
                        vuln_type="Missing HSTS Header",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        cvss_score=5.9,
                        severity="Medium",
                        description="HTTP Strict Transport Security (HSTS) header is not set. Browsers will not automatically enforce HTTPS connections.",
                        solution="Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to all HTTPS responses.",
                        affected_url=target_url,
                        plugin_id="ssl_missing_hsts",
                    ))
            except Exception:
                pass

            # Build summary and return early — no SSL cert to check on HTTP
            summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                sev = f["severity"].lower()
                if sev in summary:
                    summary[sev] += 1
            result["status"]    = "completed"
            result["findings"]  = findings
            result["summary"]   = summary
            result["tls_grade"] = "F"  # no TLS in use at all
            logger.info(f"=== SSL scan complete (HTTP site) | {summary} | tls_grade=F ===")
            return result

        # ── HTTPS site — full SSL checks ─────────────────
        port = parsed.port or 443
        cert_info = self._get_certificate_info(hostname, port)

        # Flags used later to compute the overall tls_grade
        cert_error_flag = False
        cert_expired_flag = False
        cert_expiring_soon_flag = False
        hsts_missing_flag = False
        cert_details = {}

        if cert_info["error"]:
            cert_error_flag = True
            findings.append(self._normalize_finding(
                scan_id=scan_id,
                vuln_type="SSL Certificate Error",
                owasp_category="A02:2021 - Cryptographic Failures",
                cvss_score=7.4,
                severity="High",
                description=f"SSL certificate validation failed: {cert_info['error']}",
                solution="Ensure the server has a valid, properly configured SSL certificate from a trusted Certificate Authority.",
                affected_url=target_url,
                evidence=cert_info["error"],
                plugin_id="ssl_cert_error",
            ))
        else:
            cert = cert_info["cert"]

            # Certificate details: issuer, subject, validity window,
            # negotiated protocol/cipher — surfaced in result["tls_details"]
            cert_details = self._extract_cert_details(
                cert, cert_info["protocol"], cert_info["cipher"]
            )

            # Check certificate expiry
            if cert:
                try:
                    not_after_str = cert.get("notAfter", "")
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    not_after = not_after.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_remaining = (not_after - now).days

                    if days_remaining < 0:
                        cert_expired_flag = True
                        findings.append(self._normalize_finding(
                            scan_id=scan_id,
                            vuln_type="Expired SSL Certificate",
                            owasp_category="A02:2021 - Cryptographic Failures",
                            cvss_score=7.4,
                            severity="High",
                            description=f"The SSL certificate expired on {not_after_str}. Browsers will show security warnings and block access.",
                            solution="Renew your SSL certificate immediately. Use Let's Encrypt with auto-renewal to prevent future expiry.",
                            affected_url=target_url,
                            evidence=f"Certificate expired: {not_after_str}",
                            plugin_id="ssl_cert_expired",
                        ))
                    elif days_remaining < 30:
                        cert_expiring_soon_flag = True
                        findings.append(self._normalize_finding(
                            scan_id=scan_id,
                            vuln_type="SSL Certificate Expiring Soon",
                            owasp_category="A02:2021 - Cryptographic Failures",
                            cvss_score=5.3,
                            severity="Medium",
                            description=f"The SSL certificate expires in {days_remaining} days on {not_after_str}.",
                            solution="Renew your SSL certificate before it expires. Enable auto-renewal if using Let's Encrypt.",
                            affected_url=target_url,
                            evidence=f"Certificate expires in {days_remaining} days: {not_after_str}",
                            plugin_id="ssl_cert_expiring",
                        ))
                except Exception as e:
                    logger.warning(f"Could not parse certificate expiry: {e}")

            # Check weak protocol
            weak = self._check_weak_protocols(hostname, port)
            for proto in weak:
                findings.append(self._normalize_finding(
                    scan_id=scan_id,
                    vuln_type=f"Weak TLS Protocol Supported ({proto})",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    cvss_score=5.9,
                    severity="Medium",
                    description=f"The server accepts {proto} connections which are considered cryptographically weak and vulnerable to known attacks.",
                    solution=f"Disable {proto} in your server configuration. For Nginx: ssl_protocols TLSv1.2 TLSv1.3; For Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
                    affected_url=target_url,
                    evidence=f"Server accepted {proto} handshake",
                    plugin_id=f"ssl_weak_protocol_{proto.lower().replace('.', '_')}",
                ))

            # Check weak cipher suites (RC4, DES, 3DES, NULL, EXPORT)
            weak_ciphers = self._check_cipher_suites(hostname, port)
            for family, is_accepted in weak_ciphers.items():
                if is_accepted:
                    findings.append(self._normalize_finding(
                        scan_id=scan_id,
                        vuln_type=f"Weak Cipher Suite Supported ({family})",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        cvss_score=7.4 if family in ("NULL", "EXPORT") else 5.9,
                        severity="High" if family in ("NULL", "EXPORT") else "Medium",
                        description=f"The server accepts {family} cipher suites, which are cryptographically weak, deprecated, and vulnerable to known attacks (e.g. decryption or downgrade).",
                        solution=f"Disable {family}-based cipher suites in your server configuration. For Nginx: ssl_ciphers 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK'; For Apache: SSLCipherSuite HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK",
                        affected_url=target_url,
                        evidence=f"Server negotiated a connection using a {family} cipher",
                        plugin_id=f"ssl_weak_cipher_{family.lower()}",
                    ))

            # Explicitly validate modern protocol support (TLS 1.2 / 1.3)
            protocol_support = self._check_protocol_support(hostname, port)
            if not protocol_support["TLSv1.2"] and not protocol_support["TLSv1.3"]:
                findings.append(self._normalize_finding(
                    scan_id=scan_id,
                    vuln_type="No Modern TLS Protocol Supported",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    cvss_score=8.2,
                    severity="High",
                    description="The server does not support TLS 1.2 or TLS 1.3. Only outdated, cryptographically weak protocol versions are available.",
                    solution="Enable TLS 1.2 and TLS 1.3 support in your server configuration. For Nginx: ssl_protocols TLSv1.2 TLSv1.3; For Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3",
                    affected_url=target_url,
                    evidence=f"Protocol support: {protocol_support}",
                    plugin_id="ssl_no_modern_tls",
                ))
            elif not protocol_support["TLSv1.3"]:
                findings.append(self._normalize_finding(
                    scan_id=scan_id,
                    vuln_type="TLS 1.3 Not Supported",
                    owasp_category="A02:2021 - Cryptographic Failures",
                    cvss_score=3.1,
                    severity="Low",
                    description="The server supports TLS 1.2 but not TLS 1.3. TLS 1.3 offers improved performance and removes several legacy cryptographic weaknesses present in 1.2.",
                    solution="Enable TLS 1.3 alongside TLS 1.2. For Nginx: ssl_protocols TLSv1.2 TLSv1.3; For Apache 2.4.37+: SSLProtocol -all +TLSv1.2 +TLSv1.3",
                    affected_url=target_url,
                    evidence=f"Protocol support: {protocol_support}",
                    plugin_id="ssl_no_tls13",
                ))

            # Check HSTS
            try:
                resp = requests.get(target_url, timeout=self.timeout, verify=False)
                if "strict-transport-security" not in {k.lower() for k in resp.headers}:
                    hsts_missing_flag = True
                    findings.append(self._normalize_finding(
                        scan_id=scan_id,
                        vuln_type="Missing HSTS Header",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        cvss_score=5.9,
                        severity="Medium",
                        description="HTTP Strict Transport Security (HSTS) header is not set. Users may be vulnerable to SSL stripping attacks.",
                        solution="Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to all HTTPS responses.",
                        affected_url=target_url,
                        plugin_id="ssl_missing_hsts",
                    ))
            except Exception:
                pass

        # Compute the overall TLS grade from everything gathered above.
        # weak_ciphers / protocol_support only exist if we made it past the
        # cert_info["error"] branch — default them so grading still works.
        weak_ciphers = weak_ciphers if "weak_ciphers" in locals() else {}
        protocol_support = protocol_support if "protocol_support" in locals() else {"TLSv1.2": False, "TLSv1.3": False}
        weak_protocol_list = weak if "weak" in locals() else []

        tls_grade = self._calculate_tls_grade(
            cert_error=cert_error_flag,
            cert_expired=cert_expired_flag,
            cert_expiring_soon=cert_expiring_soon_flag,
            weak_protocols=weak_protocol_list,
            weak_ciphers=weak_ciphers,
            protocol_support=protocol_support,
            hsts_missing=hsts_missing_flag,
        )

        # Build summary
        summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in summary:
                summary[sev] += 1

        result["status"]     = "completed"
        result["findings"]   = findings
        result["summary"]    = summary
        result["tls_grade"]  = tls_grade
        result["tls_details"] = cert_details

        logger.info(f"=== SSL scan complete | {summary} | tls_grade={tls_grade} ===")
        return result


# ──────────────────────────────────────────────
# Quick test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import json

    scanner = SSLScanner()

    # Test HTTP site (DVWA)
    result = scanner.run_scan("http://host.docker.internal:8888")

    print(f"\nStatus  : {result['status']}")
    print(f"Summary : {result['summary']}")
    print(f"\nFindings:")
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['vuln_type']}")
        print(f"    OWASP : {f['owasp_category']}")
        print(f"    Fix   : {f['recommendation'][:80]}...")

    with open("ssl_scan_result.json", "w") as fp:
        json.dump(result, fp, indent=2)
    print("\nSaved to ssl_scan_result.json")