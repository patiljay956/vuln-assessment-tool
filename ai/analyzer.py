"""
AI Analyzer Module — Dual Provider
====================================
Uses two AI providers for optimal performance:

    PRIMARY (per-finding enrichment):
        Groq API — Llama 3.3 70B
        Fast (~0.4s/call), reliable JSON, 30 req/min free tier
        Used for: remediation guidance + business impact per finding

    SECONDARY (executive summary + fallback):
        OpenRouter — NVIDIA Nemotron 3 Ultra (253B)
        1M context window, higher quality narrative, 1.79s latency
        Used for: executive summary (single large call)
        Also used as: fallback when Groq rate limits hit

Design principles:
    - CVSS decides severity. AI explains it.
    - All prompts return structured JSON — never free-form text.
    - Findings capped at 30 for enrichment (prevents rate limits).
    - Nemotron's 1M context used for full-scan executive summary.
    - Graceful degradation — if both providers fail, fallback summary used.

Install:
    pip install groq openai

Usage:
    from ai.analyzer import AIAnalyzer
    analyzer = AIAnalyzer()
    enriched_findings, executive_summary = analyzer.enrich(findings, target_url)
"""

import os
import json
import logging
import re
import time
from typing import Optional

logger = logging.getLogger(__name__)

BATCH_SIZE = 3  # findings per Groq API call
MAX_ENRICH  = 30  # max findings to enrich (prevents rate limits)


class AIAnalyzer:
    """
    Dual-provider AI analyzer.

    Args:
        groq_api_key:       Groq API key (or set GROQ_API_KEY env var)
        openrouter_api_key: OpenRouter API key (or set OPENROUTER_API_KEY env var)
        groq_model:         Groq model to use
        nemotron_model:     OpenRouter Nemotron model string
    """

    def __init__(
        self,
        groq_api_key: Optional[str] = None,
        openrouter_api_key: Optional[str] = None,
        groq_model: str = "llama-3.3-70b-versatile",
        nemotron_model: str = "nvidia/llama-3.1-nemotron-ultra-253b-v1:free",
    ):
        self.groq_model     = groq_model
        self.nemotron_model = nemotron_model

        # ── Groq client (primary) ─────────────
        groq_key = groq_api_key or os.getenv("GROQ_API_KEY")
        if groq_key:
            from groq import Groq
            self.groq_client = Groq(api_key=groq_key)
            logger.info(f"Groq client initialized: {groq_model}")
        else:
            self.groq_client = None
            logger.warning("GROQ_API_KEY not set — Groq unavailable")

        # ── OpenRouter client (Nemotron) ──────
        openrouter_key = openrouter_api_key or os.getenv("OPENROUTER_API_KEY")
        if openrouter_key:
            from openai import OpenAI
            self.openrouter_client = OpenAI(
                api_key=openrouter_key,
                base_url="https://openrouter.ai/api/v1",
                default_headers={
                    "HTTP-Referer": "https://github.com/Akshat023/vuln-assessment-tool",
                    "X-Title": "VulnAssess AI Scanner",
                },
            )
            logger.info(f"OpenRouter/Nemotron client initialized: {nemotron_model}")
        else:
            self.openrouter_client = None
            logger.warning("OPENROUTER_API_KEY not set — Nemotron unavailable")

        if not self.groq_client and not self.openrouter_client:
            raise ValueError(
                "No AI provider available. Set GROQ_API_KEY and/or OPENROUTER_API_KEY."
            )

    # ──────────────────────────────────────────
    # JSON parsing (shared)
    # ──────────────────────────────────────────

    def _parse_json(self, raw: str):
        """Strip markdown fences and parse JSON robustly."""
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1] if len(parts) > 1 else raw
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()
        # Remove control characters that break JSON
        raw = re.sub(r'[\x00-\x1f\x7f]', ' ', raw)
        return json.loads(raw)

    # ──────────────────────────────────────────
    # Groq call (fast, for finding batches)
    # ──────────────────────────────────────────

    def _call_groq(self, system_prompt: str, user_prompt: str) -> dict | list:
        """Call Groq API. Raises on failure."""
        if not self.groq_client:
            raise RuntimeError("Groq client not initialized")

        response = self.groq_client.chat.completions.create(
            model=self.groq_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=2048,
        )
        raw = response.choices[0].message.content.strip()
        return self._parse_json(raw)

    # ──────────────────────────────────────────
    # Nemotron call (large context, for summary)
    # ──────────────────────────────────────────

    def _call_nemotron(self, system_prompt: str, user_prompt: str) -> dict | list:
        """Call OpenRouter/Nemotron. Raises on failure."""
        if not self.openrouter_client:
            raise RuntimeError("OpenRouter client not initialized")

        response = self.openrouter_client.chat.completions.create(
            model=self.nemotron_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=2048,
        )
        raw = response.choices[0].message.content.strip()
        return self._parse_json(raw)

    # ──────────────────────────────────────────
    # Call with fallback
    # ──────────────────────────────────────────

    def _call_with_fallback(
        self,
        system_prompt: str,
        user_prompt: str,
        prefer: str = "groq",
    ) -> dict | list:
        """
        Call preferred provider, fall back to the other on failure.

        Args:
            prefer: "groq" or "nemotron"
        """
        providers = (
            [("groq", self._call_groq), ("nemotron", self._call_nemotron)]
            if prefer == "groq"
            else [("nemotron", self._call_nemotron), ("groq", self._call_groq)]
        )

        last_error = None
        for name, call_fn in providers:
            try:
                result = call_fn(system_prompt, user_prompt)
                logger.debug(f"AI call succeeded via {name}")
                return result
            except Exception as e:
                logger.warning(f"{name} failed: {e} — trying next provider")
                last_error = e
                # Brief pause before fallback
                time.sleep(1)

        raise RuntimeError(f"All AI providers failed. Last error: {last_error}")

    # ──────────────────────────────────────────
    # Job 1: Per-finding enrichment (Groq)
    # ──────────────────────────────────────────

    def _enrich_batch(self, batch: list) -> list:
        """
        Send a batch of findings to Groq and get back
        remediation + business_impact for each.
        Falls back to Nemotron if Groq rate-limits.
        """
        system_prompt = """You are a senior cybersecurity engineer writing vulnerability reports.

You will receive a JSON array of vulnerability findings. For each finding, return:
- "vuln_id": the exact vuln_id from the input (do not change it)
- "recommendation": specific, actionable fix instructions (2-3 sentences, technical but clear). Mention exact config changes, headers, or code fixes.
- "business_impact": one sentence explaining the real-world consequence for the business in terms of data, money, reputation, or compliance risk.

Rules:
- Return ONLY a valid JSON array. No markdown, no explanation, no preamble.
- Keep recommendations specific — not generic advice.
- Do not repeat the vulnerability description.

Example format:
[
  {
    "vuln_id": "abc-123",
    "recommendation": "Add X-Frame-Options: DENY header in your Nginx config: add_header X-Frame-Options DENY;",
    "business_impact": "Without this header, attackers can embed your login page in an invisible iframe to steal credentials."
  }
]"""

        # Simplify findings to save tokens
        simplified = []
        for f in batch:
            simplified.append({
                "vuln_id":        f["vuln_id"],
                "vuln_type":      f["vuln_type"],
                "owasp_category": f["owasp_category"],
                "severity":       f["severity"],
                "cvss_score":     f["cvss_score"],
                "affected_url":   f["affected_url"],
                "param":          f.get("param", ""),
                "evidence":       f.get("evidence", "")[:150],
                "solution":       f.get("solution", "")[:200],
            })

        user_prompt = f"Enrich these {len(simplified)} findings:\n{json.dumps(simplified, indent=2)}"

        # Prefer Groq for speed, fall back to Nemotron
        result = self._call_with_fallback(system_prompt, user_prompt, prefer="groq")

        if not isinstance(result, list):
            raise ValueError(f"Expected list from AI, got {type(result)}")

        return result

    # ──────────────────────────────────────────
    # Job 2: Executive summary (Nemotron)
    # Uses 1M context to process ALL findings at once
    # ──────────────────────────────────────────

    def _generate_executive_summary(self, findings: list, target_url: str) -> str:
        """
        Generate executive summary using Nemotron's 1M context window.
        Sends ALL findings in one call — no batching needed.
        Falls back to Groq if Nemotron fails.
        """
        system_prompt = """You are a cybersecurity consultant writing an executive summary for a vulnerability scan report.

Your audience is non-technical business stakeholders — CEOs, product managers, compliance officers.

Write 3-4 paragraphs covering:
1. Overall security posture (how serious is the situation overall?)
2. What an attacker could realistically do with these vulnerabilities
3. Business risk — data breach, compliance, financial, reputational impact
4. Prioritized action plan — what to fix first and why

Rules:
- Return ONLY a valid JSON object with a single key "summary" containing the full text.
- Write in plain English. No bullet points inside the summary. No technical jargon.
- Be direct and honest — don't minimize or exaggerate.
- Keep it under 350 words.
- Specifically mention the most critical vulnerability types found.

Example format:
{"summary": "The security assessment of example.com revealed..."}"""

        # Build comprehensive finding summary
        severity_counts = {
            "Critical": sum(1 for f in findings if f.get("severity") == "Critical"),
            "High":     sum(1 for f in findings if f.get("severity") == "High"),
            "Medium":   sum(1 for f in findings if f.get("severity") == "Medium"),
            "Low":      sum(1 for f in findings if f.get("severity") == "Low"),
        }

        # Group by OWASP category
        owasp_groups = {}
        for f in findings:
            cat = f.get("owasp_category", "Unknown")
            owasp_groups[cat] = owasp_groups.get(cat, 0) + 1

        # Top 10 findings for context
        top_findings = []
        for f in findings[:10]:
            top_findings.append({
                "type":     f["vuln_type"],
                "severity": f["severity"],
                "cvss":     f["cvss_score"],
                "url":      f["affected_url"],
                "owasp":    f.get("owasp_category", ""),
                "impact":   f.get("business_impact", ""),
            })

        # Detected technologies
        tech_findings = [f for f in findings if f.get("tool") in ("tech_fingerprinter", "nvd_lookup")]
        techs = list(set(
            f["vuln_type"].split("(")[0].strip()
            for f in tech_findings
            if "Version Disclosure" in f.get("vuln_type", "")
        ))

        user_prompt = f"""Generate an executive summary for this vulnerability scan:

Target URL: {target_url}
Total findings: {len(findings)}
Severity breakdown: {json.dumps(severity_counts)}
OWASP categories affected: {json.dumps(owasp_groups)}
Detected technologies: {techs}
Top findings: {json.dumps(top_findings, indent=2)}"""

        # Prefer Nemotron for quality, fall back to Groq
        result = self._call_with_fallback(system_prompt, user_prompt, prefer="nemotron")

        if isinstance(result, dict) and "summary" in result:
            return result["summary"]
        raise ValueError("AI did not return expected summary format")

    # ──────────────────────────────────────────
    # Public API: enrich
    # ──────────────────────────────────────────

    def enrich(self, findings: list, target_url: str) -> tuple[list, str]:
        """
        Main entry point. Enriches findings with AI analysis.

        Strategy:
        - Cap enrichment at MAX_ENRICH findings (prevents rate limits)
        - Use Groq for per-finding enrichment (speed)
        - Use Nemotron for executive summary (quality + 1M context)
        - Fallback between providers automatically

        Args:
            findings:   List of normalized findings from orchestrator
            target_url: The scanned URL

        Returns:
            (enriched_findings, executive_summary)
        """
        if not findings:
            logger.warning("No findings to enrich")
            return findings, f"No vulnerabilities were detected in the scan of {target_url}."

        logger.info(f"Starting AI enrichment | findings={len(findings)} | target={target_url}")

        # ── Step 1: Select findings to enrich ─────────
        # Prioritize Critical/High/Medium — skip enriching all Low findings
        findings_to_enrich = [
            f for f in findings if f.get("severity") in ("Critical", "High", "Medium")
        ]
        low_findings = [f for f in findings if f.get("severity") == "Low"]

        # If no medium+ findings, enrich everything
        if not findings_to_enrich:
            findings_to_enrich = findings[:MAX_ENRICH]
            low_findings = []

        # Cap at MAX_ENRICH
        if len(findings_to_enrich) > MAX_ENRICH:
            logger.info(f"Large scan: capping enrichment at {MAX_ENRICH} of {len(findings_to_enrich)} medium+ findings")
            findings_to_enrich = findings_to_enrich[:MAX_ENRICH]

        logger.info(f"Enriching {len(findings_to_enrich)} findings via Groq (batches of {BATCH_SIZE})")

        # ── Step 2: Batch enrichment via Groq ─────────
        enriched_map = {}  # vuln_id -> {recommendation, business_impact}

        total_batches = (len(findings_to_enrich) + BATCH_SIZE - 1) // BATCH_SIZE
        for i in range(0, len(findings_to_enrich), BATCH_SIZE):
            batch = findings_to_enrich[i:i + BATCH_SIZE]
            batch_num = (i // BATCH_SIZE) + 1
            logger.info(f"Batch {batch_num}/{total_batches} ({len(batch)} findings)")

            try:
                enriched_batch = self._enrich_batch(batch)
                for item in enriched_batch:
                    enriched_map[item["vuln_id"]] = {
                        "recommendation":  item.get("recommendation", ""),
                        "business_impact": item.get("business_impact", ""),
                    }
            except Exception as e:
                logger.error(f"Batch {batch_num} failed completely: {e} — leaving AI fields empty")

        # ── Step 3: Apply enrichment to findings ───────
        for finding in findings:
            if finding["vuln_id"] in enriched_map:
                finding["recommendation"]  = enriched_map[finding["vuln_id"]]["recommendation"]
                finding["business_impact"] = enriched_map[finding["vuln_id"]]["business_impact"]
            elif finding.get("severity") == "Low":
                # Give low findings a simple default from ZAP's solution
                finding["recommendation"]  = finding.get("solution", "")
                finding["business_impact"] = "Low-severity misconfiguration that could aid attackers in reconnaissance or initial exploitation attempts."

        # ── Step 4: Executive summary via Nemotron ──────
        logger.info("Generating executive summary via Nemotron (1M context)")
        try:
            executive_summary = self._generate_executive_summary(findings, target_url)
            logger.info("Executive summary generated successfully")
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e} — using fallback")
            # Build meaningful fallback from data
            critical = sum(1 for f in findings if f.get("severity") == "Critical")
            high     = sum(1 for f in findings if f.get("severity") == "High")
            medium   = sum(1 for f in findings if f.get("severity") == "Medium")
            low      = sum(1 for f in findings if f.get("severity") == "Low")
            top_cat  = findings[0].get("owasp_category", "security misconfigurations") if findings else "security misconfigurations"
            executive_summary = (
                f"The security assessment of {target_url} identified {len(findings)} vulnerabilities "
                f"({critical} Critical, {high} High, {medium} Medium, {low} Low). "
                f"The most prevalent finding category is {top_cat}. "
                f"Immediate remediation is recommended for all Critical and High severity findings. "
                f"Medium severity issues should be addressed in the next development sprint to reduce the overall attack surface."
            )

        logger.info(f"AI enrichment complete | enriched={len(enriched_map)}/{len(findings)}")
        return findings, executive_summary


# ──────────────────────────────────────────────
# Quick test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    from dotenv import load_dotenv
    load_dotenv()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [AI] %(message)s")

    # Load findings
    for fname in ["scan_result_enriched.json", "scan_result.json"]:
        if os.path.exists(fname):
            with open(fname) as f:
                scan_data = json.load(f)
            findings = scan_data.get("findings", [])
            target_url = scan_data.get("target") or scan_data.get("url", "http://example.com")
            print(f"Loaded {len(findings)} findings from {fname}")
            break
    else:
        print("No scan data found. Run zap_scanner.py first.")
        sys.exit(1)

    analyzer = AIAnalyzer()
    enriched, summary = analyzer.enrich(findings, target_url)

    print("\n" + "=" * 60)
    print("EXECUTIVE SUMMARY (via Nemotron)")
    print("=" * 60)
    print(summary)
    print()
    print("=" * 60)
    print("TOP 3 ENRICHED FINDINGS (via Groq)")
    print("=" * 60)
    for f in enriched[:3]:
        print(f"\n[{f['severity']}] {f['vuln_type']}")
        print(f"  Fix    : {f['recommendation'][:150]}...")
        print(f"  Impact : {f['business_impact']}")

    # Save
    with open("scan_result_enriched.json", "w") as f:
        json.dump({
            "target":            target_url,
            "findings":          enriched,
            "executive_summary": summary,
        }, f, indent=2)
    print("\nSaved to scan_result_enriched.json")