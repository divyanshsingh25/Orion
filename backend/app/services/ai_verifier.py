from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional

from app.core.config import Settings
from app.services.deterministic_verifier import DeterministicVerifier
from app.services.security_sanitizer import SecuritySanitizer

logger = logging.getLogger("orion.ai_verifier")

try:
    from openai import AsyncOpenAI
except ImportError:
    AsyncOpenAI = None


class AIVerifier:
    """AI-assisted vulnerability verification and false-positive reduction engine."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or Settings()

    async def verify_finding(self, raw_finding: Dict[str, Any]) -> Dict[str, Any]:
        """Verify a finding through deterministic rules and asynchronous AI analysis.

        Guarantees:
            - Preserves original scanner result.
            - Never crashes or breaks the scanning pipeline.
            - Redacts all secrets and PII before LLM calls.
            - Defaults to POTENTIAL on uncertainty.
        """
        # 1. Preserve original scanner classification
        scanner_result = {
            "confidence": str(raw_finding.get("confidence", "Medium")),
            "severity": str(raw_finding.get("severity", "Medium")),
            "source_module": str(raw_finding.get("source_module", "scanner")),
            "finding_type": str(raw_finding.get("finding_type", raw_finding.get("type", "unknown"))),
        }

        # 2. Run deterministic ground-truth verification
        try:
            deterministic_res = DeterministicVerifier.verify(raw_finding)
        except Exception as e:
            logger.warning(f"Deterministic verification error: {e}")
            deterministic_res = {
                "verdict": "POTENTIAL",
                "confidence": 0.50,
                "reasoning": "Deterministic verification encountered unexpected error; defaulting to POTENTIAL.",
                "checks_applied": ["error_fallback"],
            }

        # 3. Check if LLM is enabled and configured
        ai_res = None
        has_llm = bool(
            AsyncOpenAI is not None
            and self.settings.llm_api_key
            and self.settings.llm_api_key != "your-api-key-here"
        )

        if has_llm:
            try:
                ai_res = await self._run_llm_analysis(raw_finding, deterministic_res)
            except Exception as e:
                logger.warning(f"AI LLM verification failed gracefully: {e}")
                ai_res = None

        # 4. Synthesize final classification
        if ai_res and ai_res.get("verdict"):
            final_verdict = ai_res["verdict"]
            final_reasoning = f"[AI Verified] {ai_res.get('reasoning', deterministic_res['reasoning'])}"
            final_confidence = float(ai_res.get("confidence", deterministic_res["confidence"]))
        else:
            final_verdict = deterministic_res["verdict"]
            final_reasoning = f"[Deterministic] {deterministic_res['reasoning']}"
            final_confidence = float(deterministic_res["confidence"])

        # Enforce Ground-Truth Safety Invariant:
        # If deterministic found FALSE_POSITIVE (e.g. escaped HTML in JSON), AI cannot override it to CONFIRMED
        if deterministic_res["verdict"] == "FALSE_POSITIVE" and final_verdict == "CONFIRMED":
            final_verdict = "POTENTIAL"
            final_reasoning = f"[Safety Guard: Overridden to POTENTIAL] {deterministic_res['reasoning']}"

        return {
            "scanner_result": scanner_result,
            "deterministic_verification": deterministic_res,
            "ai_verification": ai_res or {
                "verdict": deterministic_res["verdict"],
                "confidence": deterministic_res["confidence"],
                "reasoning": "Evaluated using local deterministic verification rules.",
            },
            "final_classification": final_verdict,
            "verification_reasoning": final_reasoning,
            "verification_confidence": round(final_confidence, 2),
        }

    async def _run_llm_analysis(
        self,
        raw_finding: Dict[str, Any],
        deterministic_res: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Perform sanitized evidence analysis via LLM."""
        sanitized_finding = SecuritySanitizer.sanitize_dict({
            "title": raw_finding.get("title"),
            "finding_type": raw_finding.get("finding_type", raw_finding.get("type")),
            "affected_url": raw_finding.get("affected_url"),
            "affected_parameter": raw_finding.get("affected_parameter"),
            "evidence": raw_finding.get("evidence"),
            "http_request": raw_finding.get("http_request"),
            "http_response": (raw_finding.get("http_response") or "")[:2000],
        })

        client = AsyncOpenAI(
            api_key=self.settings.llm_api_key,
            base_url=self.settings.llm_base_url,
            timeout=12.0,  # Strict timeout so scanning is never stalled
        )

        system_prompt = (
            "You are an expert Security Assessment Verification Engine.\n"
            "Your task is to analyze scan evidence and classify whether a detected vulnerability is "
            "CONFIRMED, POTENTIAL, or FALSE_POSITIVE.\n\n"
            "STRICT RULES:\n"
            "1. Reflection alone in HTML/JSON must NOT confirm XSS. If entity-encoded or in JSON, it is FALSE_POSITIVE or POTENTIAL.\n"
            "2. An HTTP 'Allow:' header or OPTIONS response alone is NOT a vulnerability and must NOT be CONFIRMED or FALSE_POSITIVE; it is POTENTIAL (insufficient evidence) until actual write/delete execution is proven.\n"
            "3. Passive Server/banner version string matching alone must NOT confirm a CVE (classify as POTENTIAL).\n"
            "4. If the evidence is ambiguous, incomplete, or uncertain, you MUST return POTENTIAL (never FALSE_POSITIVE).\n"
            "5. You must output ONLY a valid JSON object matching the requested schema."
        )

        user_prompt = (
            f"Finding Data:\n"
            f"- Title: {sanitized_finding.get('title')}\n"
            f"- Type: {sanitized_finding.get('finding_type')}\n"
            f"- Affected URL: {sanitized_finding.get('affected_url')}\n"
            f"- Affected Parameter: {sanitized_finding.get('affected_parameter')}\n"
            f"- Scanner Evidence: {sanitized_finding.get('evidence')}\n"
            f"- HTTP Request: {sanitized_finding.get('http_request')}\n"
            f"- HTTP Response: {sanitized_finding.get('http_response')}\n"
            f"- Baseline Check Verdict: {deterministic_res.get('verdict')} ({deterministic_res.get('reasoning')})\n\n"
            "Respond ONLY with this exact JSON format:\n"
            "{\n"
            '  "verdict": "CONFIRMED" | "POTENTIAL" | "FALSE_POSITIVE",\n'
            '  "confidence": 0.0 to 1.0,\n'
            '  "reasoning": "concise technical justification"\n'
            "}"
        )

        response = await client.chat.completions.create(
            model=self.settings.llm_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            max_tokens=250,
            response_format={"type": "json_object"} if "gpt-4" in self.settings.llm_model or "gpt-3.5" in self.settings.llm_model else None,
        )

        content = response.choices[0].message.content or "{}"
        # Extract JSON if markdown wrapped
        content = re.sub(r"^```json\s*", "", content.strip())
        content = re.sub(r"\s*```$", "", content)

        data = json.loads(content)
        verdict = str(data.get("verdict", "")).upper()
        if verdict not in {"CONFIRMED", "POTENTIAL", "FALSE_POSITIVE"}:
            verdict = "POTENTIAL"

        confidence = float(data.get("confidence", 0.5))
        confidence = max(0.1, min(1.0, confidence))

        return {
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": str(data.get("reasoning") or "Evaluated by AI evidence analysis."),
        }
