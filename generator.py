"""
Sentinel-AI - RAG Generator & Forensic Synthesizer
Dual-mode generation engine:
1. Native Local Threat Synthesizer: 100% offline, zero API keys required.
2. Pluggable Cloud LLM Generator (Gemini API / Compatible): Uses GEMINI_API_KEY if configured,
   with automatic failover to the local synthesizer.
"""

import os
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional

class ThreatForensicGenerator:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model_name = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

    def _call_gemini_api(self, prompt: str, system_instruction: str = "") -> Optional[str]:
        """Calls Gemini API if API key is provided."""
        if not self.api_key:
            return None

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        
        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 1024
            }
        }
        
        if system_instruction:
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=8) as response:
                if response.status == 200:
                    res_json = json.loads(response.read().decode("utf-8"))
                    candidates = res_json.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            return parts[0].get("text", "").strip()
        except Exception:
            # Silently fall back to native offline synthesizer
            pass

        return None

    def synthesize_url_dossier(
        self,
        url: str,
        scan_result: Dict[str, Any],
        retrieved_docs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Synthesizes a deep forensic threat dossier for a scanned URL or QR code
        using retrieved threat intelligence articles.
        """
        is_phishing = scan_result.get("is_phishing", False)
        verdict = scan_result.get("verdict", "unknown").upper()
        confidence = scan_result.get("confidence", 0.0)
        threat_type = scan_result.get("threat_type")
        target_brand = scan_result.get("target_brand")
        threat_reason = scan_result.get("threat_reason")
        cleaned_url = scan_result.get("cleaned_url", url)

        # Build citations list
        citations = []
        mitre_techniques = []
        for doc in retrieved_docs:
            citations.append({
                "id": doc.get("id"),
                "title": doc.get("title"),
                "mitre_id": doc.get("mitre_id"),
                "category": doc.get("category"),
                "relevance_score": doc.get("score"),
                "summary": doc.get("summary")
            })
            if doc.get("mitre_id") and doc.get("mitre_id") not in mitre_techniques:
                mitre_techniques.append(doc.get("mitre_id"))

        # Try LLM generation if API key is present
        if self.api_key:
            doc_context = "\n\n".join([
                f"[{d.get('mitre_id', 'REF')}] {d.get('title')}:\n{d.get('content')}\nMitigation: {d.get('mitigation')}"
                for d in retrieved_docs
            ])
            llm_prompt = (
                f"You are Sentinel-AI's Lead Threat Intelligence Analyst. Produce a concise, high-impact "
                f"forensic evaluation of the scanned URL based on the provided threat intelligence.\n\n"
                f"Target URL: {url}\n"
                f"ML Verdict: {verdict} ({confidence}% confidence)\n"
                f"Detected Brand / Anomaly: {target_brand or 'None'}\n"
                f"Specific Indicator: {threat_reason or 'Lexical classification'}\n\n"
                f"Retrieved Threat Intelligence Context:\n{doc_context}\n\n"
                f"Provide: (1) Executive Threat Summary, (2) Attack Mechanism & MITRE Techniques, "
                f"(3) Recommended SOC/Incident Response Playbook."
            )
            llm_text = self._call_gemini_api(
                llm_prompt,
                "You are an enterprise cybersecurity expert specializing in phishing and domain spoofing analysis."
            )
            if llm_text:
                return {
                    "source": "rag_llm",
                    "executive_summary": llm_text,
                    "mitre_techniques": mitre_techniques,
                    "citations": citations,
                    "action_steps": [
                        "Block domain on enterprise DNS resolvers and Secure Web Gateways (SWG).",
                        "Audit web proxy logs for internal network requests to this target.",
                        "Report domain to registrar abuse contact and Anti-Phishing Working Group (APWG)."
                    ]
                }

        # --- High-Fidelity Local Forensic Synthesizer (Offline RAG) ---
        if is_phishing:
            if threat_type == "punycode_homoglyph":
                attack_mechanism = (
                    f"Internationalized Domain Name (IDN) Homoglyph deception exploiting Unicode script similarity "
                    f"to construct visually indistinguishable lookalike domains."
                )
            elif threat_type in ("typosquatting", "leetspeak_typosquatting", "typosquatting_edit_distance"):
                brand_str = f"impersonating {target_brand}" if target_brand else "targeting high-profile online platforms"
                attack_mechanism = (
                    f"Alphanumeric deception (Levenshtein distance / leetspeak mutation) {brand_str}. "
                    f"Attackers deploy these lookalikes to exploit typo frequency and cognitive visual assumptions."
                )
            elif threat_type == "combosquatting":
                attack_mechanism = (
                    f"Combosquatting vector concatenating legitimate brand identifier '{target_brand}' "
                    f"with administrative or urgent keywords to simulate authentic authorization portals."
                )
            else:
                attack_mechanism = (
                    f"Lexical signature indicators matching malicious phishing URL infrastructure. "
                    f"Feature analysis detected suspicious token sequences characteristic of credential harvesting kits."
                )

            summary = (
                f"CRITICAL THREAT: The scanned URL '{cleaned_url}' is classified as a malicious PHISHING destination "
                f"with {confidence}% confidence. {threat_reason or 'Lexical patterns indicate an active threat.'} "
                f"Visiting this resource exposes users to credential harvesting and session hijacking."
            )

            action_steps = [
                "Containment: Do not navigate to the URL, submit credentials, or authorize OAuth prompts.",
                "Perimeter Blocking: Blacklist domain and corresponding IP on corporate firewalls, DNS resolvers, and Secure Email Gateways.",
                "Identity Protection: If any employee navigated to this destination, revoke active refresh tokens and mandate a password reset.",
                "Takedown Action: File an abuse complaint with the authoritative registrar and report to Google Safe Browsing and APWG."
            ]
        else:
            attack_mechanism = (
                f"Domain structure and lexical tokens align with legitimate Internet naming conventions. "
                f"No deceptive homoglyphs, brand spoofing variations, or malicious token combinations were detected."
            )
            summary = (
                f"SAFE VERDICT: '{cleaned_url}' is classified as a legitimate, healthy domain with {confidence}% confidence. "
                f"No brand impersonation, combosquatting, or known phishing signatures were matched."
            )
            action_steps = [
                "Routine Access: No anomalous threats detected; site appears authentic.",
                "Best Practice: Verify TLS certificate details in browser address bar before providing sensitive data.",
                "Continuous Monitoring: Retain standard security monitoring protocols for newly added subdomains."
            ]

        # Extract contextual mitigations from top matching document
        top_mitigation = retrieved_docs[0].get("mitigation") if retrieved_docs else None
        if top_mitigation and top_mitigation not in action_steps:
            action_steps.append(f"Strategic Defense: {top_mitigation}")

        return {
            "source": "rag_native_synthesizer",
            "executive_summary": summary,
            "attack_mechanism": attack_mechanism,
            "mitre_techniques": mitre_techniques or ["T1566.001"],
            "action_steps": action_steps,
            "citations": citations
        }

    def generate_chat_response(
        self,
        query: str,
        conversation_history: List[Dict[str, str]],
        retrieved_docs: List[Dict[str, Any]],
        context_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generates conversational Q&A answer for the Threat Copilot assistant.
        Uses retrieved documents for grounding.
        """
        # Build structured citations
        citations = []
        for doc in retrieved_docs:
            citations.append({
                "id": doc.get("id"),
                "title": doc.get("title"),
                "mitre_id": doc.get("mitre_id"),
                "category": doc.get("category"),
                "score": doc.get("score"),
                "summary": doc.get("summary")
            })

        # Try LLM if configured
        if self.api_key:
            doc_context = "\n\n".join([
                f"Document [{d.get('id')} - {d.get('title')}]:\n{d.get('content')}\nMitigation: {d.get('mitigation')}"
                for d in retrieved_docs
            ])
            llm_prompt = (
                f"User Question: {query}\n"
                f"Active Scanned URL Context: {context_url or 'None'}\n\n"
                f"Retrieved Threat Intelligence Articles:\n{doc_context}\n\n"
                f"Answer the user's cybersecurity question authoritatively, accurately, and concisely. "
                f"Reference the threat techniques, MITRE IDs, and actionable playbooks from the retrieved context."
            )
            llm_text = self._call_gemini_api(
                llm_prompt,
                "You are Sentinel-AI's Copilot, an enterprise threat intelligence and anti-phishing expert assistant."
            )
            if llm_text:
                return {
                    "source": "rag_llm",
                    "answer": llm_text,
                    "citations": citations,
                    "suggested_questions": self._generate_suggested_questions(query, retrieved_docs)
                }

        # --- Local Grounded Threat Copilot Generator (Offline RAG) ---
        q_lower = query.lower()
        top_doc = retrieved_docs[0] if retrieved_docs else None
        top_score = top_doc.get("score", 0.0) if top_doc else 0.0

        # Build grounded response based on top retrieved documents and user query intent
        response_parts = []

        if top_doc and top_score >= 0.12:
            mitre_str = f" (**{top_doc.get('mitre_id')}**)" if top_doc.get('mitre_id') else ""
            response_parts.append(
                f"### 🛡️ Threat Intelligence Analysis: {top_doc.get('title')}{mitre_str}\n\n"
                f"{top_doc.get('summary')}\n\n"
                f"{top_doc.get('content')}"
            )

            if top_doc.get("mitigation"):
                response_parts.append(
                    f"\n\n#### 🎯 Recommended Defense & Mitigation Playbook\n"
                    f"{top_doc.get('mitigation')}"
                )

            # If there's a complementary secondary document retrieved
            if len(retrieved_docs) > 1 and retrieved_docs[1].get("score", 0) > 0.2:
                sec_doc = retrieved_docs[1]
                response_parts.append(
                    f"\n\n#### 🔍 Correlated Threat Vector: {sec_doc.get('title')}\n"
                    f"{sec_doc.get('summary')}"
                )
        else:
            response_parts.append(
                "Sentinel-AI analyzed your query. While no direct single match was found in the local threat corpus, "
                "our general security policy recommends verifying the domain's root TLD, inspecting for subtle character "
                "substitutions, and never submitting credentials on unverified third-party hosts."
            )

        if context_url:
            response_parts.append(
                f"\n\n*Currently active scan context: `{context_url}`*"
            )

        answer_text = "".join(response_parts)
        suggested_questions = self._generate_suggested_questions(query, retrieved_docs)

        return {
            "source": "rag_native_synthesizer",
            "answer": answer_text,
            "citations": citations,
            "suggested_questions": suggested_questions
        }

    def _generate_suggested_questions(self, query: str, docs: List[Dict[str, Any]]) -> List[str]:
        """Provides relevant dynamic follow-up questions."""
        q_lower = query.lower()
        if "qr" in q_lower or "quish" in q_lower:
            return [
                "How do Secure Email Gateways fail to detect Quishing?",
                "What MDM policies protect corporate smartphones from QR scams?",
                "How can users verify QR codes before opening them?"
            ]
        elif "typo" in q_lower or "squat" in q_lower or "homoglyph" in q_lower:
            return [
                "What is the difference between typosquatting and combosquatting?",
                "How does Punycode IDN spoofing work?",
                "What steps should our SOC take to file a domain takedown?"
            ]
        elif "cred" in q_lower or "click" in q_lower or "incident" in q_lower:
            return [
                "What are the immediate steps if an employee entered credentials?",
                "How does FIDO2/WebAuthn make authentication immune to phishing?",
                "How do reverse proxies like EvilProxy bypass traditional MFA?"
            ]
        else:
            return [
                "Explain the MITRE ATT&CK T1566 phishing framework.",
                "How does Sentinel-AI detect typosquatting and leetspeak in real time?",
                "What is Adversary-in-the-Middle (AiTM) reverse proxy phishing?"
            ]
