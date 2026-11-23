"""
Sentinel-AI - RAG Semantic Retriever
High-performance local vector retrieval using TF-IDF and hybrid keyword boosting.
Runs 100% locally and offline without external vector database servers.
"""

import os
import json
import re
from typing import List, Dict, Any, Optional
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

KB_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "knowledge_base.json")

class ThreatKnowledgeRetriever:
    def __init__(self, kb_path: str = KB_DEFAULT_PATH):
        self.kb_path = kb_path
        self.documents: List[Dict[str, Any]] = []
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.doc_vectors = None
        self._load_and_index()

    def _load_and_index(self):
        """Loads knowledge base JSON and builds TF-IDF vector index."""
        if not os.path.exists(self.kb_path):
            raise FileNotFoundError(f"Knowledge base file not found at: {self.kb_path}")

        with open(self.kb_path, "r", encoding="utf-8") as f:
            self.documents = json.load(f)

        # Create rich composite search text for each document
        corpus = []
        for doc in self.documents:
            tags_str = " ".join(doc.get("tags", []))
            mitre_id = doc.get("mitre_id", "")
            title = doc.get("title", "")
            summary = doc.get("summary", "")
            content = doc.get("content", "")
            mitigation = doc.get("mitigation", "")
            
            # Weighted repetition of key identifiers to boost title/tags
            composite_text = f"{title} {title} {mitre_id} {mitre_id} {tags_str} {tags_str} {summary} {content} {mitigation}"
            corpus.append(composite_text.lower())

        self.vectorizer = TfidfVectorizer(
            stop_words="english",
            token_pattern=r"(?u)\b[\w\.\-]+\b",
            ngram_range=(1, 2)
        )
        self.doc_vectors = self.vectorizer.fit_transform(corpus)

    def search(
        self,
        query: str,
        top_k: int = 3,
        category: Optional[str] = None,
        min_score: float = 0.05
    ) -> List[Dict[str, Any]]:
        """
        Executes hybrid semantic vector search + keyword boost over the knowledge base.
        
        Args:
            query: The user query, question, or threat description.
            top_k: Maximum number of knowledge chunks to return.
            category: Optional category filter (e.g. 'brand_profile', 'incident_response').
            min_score: Minimum similarity score threshold.
            
        Returns:
            List of matching documents with score, citations, and metadata.
        """
        if not query or not query.strip():
            return []

        cleaned_query = query.strip().lower()
        query_vec = self.vectorizer.transform([cleaned_query])
        cosine_sims = cosine_similarity(query_vec, self.doc_vectors)[0]

        # Tokenize query for keyword and tag boosting
        query_tokens = set(re.findall(r"[\w\.\-]+", cleaned_query))

        ranked_results = []
        for idx, doc in enumerate(self.documents):
            # Category filter
            if category and doc.get("category") != category:
                continue

            base_score = float(cosine_sims[idx])

            # Keyword & tag boosting
            bonus = 0.0
            doc_id = doc.get("id", "")
            if doc_id == "ir-credentials-submitted" and any(
                phrase in cleaned_query
                for phrase in (
                    "credentials submitted",
                    "entered password",
                    "entered my password",
                    "submitted password",
                    "login details",
                    "password was entered",
                )
            ):
                bonus += 0.75
            elif doc_id == "ir-link-clicked" and any(
                phrase in cleaned_query
                for phrase in (
                    "malicious link clicked",
                    "clicked a link",
                    "did not enter",
                    "no credentials",
                    "visited a phishing",
                )
            ):
                bonus += 0.75
            elif doc_id == "takedown-procedure" and any(
                phrase in cleaned_query
                for phrase in ("takedown", "abuse report", "report domain", "remove website")
            ):
                bonus += 0.75

            doc_tags = set(t.lower() for t in doc.get("tags", []))
            tag_overlap = len(query_tokens.intersection(doc_tags))
            bonus += tag_overlap * 0.12

            # MITRE ID direct hit
            mitre_id = doc.get("mitre_id", "").lower()
            if mitre_id and any(tok in mitre_id or mitre_id in tok for tok in query_tokens):
                bonus += 0.35

            # Title keyword overlap
            title_lower = doc.get("title", "").lower()
            if any(tok in title_lower for tok in query_tokens if len(tok) >= 4):
                bonus += 0.15

            final_score = round(min(1.0, base_score + bonus), 4)

            if final_score >= min_score or (base_score > 0 and len(ranked_results) < top_k):
                result_entry = dict(doc)
                result_entry["score"] = final_score
                result_entry["cosine_similarity"] = round(base_score, 4)
                ranked_results.append(result_entry)

        # Sort descending by score
        ranked_results.sort(key=lambda x: x["score"], reverse=True)
        return ranked_results[:top_k]

    def get_document_by_id(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single knowledge base document by its unique ID."""
        for doc in self.documents:
            if doc.get("id") == doc_id:
                return dict(doc)
        return None

    def get_topics_overview(self) -> Dict[str, Any]:
        """Returns metadata summary of the knowledge base for UI display."""
        categories = {}
        for doc in self.documents:
            cat = doc.get("category", "general")
            categories.setdefault(cat, []).append({
                "id": doc.get("id"),
                "title": doc.get("title"),
                "mitre_id": doc.get("mitre_id"),
                "tags": doc.get("tags", [])
            })

        return {
            "total_documents": len(self.documents),
            "categories": categories
        }
