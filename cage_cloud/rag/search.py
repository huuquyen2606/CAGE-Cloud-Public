#!/usr/bin/env python3
"""
CVE RAG Search - Semantic Search với Qwen/Qwen3-Embedding-8B + FAISS

Qwen3 embedding dùng pattern chính thức:
  - Documents: embed raw text
  - Queries:   "Instruct: <instruction>\nQuery: <query>"
  - Pooling:   last-token pooling + L2 normalization

Usage:
    python3 rag_search.py --build
    python3 rag_search.py --query "spring boot ssrf aws iam"
    python3 rag_search.py --query "s3 public bucket" --provider aws --top-k 5
"""

import argparse
import json
import os
import pickle
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

import numpy as np

# -- Paths --
DATASET_ROOT = Path(
    os.environ.get(
        "CVE_DATASET_ROOT",
        "/root/NCKH/CVE-CLOUD/COT_Planner_CVE-CLOUD/output",
    )
)
DEFAULT_INDEX_DIR = Path(
    os.environ.get(
        "RAG_INDEX_DIR",
        "/root/NCKH/CloudPentest/rag_index",
    )
)

# -- Qwen3 Embedding config --
MODEL_NAME = os.environ.get("RAG_EMBED_MODEL", "Qwen/Qwen3-Embedding-8B")
QUERY_INSTRUCTION = (
    "Given a cloud pentest query, retrieve the most relevant CVE documents."
)
INDEX_FORMAT_VERSION = 2
INDEX_BACKEND = "transformers-qwen3"
DEFAULT_MAX_LENGTH = int(os.environ.get("QWEN_MAX_LENGTH", "1024"))
DEFAULT_BATCH_SIZE = int(os.environ.get("QWEN_BATCH_SIZE", "4"))


def _lazy_import_faiss():
    try:
        import faiss
    except ImportError as exc:
        raise RuntimeError(
            "faiss-cpu is required for semantic RAG. Install dependencies first."
        ) from exc
    return faiss


def _lazy_import_qwen_backend():
    try:
        import torch
        from transformers import AutoModel, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError(
            "Qwen3 semantic RAG requires torch and transformers>=4.51.0. "
            "Install/update dependencies before building or querying the index."
        ) from exc
    return torch, AutoModel, AutoTokenizer


# =============================================================================
# Data Classes (interface giữ nguyên cho rag_integration.py)
# =============================================================================


@dataclass
class CVEDocument:
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cloud_type: str
    tags: List[str] = field(default_factory=list)
    vuln_type: str = ""
    attack_phases: List[str] = field(default_factory=list)
    exploit_commands: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    search_text: str = ""


@dataclass
class SearchResult:
    document: CVEDocument
    score: float


# =============================================================================
# Text Preparation
# =============================================================================


def _build_search_text(data: dict) -> str:
    """
    Gộp thông tin CVE thành 1 chuỗi giàu ngữ cảnh để Qwen3 embed document.
    """
    parts = []

    meta = data.get("metadata", {})
    title = meta.get("title", "")
    parts.append(title)
    parts.append(title)
    parts.append(meta.get("description", ""))
    parts.extend(meta.get("tags", []))

    vuln = data.get("vulnerability", {})
    parts.append(vuln.get("type", ""))
    parts.append(vuln.get("root_cause", ""))
    cwes = vuln.get("cwe", "")
    if isinstance(cwes, list):
        parts.extend(cwes)
    elif isinstance(cwes, str):
        parts.append(cwes)

    attack_path = data.get("attack_path", {})
    tasks = attack_path.get("tasks", []) if isinstance(attack_path, dict) else attack_path

    for task in tasks:
        parts.append(task.get("instruction", ""))
        parts.append(task.get("action_type", ""))
        parts.append(task.get("action_method", ""))
        sc = task.get("semantic_context", {})
        if isinstance(sc, dict):
            parts.append(sc.get("objective", ""))
            parts.append(sc.get("target_service", ""))
            parts.extend(sc.get("target_resources", []))

    for pre in data.get("preconditions", []):
        if isinstance(pre, str):
            parts.append(pre)

    clf = data.get("classification", {})
    parts.append(clf.get("reason", ""))
    parts.append(clf.get("cloud_type", ""))

    # Giữ text gọn để build/index/search ổn định, tránh đẩy quá dài không cần thiết.
    text = " ".join(p for p in parts if p)
    return text[:1800]


def _extract_phases(data: dict) -> List[str]:
    attack_path = data.get("attack_path", {})
    tasks = attack_path.get("tasks", []) if isinstance(attack_path, dict) else attack_path
    phases = []
    for task in tasks:
        phase = task.get("phase", "")
        if phase and phase not in phases:
            phases.append(phase)
    return phases


def _extract_commands(data: dict) -> List[str]:
    guidance = data.get("agent_guidance", {})
    if guidance:
        hints = guidance.get("generator_hints", {})
        if isinstance(hints, dict):
            cmds = hints.get("commands", [])
            if cmds:
                return cmds[:5]

    attack_path = data.get("attack_path", {})
    tasks = attack_path.get("tasks", []) if isinstance(attack_path, dict) else attack_path
    cmds = []
    for task in tasks:
        method = task.get("action_method", "")
        if method:
            cmds.append(method)
    return cmds[:5]


def load_all_cves(dataset_root: Path) -> List[CVEDocument]:
    """Load tất cả CVE JSON files recursive từ dataset root."""
    docs = []
    for json_file in sorted(dataset_root.rglob("CVE-*.json")):
        try:
            with open(json_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)

            meta = data.get("metadata", {})
            clf = data.get("classification", {})

            raw_cvss = meta.get("cvss", 0)
            if isinstance(raw_cvss, str):
                try:
                    raw_cvss = float(raw_cvss.split("|")[0])
                except ValueError:
                    raw_cvss = 0.0

            docs.append(
                CVEDocument(
                    cve_id=meta.get("cve_id", json_file.stem),
                    title=meta.get("title", ""),
                    description=meta.get("description", ""),
                    severity=meta.get("severity", "MEDIUM"),
                    cvss_score=float(raw_cvss),
                    cloud_type=clf.get("cloud_type", "other"),
                    tags=meta.get("tags", []),
                    vuln_type=data.get("vulnerability", {}).get("type", ""),
                    attack_phases=_extract_phases(data),
                    exploit_commands=_extract_commands(data),
                    preconditions=data.get("preconditions", [])[:3],
                    search_text=_build_search_text(data),
                )
            )
        except Exception as exc:
            print(f"  Skip {json_file.name}: {exc}")

    return docs


# =============================================================================
# CVERAGSearch - Qwen3 Embedding + FAISS
# =============================================================================


class CVERAGSearch:
    """
    Semantic search dùng Qwen/Qwen3-Embedding-8B + FAISS IndexFlatIP.

    Interface giữ nguyên để rag_integration.py không cần đổi:
        rag = CVERAGSearch()
        rag.load_index(path)
        results = rag.search(query, top_k, provider_filter, severity_filter)
        results[i].document
        results[i].score
    """

    def __init__(
        self,
        model_name: str = MODEL_NAME,
        query_instruction: str = QUERY_INSTRUCTION,
        max_length: int = DEFAULT_MAX_LENGTH,
    ):
        self.model_name = model_name
        self.query_instruction = query_instruction
        self.max_length = max_length

        self.model: Optional[Any] = None
        self.tokenizer: Optional[Any] = None
        self.torch: Optional[Any] = None
        self.index: Optional[Any] = None
        self.documents: List[CVEDocument] = []
        self._built = False
        self._keyword_only = False

    # -- Model -------------------------------------------------------------

    def _select_torch_dtype(self, torch):
        override = os.environ.get("QWEN_TORCH_DTYPE")
        if override:
            mapping = {
                "auto": "auto",
                "float16": torch.float16,
                "float32": torch.float32,
                "bfloat16": torch.bfloat16,
            }
            if override not in mapping:
                raise RuntimeError(
                    "Unsupported QWEN_TORCH_DTYPE. Use one of: auto, float16, float32, bfloat16."
                )
            return mapping[override]

        if torch.cuda.is_available():
            return torch.float16
        return torch.float32

    def _load_model(self) -> None:
        if self.model is not None and self.tokenizer is not None:
            return

        torch, AutoModel, AutoTokenizer = _lazy_import_qwen_backend()
        self.torch = torch

        device_map = os.environ.get("QWEN_DEVICE_MAP", "auto")
        torch_dtype = self._select_torch_dtype(torch)

        print(f"  Loading embedding model: {self.model_name}...")
        t0 = time.time()

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                padding_side="left",
            )
            if self.tokenizer.pad_token is None and self.tokenizer.eos_token is not None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            self.model = AutoModel.from_pretrained(
                self.model_name,
                torch_dtype=torch_dtype,
                device_map=device_map,
            )
            self.model.eval()
        except Exception as exc:
            raise RuntimeError(
                "Could not load Qwen/Qwen3-Embedding-8B. "
                "Ensure transformers>=4.51.0, accelerate is installed, "
                "and the machine has enough RAM/VRAM."
            ) from exc

        dim = getattr(self.model.config, "hidden_size", "unknown")
        print(f"  Model loaded in {time.time() - t0:.1f}s | dim={dim}")

    def _last_token_pool(self, last_hidden_states, attention_mask):
        left_padding = bool(
            (attention_mask[:, -1].sum() == attention_mask.shape[0]).item()
        )
        if left_padding:
            return last_hidden_states[:, -1]

        sequence_lengths = attention_mask.sum(dim=1) - 1
        batch_size = last_hidden_states.shape[0]
        return last_hidden_states[
            self.torch.arange(batch_size, device=last_hidden_states.device),
            sequence_lengths,
        ]

    def _format_query(self, query: str) -> str:
        return f"Instruct: {self.query_instruction}\nQuery: {query.strip()}"

    def _encode(
        self,
        texts: List[str],
        *,
        is_query: bool,
        batch_size: int = DEFAULT_BATCH_SIZE,
        show_progress: bool = False,
    ) -> np.ndarray:
        """Encode texts -> L2-normalized float32 vectors."""
        self._load_model()

        if not texts:
            return np.zeros((0, 0), dtype=np.float32)

        batch_size = max(1, batch_size)
        formatted = [self._format_query(text) if is_query else text for text in texts]

        batches = []
        total_batches = (len(formatted) + batch_size - 1) // batch_size

        for batch_idx, start in enumerate(range(0, len(formatted), batch_size), start=1):
            batch = formatted[start : start + batch_size]
            inputs = self.tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=self.max_length,
                return_tensors="pt",
            )
            inputs = {key: value.to(self.model.device) for key, value in inputs.items()}

            with self.torch.no_grad():
                outputs = self.model(**inputs)
                embeddings = self._last_token_pool(
                    outputs.last_hidden_state,
                    inputs["attention_mask"],
                )
                embeddings = self.torch.nn.functional.normalize(
                    embeddings,
                    p=2,
                    dim=1,
                )

            batches.append(embeddings.cpu().float().numpy())

            if show_progress:
                print(f"    Encoded batch {batch_idx}/{total_batches}", end="\r", flush=True)

        if show_progress and total_batches:
            print(f"    Encoded batch {total_batches}/{total_batches}")

        return np.concatenate(batches, axis=0).astype(np.float32)

    # -- Build -------------------------------------------------------------

    def build_index(self, documents: List[CVEDocument]) -> None:
        """Encode tất cả CVE docs và build FAISS index."""
        if not documents:
            raise ValueError("No documents")

        faiss = _lazy_import_faiss()

        self.documents = documents
        print(f"  Encoding {len(documents)} CVE documents with {self.model_name}...")
        t0 = time.time()

        texts = [doc.search_text for doc in documents]
        vectors = self._encode(
            texts,
            is_query=False,
            batch_size=DEFAULT_BATCH_SIZE,
            show_progress=True,
        )

        build_time = time.time() - t0
        print(
            f"  Encoded in {build_time:.1f}s "
            f"({build_time / len(documents) * 1000:.0f}ms/doc)"
        )

        dim = vectors.shape[1]
        self.index = faiss.IndexFlatIP(dim)
        self.index.add(vectors)
        self._built = True
        print(f"  FAISS index: {self.index.ntotal} vectors, dim={dim}")

    # -- Save / Load -------------------------------------------------------

    def save_index(self, index_dir: str) -> None:
        if self.index is None:
            raise RuntimeError("Index not built.")

        faiss = _lazy_import_faiss()
        path = Path(index_dir)
        path.mkdir(parents=True, exist_ok=True)

        faiss.write_index(self.index, str(path / "faiss.index"))

        with open(path / "documents.pkl", "wb") as handle:
            pickle.dump(self.documents, handle)

        meta = {
            "format_version": INDEX_FORMAT_VERSION,
            "backend": INDEX_BACKEND,
            "model_name": self.model_name,
            "query_instruction": self.query_instruction,
            "query_format": "Instruct: <instruction>\\nQuery: <query>",
            "document_format": "raw",
            "pooling": "last_token",
            "normalized": True,
            "max_length": self.max_length,
            "embedding_dim": int(self.index.d),
            "n_docs": len(self.documents),
        }
        with open(path / "meta.json", "w", encoding="utf-8") as handle:
            json.dump(meta, handle, indent=2)

        print(f"  Saved to {path}/ ({len(self.documents)} docs, dim={self.index.d})")

    def _read_meta(self, index_dir: Path) -> dict:
        meta_path = index_dir / "meta.json"
        if not meta_path.exists():
            raise RuntimeError(
                "RAG meta.json is missing. Rebuild the index with: python3 rag_search.py --build"
            )
        with open(meta_path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _validate_meta(self, meta: dict, index_dir: Path) -> None:
        if meta.get("format_version") != INDEX_FORMAT_VERSION or meta.get("backend") != INDEX_BACKEND:
            raise RuntimeError(
                "Legacy or incompatible RAG index detected at "
                f"{index_dir} (model={meta.get('model_name', 'unknown')}). "
                "This code now requires a Qwen3 index with last-token pooling and "
                "Instruct+Query formatting. Rebuild with: python3 rag_search.py --build"
            )

        if meta.get("document_format") != "raw" or meta.get("pooling") != "last_token":
            raise RuntimeError(
                "RAG index metadata does not match the Qwen3 embedding format. "
                "Rebuild with: python3 rag_search.py --build"
            )

    def load_index(self, index_dir: str) -> None:
        path = Path(index_dir)
        meta = self._read_meta(path)

        # Load documents pickle (always needed)
        pkl_path = path / "documents.pkl"
        if not pkl_path.exists():
            raise RuntimeError(
                "RAG documents.pkl not found. Rebuild with: python3 rag_search.py --build"
            )
        with open(pkl_path, "rb") as handle:
            self.documents = pickle.load(handle)

        expected_docs = meta.get("n_docs")
        if expected_docs is not None and int(expected_docs) != len(self.documents):
            raise RuntimeError(
                "RAG documents.pkl does not match meta.json doc count. "
                "Rebuild with: python3 rag_search.py --build"
            )

        # Try loading FAISS index if format is compatible
        try:
            self._validate_meta(meta, path)
            self.model_name = meta.get("model_name", self.model_name)
            self.query_instruction = meta.get("query_instruction", self.query_instruction)
            self.max_length = int(meta.get("max_length", self.max_length))

            faiss = _lazy_import_faiss()
            self.index = faiss.read_index(str(path / "faiss.index"))

            if self.index.ntotal != len(self.documents):
                raise RuntimeError("Vector/doc count mismatch")

            self._built = True
            print(
                f"  Loaded semantic index: {self.index.ntotal} vectors dim={self.index.d}, "
                f"{len(self.documents)} docs | model={self.model_name}"
            )
        except (RuntimeError, Exception) as e:
            self.index = None
            self._built = True
            self._keyword_only = True
            print(
                f"  Loaded {len(self.documents)} CVE docs (keyword mode — "
                f"semantic index unavailable: {str(e)[:80]})"
            )

    # -- Search ------------------------------------------------------------

    def search(
        self,
        query: str,
        top_k: int = 5,
        provider_filter: Optional[str] = None,
        severity_filter: Optional[List[str]] = None,
    ) -> List[SearchResult]:
        """
        Search CVEs — semantic (FAISS) or keyword fallback.

        Args:
            query: free-text, e.g. "spring boot ssrf aws iam metadata"
            top_k: number of results
            provider_filter: "aws"|"azure"|"gcp"|"other"|None
            severity_filter: ["CRITICAL","HIGH"]|None
        """
        if not self._built:
            raise RuntimeError("Index not loaded.")

        if not query.strip():
            return []

        top_k = max(1, top_k)
        normalized_severity = None
        if severity_filter:
            normalized_severity = [level.upper() for level in severity_filter]

        if self._keyword_only or self.index is None:
            return self._keyword_search(
                query, top_k, provider_filter, normalized_severity
            )

        q_vec = self._encode([query], is_query=True, batch_size=1)

        fetch_k = min(max(top_k * 15, top_k), self.index.ntotal)
        scores, indices = self.index.search(q_vec, fetch_k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0:
                continue

            doc = self.documents[idx]

            if provider_filter:
                provider = provider_filter.lower()
                if doc.cloud_type not in (provider, "other"):
                    continue

            if normalized_severity and doc.severity.upper() not in normalized_severity:
                continue

            results.append(SearchResult(document=doc, score=float(score)))
            if len(results) >= top_k:
                break

        return results

    def _keyword_search(
        self,
        query: str,
        top_k: int,
        provider_filter: Optional[str],
        severity_filter: Optional[List[str]],
    ) -> List[SearchResult]:
        """TF-based keyword search over loaded CVEDocuments."""
        query_terms = set(query.lower().split())
        if not query_terms:
            return []

        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        scored: List[tuple] = []

        for doc in self.documents:
            if provider_filter:
                pf = provider_filter.lower()
                if doc.cloud_type not in (pf, "other"):
                    continue
            if severity_filter and doc.severity.upper() not in severity_filter:
                continue

            title_lower = doc.title.lower()
            tags_lower = {t.lower() for t in doc.tags}
            search_lower = doc.search_text.lower() if doc.search_text else ""

            score = 0.0
            for term in query_terms:
                if term in title_lower:
                    score += 3.0
                if term in tags_lower:
                    score += 2.0
                if term in search_lower:
                    score += 1.0

            if score > 0:
                score += severity_order.get(doc.severity, 0) * 0.1
                scored.append((score, doc))

        scored.sort(key=lambda x: -x[0])
        return [
            SearchResult(document=doc, score=score)
            for score, doc in scored[:top_k]
        ]


# =============================================================================
# CLI
# =============================================================================


def build(index_dir: str = str(DEFAULT_INDEX_DIR)) -> CVERAGSearch:
    print(f"Loading CVEs from {DATASET_ROOT}...")
    docs = load_all_cves(DATASET_ROOT)
    print(f"  Loaded {len(docs)} CVE documents")

    rag = CVERAGSearch()
    rag.build_index(docs)
    rag.save_index(index_dir)
    print(f"Semantic index built -> {index_dir}")
    return rag


def main():
    parser = argparse.ArgumentParser(
        description="CVE Semantic RAG Search - Qwen3 Embedding + FAISS"
    )
    parser.add_argument("--build", action="store_true", help="Build and save FAISS index")
    parser.add_argument("--query", type=str, default=None)
    parser.add_argument("--provider", type=str, default=None, help="aws|azure|gcp|other")
    parser.add_argument("--severity", nargs="+", default=None, help="CRITICAL HIGH MEDIUM LOW")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--index-dir", type=str, default=str(DEFAULT_INDEX_DIR))
    args = parser.parse_args()

    if args.build:
        build(args.index_dir)

    if args.query:
        rag = CVERAGSearch()
        index_path = Path(args.index_dir)

        if not index_path.exists() or not (index_path / "meta.json").exists():
            print("Index not found, building first...")
            build(args.index_dir)

        try:
            rag.load_index(args.index_dir)
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from exc

        print(f"\nSemantic Query: '{args.query}'")
        if args.provider:
            print(f"  Provider filter: {args.provider}")
        if args.severity:
            print(f"  Severity filter: {args.severity}")
        print()

        t0 = time.time()
        results = rag.search(
            query=args.query,
            top_k=args.top_k,
            provider_filter=args.provider,
            severity_filter=args.severity,
        )
        elapsed_ms = (time.time() - t0) * 1000

        print(f"Search time: {elapsed_ms:.1f}ms")
        print()

        if not results:
            print("No results.")
        else:
            for rank, result in enumerate(results, 1):
                doc = result.document
                print(f"  #{rank} [{doc.severity}] {doc.cve_id} (cosine={result.score:.3f})")
                print(f"      {doc.title}")
                print(f"      Cloud: {doc.cloud_type} | Phases: {' -> '.join(doc.attack_phases)}")
                if doc.exploit_commands:
                    print(f"      Methods: {', '.join(doc.exploit_commands[:3])}")
                print()


if __name__ == "__main__":
    main()
