"""High-level API: inspect a message from raw text to explained verdict."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

from .engine import InferenceResult, infer, reasoning_graph, what_if
from .extractor import Extraction, extract
from .knowledge import KnowledgeBase

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def verdict(kb: KnowledgeBase, result: InferenceResult) -> dict:
    """Overall risk = the most certain threat conclusion, mapped to a band.

    The headline is the first threat in the knowledge base's priority order
    that holds, so a specific scam type ("Credential phishing") is preferred
    over a generic one ("Pretends to be a trusted organisation").
    """
    threats = kb.verdict.get("threats", [])
    scored = [(t, result.facts.get(t, 0.0)) for t in threats]
    risk = max([cf for _, cf in scored] + [0.0])
    band = next((b for b in kb.verdict.get("bands", []) if risk >= b["min"]),
                {"label": "Low risk", "tone": "calm"})
    found = [{"fact": t, "label": kb.label(t), "cf": round(cf, 4)} for t, cf in scored if cf >= kb.threshold]
    headline = next((f for f in found if f["cf"] >= 0.4), found[0] if found else None)
    return {"risk": round(risk, 4), "label": band["label"], "tone": band["tone"],
            "top": headline, "threats": sorted(found, key=lambda f: -f["cf"])}


def inspect(kb: KnowledgeBase, text: str, overrides: Optional[Dict[str, Optional[float]]] = None) -> dict:
    """Extract signals, apply user overrides, reason, and package everything."""
    extraction = extract(text)
    facts: Dict[str, Optional[float]] = {k: v for k, v in extraction.facts.items() if k in kb.questions}
    for fact, value in (overrides or {}).items():
        if fact not in kb.questions:
            raise ValueError(f"unknown signal {fact!r}")
        if value is None:
            facts.pop(fact, None)
        else:
            facts[fact] = float(value)
    result = infer(kb, facts)
    return {
        "extraction": extraction,
        "facts": facts,
        "result": result,
        "verdict": verdict(kb, result),
        "graph": reasoning_graph(result),
        "whatif": what_if(kb, facts),
    }


def load_samples() -> dict:
    index = json.loads((SAMPLES_DIR / "index.json").read_text(encoding="utf-8"))
    return {k: {**v, "text": (SAMPLES_DIR / v["file"]).read_text(encoding="utf-8")} for k, v in index.items()}
