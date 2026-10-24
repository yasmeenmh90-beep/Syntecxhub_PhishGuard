"""PhishGuard: an explainable rule-based expert system for scam messages."""
from .engine import InferenceResult, combine, describe_cf, infer, reasoning_graph, what_if
from .extractor import Extraction, extract
from .inspect import inspect, load_samples, verdict
from .knowledge import KnowledgeBase, KnowledgeBaseError, Rule, split_literal

__version__ = "1.0.0"
__all__ = ["Extraction", "InferenceResult", "KnowledgeBase", "KnowledgeBaseError", "Rule", "combine",
           "describe_cf", "extract", "infer", "inspect", "load_samples", "reasoning_graph", "split_literal",
           "verdict", "what_if", "__version__"]
