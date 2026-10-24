"""Knowledge base: questions, rules, actions and scenarios, loaded from JSON.

The knowledge base is pure data. The inference engine (``engine.py``) knows
nothing about phishing, so a different JSON file turns this into a different
expert system without touching any Python code.

Literals
    A literal is a fact name such as ``"slow"`` or a negated fact such as
    ``"not:airplane_mode"``. A negated condition is satisfied only by a known
    negative answer. A fact that was never answered is *unknown*, which is not
    the same as *false*.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

NEG = "not:"
SEVERITIES = ("danger", "caution", "advice")  # most to least serious
DEFAULT_KB = Path(__file__).resolve().parent.parent / "knowledge" / "phishing.json"


class KnowledgeBaseError(ValueError):
    """Raised when a knowledge base is malformed."""


def split_literal(literal: str) -> Tuple[str, bool]:
    """Return ``(fact, negated)`` for a literal."""
    if literal.startswith(NEG):
        return literal[len(NEG):], True
    return literal, False


@dataclass(frozen=True)
class Question:
    id: str
    text: str
    category: str = "general"
    help: str = ""


@dataclass(frozen=True)
class Rule:
    id: str
    conditions: Tuple[str, ...]
    conclusion: str
    cf: float = 1.0
    priority: int = 0
    explanation: str = ""
    category: str = "general"

    def __str__(self) -> str:
        return f"{self.id}: IF {' AND '.join(self.conditions)} THEN {self.conclusion} (CF {self.cf:g})"


@dataclass(frozen=True)
class Action:
    id: str
    advice: str
    severity: str = "advice"
    title: str = ""

    @property
    def name(self) -> str:
        return self.title or self.id.replace("_", " ").capitalize()


@dataclass(frozen=True)
class Scenario:
    id: str
    description: str
    facts: Dict[str, float]


@dataclass(frozen=True)
class LintIssue:
    level: str  # "error" or "warning"
    message: str

    def __str__(self) -> str:
        return f"{self.level.upper()}: {self.message}"


@dataclass
class KnowledgeBase:
    name: str
    rules: Tuple[Rule, ...]
    questions: Dict[str, Question] = field(default_factory=dict)
    actions: Dict[str, Action] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    scenarios: Dict[str, Scenario] = field(default_factory=dict)
    version: str = "1.0"
    description: str = ""
    threshold: float = 0.2
    verdict: Dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        errors = [i for i in self.lint() if i.level == "error"]
        if errors:
            raise KnowledgeBaseError("; ".join(i.message for i in errors))
        self._levels = self._compute_levels()

    # ------------------------------------------------------------- loading
    @classmethod
    def from_dict(cls, data: dict) -> "KnowledgeBase":
        try:
            questions = {q["id"]: Question(q["id"], q["text"], q.get("category", "general"), q.get("help", ""))
                         for q in data.get("questions", [])}
            rules = tuple(
                Rule(
                    id=r["id"],
                    conditions=tuple(r["if"]),
                    conclusion=r["then"],
                    cf=float(r.get("cf", 1.0)),
                    priority=int(r.get("priority", 0)),
                    explanation=r.get("because", ""),
                    category=r.get("category", "general"),
                )
                for r in data["rules"]
            )
            actions = {aid: Action(aid, a["advice"], a.get("severity", "advice"), a.get("title", ""))
                       for aid, a in data.get("actions", {}).items()}
            scenarios = {sid: Scenario(sid, s.get("description", ""), normalize_answers(s["facts"]))
                         for sid, s in data.get("scenarios", {}).items()}
        except (KeyError, TypeError) as exc:
            raise KnowledgeBaseError(f"Malformed knowledge base: missing or invalid field {exc}") from exc
        return cls(
            name=data.get("name", "Knowledge base"),
            version=str(data.get("version", "1.0")),
            description=data.get("description", ""),
            threshold=float(data.get("threshold", 0.2)),
            rules=rules,
            questions=questions,
            actions=actions,
            labels=dict(data.get("labels", {})),
            scenarios=scenarios,
            verdict=dict(data.get("verdict", {})),
        )

    @classmethod
    def load(cls, path: Union[str, Path, None] = None) -> "KnowledgeBase":
        path = Path(path) if path else DEFAULT_KB
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise KnowledgeBaseError(f"Invalid JSON in {path}: {exc}") from exc
        return cls.from_dict(data)

    # ------------------------------------------------------------- queries
    @property
    def derived_facts(self) -> set:
        return {split_literal(r.conclusion)[0] for r in self.rules}

    def rules_concluding(self, fact: str) -> List[Rule]:
        return [r for r in self.rules if split_literal(r.conclusion)[0] == fact]

    def rules_using(self, fact: str) -> List[Rule]:
        return [r for r in self.rules if any(split_literal(c)[0] == fact for c in r.conditions)]

    def label(self, fact: str) -> str:
        if fact in self.actions:
            return self.actions[fact].advice
        if fact in self.questions:
            return self.questions[fact].text
        return self.labels.get(fact, fact.replace("_", " "))

    def level(self, rule: Rule) -> int:
        """Stratum of a rule: 1 + the deepest derived fact it depends on."""
        return self._levels[rule.id]

    # ----------------------------------------------------------- validation
    def lint(self) -> List[LintIssue]:
        """Check the knowledge base for errors and suspicious patterns."""
        issues: List[LintIssue] = []
        err = lambda m: issues.append(LintIssue("error", m))
        warn = lambda m: issues.append(LintIssue("warning", m))

        ids = [r.id for r in self.rules]
        for dup in sorted({i for i in ids if ids.count(i) > 1}):
            err(f"duplicate rule id '{dup}'")
        if not 0 < self.threshold < 1:
            err("threshold must be between 0 and 1")
        derived = {split_literal(r.conclusion)[0] for r in self.rules}
        askable = set(self.questions)
        for rule in self.rules:
            if not rule.conditions:
                err(f"rule {rule.id} has no conditions")
            if not 0 < rule.cf <= 1:
                err(f"rule {rule.id}: cf must be in (0, 1], got {rule.cf}")
            fact, _ = split_literal(rule.conclusion)
            if fact in askable:
                err(f"rule {rule.id} concludes '{fact}', which is a user question")
            for cond in rule.conditions:
                cfact, neg = split_literal(cond)
                if cfact not in askable and cfact not in derived:
                    err(f"rule {rule.id} uses unknown fact '{cfact}' (not a question and never concluded)")
                elif neg and cfact in derived and cfact not in askable and \
                        not any(split_literal(r.conclusion) == (cfact, True) for r in self.rules):
                    warn(f"rule {rule.id} requires 'not:{cfact}', but no rule ever concludes it")
        for aid in self.actions:
            if self.actions[aid].severity not in SEVERITIES:
                err(f"action '{aid}' has unknown severity '{self.actions[aid].severity}'")
            if aid not in derived:
                warn(f"action '{aid}' is never concluded by any rule")
        for qid in askable:
            if not self.rules_using(qid):
                warn(f"question '{qid}' is not used by any rule")
        for fact in derived:
            if fact not in self.actions and fact not in self.labels:
                warn(f"derived fact '{fact}' has no human-readable label")
        for sid, scen in self.scenarios.items():
            unknown = set(scen.facts) - askable
            if unknown:
                err(f"scenario '{sid}' uses unknown questions: {', '.join(sorted(unknown))}")
        if self._has_cycle():
            warn("the rule graph contains a cycle; inference still terminates (each rule fires once)")
        return issues

    def _dependency_graph(self) -> Dict[str, set]:
        graph: Dict[str, set] = {}
        for r in self.rules:
            graph.setdefault(split_literal(r.conclusion)[0], set()).update(split_literal(c)[0] for c in r.conditions)
        return graph

    def _has_cycle(self) -> bool:
        graph, state = self._dependency_graph(), {}

        def visit(n: str) -> bool:
            state[n] = 1
            for m in graph.get(n, ()):
                if state.get(m) == 1 or (state.get(m) is None and visit(m)):
                    return True
            state[n] = 2
            return False

        return any(state.get(n) is None and visit(n) for n in list(graph))

    def _compute_levels(self) -> Dict[str, int]:
        """Assign each rule a stratum so premises are complete before use.

        A user fact has level 0; a derived fact takes the highest level of the
        rules concluding it; a rule sits one level above its deepest premise.
        On a cycle the back-edge is treated as level 0, which keeps levels
        finite (cyclic rule bases still terminate, just without the ordering
        guarantee).
        """
        fact_level: Dict[str, int] = {}
        on_stack: set = set()

        def level_of_fact(fact: str) -> int:
            if fact in fact_level:
                return fact_level[fact]
            if fact in on_stack:
                return 0
            on_stack.add(fact)
            concluders = self.rules_concluding(fact)
            value = max((level_of_rule(r) for r in concluders), default=0)
            on_stack.discard(fact)
            fact_level[fact] = value
            return value

        def level_of_rule(rule: Rule) -> int:
            return 1 + max((level_of_fact(split_literal(c)[0]) for c in rule.conditions), default=0)

        return {r.id: level_of_rule(r) for r in self.rules}


# Answer vocabulary shared by the CLI, GUI and JSON inputs
ANSWER_CF = {
    "yes": 1.0,
    "probably": 0.6,
    "unknown": None,
    "probably not": -0.6,
    "no": -1.0,
}


def normalize_answers(raw: Union[list, dict], kb: Optional[KnowledgeBase] = None) -> Dict[str, float]:
    """Turn user input into ``{fact: certainty}`` with certainty in [-1, 1].

    Accepts the original list form (``["slow", "not:airplane_mode"]``) or a
    mapping whose values are numbers in [-1, 1], booleans, or answer words
    (``"yes"``, ``"probably"``, ``"unknown"``, ``"probably not"``, ``"no"``).
    Unknown answers are dropped: unknown is not evidence either way.
    """
    facts: Dict[str, float] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, str):
                raise ValueError("Fact lists must contain only strings.")
            fact, neg = split_literal(item)
            value = -1.0 if neg else 1.0
            if fact in facts and facts[fact] != value:
                raise ValueError(f"Contradictory facts: {fact} and not:{fact}")
            facts[fact] = value
    elif isinstance(raw, dict):
        for fact, value in raw.items():
            if not isinstance(fact, str) or fact.startswith(NEG):
                raise ValueError(f"Invalid fact name {fact!r}; use a negative certainty instead of 'not:'.")
            if isinstance(value, bool):
                value = 1.0 if value else -1.0
            elif isinstance(value, str):
                key = value.strip().lower()
                if key not in ANSWER_CF:
                    raise ValueError(f"Unknown answer {value!r} for {fact}; use one of {', '.join(ANSWER_CF)}.")
                value = ANSWER_CF[key]
                if value is None:
                    continue
            elif value is None:
                continue
            elif isinstance(value, (int, float)):
                value = float(value)
            else:
                raise ValueError(f"Invalid certainty for {fact}: {value!r}")
            if not -1.0 <= value <= 1.0:
                raise ValueError(f"Certainty for {fact} must be between -1 and 1, got {value}.")
            if value != 0:
                facts[fact] = value
    else:
        raise ValueError("Facts must be a JSON list of strings or an object of {fact: certainty}.")
    if kb is not None:
        unknown = set(facts) - set(kb.questions)
        if unknown:
            raise ValueError("Unknown user facts: " + ", ".join(sorted(unknown)))
    return facts
