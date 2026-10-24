"""Forward-chaining inference engine with certainty factors.

Recognise-act cycle
    1. Match: find every unfired rule whose conditions are all satisfied
       (the *conflict set*).
    2. Resolve: pick one rule by the conflict-resolution strategy.
    3. Act: fire it, updating the certainty of its conclusion.
    Repeat until the conflict set is empty (a fixed point).

Certainty factors (MYCIN-style)
    Every fact has a certainty in [-1, 1]: 1 = definitely true,
    -1 = definitely false, 0 / absent = unknown.

    * A condition ``x`` holds if cf(x) >= threshold; ``not:x`` holds if
      cf(x) <= -threshold.
    * Premise certainty = min over the conditions.
    * A rule contributes  rule.cf * premise  to its conclusion.
    * Several rules supporting the same conclusion combine with
      ``a + b * (1 - a)`` (for positive values), so independent evidence
      strengthens a conclusion without ever exceeding 1.

Conflict resolution
    Rules fire in dependency order (their *stratum*): a rule only fires once
    every rule that could add evidence to its premises has had its chance.
    Within a stratum, higher ``priority`` wins, then the more specific rule
    (more conditions), then the order in the knowledge base. Each rule fires
    at most once (refraction), so inference always terminates, even on
    cyclic rule bases.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence

from .knowledge import SEVERITIES, KnowledgeBase, Rule, normalize_answers, split_literal


def combine(a: float, b: float) -> float:
    """Combine two certainty factors for the same hypothesis (MYCIN)."""
    if a >= 0 and b >= 0:
        return a + b * (1 - a)
    if a <= 0 and b <= 0:
        return a + b * (1 + a)
    return (a + b) / (1 - min(abs(a), abs(b)))


def describe_cf(cf: float) -> str:
    """Plain-language label for a certainty factor."""
    magnitude = abs(cf)
    if magnitude >= 0.95:
        word = "certain"
    elif magnitude >= 0.8:
        word = "very likely"
    elif magnitude >= 0.6:
        word = "likely"
    elif magnitude >= 0.4:
        word = "possible"
    else:
        word = "weak"
    return word if cf >= 0 else f"{word} NOT"


@dataclass(frozen=True)
class Step:
    """One rule firing, with everything needed to explain it."""

    step: int
    rule: str
    stratum: int
    conflict_set: List[str]
    matched: List[Dict[str, float]]  # [{"literal": ..., "cf": ...}]
    premise_cf: float
    rule_cf: float
    contribution: float
    conclusion: str
    cf_before: float
    cf_after: float
    new_fact: bool
    explanation: str

    def to_dict(self) -> dict:
        d = asdict(self)
        for key in ("premise_cf", "rule_cf", "contribution", "cf_before", "cf_after"):
            d[key] = round(d[key], 4)
        d["matched"] = [{"literal": m["literal"], "cf": round(m["cf"], 4)} for m in self.matched]
        return d


@dataclass
class InferenceResult:
    kb: KnowledgeBase
    initial: Dict[str, float]
    facts: Dict[str, float]
    trace: List[Step] = field(default_factory=list)

    @property
    def threshold(self) -> float:
        return self.kb.threshold

    def holds(self, fact: str) -> bool:
        return self.facts.get(fact, 0.0) >= self.threshold

    @property
    def derived(self) -> Dict[str, float]:
        return {f: cf for f, cf in self.facts.items() if f not in self.initial}

    @property
    def conclusions(self) -> List[tuple]:
        """Intermediate diagnoses (not actions) that hold, most certain first."""
        items = [(f, cf) for f, cf in self.derived.items() if f not in self.kb.actions and cf >= self.threshold]
        return sorted(items, key=lambda x: -x[1])

    @property
    def recommendations(self) -> List[dict]:
        """Actions that hold, ordered by severity, then certainty."""
        recs = []
        for fact, cf in self.facts.items():
            action = self.kb.actions.get(fact)
            if action and cf >= self.threshold:
                recs.append({"action": fact, "title": action.name, "advice": action.advice, "severity": action.severity,
                             "cf": round(cf, 4), "confidence": describe_cf(cf)})
        return sorted(recs, key=lambda r: (SEVERITIES.index(r["severity"]), -r["cf"]))

    def how(self, fact: str) -> dict:
        """Proof tree explaining how ``fact`` got its certainty."""
        return self._how(fact, set())

    def _how(self, fact: str, seen: set) -> dict:
        cf = self.facts.get(fact, 0.0)
        node = {"fact": fact, "label": self.kb.label(fact), "cf": round(cf, 4)}
        if fact in self.initial:
            node["source"] = "user"
            return node
        if fact in seen:
            node["source"] = "cycle"
            return node
        steps = [s for s in self.trace if split_literal(s.conclusion)[0] == fact]
        if not steps:
            node["source"] = "unknown"
            return node
        node["source"] = "inferred"
        node["by"] = [
            {
                "rule": s.rule,
                "explanation": s.explanation,
                "contribution": round(s.contribution, 4),
                "premises": [self._how(split_literal(m["literal"])[0], seen | {fact}) for m in s.matched],
            }
            for s in steps
        ]
        return node

    def to_dict(self) -> dict:
        return {
            "knowledge_base": {"name": self.kb.name, "version": self.kb.version},
            "threshold": self.threshold,
            "initial_facts": {k: round(v, 4) for k, v in self.initial.items()},
            "final_facts": {k: round(v, 4) for k, v in sorted(self.facts.items())},
            "conclusions": [{"fact": f, "label": self.kb.label(f), "cf": round(cf, 4)} for f, cf in self.conclusions],
            "recommendations": self.recommendations,
            "trace": [s.to_dict() for s in self.trace],
            "explanations": {r["action"]: self.how(r["action"]) for r in self.recommendations},
        }


def _literal_cf(facts: Mapping[str, float], literal: str) -> float:
    fact, negated = split_literal(literal)
    cf = facts.get(fact, 0.0)
    return -cf if negated else cf


def infer(kb: KnowledgeBase, answers, validate: bool = True) -> InferenceResult:
    """Run forward chaining from ``answers`` to a fixed point.

    ``answers`` may be a list of literals or a mapping of certainties (see
    :func:`knowledge.normalize_answers`). The input is never mutated.
    """
    initial = normalize_answers(answers, kb if validate else None)
    facts: Dict[str, float] = dict(initial)
    order = {r.id: i for i, r in enumerate(kb.rules)}
    fired: set = set()
    trace: List[Step] = []
    th = kb.threshold

    def ready(rule: Rule) -> bool:
        return rule.id not in fired and all(_literal_cf(facts, c) >= th for c in rule.conditions)

    while True:
        conflict_set = [r for r in kb.rules if ready(r)]
        if not conflict_set:
            break
        rule = min(conflict_set, key=lambda r: (kb.level(r), -r.priority, -len(r.conditions), order[r.id]))
        matched = [{"literal": c, "cf": _literal_cf(facts, c)} for c in rule.conditions]
        premise = min(m["cf"] for m in matched)
        contribution = rule.cf * premise
        fact, negated = split_literal(rule.conclusion)
        if negated:
            contribution = -contribution
        before = facts.get(fact, 0.0)
        after = combine(before, contribution) if fact in facts else contribution
        facts[fact] = after
        fired.add(rule.id)
        trace.append(Step(
            step=len(trace) + 1,
            rule=rule.id,
            stratum=kb.level(rule),
            conflict_set=[r.id for r in conflict_set],
            matched=matched,
            premise_cf=premise,
            rule_cf=rule.cf,
            contribution=contribution,
            conclusion=rule.conclusion,
            cf_before=before,
            cf_after=after,
            new_fact=abs(before) < th <= abs(after),
            explanation=rule.explanation,
        ))
    return InferenceResult(kb=kb, initial=initial, facts=facts, trace=trace)


# --------------------------------------------------------------- relevance
def _possibility_checker(kb: KnowledgeBase, answers: Mapping[str, Optional[float]]):
    """Return ``rule_possible(rule)``: could this rule still fire?

    Unasked questions might still be answered either way; asked questions are
    fixed (``None`` = "don't know", which can never satisfy a condition); a
    derived literal is possible if some still-possible rule could conclude it.
    """
    th = kb.threshold
    memo: Dict[str, bool] = {}

    def literal_possible(literal: str, visiting: frozenset) -> bool:
        fact, neg = split_literal(literal)
        if fact in kb.questions:
            if fact not in answers:
                return True
            cf = answers[fact]
            return cf is not None and ((-cf if neg else cf) >= th)
        if fact in visiting:
            return False
        return any(check(r, visiting | {fact}) for r in kb.rules_concluding(fact)
                   if split_literal(r.conclusion)[1] == neg)

    def check(rule: Rule, visiting: frozenset = frozenset()) -> bool:
        if not visiting and rule.id in memo:
            return memo[rule.id]
        result = all(literal_possible(c, visiting) for c in rule.conditions)
        if not visiting:
            memo[rule.id] = result
        return result

    return check


def relevant_questions(kb: KnowledgeBase, answers: Mapping[str, Optional[float]]) -> List[str]:
    """Questions (in knowledge-base order) whose answer could still matter.

    ``answers`` maps already-asked question ids to a certainty, or ``None``
    for "don't know". A question is relevant if it is unasked and appears in
    at least one rule that could still fire given what is already known.
    This is what lets the interview skip questions that cannot change the
    outcome.
    """
    possible = _possibility_checker(kb, answers)
    needed = {split_literal(c)[0] for r in kb.rules if possible(r) for c in r.conditions}
    return [q for q in kb.questions if q not in answers and q in needed]


def why(kb: KnowledgeBase, question: str, answers: Mapping[str, Optional[float]]) -> List[Rule]:
    """The still-possible rules that would use the answer to ``question``."""
    others = {k: v for k, v in answers.items() if k != question}
    possible = _possibility_checker(kb, others)
    return [r for r in kb.rules_using(question) if possible(r)]


# --------------------------------------------------------------- what-if
def what_if(kb: KnowledgeBase, answers: Mapping[str, Optional[float]], limit: int = 5,
            locked: Sequence[str] = ()) -> List[dict]:
    """Find the answers that would change the recommendations the most.

    Two kinds of candidate are tried, each as a definite Yes and a definite No:

    * questions already answered (sensitivity: "what if I was wrong?")
    * unanswered questions in a rule that is already partly satisfied
      ("one more answer would complete this chain")

    ``locked`` questions (e.g. measured by a system scan) are never varied.
    Returns the most decisive changes first, each with the recommendations it
    would add and remove.
    """
    def recs(ans) -> Dict[str, dict]:
        return {r["action"]: r for r in infer(kb, ans).recommendations}

    base_answers = {k: v for k, v in answers.items()}
    base_result = infer(kb, base_answers)
    base = {r["action"]: r for r in base_result.recommendations}
    th = kb.threshold

    candidates = [q for q, v in answers.items() if v is not None and q in kb.questions]
    for rule in kb.rules:
        held = [c for c in rule.conditions if _literal_cf(base_result.facts, c) >= th]
        if held:
            for c in rule.conditions:
                fact, _ = split_literal(c)
                if fact in kb.questions and answers.get(fact) is None and fact not in candidates:
                    candidates.append(fact)

    changes = []
    for q in [c for c in candidates if c not in set(locked)]:
        current = answers.get(q)
        for alt in (1.0, -1.0):
            if current is not None and (current > 0) == (alt > 0):
                continue
            trial = dict(base_answers)
            trial[q] = alt
            after = recs(trial)
            added = [after[a] for a in after if a not in base]
            removed = [base[a] for a in base if a not in after]
            if not added and not removed:
                continue
            urgent = any(r["severity"] == "urgent" for r in added)
            changes.append({
                "question": q,
                "text": kb.questions[q].text,
                "current": current,
                "alternative": alt,
                "kind": "flip" if current is not None else "confirm",
                "adds": added,
                "removes": removed,
                "score": len(added) + len(removed) + (3 if urgent else 0),
            })
    changes.sort(key=lambda c: (-c["score"], c["kind"] != "flip", list(kb.questions).index(c["question"])))
    return changes[:limit]


# ------------------------------------------------------------------ graph
def reasoning_graph(result: InferenceResult) -> dict:
    """Nodes and edges of the rules that fired, laid out by stratum.

    Column 0 holds the user's answers; derived facts sit in the column of the
    deepest rule that concluded them, so the graph reads left to right from
    evidence to recommendation.
    """
    kb = result.kb
    column: Dict[str, int] = {}
    edges = []
    for s in result.trace:
        target = split_literal(s.conclusion)[0]
        column[target] = max(column.get(target, 0), s.stratum)
        for m in s.matched:
            source = split_literal(m["literal"])[0]
            column.setdefault(source, 0 if source in result.initial else s.stratum - 1)
            edges.append({"source": source, "target": target, "rule": s.rule,
                          "negated": m["literal"].startswith("not:"), "cf": round(s.contribution, 4)})
    nodes = []
    for fact, col in column.items():
        kind = "answer" if fact in result.initial else "action" if fact in kb.actions else "finding"
        node = {"id": fact, "column": col, "kind": kind, "cf": round(result.facts.get(fact, 0.0), 4),
                "label": kb.questions[fact].text if fact in kb.questions else kb.label(fact)}
        if kind == "action":
            node["severity"] = kb.actions[fact].severity
            node["title"] = kb.actions[fact].name
        nodes.append(node)
    return {"nodes": nodes, "edges": edges, "columns": (max(column.values()) + 1) if column else 0}
