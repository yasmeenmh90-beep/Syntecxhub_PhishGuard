"""Render inference results as plain text, Markdown or JSON."""
from __future__ import annotations

import json
from typing import List

from .engine import InferenceResult, describe_cf
from .knowledge import split_literal

SEVERITY_TAG = {"danger": "DANGER", "caution": "CAUTION", "advice": "ADVICE"}
DISCLAIMER = ("Educational rule-based analysis: a verdict is an assessment of warning signs, not proof. "
              "When in doubt, contact the organisation through a channel you already trust.")


def bar(cf: float, width: int = 10) -> str:
    filled = round(abs(cf) * width)
    return "█" * filled + "░" * (width - filled)


def fmt_answer(cf: float) -> str:
    if cf >= 0.95:
        return "yes"
    if cf > 0:
        return f"probably ({cf:.2f})"
    if cf <= -0.95:
        return "no"
    return f"probably not ({cf:.2f})"


UNICODE_TREE = {"last": "└─ ", "mid": "├─ ", "pipe": "│  ", "arrow": "→"}
ASCII_TREE = {"last": "`- ", "mid": "|- ", "pipe": "|  ", "arrow": "->"}


def fmt_signal(cf: float) -> str:
    if cf >= 0.95:
        return "detected"
    if cf > 0:
        return f"probably present ({cf:.2f})"
    if cf <= -0.95:
        return "ruled out"
    return f"probably absent ({cf:.2f})"


def _tree_lines(node: dict, glyphs: dict, prefix: str = "", last: bool = True, root: bool = True) -> List[str]:
    branch = "" if root else (glyphs["last"] if last else glyphs["mid"])
    if node["source"] == "user":
        text = f"{node['fact']}: {fmt_signal(node['cf'])}"
    elif node["source"] == "inferred":
        text = f"{node['fact']}  [CF {node['cf']:.2f}]  {node['label']}"
    else:
        text = f"{node['fact']}  ({node['source']})"
    lines = [prefix + branch + text]
    child_prefix = prefix + ("" if root else ("   " if last else glyphs["pipe"]))
    children = [(support["rule"], premise) for support in node.get("by", []) for premise in support["premises"]]
    for i, (rule, premise) in enumerate(children):
        sub = _tree_lines(premise, glyphs, child_prefix, i == len(children) - 1, root=False)
        sub[0] += f"   {glyphs['arrow']} {rule}"  # this premise feeds rule `rule`
        lines.extend(sub)
    return lines


def how_text(result: InferenceResult, fact: str, ascii_only: bool = False) -> str:
    """Proof tree for ``fact``. Each premise line ends with the rule it feeds."""
    return "\n".join(_tree_lines(result.how(fact), ASCII_TREE if ascii_only else UNICODE_TREE))


def to_text(result: InferenceResult, show_trace: bool = True, show_how: bool = True) -> str:
    kb = result.kb
    out: List[str] = []
    rule = "=" * 64
    out += [f"PHISHGUARD | Reasoning report", rule, f"Knowledge base: {kb.name} v{kb.version}  "
            f"({len(kb.rules)} rules, threshold {kb.threshold})", ""]

    out.append("SIGNALS FOUND IN THE MESSAGE")
    if result.initial:
        for fact, cf in result.initial.items():
            out.append(f"  • {kb.label(fact)}  →  {fmt_signal(cf)}")
    else:
        out.append("  (none)")

    recs = result.recommendations
    out += ["", "WHAT TO DO"]
    if recs:
        for i, r in enumerate(recs, 1):
            out.append(f"  {i}. [{SEVERITY_TAG[r['severity']]}] {r['advice']}")
            out.append(f"     certainty {bar(r['cf'])} {r['cf']:.2f} ({r['confidence']})")
    else:
        out.append("  No recommendation can be inferred from the supplied facts. Add more observations.")

    if result.conclusions:
        out += ["", "WHAT THE ENGINE CONCLUDED"]
        for fact, cf in result.conclusions:
            out.append(f"  {bar(cf)} {cf:.2f}  {kb.label(fact)}  ({describe_cf(cf)})")

    if show_trace:
        out += ["", "INFERENCE TRACE (forward chaining)"]
        if not result.trace:
            out.append("  No rules fired. Unknown answers are kept as unknown, never assumed false.")
        for s in result.trace:
            conds = " AND ".join(f"{m['literal']} ({m['cf']:.2f})" for m in s.matched)
            out.append(f"  Step {s.step}  [{s.rule}]  stratum {s.stratum}  "
                       f"conflict set: {', '.join(s.conflict_set)}")
            out.append(f"     IF {conds}")
            combined = f"  combined with {s.cf_before:.2f} → {s.cf_after:.2f}" if s.cf_before else ""
            out.append(f"     THEN {s.conclusion}   CF = {s.rule_cf:g} × {s.premise_cf:.2f} = "
                       f"{abs(s.contribution):.2f}{combined}")
            if s.explanation:
                out.append(f"     because: {s.explanation}")

    if show_how and recs:
        out += ["", "HOW EACH RECOMMENDATION WAS REACHED"]
        for r in recs:
            out.append("")
            out.extend("  " + line for line in how_text(result, r["action"]).splitlines())

    out += ["", DISCLAIMER]
    return "\n".join(out)


def to_markdown(result: InferenceResult) -> str:
    kb = result.kb
    md: List[str] = [f"# PhishGuard reasoning report", "",
                     f"*Knowledge base:* {kb.name} v{kb.version} · {len(kb.rules)} rules · "
                     f"threshold {kb.threshold}", "", "## Signals found", ""]
    if result.initial:
        md += ["| Signal | Status | Certainty |", "|---|---|---|"]
        md += [f"| {kb.label(f)} | {fmt_signal(cf).split(' (')[0]} | {cf:+.2f} |" for f, cf in result.initial.items()]
    else:
        md.append("_None._")
    md += ["", "## What to do", ""]
    if result.recommendations:
        md += ["| # | Priority | Recommendation | Certainty |", "|---|---|---|---|"]
        md += [f"| {i} | {SEVERITY_TAG[r['severity']]} | {r['advice']} | {r['cf']:.2f} ({r['confidence']}) |"
               for i, r in enumerate(result.recommendations, 1)]
    else:
        md.append("_No recommendation can be inferred from the supplied facts._")
    if result.conclusions:
        md += ["", "## Conclusions", "", "| Conclusion | Certainty |", "|---|---|"]
        md += [f"| {kb.label(f)} | {cf:.2f} ({describe_cf(cf)}) |" for f, cf in result.conclusions]
    md += ["", "## Inference trace", ""]
    if result.trace:
        md += ["| Step | Rule | IF | THEN | CF |", "|---|---|---|---|---|"]
        for s in result.trace:
            conds = " ∧ ".join(f"`{m['literal']}`" for m in s.matched)
            md.append(f"| {s.step} | {s.rule} | {conds} | `{s.conclusion}` | {s.cf_after:.2f} |")
    else:
        md.append("_No rules fired._")
    if result.recommendations:
        md += ["", "## How each recommendation was reached", ""]
        for r in result.recommendations:
            md += ["```text", how_text(result, r["action"]), "```", ""]
    md += ["", f"> {DISCLAIMER}", ""]
    return "\n".join(md)


def to_json(result: InferenceResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def rules_table(kb) -> str:
    lines = []
    for cat in dict.fromkeys(r.category for r in kb.rules):
        lines.append(f"\n[{cat}]")
        for r in kb.rules:
            if r.category == cat:
                concl = split_literal(r.conclusion)[0]
                tag = " (action)" if concl in kb.actions else ""
                lines.append(f"  {r.id:<4} IF {' AND '.join(r.conditions)}")
                lines.append(f"       THEN {r.conclusion}{tag}   CF {r.cf:g}"
                             + (f"  priority {r.priority}" if r.priority else ""))
    return "\n".join(lines).lstrip("\n")


def format_what_if(changes: List[dict]) -> str:
    if not changes:
        return "No single answer would change the recommendations."
    lines = ["ANSWERS THAT WOULD CHANGE THE ADVICE"]
    for c in changes:
        alt = "Yes" if c["alternative"] > 0 else "No"
        lead = "If you answered" if c["kind"] == "flip" else "If you can confirm"
        lines.append(f"\n  {lead} {alt}: {c['text']}")
        for r in c["adds"]:
            lines.append(f"     + [{SEVERITY_TAG[r['severity']]}] {r['advice']}  ({r['cf']:.2f})")
        for r in c["removes"]:
            lines.append(f"     - no longer: {r['advice']}")
    return "\n".join(lines)
