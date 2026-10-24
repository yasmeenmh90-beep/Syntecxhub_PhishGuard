"""PhishGuard command line.

    python3 phishguard.py inspect message.eml          inspect a saved email or text file
    python3 phishguard.py inspect --sample bank_alert  inspect a bundled sample
    pbpaste | python3 phishguard.py inspect            inspect the clipboard (macOS)
    python3 phishguard.py explain credential_phishing --sample bank_alert
    python3 phishguard.py samples | rules | lint
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .inspect import inspect, load_samples
from .knowledge import KnowledgeBase, KnowledgeBaseError
from .report import how_text, rules_table, to_json, to_markdown, to_text

COMMANDS = ("inspect", "explain", "samples", "rules", "lint")


def _source(p: argparse.ArgumentParser) -> None:
    p.add_argument("file", nargs="?", help="file containing the message (omit to read standard input)")
    p.add_argument("--sample", metavar="NAME", help="use a bundled sample (see `samples`)")
    p.add_argument("--text", help="the message text itself")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishguard", description="Explainable rule-based scam-message detector.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    i = sub.add_parser("inspect", help="inspect a message (default)")
    _source(i)
    i.add_argument("--json", action="store_true", help="print the full analysis as JSON")
    i.add_argument("--brief", action="store_true", help="verdict, signs and advice only")
    i.add_argument("--report", metavar="FILE", help="save a report (.md, .json or .txt)")
    e = sub.add_parser("explain", help="show HOW a conclusion was reached (proof tree)")
    e.add_argument("fact", help="e.g. credential_phishing, payment_scam, dont_pay")
    _source(e)
    for name, text in (("samples", "list bundled sample messages"), ("rules", "print the rule base"),
                       ("lint", "validate the rule base")):
        sub.add_parser(name, help=text)
    return parser


def _read(args) -> str:
    if args.sample:
        samples = load_samples()
        if args.sample not in samples:
            raise ValueError(f"Unknown sample {args.sample!r}; choose from {', '.join(samples)}.")
        return samples[args.sample]["text"]
    if args.text:
        return args.text
    if args.file:
        return Path(args.file).read_text(encoding="utf-8", errors="replace")
    if sys.stdin.isatty():
        print("Paste the message, then press Ctrl+D (Ctrl+Z then Enter on Windows):", file=sys.stderr)
    return sys.stdin.read()


def format_inspection(kb: KnowledgeBase, out: dict, brief: bool = False) -> str:
    v, ex = out["verdict"], out["extraction"]
    lines = ["=" * 64, f"  VERDICT: {v['label'].upper()}   (risk {round(v['risk'] * 100)}%)"]
    if v["top"]:
        lines.append(f"  Most likely: {v['top']['label']}")
    lines += ["=" * 64, "", f"WARNING SIGNS IN THIS {ex.kind.upper()}"]
    context = set(kb.verdict.get("context", []))
    present = [s for s in ex.signals.values() if s.cf > 0 and s.fact in kb.questions and s.fact not in context]
    if not present:
        lines.append("  None found.")
    for s in ex.signals.values():
        if s.cf > 0 and s.fact in context and s.fact != "has_links":
            lines.append(f"  (context, not a warning by itself: {s.reason})")
    for n, s in enumerate(present, 1):
        lines.append(f"  {n}. {kb.questions[s.fact].text}")
        lines.append(f"     {s.reason}")
    recs = out["result"].recommendations
    lines += ["", "WHAT TO DO"]
    lines += [f"  [{r['severity'].upper()}] {r['title']}: {r['advice']}" for r in recs] or ["  No action needed from the rules."]
    if not brief:
        lines += ["", to_text(out["result"], show_how=True)]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "inspect")
    args = build_parser().parse_args(argv)
    try:
        kb = KnowledgeBase.load()
        if args.command == "lint":
            issues = kb.lint()
            print(f"{kb.name} v{kb.version}: {len(kb.rules)} rules, {len(kb.questions)} warning signs, "
                  f"{len(kb.actions)} actions, max chain depth {max(kb.level(r) for r in kb.rules)}")
            for i in issues:
                print("  " + str(i))
            print("OK: no problems found." if not issues else f"{len(issues)} issue(s).")
            return 1 if any(i.level == "error" for i in issues) else 0
        if args.command == "samples":
            for name, s in load_samples().items():
                print(f"  {name:<20} {s['title']}  ({s['kind']})")
            return 0
        if args.command == "rules":
            print(rules_table(kb))
            return 0
        text = _read(args)
        if not text.strip():
            raise ValueError("No message given.")
        out = inspect(kb, text)
        if args.command == "explain":
            if out["result"].facts.get(args.fact, 0) <= 0:
                print(f"'{args.fact}' was not concluded for this message.")
                return 1
            print(how_text(out["result"], args.fact))
            return 0
        if args.json:
            payload = out["result"].to_dict()
            payload.update({"verdict": out["verdict"], "extraction": out["extraction"].to_dict()})
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(format_inspection(kb, out, brief=args.brief))
        if args.report:
            target = Path(args.report)
            fmt = target.suffix.lower()
            content = to_json(out["result"]) if fmt == ".json" else to_markdown(out["result"]) if fmt == ".md" else format_inspection(kb, out)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            print(f"\nSaved report: {target}")
        return 0
    except (KnowledgeBaseError, ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
