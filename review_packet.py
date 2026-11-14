#!/usr/bin/env python3
"""review-packet: build a deterministic pre-review packet from a git diff.

AI code review tools (e.g. alibaba/open-code-review, trending #1 on GitHub
today) do their best work when the diff arrives with structure: per-file
stats, risky patterns, and a short summary the model can anchor on.
This CLI produces that packet deterministically — no model, no network —
so the same diff always yields the same packet.

Usage:
    python3 review_packet.py [--repo PATH] [--base HEAD~1] [--diff FILE]
                             [--format json|md] [--out FILE]
Exit code: 0 = packet built; 1 = a high-severity pattern was found
           (use --no-fail to always exit 0).
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# (id, severity, pattern, message)
PATTERNS = [
    ("secret-like", "high",
     re.compile(r"(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*"
                r"['\"][^'\"\s]{8,}['\"]"),
     "possible hard-coded credential"),
    ("private-key", "high",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "private key material in diff"),
    ("todo-fixme", "low",
     re.compile(r"(?i)\b(TODO|FIXME|XXX|HACK)\b"),
     "TODO/FIXME marker added"),
    ("debug-print", "low",
     re.compile(r"\b(print\(|console\.log\(|debugger;|pdb\.set_trace\(\))"),
     "debug print left in code"),
    ("eval-exec", "medium",
     re.compile(r"\b(eval|exec)\s*\("),
     "eval/exec — check the input is trusted"),
    ("shell-true", "medium",
     re.compile(r"shell\s*=\s*True"),
     "subprocess with shell=True — injection risk"),
    ("sql-concat", "medium",
     re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+[^'\"]*\+"),
     "SQL string concatenation — prefer parameters"),
]

LARGE_FILE_ADDED_LINES = 500
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
             "poetry.lock", "Pipfile.lock", "Cargo.lock", "Gemfile.lock"}


@dataclass
class FileEntry:
    path: str
    added: int = 0
    deleted: int = 0
    is_new: bool = False
    is_binary: bool = False
    findings: list[dict] = field(default_factory=list)


def parse_numstat(text: str) -> dict[str, FileEntry]:
    """Parse `git diff --numstat` output into per-file entries."""
    entries: dict[str, FileEntry] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        added, deleted, path = parts
        entry = FileEntry(path=path)
        if added == "-" and deleted == "-":
            entry.is_binary = True
        else:
            entry.added = int(added)
            entry.deleted = int(deleted)
        entries[path] = entry
    return entries


def parse_name_status(text: str, entries: dict[str, FileEntry]) -> None:
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] in ("A", "C"):
            if parts[1] in entries:
                entries[parts[1]].is_new = True


def scan_diff_lines(diff_text: str) -> dict[str, list[dict]]:
    """Scan added lines of a unified diff for risky patterns."""
    per_file: dict[str, list[dict]] = {}
    current: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            per_file.setdefault(current, [])
        elif line.startswith("+") and not line.startswith("+++") \
                and current is not None:
            content = line[1:]
            for pid, severity, pattern, message in PATTERNS:
                if pattern.search(content):
                    per_file[current].append({
                        "rule": pid, "severity": severity,
                        "message": message, "line": content.strip()[:120],
                    })
    return per_file


def build_packet(repo: Path, base: str, diff_text: str,
                 numstat_text: str, status_text: str) -> dict:
    entries = parse_numstat(numstat_text)
    parse_name_status(status_text, entries)
    pattern_hits = scan_diff_lines(diff_text)
    for path, hits in pattern_hits.items():
        if path in entries:
            entries[path].findings.extend(hits)

    files = []
    high = 0
    for entry in sorted(entries.values(), key=lambda e: e.path):
        if entry.added >= LARGE_FILE_ADDED_LINES:
            entry.findings.append({
                "rule": "large-file", "severity": "medium",
                "message": f"{entry.added} lines added — consider splitting",
                "line": "",
            })
        if Path(entry.path).name in LOCKFILES and entry.added > 0:
            entry.findings.append({
                "rule": "lockfile-churn", "severity": "low",
                "message": "lockfile changed — review dependency changes",
                "line": "",
            })
        high += sum(1 for f in entry.findings if f["severity"] == "high")
        files.append({
            "path": entry.path, "added": entry.added,
            "deleted": entry.deleted, "is_new": entry.is_new,
            "is_binary": entry.is_binary, "findings": entry.findings,
        })

    total_added = sum(f["added"] for f in files)
    total_deleted = sum(f["deleted"] for f in files)
    return {
        "repo": str(repo),
        "base": base,
        "summary": {
            "files_changed": len(files),
            "lines_added": total_added,
            "lines_deleted": total_deleted,
            "new_files": sum(1 for f in files if f["is_new"]),
            "binary_files": sum(1 for f in files if f["is_binary"]),
            "high_severity_findings": high,
            "total_findings": sum(len(f["findings"]) for f in files),
        },
        "files": files,
    }


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args],
                            capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: "
                           f"{result.stderr.strip()}")
    return result.stdout


def packet_from_repo(repo: Path, base: str) -> dict:
    diff_text = _git(repo, "diff", base, "--no-color")
    numstat = _git(repo, "diff", base, "--numstat")
    status = _git(repo, "diff", base, "--name-status")
    return build_packet(repo, base, diff_text, numstat, status)


def packet_from_diff_file(diff_file: Path) -> dict:
    diff_text = diff_file.read_text(encoding="utf-8", errors="replace")
    # Re-derive numstat-like entries from the diff itself.
    entries: dict[str, FileEntry] = {}
    current: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            entries.setdefault(current, FileEntry(path=current))
        elif line.startswith("--- a/") and current is None:
            pass
        elif line.startswith("+") and not line.startswith("+++") \
                and current is not None:
            entries[current].added += 1
        elif line.startswith("-") and not line.startswith("---") \
                and current is not None:
            entries[current].deleted += 1
        elif line.startswith("Binary files "):
            parts = line.split()
            if len(parts) >= 3:
                name = parts[2].lstrip("b/")
                entries.setdefault(name, FileEntry(path=name, is_binary=True))
    numstat = "\n".join(
        f"{e.added}\t{e.deleted}\t{e.path}" for e in entries.values())
    status = "\n".join(f"A\t{e.path}" for e in entries.values()
                       if e.added and not e.deleted)
    return build_packet(diff_file.parent, "diff-file", diff_text,
                        numstat, status)


def render_markdown(packet: dict) -> str:
    s = packet["summary"]
    lines = [
        "# Review packet",
        "",
        f"Base: `{packet['base']}` — {s['files_changed']} file(s) changed, "
        f"+{s['lines_added']} / -{s['lines_deleted']}, "
        f"{s['new_files']} new, {s['high_severity_findings']} high-severity "
        f"finding(s).",
        "",
        "| File | + | - | Findings |",
        "|---|---|---|---|",
    ]
    for f in packet["files"]:
        notes = "; ".join(f"{x['rule']}({x['severity']})"
                          for x in f["findings"]) or "—"
        lines.append(f"| `{f['path']}` | {f['added']} | {f['deleted']} | "
                     f"{notes} |")
    high = [f for f in packet["files"] for x in f["findings"]
            if x["severity"] == "high"]
    if high:
        lines.append("")
        lines.append("## High-severity findings")
        for f in packet["files"]:
            for x in f["findings"]:
                if x["severity"] == "high":
                    lines.append(f"- `{f['path']}`: {x['message']}"
                                 + (f" — `{x['line']}`" if x["line"] else ""))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic pre-review packet from a git diff.")
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--base", default="HEAD~1")
    parser.add_argument("--diff", type=Path, default=None,
                        help="read a unified diff file instead of running git")
    parser.add_argument("--format", choices=["json", "md"], default="json")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--no-fail", action="store_true",
                        help="always exit 0 even with high-severity findings")
    args = parser.parse_args(argv)

    try:
        packet = (packet_from_diff_file(args.diff) if args.diff
                  else packet_from_repo(args.repo, args.base))
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    text = (json.dumps(packet, indent=2) if args.format == "json"
            else render_markdown(packet))
    if args.out:
        args.out.write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text, end="" if args.format == "md" else "\n")

    if args.no_fail:
        return 0
    return 1 if packet["summary"]["high_severity_findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
