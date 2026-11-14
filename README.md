# review-packet

Build a deterministic pre-review packet from a git diff — the structured input that AI code-review pipelines (like [alibaba/open-code-review](https://github.com/alibaba/open-code-review), trending #1 on GitHub today) work best with. No model, no network: the same diff always yields the same packet.

## Quick start

```bash
# Packet for the last commit, as JSON
python3 review_packet.py --repo . --base HEAD~1

# Or feed it a diff file
python3 review_packet.py --diff examples/change.diff --format md
```

Exit code is 1 when a high-severity pattern is found — use it as a CI gate, or pass `--no-fail` to only report.

## What the packet contains

```json
{
  "repo": ".",
  "base": "HEAD~1",
  "summary": {
    "files_changed": 2,
    "lines_added": 4,
    "lines_deleted": 0,
    "new_files": 1,
    "binary_files": 0,
    "high_severity_findings": 1,
    "total_findings": 3
  },
  "files": [
    {
      "path": "app.py", "added": 2, "deleted": 0,
      "is_new": false, "is_binary": false,
      "findings": [
        {"rule": "secret-like", "severity": "high",
         "message": "possible hard-coded credential",
         "line": "API_KEY = \"sk-live-...\""}
      ]
    }
  ]
}
```

## Checks

| Rule | Severity | Catches |
|---|---|---|
| `secret-like` | high | hard-coded API keys / secrets / tokens |
| `private-key` | high | private key material in the diff |
| `eval-exec` | medium | `eval()` / `exec()` |
| `shell-true` | medium | `subprocess(..., shell=True)` |
| `sql-concat` | medium | SQL string concatenation |
| `large-file` | medium | 500+ lines added to one file |
| `todo-fixme` | low | TODO / FIXME markers added |
| `debug-print` | low | `print()` / `console.log()` / `debugger` left in |
| `lockfile-churn` | low | lockfile changes worth a second look |

## Example output

```
$ python3 review_packet.py --diff examples/change.diff --format md
# Review packet

Base: `diff-file` — 2 file(s) changed, +4 / -0, 0 new, 1 high-severity finding(s).

| File | + | - | Findings |
|---|---|---|---|
| `app.py` | 2 | 0 | secret-like(high); debug-print(low) |
| `util.py` | 2 | 0 | shell-true(medium) |

## High-severity findings
- `app.py`: possible hard-coded credential — `API_KEY = "sk-live-abcdefgh12345678"`
```

Pipe the JSON into your reviewer of choice — `open-code-review`, a local LLM, or a human.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

10 tests, all offline — including a real temporary git repo built with `git init`/`commit` to exercise the `--repo` path end to end.
