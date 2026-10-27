# SAST Learning: Tracing Vulnerabilities in a Flask App

I'm learning static analysis (SAST) by hand before building a tool for it. This repo is where I trace vulnerabilities from **source** (where untrusted input enters) to **sink** (where it does something dangerous), and write down what I find, including where a simple tool would get it wrong.

The target is [we45's Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App), a deliberately insecure training app. **The vulnerabilities in `app/` are theirs, not mine.** My work is the analysis.

## Why

I found and fixed a path traversal bug in a production service I maintain. I wanted to know whether the pattern generalizes, so I'm building a rule-based SAST tool for Flask handlers, starting with path traversal. Before writing any rules, I'm tracing real vulnerabilities by hand so I understand what the tool has to detect and where it will raise false alarms.

## What's here

| File | What it is |
|---|---|
| [Source-to-sink-log.md](Source-to-sink-log.md) | My traces, one per route: source, sanitizer, hops, sink, explanation, fix |
| [Backward Tracing and Taint Lessons.md](Backward%20Tracing%20and%20Taint%20Lessons.md) | Notes on the method and the mistakes I made while learning it |
| `app/` | The original vulnerable Flask app (from we45) |

## Traces so far

| Route | Bug class | Result |
|---|---|---|
| `/search` | SQL injection | `content['search']` is formatted into a SQL string and run, with no sanitizer |
| `/yaml_hammer` | Unsafe deserialization | The uploaded file's content reaches `yaml.load` unsanitized |
| `/yaml_hammer` (filename) | Path traversal, **blocked** | `secure_filename` breaks the chain, so a naive tool would raise a false positive |

## Method

Work **backward from sinks**:

1. Grep for a list of dangerous calls (`execute`, `yaml.load`, `open`, `.save`, and so on).
2. Triage the hits and drop false matches such as docstrings.
3. Name the argument each real sink receives.
4. Walk up one assignment at a time. A hop continues the chain, a sanitizer may break it, and a `request.` read is the source.
5. Record the chain as `source / sanitizer / hop / sink` with line numbers.

One lesson that came up repeatedly: **a sanitizer cleans a specific value, not a route.** An upload has a filename and contents, each with its own chain.

## Limits I've found so far

- A tool that follows variable names loses the trail when data is written to a file and read back (`f.save` then `open`), which means a false negative.
- A tool without a sanitizer list flags `secure_filename`-protected paths, which means a false positive.
- Text search matches comments and docstrings.

## Next

- [ ] Trace the `str(e)` into `render_template_string` flow in `/search`
- [ ] Trace the 404 handler
- [ ] Write Semgrep rules for the path traversal pattern
- [ ] Build the rule engine, starting with path traversal
- [ ] Scan real Flask repos and hand-triage the results to measure the false positive rate

## Credit

The vulnerable app is by [we45](https://github.com/we45/Vulnerable-Flask-App). This repo contains intentionally insecure code. Don't deploy it.
