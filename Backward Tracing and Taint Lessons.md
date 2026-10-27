---
tags: [sast, taint-analysis, flask, security]
related: "[[Source-to-Sink Tracing]]"
---

# Backward Tracing and Taint Lessons

Lessons from tracing `/search` (SQL injection) and `/yaml_hammer` (unsafe deserialization) in the vulnerable Flask app. Builds on [[Source-to-Sink Tracing]].

## 1. Sources vs. containers vs. server values

A **source** is a value the *client* decided. Test: "If I send a different request, does this value change?"

| Line | Value | Verdict |
|---|---|---|
| `token = request.headers.get('Authorization')` | header | Source |
| `content = request.json` | whole body | **Container**, not the dangerous value |
| `search_term = content['search']` | one key | **Source** (each key is its own source) |
| `results = []` | server-made | Not a source |
| `search_query = db.engine.execute(...)` | result of the sink | Neither; the *call* is the sink |

Mistake I made: I listed every variable in the route as a "source." Sort lines into source / hop / sink first.

## 2. How SQL injection works

```python
str_query = "... WHERE username = '%s';" % search_term
```

- `%s` is just Python string formatting. No database is involved yet.
- The database receives **one block of text**. It can't tell which part was my code and which was the user's.
- The single quotes are the only signal for data vs. command.
- If the user types a quote, they end the data section early. Their remaining text is now read as **command**: `' OR '1'='1` returns every row.
- **Fix:** parameterized query, so the command and data travel separately and the value is never parsed as syntax.

The bug isn't "data became a command." It's that **the command was built out of text the user wrote**.

## 3. Forward vs. backward tracing

- **Forward:** start at a source, follow it to a sink. Good for *discovering* what belongs on the sink list.
- **Backward:** start at a sink, ask "can attacker data reach this argument?" Good for *reviewing* unfamiliar code. This is how a tool works: search for a list of sink patterns.

**Backward routine**
1. Grep for a sink list.
2. Triage the hits. Skip false positives (line 175 matched `requests\.` in a docstring).
3. Name the **argument** of each real sink. The danger is in what's passed in.
4. Find that variable's assignment, one hop at a time. Another variable means a hop. A `request.` read means a source, so stop. A constant means safe, so stop.
5. Note any `if` / validator / escape as a sanitizer candidate.

```
grep -nE "subprocess|Popen|os\.system|eval\(|exec\(|open\(|send_file|\.execute\(|pickle|yaml\.load|requests\.|redirect\(|extract_info|\.save\(" app/app.py
```

Mistake I made: my sink list missed `.save(`. A sink list only finds what's on it.

## 4. A hop is a line the value passes *through*

Walking up from `open(file_path)`:

```
sink:       326  open(file_path, 'r')
hop:        323  file_path = cwd + '/Files/' + fname
hop:        321  fname = str(rand) + fname
sanitizer:  320  fname = secure_filename(f.filename)
source:     318  f = request.files['file']
```

- Line 324 (`f.save(file_path)`) is a *use* of `file_path`, not a hop on the way up. It is a second sink for the same value.
- Reassigning the same name (line 321) is still a hop.
- Write the **line number**, not the variable name, in the source field.

## 5. One upload, two tainted values

A file upload carries two separate client-controlled values, each with its own chain:

| Value | Flows to | Sanitizer | Result |
|---|---|---|---|
| `f.filename` | `file_path` → `f.save`, `open` | `secure_filename` (line 320) | Chain broken. Path traversal is blocked. |
| file **content** | `y` → `yaml.load` | **none** | Chain reaches sink. **Real vulnerability.** |

**Taint is a label on a value, not on a route.** Always ask: sanitized *which value*? "Is there a sanitizer somewhere in this route?" gives wrong answers.

`secure_filename` only cleans `f.filename`, not the content.

## 6. Unsafe deserialization (`yaml.load`)

- YAML isn't just data like JSON. Old-style `yaml.load` lets the text name Python objects and functions to run.
- So attacker-written file content can execute code. **Impact** is remote code execution. The **bug class** is unsafe deserialization.
- `yaml.load` is a sink by itself, like `pickle.loads`.
- Fix: `yaml.safe_load`.

Final chain for `/yaml_hammer`:

```
source:     318  f = request.files['file']
sanitizer:  none  (for the content)
hop:        324  f.save(file_path)      content written to disk
hop:        326  open(file_path)        same file reopened
hop:        327  y = yfile.read()       content now in y
sink:       329  ydata = yaml.load(y)
```

Note: `secure_filename` on line 320 only cleans `f.filename`, not the content.

## 7. Where a simple tool loses the trail

Between 324 and 326 the name changes from `f` to `yfile`, and no `=` links them. A tool that follows variable names concludes `y` is clean (**false negative**).

The only link is `file_path`, the same string used on the write and the read. To bridge it:
1. On a tainted **write** to a path, record "the file at this path is tainted."
2. On a later **read** of that path, mark the result tainted.

This is second-order taint (see the stored-data row in [[Source-to-Sink Tracing]]), with a file instead of a database.

**Design options for my tool**
- Handle it (more work).
- Skip it and accept the false negative.
- Flag anything that reads a saved upload and accept the noise.

With 3-5 hours a week, I need to choose and be able to justify it.

## 8. False positives, for the interview

- A tool that sees "tainted variable reaches `open()`" flags line 326. A human reads line 320 and dismisses it. The tool has to know `secure_filename` is a sanitizer.
- A text grep can match docstrings, as on line 175.
- `%` into a query isn't dangerous when the value is a hard-coded constant.

These are the cases my tool can't always tell apart, which is the talking point.

## Open items
- [ ] Trace the second flow in `/search`: `str(e)` on line 280 into `render_template_string`.
- [ ] Trace the `/` 404 handler (line 114).
- [ ] Add the yaml chain to `Source-to-sink-log.md`.
