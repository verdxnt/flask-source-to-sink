# Source-to-Sink Log

## `/search` (POST)

**Vulnerability:** SQL injection

### Chain

```
source:     line 259   (search_term = content['search'])
sanitizer:  none       (nothing between 259 and 265 checks or escapes it)
hop:        line 261   (search_term is pasted into str_query via % formatting)
sink:       line 265   (db.engine.execute(str_query))
```

### Explanation

**Attack.** The client sends `' OR '1'='1`. Python pastes it in blindly:

```sql
... WHERE username = '' OR '1'='1';
```

Reading this the way the database does:

1. `username = ''` opens a quote and immediately closes it.
2. `OR '1'='1'` is now outside any quotes, so the database reads it as part of the command. `'1'='1'` is always true.

### Fix

Use a parameterized query, where you send the command and the data separately:

```python
db.engine.execute("... WHERE username = %s", (search_term,))
```

### What I learned from this trace

- `content = request.json` is a container. The source is the specific key, `content['search']`.
- `results = []` is server-made, so it isn't a source.
- The sink is the `db.engine.execute(...)` call, not the variable that holds its result.
- Reading or printing a value (line 260) isn't a sanitizer. Only code that makes it safe counts.

---

## `/yaml_hammer` (POST)

**Vulnerability:** Unsafe deserialization (`yaml.load` on an uploaded file)

### Chain (file content)

```
source:     line 318   (f = request.files['file'])
sanitizer:  none       (for the content)
hop:        line 324   (f.save(file_path) writes the content to disk)
hop:        line 326   (open(file_path) reopens the same file)
hop:        line 327   (y = yfile.read() puts the content in y)
sink:       line 329   (ydata = yaml.load(y))
```

Note: `secure_filename` on line 320 only cleans `f.filename`, not the content.

### Chain (filename), broken by a sanitizer

```
source:     line 318   (f.filename)
sanitizer:  line 320   (fname = secure_filename(f.filename))
hop:        line 321   (fname = str(rand) + fname)
hop:        line 323   (file_path = cwd + '/Files/' + fname)
sink:       line 326   (open(file_path, 'r'))  also line 324 (f.save)
```

Taint is broken at 320, so path traversal is blocked. A naive tool would still flag line 326 (false positive).

### Explanation

An upload carries two client-controlled values: the filename and the content. Each has its own chain, and cleaning one does nothing for the other. `yaml.load` turns attacker-written text into live Python objects, and YAML can name functions to run, so this is remote code execution.

### Fix

```python
ydata = yaml.safe_load(y)
```

### What I learned from this trace

- Work backward from sinks: grep a sink list, name the argument, then walk up one assignment at a time.
- A hop is a line the value passes through. A line that only uses the variable (324 for `file_path`) isn't a hop on the way up, but it can be a second sink.
- Ask "sanitized *which value*?" A sanitizer on the filename says nothing about the content.
- A tool that follows variable names loses the trail between `f.save` (324) and `open` (326), because the only link is the path string. That's a false negative to design around.
- My first sink list missed `.save(`, so a sink list only finds what's on it.
- My grep also matched line 175, a docstring, which is a false positive from text search.
