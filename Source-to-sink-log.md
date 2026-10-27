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
