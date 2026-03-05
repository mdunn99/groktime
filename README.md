# GrokTime

A self-learning log parser. Feed it log files, get back structured dicts. When it encounters a log format it doesn't recognise, it calls OpenAI to generate a new Grok pattern on the fly, validates it, and caches it to `patterns.json` for free reuse.

---

## Requirements

- Python 3.10+
- An OpenAI API key

## Installation

```bash
git clone https://github.com/mdunn99/groktime.git
cd groktime
python -m venv .venv && source .venv/bin/activate
pip install pygrok openai watchdog
```

Create a `.env` file in the project root:
```
OPENAI_API_KEY=your_key_here
```

---

## Usage

### One-shot parsing — `parse_logs`

Parse a list of log files and get back a flat list of dicts, one per log line.

```python
from groktime import parse_logs

events = parse_logs(["logs/auth.log", "logs/apache.log"])

for event in events:
    print(event)
    # {"timestamp": "Mar 1 12:00:00", "host": "myserver", "src_ip": "10.0.0.1", ...}
```

Each dict contains whichever of the following fields were present in the log line:

```
timestamp, host, proc, pid, severity, facility, login, target_user,
auth_method, login_status, src_ip, dst_ip, src_port, dst_port, url,
domain, path, uri, hash, hash_algo, signature, command, args,
session_id, request_id, trace_id, status_code, bytes_sent, bytes_recv,
duration, tty, pwd
```

### Live file watching — `run_observer`

Tails a set of log files and processes new lines as they're written. This is a blocking call — run it in a thread if you need your app to keep doing other things.

```python
from groktime import run_observer
import threading

t = threading.Thread(
    target=run_observer,
    args=("logs/list_of_file_paths",),
    kwargs={"output": "out.json", "grok_patterns_file": "patterns.json"},
    daemon=True
)
t.start()
```

`list_of_file_paths` is a plain text file with one log path per line:
```
/var/log/auth.log
/var/log/apache2/access.log
/var/log/syslog
```

---



## How it works

1. Each log line is matched against the patterns in `patterns.json`
2. On a match, the extracted fields are returned as a dict
3. On a miss, OpenAI generates a new Grok pattern for that line format
4. The new pattern is validated, and if it matches, appended to `patterns.json`
5. All subsequent lines of the same format hit the cache — no further API calls

Pattern generation uses a low reasoning effort model so API costs are negligible.

---

## Note
AI was used conservatively during the creation of this project. AI did produce this README file.
