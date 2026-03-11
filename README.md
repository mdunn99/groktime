# grokmoment

A Python library for parsing log files and entries into structured events using Grok patterns. When a log line doesn't match any known pattern, grokmoment automatically generates a new one via LLM and persists it for future use.

## Requirements

- Python 3.10+
- An OpenAI API key set as `OPENAI_API_KEY` in your environment

```bash
pip install pygrok openai
```

## Usage

```python
from grokmoment import parse_logs_by_file, parse_logs_by_excerpt

events = parse_logs_by_file("auth.log", patterns_file="patterns.json")
events = parse_logs_by_excerpt(log_entry_list)
```

`parse_logs_by_file` and `parse_logs_by_excerpt` return a list of dicts, one per successfully parsed log line, with keys drawn from a set of easily-configurable field names (see the top of `grokmoment.py` for details.

If a line doesn't match any existing pattern, grokmoment calls the OpenAI API to generate one, validates it, and appends it to `patterns_file`. Patterns persist across runs.

## Pattern file format

`patterns.json` is a simple JSON file with a `patterns` array:

```json
{
    "patterns": [
        "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host} %{WORD:proc}\\[%{INT:pid}\\]: %{GREEDYDATA:args}"
    ]
}
```

New patterns discovered at runtime are appended to this array automatically.
