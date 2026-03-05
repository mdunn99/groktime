# groktime.py

from pygrok import Grok
import json
from datetime import datetime

VARIABLES = ["timestamp", "host", "proc", "pid", "severity", "facility",
        "login", "target_user", "auth_method", "login_status", "src_ip",
        "dst_ip", "src_port", "dst_port", "url", "domain", "path", "uri",
        "hash", "hash_algo", "signature", "command", "args", "session_id",
        "request_id", "trace_id", "status_code", "bytes_sent", "bytes_recv", 
        "duration", "tty", "pwd"]

MODEL = "gpt-5-mini"
LLM_REASONING_EFFORT = "low"


class LLMCalls:
    def __init__(self):
        from openai import OpenAI
        self.client = OpenAI()
        self.prompt = self._build_prompt()

    def _build_prompt(self) -> str:
        return f"""You produce Grok patterns to parse individual log lines using Python's pygrok library.

                Only use field names from this list: {", ".join(VARIABLES)}

                Rules:
                - Choose the most specific appropriate Grok pattern for each field (e.g. INT for ports and pids, IP for addresses, USERNAME for logins, PATH for file paths, SYSLOGTIMESTAMP for syslog timestamps).
                - Prefer WORD over DATA. Use DATA only when a field may contain spaces and is bounded by clear delimiters on both sides.
                - Use GREEDYDATA only at the end of a pattern.
                - Treat known literal words in the log line as literals in the pattern, not as fields to capture.
                - Escape literal square brackets with a backslash: \\[ and \\].
                - Return the Grok pattern in the pattern field and an explanation in the note field.
                - Use HOSTNAME never HOST
                """

    def get_pattern(self, log_string: str) -> str:
        response = self.client.responses.create(
            model=MODEL,
            input=[
                {"role": "system", "content": self.prompt},
                {"role": "user", "content": log_string},
            ],
            text={
                "format": {
                    "type": "json_schema",
                    "name": "grok",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "pattern": {
                                "type": "string",
                                "description": "A single Grok pattern string using %{PATTERN:name} syntax."
                            },
                            "note": {
                                "type": "string",
                                "description": "Explanation of pattern construction decisions."
                            }
                        },
                        "required": ["pattern", "note"],
                        "additionalProperties": False
                    }
                }
            },
            reasoning={"effort": LLM_REASONING_EFFORT},
            store=True,
            include=["reasoning.encrypted_content"]
        )
        return json.loads(response.output_text)["pattern"]


class PatternStore:
    """Owns the pattern list and its persistence."""

    def __init__(self, patterns_file: str):
        self.patterns_file = patterns_file
        with open(patterns_file, 'r') as f:
            self._data = json.load(f)

    @property
    def patterns(self) -> list[str]:
        return self._data["patterns"]

    def add(self, pattern: str) -> None:
        self._data["patterns"].append(pattern)

    def save(self) -> None:
        with open(self.patterns_file, 'r+') as f:
            f.seek(0)
            json.dump(self._data, f, indent=4)
            f.truncate()


class GrokMatcher:
    """Matches log lines against known patterns, expanding the set via LLM when needed."""

    def __init__(self, store: PatternStore, llm: LLMCalls):
        self.store = store
        self.llm = llm
        self._compiled: list[Grok] = [Grok(p) for p in store.patterns]

    def match(self, log_line: str) -> dict | None:
        for grok in self._compiled:
            result = grok.match(log_line)
            if result:
                return result

        return self._learn_and_match(log_line)

    def _learn_and_match(self, log_line: str) -> dict | None:
        for _ in range(3):
            pattern = self.llm.get_pattern(log_line)
            try:
                grok = Grok(pattern)
            except KeyError:
                continue
            result = grok.match(log_line)
            if result:
                self.store.add(pattern)
                self._compiled.append(grok)
                return result
        return None


class LogProcessor:
    """Parses a list of log lines into structured events."""

    def __init__(self, matcher: GrokMatcher):
        self.matcher = matcher

    def process(self, lines: list[str]) -> list[dict]:
        events = []
        for line in lines:
            line = line.rstrip()
            match = self.matcher.match(line)
            if not match:
                print(f"Error parsing line, skipping: {line!r}")
                continue
            events.append(match)
        return events


def parse_logs(log_path: str, patterns_file: str = "patterns.json") -> list[dict]:
    """
    Parse a log file into structured events.
    Discovers and persists new Grok patterns automatically.
    """
    store = PatternStore(patterns_file)
    matcher = GrokMatcher(store=store, llm=LLMCalls())
    processor = LogProcessor(matcher=matcher)

    with open(log_path, 'r') as f:
        lines = f.readlines()

    store.save()
    return processor.process(lines)