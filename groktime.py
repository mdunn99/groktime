from pygrok import Grok
import json
from datetime import datetime
import argparse
from time import sleep
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
import os

# CONFIGURABLE OBJECTS
VARIABLES = ["timestamp", "host", "proc", "pid", "severity", "facility",
        "login", "target_user", "auth_method", "login_status", "src_ip",
        "dst_ip", "src_port", "dst_port", "url", "domain", "path", "uri",
        "hash", "hash_algo", "signature", "command", "args", "session_id",
        "request_id", "trace_id", "status_code", "bytes_sent", "bytes_recv", "duration", "tty", "pwd"]
LLM_REASONING_EFFORT = "low"

class LLMCalls:
    def __init__(self):
        self.instantiated = False
        self.prompt = self._build_prompt()

    def _get_client(self):
        from openai import OpenAI

        self.client = OpenAI()
        self.instantiated = True

    # only have to do this once
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

    def call_api(self, log_string: str) -> str:
        self._get_client() if not self.instantiated else ''

        response = self.client.responses.create(
        model="gpt-5-mini",
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
                "required": [
                "pattern", "note"
                ],
                "additionalProperties": False
            }
            },
            "verbosity": "medium"
        },
        reasoning={"effort": LLM_REASONING_EFFORT},
        store=True,
        include=[
            "reasoning.encrypted_content"
        ]
        )
        response = response.output_text # the string output of the api response
        return json.loads(response)["pattern"] # the parsed dictionary version of the expected schema output in object "pattern"

class GrokMatcher(LLMCalls):
    def __init__(self, grok_patterns_file: str):
        super().__init__()
        self.grok_patterns_file = grok_patterns_file
        with open(grok_patterns_file, 'r') as f:
            self.pattern_dict = json.load(f)
        self.pygrok_object_list = [Grok(p) for p in self.pattern_dict["patterns"]]

    def _handle_new_formats(self, log_string: str) -> tuple[dict | None, str | None, Grok | None]:
        new_grok_pattern = self.call_api(log_string)
        try:
            pygrok_object = Grok(new_grok_pattern)
        except KeyError as e:
            #print(f"KeyError: {e} is not valid. Retrying...")
            return None, None, None
        grok_match = pygrok_object.match(log_string)
        return grok_match, new_grok_pattern, pygrok_object

    # loop through grok list to find the first match
    def match_grok_pattern(self, log_line: str) -> dict | None:
        grok_match = None
        for obj in self.pygrok_object_list:
            grok_match = obj.match(log_line) # match log line to pygrok object
            if grok_match:
                return grok_match
            else:
                continue

        if not grok_match:
            try:
                for i in range(3): # retry 3 times in case api gets the parsing wrong (grok_match == None)
                    #print('retrying api call...'  if i >0 else 'new format found...')
                    grok_match, grok_pattern, pygrok_object = self._handle_new_formats(log_line)
                    if grok_match and grok_pattern and pygrok_object:
                        self.pattern_dict['patterns'].append(grok_pattern)
                        self.pygrok_object_list.append(pygrok_object)
                        return grok_match
            except Exception as e:
                #print(e)
                return None

class FileHandler:
    def __init__(self, grok_matcher: GrokMatcher):
        self.grok_matcher = grok_matcher

    # append new pattern(s) to master file, lets do this periodically instead of every call maybe?
    def dump_patterns_to_file(self) -> None:
        with open(self.grok_matcher.grok_patterns_file, 'r+') as f:
            f.seek(0)
            json.dump(self.grok_matcher.pattern_dict, f, indent=4) # dump the appended pattern to the json file
            f.truncate()

class LogProcessor:
    def __init__(self, output: str, grok_patterns_file: str):
        self.grok_matcher = GrokMatcher(grok_patterns_file=grok_patterns_file)
        self.file_handler = FileHandler(self.grok_matcher)
        self.grok_patterns_file = grok_patterns_file
        self.output = output

    def _send_to_api(self, json_object: dict) -> dict:
        return json_object
        #print(json_object)

    # need to be appending rather than just writing
    def _write_to_json(self, events: dict) -> None:
        with open(self.output, 'w') as f:
            json.dump(events, f, indent=4)
        #print('json wrote to file! ☑')

    # highly problematic
    def convert_to_unix_time(self, timestamp: str) -> float | str:
        current_year = datetime.now().year

        # True if year must be implied
        # False otherwise
        formats = [
            ("%d/%b/%Y:%H:%M:%S %z", False),
            ("%b %d %H:%M:%S", True),
        ]

        for fmt, needs_year in formats:
            try:
                timestamp_str = f"{current_year} {timestamp}" if needs_year else timestamp
                fmt_str = f"%Y {fmt}" if needs_year else fmt
                dt = datetime.strptime(timestamp_str, fmt_str)
                return dt.timestamp()
            except ValueError:
                continue

        #print('failed to convert timestamp')
        return timestamp

    def process(self, log_excerpt: list[str]) -> list:
        events: list[dict] = []
        for i, entry in enumerate(log_excerpt):
            entry = entry.rstrip()
            grok_match = self.grok_matcher.match_grok_pattern(entry)
            if not grok_match:
                #print(f'Error parsing line. Skipping.')
                continue

            #new_timestamp = self.convert_to_unix_time(grok_match["timestamp"])
            #grok_match.update({"timestamp": new_timestamp})
            events.append(grok_match)
            #self._send_to_api(grok_match) # 'send to api'

        self.file_handler.dump_patterns_to_file() # dump current patterns to a file like patterns.json
        if self.output:
            self._write_to_json(events)
        #print(f'Processed log excerpt with {len(events)} events.\n')
        return events

            
class EventHandler(FileSystemEventHandler):
    def __init__(self, list_of_logs: list[str], output: str="", grok_patterns_file: str="", verbose: int=0):
        self.processor = LogProcessor(output, grok_patterns_file)
        self.list_of_logs = list_of_logs
        self.output = output
        self.patterns_file = grok_patterns_file

        # Maps absolute log path -> current byte offset
        self.file_offsets: dict[str, int] = {}

        for log in list_of_logs:
            log_path = os.path.abspath(log.rstrip())
            log_name = os.path.basename(log_path)
            #print(f'processing {log_name}')
            try:
                with open(log_path, 'r') as f:
                    lines = f.readlines()
                    self.file_offsets[log_path] = f.tell()
            except FileNotFoundError as e:
                #print(f"{e}. Skipping...\n")
                continue
            self.processor.process(log_excerpt=[l.rstrip() for l in lines[-500:]])
        #print('Waiting for event...')

    def on_modified(self, event: FileSystemEvent) -> None:
        log_path = os.path.abspath(event.src_path)
        if log_path not in self.file_offsets:
            return

        offset = self.file_offsets[log_path]
        try:
            with open(log_path, 'r') as f:
                f.seek(offset)
                new_lines = f.readlines()
                self.file_offsets[log_path] = f.tell()
        except FileNotFoundError as e:
            #print(f"{e}. Skipping...\n")
            return

        if not new_lines:
            return

        self.processor.process(log_excerpt=[l.rstrip() for l in new_lines])
        #print('Waiting for event...')

def run_observer(file_path_list: str, output: str="", grok_patterns_file: str="patterns.json", verbose: int=0) -> None:
    list_of_logs = []
    with open(file_path_list, 'r') as f:
        for log in f:
            list_of_logs.append(log)
    event_handler = EventHandler(list_of_logs=list_of_logs, output=output, grok_patterns_file=grok_patterns_file, verbose=verbose)
    observer = Observer()
    observer.schedule(event_handler, ".", recursive=True)
    observer.start()
    try:
        while True:
            sleep(1)
    finally:
        observer.stop()
        observer.join()

def parse_logs(log_paths: list[str], grok_patterns_file: str="patterns.json") -> list:
    """
    One-shot parse of given log files. Returns a dict of {filename: [events]}.
    Use this instead of run_observer if you don't need live watching.
    """
    processor = LogProcessor(output="", grok_patterns_file=grok_patterns_file)
    results = []
    for log_path in log_paths:
        log_path = log_path.rstrip()
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError as e:
            #print(f"{e}. Skipping...")
            continue
        events = processor.process(log_excerpt=[l.rstrip() for l in lines])
        results.extend(events)
    return results