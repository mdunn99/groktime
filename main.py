from pygrok import Grok
import json
from datetime import datetime
import argparse
#import logging

parser = argparse.ArgumentParser(description="GrokTime - Log Parser")
parser.add_argument("-l", "--log", help="Log to pass into parser")
parser.add_argument("-o", "--output", help="Output json file (default: out.json)")
parser.add_argument("-p", "--patterns", help="The pattern json file to parse through (default: patterns.json)")
args = parser.parse_args()

instatiated = False

def instatiate_openai():
    global instatiated, client
    instatiated = True
    from openai import OpenAI
    client = OpenAI()

VARIABLES = ["timestamp", "host", "proc", "pid", "severity", "facility",
            "login", "target_user", "auth_method", "login_status", "src_ip",
            "dst_ip", "src_port", "dst_port", "url", "domain", "path", "uri",
            "hash", "hash_algo", "signature", "command", "args", "session_id",
            "request_id", "trace_id", "status_code", "bytes_sent", "bytes_recv", "duration", "tty", "pwd"]

def build_prompt():
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

def call_api(log_string):
    response = client.responses.create(
    model="gpt-5-mini",
    input=[
        {"role": "system", "content": build_prompt()},
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
    reasoning={"effort": "low"},
    store=True,
    include=[
        "reasoning.encrypted_content"
    ]
    )
    return response.output_text

def convert_to_unix_time(timestamp: str) -> float | str:
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

    print('failed to convert timestamp')
    return timestamp

# instatiate or return a list of grok patterns
def return_grok_patterns_list(grok_patterns_master_file: str='patterns.json'):
    with open(grok_patterns_master_file, 'r') as f:
        pattern_dict = json.load(f)['patterns'] # load grok patterns file as a python dict
        grok_list = [p for p in pattern_dict] # define the list of grok patterns
        return grok_list

# instatiate or return a list of pygrok objects so that grok is not called on patterns every log line.
def return_compiled_pygrok_objects(grok_list: list) -> list[Grok]:
    global pygrok_list
    pygrok_list = [Grok(p) for p in grok_list] # pre-compile the patterns for easy iteration
    return pygrok_list

# append new pattern to master file
def append_master_file(pattern_to_append: str, grok_patterns_master_file: str='patterns.json') -> None:
    with open(grok_patterns_master_file, 'r+') as f:
        grok_patterns_dict = json.load(f) # load grok patterns file as a python dict
        grok_patterns_dict["patterns"].append(pattern_to_append) # append pattern to python dict
        f.seek(0) # move the cursor to the beginning of the file
        json.dump(grok_patterns_dict, f, indent=4) # dump the appended pattern to the json file
        return

def handle_new_formats(log_string: str):
    api_response = call_api(log_string)
    new_grok_pattern = json.loads(api_response)["pattern"]
    try:
        pygrok_object = Grok(new_grok_pattern)
    except KeyError as e:
        print(f"KeyError: {e} is not valid. Retrying...")
        return None, None, None
    grok_match = pygrok_object.match(log_string)

    return grok_match, new_grok_pattern, pygrok_object

# loop through grok list to find the first match
def match_grok_pattern(log_line: str) -> dict | None:
    global instatiated
    grok_match = None
    for obj in pygrok_list:
        grok_match = obj.match(log_line) # match log line to pygrok object
        if grok_match:
            return grok_match
    if not grok_match:
        for i in range(3): # retry 3 times in case api gets the parsing wrong (grok_match == None)
            print('retrying api call...'  if i >0 else 'new format found...')
            instatiate_openai() if not instatiated else ''
            grok_match, grok_pattern, pygrok_object = handle_new_formats(log_line)
            if grok_match:
                append_master_file(grok_pattern)
                pygrok_list.append(pygrok_object)
                return grok_match
        return None

def main(log: str, output: str='out.json', grok_patterns_file: str='patterns.json') -> None:
    global grok_list
    all_events = dict()
    grok_list = return_grok_patterns_list(grok_patterns_file)
    pygrok_list = return_compiled_pygrok_objects(grok_list)
    with open(log) as f:
        for i, line in enumerate(f): # reads each new line!
            line = line.rstrip()
            grok_match = match_grok_pattern(line)
            try:
                new_timestamp = convert_to_unix_time(grok_match["timestamp"])
                grok_match.update({"timestamp": new_timestamp})
                all_events[i] = grok_match
            except Exception:
                print('Error parsing line. Skipping')
                continue
    with open(output, 'w') as f:
        json.dump(all_events, f, indent=4)
    print('json wrote to file! ☑')
    return

if args.output:
    if args.patterns:
        main(log=args.log, output=args.output, grok_patterns_file=args.patterns)
    else:
        main(log=args.log, output=args.output)
if not args.output:
    if args.patterns:
        main(log=args.log, grok_patterns_file=args.patterns)
    else:
        main(log=args.log)