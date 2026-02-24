from pygrok import Grok
import json
import datetime
from time import sleep
from openai import OpenAI
import argparse
#import logging
client = OpenAI()

parser = argparse.ArgumentParser(description="GrokTime - Log Parser")
parser.add_argument("-l", "--log", help="Log to pass into parser")
args = parser.parse_args()

VARIABLES = ["timestamp", "host", "proc", "pid", "severity", "facility",
            "login", "target_user", "auth_method", "login_status", "src_ip",
            "dst_ip", "src_port", "dst_port", "url", "domain", "path", "uri",
            "hash", "hash_algo", "signature", "command  ", "args", "session_id",
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
            - Use HOSTNAME not HOST
            """

def call_api(log_string):
    response = client.responses.create(
    model="gpt-5-nano",
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

# instatiate or return a list of grok patterns
def return_grok_patterns_list(grok_patterns_master_file: str='patterns.json'):
    with open(grok_patterns_master_file, 'r') as f:
        pattern_dict = json.load(f)['patterns'] # load grok patterns file as a python dict
        grok_list = [p for p in pattern_dict] # define the list of grok patterns
        return grok_list

# instatiate or return a list of pygrok objects so that grok is not called on patterns every log line.
def return_compiled_pygrok_objects(grok_list: list):
    objects = [Grok(p) for p in grok_list] # pre-compile the patterns for easy iteration
    return objects

# append new pattern to master file
def append_master_file(pattern_to_append: str, grok_patterns_master_file: str='patterns.json'):
    with open(grok_patterns_master_file, 'r+') as f:
        grok_patterns_dict = json.load(f) # load grok patterns file as a python dict
        grok_patterns_dict["patterns"].append(pattern_to_append) # append pattern to python dict
        f.seek(0) # move the cursor to the beginning of the file
        json.dump(grok_patterns_dict, f, indent=4) # dump the appended pattern to the json file
        return

# when new formats arrive, this function is called to handle the logic of:
# 1. grabbing a new grok pattern string from openapi
# 2. ensuring this new grok pattern returns non-null
# 3. appending this new grok pattern to the master file
# 4. re-instatiating the grok_list and compiled_pygrok_objects, respectively
def handle_new_formats(log_string: str):
    global grok_list, pygrok_objects
    api_response = call_api(log_string)
    print("api call complete")
    new_grok_pattern = json.loads(api_response)["pattern"]

    grok = Grok(new_grok_pattern)
    grok_match = grok.match(log_string)
    print("created new parsed string")

    append_master_file(new_grok_pattern)
    print("appended new grok pattern to master file")
    grok_list = return_grok_patterns_list()
    pygrok_objects = return_compiled_pygrok_objects(grok_list)
    print("re-instatiated grok strings and pygrok objects")
    return grok_match

# loop through grok list to find the first match
def match_grok_pattern(log_line: str, pygrok_objects: list):
    grok_match = None
    for object in pygrok_objects:
        grok_match = object.match(log_line) # match log line to pygrok object
        if grok_match:
            break
    for i in range(3): # loop through this process 3 times in case api fucks it up
        if i > 0:
            print('retrying api call...') 
        if not grok_match:
            print('new format found...')
            grok_match = handle_new_formats(log_line)
        else:
            break
    print(grok_match)
    return grok_match

def main(log: str, output: str=''):
    global grok_list, pygrok_objects
    all_events = dict()
    grok_list = return_grok_patterns_list()
    pygrok_objects = return_compiled_pygrok_objects(grok_list)
    with open(log) as f:
        for i, line in enumerate(f): # reads each new line!
            line = line.rstrip()
            matched_output = match_grok_pattern(line, pygrok_objects)
            #all_events.update(matched_output)

if args.log:
    main(args.log)
