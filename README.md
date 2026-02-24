# GrokTime - Dynamic Grokker
Using the power of OpenAI's GPT-5-nano, this library dynamically writes Grok patterns to an adjustable config file to make the process of log ingestion easier. This library was built to support my UCF Knight Hacks project: "Vigil" (a work in progress SIEM).

## Core Features
- A preset list of common Grok patterns in common log formats
- Negligible compute/API cost for writing new Grok patterns
- Configurable variable names

## Dependencies
- `pygrok`
- `openai`

## Need to:
- Remove incorrect patterns after appending them
- Error handling
- Have a more robust decision tree
- Add more datetime formats
