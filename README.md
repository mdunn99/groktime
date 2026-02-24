# GrokTime - Dynamic Grokker
Using the power of OpenAI's GPT-5-nano, this library dynamically writes Grok patterns to an adjustable config file to make the process of log ingestion easier. This library was built to support my UCF Knight Hacks project: "Vigil" (a work in progress SIEM).

## Core Features
- A preset list of common Grok patterns in common log formats
- Negligible compute/API cost for writing new Grok patterns
- Configurable variable names

## Dependencies
- `pygrok`
- `openai`

## Use
1. Clone this repo: `git clone https://github.com/mdunn99/groktime.git`
2. Create a virtual environment
3. Create a `.env` file in your project folder and add your OpenAI API key: `OPENAI_API_KEY=<YOUR_KEY_HERE>`
4. Install the dependencies: `pip install pygrok openai`
5. Run: `python3 main.py -l LOG_FILE`

## Need to:
- Remove incorrect patterns after appending them
- Error handling
- Have a more robust decision tree
- Add more datetime formats
