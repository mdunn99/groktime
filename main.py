import argparse
from groktime import run_observer

def main() -> None:
    parser = argparse.ArgumentParser(description="GrokTime - Log Parser")
    parser.add_argument("-l", "--logs", required=True, help="File specifying logs (separated by newline) to be observed")
    parser.add_argument("-o", "--output", default="", help="Output json file")
    parser.add_argument(
        "-p",
        "--patterns",
        default="patterns.json",
        help="The pattern json file to parse through",
    )
    args = parser.parse_args()
    run_observer(file_path_list=args.logs, output=args.output, grok_patterns_file=args.patterns)

if __name__ == "__main__":
    main()