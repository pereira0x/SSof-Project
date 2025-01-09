import sys
import json
import esprima
from src.Pattern import Pattern
from src.Policy import Policy
from src.MultiLabelling import MultiLabelling
from src.Vulnerabilities import Vulnerabilities
from src.Analyser import Analyser
import os


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <slice> <patterns>", file=sys.stderr)
        return

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        slice_code = f.read()

    with open(sys.argv[2], "r", encoding="utf-8") as f:
        patterns = json.load(f)
    patterns = [Pattern(data) for data in patterns]

    policy = Policy(patterns)
    multiLabelling = MultiLabelling()
    vulnerabilities = Vulnerabilities()

    ast = esprima.parseScript(slice_code, loc=True)

    analyser = Analyser(policy, multiLabelling, vulnerabilities)
    analyser.visit(ast)

    output_folder = "./output/"
    os.makedirs(output_folder, exist_ok=True)
    # remove .js from the file name
    sys.argv[1] = sys.argv[1].replace(".js", "")
    output_file = os.path.join(
        output_folder, os.path.basename(sys.argv[1]) + ".output.json"
    )

    with open(output_file, "w", encoding="utf-8") as f:
        vuln = json.dumps(vulnerabilities.jsonify(), indent=4)
        f.write(vuln)


if __name__ == "__main__":
    main()
