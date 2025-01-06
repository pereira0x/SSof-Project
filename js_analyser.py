import sys
import esprima
import json
from Pattern import Pattern
from Policy import Policy
from MultiLabelling import MultiLabelling
from Vulnerabilities import Vulnerabilities
from Analyser import Analyser


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <slice> <patterns>", file=sys.stderr)
        return

    with open(sys.argv[1], "r") as f:
        slice = f.read()

    with open(sys.argv[2], "r") as f:
        patterns = json.load(f)
    patterns = [Pattern(data) for data in patterns]
    print(patterns)

    policy = Policy(patterns)
    multiLabelling = MultiLabelling()
    vulnerabilities = Vulnerabilities()
    print(policy)
    print(multiLabelling)
    print(vulnerabilities)

    ast = esprima.parseScript(slice, loc=True)
    #print(ast)
    
    analyser = Analyser(policy, multiLabelling, vulnerabilities)
    analyser.visit(ast)
    print(policy)
    print(multiLabelling)
    print(vulnerabilities)


if __name__ == "__main__":
    main()
