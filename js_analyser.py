import sys
import esprima
import json


class Pattern:
    def __init__(self, data):
        self.vulnerability = data["vulnerability"]
        self.sources = data["sources"]
        self.sanitizers = data["sanitizers"]
        self.sinks = data["sinks"]
        self.implicit = data["implicit"] == "yes"

    def __repr__(self):
        return f"Vulnerability {self.vulnerability}: sources={self.sources} sanitizers={self.sanitizers} s__repr__ink={self.sinks} implicit={self.implicit}"

    def __eq__(self, other):
        return (
            self.vulnerability == other.vulnerability
            and self.sources == other.sources
            and self.sanitizers == other.sanitizers
            and self.sinks == other.sinks
            and self.implicit == other.implicit
        )


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <slice> <patterns>", file=sys.stderr)
        return

    with open(sys.argv[1], "r") as f:
        slice = f.read()

    ast = esprima.parseScript(slice, loc=True).toDict()
    print(ast)

    with open(sys.argv[2], "r") as f:
        patterns = json.load(f)
    patterns = [Pattern(data) for data in patterns]
    print(patterns)


if __name__ == "__main__":
    main()
