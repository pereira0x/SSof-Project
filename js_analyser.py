import sys
import esprima


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <slice> <patterns>", file=sys.stderr)
        return

    with open(sys.argv[1], "r") as f:
        slice = f.read()

    ast = esprima.parseScript(slice, loc=True).toDict()
    print(ast)

    with open(sys.argv[2], "r") as f:
        patterns = f.read()

    print(patterns)    
if __name__ == "__main__":
    main()
