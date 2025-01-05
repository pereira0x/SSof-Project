import sys

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <slice> <patterns>", file=sys.stderr)
        return

    with open(sys.argv[1], "r") as f:
        slice = f.read()

if __name__ == "__main__":
    main()
