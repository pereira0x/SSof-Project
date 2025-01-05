class Source:
    def __init__(self, name, lineno):
        self.name = name
        self.lineno = lineno

    def __repr__(self):
        return f"Source | name: {self.name}: lineno={self.lineno}"

    def __eq__(self, other):
        if isinstance(other, Source):
            return self.name == other.name and self.lineno == other.line
        return False
