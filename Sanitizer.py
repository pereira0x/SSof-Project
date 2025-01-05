class Sanitizer:
    def __init__(self, name, lineno):
        self.name = name
        self.lineno = lineno

    def __repr__(self):
        return f"Sanitizer | name: {self.name}: lineno={self.lineno}"

    def __eq__(self, other):
        if isinstance(other, Sanitizer):
            return self.name == other.name and self.lineno == other.lineno
        return False
