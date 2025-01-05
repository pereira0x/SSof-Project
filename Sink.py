class Sink:
    def __init__(self, name, lineno):
        self.name = name
        self.line = lineno

    def __repr__(self):
        return f"Sink | name: {self.name}: lineno={self.lineno}"
    
    def __eq__(self, other):
        if isinstance(other, Sink):
            return self.name == other.name and self.lineno == other.lineno
        return False