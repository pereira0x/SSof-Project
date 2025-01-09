class Symbol:
    def __init__(self, name, lineno):
        self.name = name
        self.lineno = lineno

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.name == other.name and self.lineno == other.lineno
        return False

    def __repr__(self):
        return f"{self.__class__.__name__} | name: {self.name}: lineno={self.lineno}"
