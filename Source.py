from Symbol import Symbol


class Source(Symbol):
    def __repr__(self):
        return f"Source | name: {self.name}: lineno={self.lineno}"
