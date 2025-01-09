from Symbol import Symbol


class Sink(Symbol):
    def __repr__(self):
        return f"Sink | name: {self.name}: lineno={self.lineno}"
