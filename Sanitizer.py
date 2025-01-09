from Symbol import Symbol


class Sanitizer(Symbol):
    def __repr__(self):
        return f"Sanitizer | name: {self.name}: lineno={self.lineno}"
