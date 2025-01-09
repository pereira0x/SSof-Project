import copy
from src.Source import Source
from src.Sanitizer import Sanitizer


class Label:
    def __init__(self):
        self.source_sanitizers = []
        self.is_implicit = False

    def addSourceSanitizers(self, source, sanitizers):
        if not self.hasSourceSanitizers((source, sanitizers)):
            self.source_sanitizers.append((source, sanitizers))

    def hasSourceSanitizers(self, ss):
        return ss in self.source_sanitizers

    def addSource(self, source):
        if not isinstance(source, Source):
            raise ValueError("Error: not a Source object")

        if not self.hasSourceSanitizers((source, [])):
            self.source_sanitizers.append((source, []))

    def addSanitizer(self, sanitizer):
        # add the sanitizer to all source_sanitizer pairs
        if not isinstance(sanitizer, Sanitizer):
            raise ValueError("Error: not a Sanitizer object")

        for ss in self.source_sanitizers:
            (source, sanitizers) = ss
            if sanitizer not in sanitizers:
                #  remove duplicates (if its hard to understand, use a whiteboard, trust me)
                #  self.source_sanitizers = [(1,[2,3]), (1,[2])]
                #  Add sanitizer 3
                #  [(1,[2,3]), (1,[2,3])] would be also incorrect
                #  [(1,[2,3])] is correct  - needed to remove the duplicate
                if (source, sanitizers + [sanitizer]) not in self.source_sanitizers:
                    sanitizers.append(sanitizer)
                else:
                    self.source_sanitizers.remove(ss)

    def __repr__(self):
        return f"Label | source_sanitizers: {self.source_sanitizers} | is_implicit: {self.is_implicit}"

    def __add__(self, other):
        newLabel = Label()
        otherSourceSanitizers = list(
            filter(lambda ss: not self.hasSourceSanitizers(ss), other.source_sanitizers)
        )
        newLabel.source_sanitizers = copy.deepcopy(
            self.source_sanitizers + otherSourceSanitizers
        )
        newLabel.is_implicit = self.is_implicit or other.is_implicit
        return newLabel

    def __eq__(self, other):
        if isinstance(other, Label):
            for ss in other.source_sanitizers:
                if ss not in self.source_sanitizers:
                    return False
            for ss in self.source_sanitizers:
                if ss not in other.source_sanitizers:
                    return False
            return True
        return False

    def deepcopy(self):
        newLabel = Label()
        newLabel.source_sanitizers = copy.deepcopy(self.source_sanitizers)
        newLabel.is_implicit = self.is_implicit
        return newLabel
