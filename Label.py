import copy
from Source import Source
from Sanitizer import Sanitizer


class Label:

    def __init__(self):
        self.source_sanitizers = []

    def addSourceSanitizers(self, source, sanitizers):
        if not self.hasSourceSanitizers((source, sanitizers)):
            self.source_sanitizers.append((source, sanitizers))

    def hasSourceSanitizers(self, ss):
        return ss in self.source_sanitizers

    def addSource(self, source):
        if isinstance(source, Source):
            if not self.hasSourceSanitizers((source, [])):
                self.source_sanitizers.append((source, []))
        else:
            raise ValueError("Invalid source")

    def addSanitizer(self, sanitizer):
        # add the sanitizer to all source_sanitizer pairs
        if isinstance(sanitizer, Sanitizer):
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
        else:
            raise ValueError("Invalid sanitizer")

    def __repr__(self):
        return f"Label | source_sanitizers: {self.source_sanitizers}"

    def __add__(self, other):
        newLabel = Label()
        otherSourceSanitizers = list(
            filter(lambda ss: not self.hasSourceSanitizers(ss), other.source_sanitizers)
        )
        newLabel.source_sanitizers = copy.deepcopy(
            self.source_sanitizers + otherSourceSanitizers
        )
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
        return newLabel
