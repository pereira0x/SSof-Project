from src.Label import Label


class MultiLabel:
    def __init__(self):
        self.labels = {}
        # relate name of vulnerability to label(s)

    def addLabel(self, vulnerability_name, label):
        if not isinstance(label, Label):
            raise ValueError("Error: not a Label object")

        if vulnerability_name in self.labels:
            self.labels[vulnerability_name] = self.labels[vulnerability_name] + label
        else:
            self.labels[vulnerability_name] = label

    def getLabel(self, vulnerability_name):
        if vulnerability_name not in self.labels:
            return None
        return self.labels[vulnerability_name]

    def __repr__(self):
        return f"MultiLabel | labels: {self.labels}"

    def __add__(self, other):
        if not isinstance(other, MultiLabel):
            raise ValueError("Error: not a MultiLabel object")

        newMultiLabel = MultiLabel()
        for vulnerability_name in self.labels:
            newMultiLabel.addLabel(
                vulnerability_name, self.getLabel(vulnerability_name).deepcopy()
            )
        for vulnerability_name in other.labels:
            newMultiLabel.addLabel(
                vulnerability_name, other.getLabel(vulnerability_name).deepcopy()
            )
        return newMultiLabel

    def deepcopy(self):
        newMultiLabel = MultiLabel()
        for vulnerability_name in self.labels:
            newMultiLabel.addLabel(
                vulnerability_name, self.labels[vulnerability_name].deepcopy()
            )
        return newMultiLabel
