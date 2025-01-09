from src.MultiLabel import MultiLabel


class MultiLabelling:
    def __init__(self):
        self.multiLabels = {}
        # map variable name to MultiLabel(s)

    def getMultiLabelByVarName(self, varName):
        if varName not in self.multiLabels:
            return None
        return self.multiLabels[varName]

    def setMultiLabel(self, varName, multiLabel):
        if not isinstance(multiLabel, MultiLabel):
            raise ValueError("Error: not a MultiLabel object")

        self.multiLabels[varName] = multiLabel

    def __repr__(self):
        return f"MultiLabelling | multiLabels: {self.multiLabels}"

    def __add__(self, other):
        if not isinstance(other, MultiLabelling):
            raise ValueError("Error: not a MultiLabelling object")

        newMultiLabelling = MultiLabelling()
        for varName in self.multiLabels:
            newMultiLabelling.setMultiLabel(
                varName, self.getMultiLabelByVarName(varName).deepcopy()
            )
        for varName in other.multiLabels:
            if varName in newMultiLabelling.multiLabels:
                newMultiLabelling.setMultiLabel(
                    varName,
                    newMultiLabelling.getMultiLabelByVarName(varName)
                    + other.getMultiLabelsByVarName(varName),
                )
            else:
                newMultiLabelling.setMultiLabel(
                    varName, other.getMultiLabelsByVarName(varName).deepcopy()
                )
        return newMultiLabelling

    def deepcopy(self):
        newMultiLabelling = MultiLabelling()
        for varName in self.multiLabels:
            newMultiLabelling.setMultiLabel(
                varName, self.multiLabels[varName].deepcopy()
            )
        return newMultiLabelling
