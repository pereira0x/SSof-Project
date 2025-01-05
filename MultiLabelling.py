from MultiLabel import MultiLabel


class MultiLabelling:
    def __init__(self):
        self.multiLabels = {}
        # map variable name to MultiLabel(s)

    def getMultiLabelsByVarName(self, varName):
        if varName not in self.multiLabels:
            return None
        return self.multiLabels[varName]

    def setMultiLabel(self, varName, multiLabel):
        if isinstance(multiLabel, MultiLabel):
            self.multiLabels[varName] = multiLabel
        else:
            raise ValueError("Invalid multiLabel")
        
    def __repr__(self):
            return f"MultiLabelling | multiLabels: {self.multiLabels}"
        
    def __add__(self, other):
        if isinstance(other, MultiLabelling):
            newMultiLabelling = MultiLabelling()
            for varName in self.multiLabels:
                newMultiLabelling.setMultiLabel(
                    varName, self.getMultiLabelsByVarName(varName).deepcopy()
                )
            for varName in other.multiLabels:
                if varName in newMultiLabelling.multiLabels:
                    newMultiLabelling.setMultiLabel(
                        varName,
                        newMultiLabelling.getMultiLabelsByVarName(varName)
                        + other.getMultiLabelsByVarName(varName),
                    )
                else:
                    newMultiLabelling.setMultiLabel(
                        varName, other.getMultiLabelsByVarName(varName).deepcopy()
                    )
            return newMultiLabelling
        else:
            raise ValueError("Invalid multiLabel")

    def deepcopy(self):
        newMultiLabelling = MultiLabelling()
        for varName in self.multiLabels:
            newMultiLabelling.setMultiLabel(varName, self.multiLabels[varName].deepcopy())
        return newMultiLabelling
