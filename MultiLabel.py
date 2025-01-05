from Label import Label
from Pattern import Pattern

class MultiLabel:
    
    def __init__(self):
        self.labels = {}
        # relate name of vulnerability to label(s)
            
    def addLabel(self, vulnerability_name, label):
        if(isinstance(label, Label)):
            if(vulnerability_name in self.labels):
                self.labels[vulnerability_name] = self.labels[vulnerability_name] + label
            else:
                self.labels[vulnerability_name] = label
        else:
            raise ValueError("Invalid label")
        
    def getLabel(self, vulnerability_name):
        if(vulnerability_name not in self.labels):
            return None
        return self.labels[vulnerability_name]

    def __repr__(self):
        return f"MultiLabel | labels: {self.labels}"
    
    def __add__(self, other):
        if(isinstance(other, MultiLabel)):
            newMultiLabel = MultiLabel()
            for vulnerability_name in self.labels:
                newMultiLabel.addLabel(vulnerability_name, self.getLabel(vulnerability_name).deepcopy())
            for vulnerability_name in other.labels:
                newMultiLabel.addLabel(vulnerability_name, other.getLabel(vulnerability_name).deepcopy())
            return newMultiLabel
        else:
            raise ValueError("Invalid multiLabel")
        
    def deepcopy(self):
        newMultiLabel = MultiLabel()
        for vulnerability_name in self.labels:
            newMultiLabel.addLabel(vulnerability_name, self.labels[vulnerability_name].deepcopy())
        return newMultiLabel