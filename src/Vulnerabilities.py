from src.MultiLabel import MultiLabel
from src.Sink import Sink
import json


class Vulnerabilities:
    def __init__(self):
        self.vulnerability = {}
        # maps name of vulnerability to the illegal flow (sink, labels[])

        """
        vul1: (sink1, [l1, l2, l3]), vul2: (sink2, [l4, l5, l6])
        
        want to add vul1: (sink1, [l7])
        
        vul1: (sink1, [l1, l2, l3, l7]), vul2: (sink2, [l4, l5, l6])
        
        because sink1 already exists, add l7 to the existing sink1 and do not create a new flow
        
        """

    def getIllegalInformationFlowsByName(self, name):
        return self.vulnerability[name]

    def addIllegalInformationFlow(self, sink, vulnName, multiLabel):
        if not isinstance(multiLabel, MultiLabel):
            raise ValueError("Error: not a MultiLabel object")

        if not isinstance(sink, Sink):
            raise ValueError("Error: not a Sink object")

        if vulnName in self.vulnerability:
            currentFlows = self.vulnerability[vulnName]  # [sink, labels[]]
            labels = multiLabel.getLabel(vulnName)
            newFlow = [sink, labels]

            if newFlow not in currentFlows:
                foundSink = False
                for currentFlow in currentFlows:
                    if currentFlow[0] == sink:
                        currentFlow[1] = currentFlow[1] + labels
                        foundSink = True
                        break
                if not foundSink:
                    self.vulnerability[vulnName] = currentFlows + (newFlow,)
        else:
            self.vulnerability[vulnName] = ([sink, multiLabel.getLabel(vulnName)],)

    def __repr__(self):
        return f"Vulnerabilities | vulnerability: {self.vulnerability}"

    def jsonify(self):
        result = []

        for key, value in self.vulnerability.items():
            count = 1
            for sink, label in value:
                for source, sanitizers in label.source_sanitizers:
                    vuln = next(
                        (
                            v
                            for v in result
                            if v["vulnerability"][0] == key
                            and v["source"] == [source.name, source.lineno]
                            and v["sink"] == [sink.name, sink.lineno]
                        ),
                        None,
                    )
                    if vuln:
                        if not sanitizers:
                            vuln["unsanitized_flows"] = "yes"
                        else:
                            vuln["sanitized_flows"].append(
                                [
                                    [sanitizer.name, sanitizer.lineno]
                                    for sanitizer in sanitizers
                                ]
                            )
                    else:
                        vuln = {
                            "vulnerability": key + "_" + str(count),
                            "source": [source.name, source.lineno],
                            "sink": [sink.name, sink.lineno],
                            "implicit": "no" if not label.is_implicit else "yes",
                        }
                        if not sanitizers:
                            vuln["unsanitized_flows"] = "yes"
                            vuln["sanitized_flows"] = []
                        else:
                            vuln["unsanitized_flows"] = "no"
                            vuln["sanitized_flows"] = [
                                [
                                    [sanitizer.name, sanitizer.lineno]
                                    for sanitizer in sanitizers
                                ]
                            ]
                        result.append(vuln)
                        count += 1

        return result
