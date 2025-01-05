from MultiLabel import MultiLabel
from Sink import Sink
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

    def getIllegalFlowsByName(self, name):
        return self.vulnerability[name]

    def addIllegalFlow(self, sink, vulnName, multiLabel):
        if isinstance(sink, Sink):
            if isinstance(multiLabel, MultiLabel):
                if vulnName not in self.vulnerability:
                    self.vulnerability[vulnName] = (
                        [sink, multiLabel.getLabel(vulnName)],
                    )
                else:
                    existingFlows = self.vulnerability[vulnName] # [sink, labels[]]
                    labels = multiLabel.getLabel(vulnName)
                    newFlow = [sink, labels]

                    if newFlow not in existingFlows:
                        existSink = False
                        for flow in existingFlows:
                            if flow[0] == sink:
                                flow[1] = flow[1] + labels
                                existSink = True
                                break
                        if not existSink:
                            self.vulnerability[vulnName] = existingFlows + (newFlow,)

            else:
                raise ValueError("Invalid multiLabel")
        else:
            raise ValueError("Invalid sink")

    def __repr__(self):
        return f"Vulnerabilities | vulnerability: {self.vulnerability}"

    def toJSON(self):
        data = self.vulnerability
        result = []

        for key, value in data.items():
            count = 1
            for sink, label in value:
                for source, sanitizers in label.getSourcesSanitizers():
                    done = False
                    for vuln in result:
                        if (
                            vuln["vulnerability"][0] == key
                            and vuln["source"] == [source.getName(), source.getLine()]
                            and vuln["sink"] == [sink.getName(), sink.getLine()]
                        ):
                            if sanitizers == []:
                                vuln["unsanitized_flows"] = "yes"
                            else:
                                vuln["sanitized_flows"].append(
                                    [[x.getName(), x.getLine()] for x in sanitizers]
                                )
                            done = True
                            break
                    if not done:
                        vuln = {
                            "vulnerability": key + "_" + str(count),
                            "source": [source.getName(), source.getLine()],
                            "sink": [sink.getName(), sink.getLine()],
                        }
                        if sanitizers == []:
                            vuln["unsanitized_flows"] = "yes"
                            vuln["sanitized_flows"] = []
                        else:
                            vuln["unsanitized_flows"] = "no"
                            vuln["sanitized_flows"] = [
                                [[x.getName(), x.getLine()] for x in sanitizers]
                            ]
                        result.append(vuln)
                        count += 1

        return result
