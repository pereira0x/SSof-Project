from src.MultiLabel import MultiLabel
from src.Pattern import Pattern
from src.Source import Source
from src.Sink import Sink
from src.Sanitizer import Sanitizer


class Policy:
    def __init__(self, patterns):
        for pattern in patterns:
            if not isinstance(pattern, Pattern):
                raise ValueError("Error: not a Pattern object")
        self.patterns = patterns

    def getAllVulnerabilities(self):
        vulns = []
        for pattern in self.patterns:
            vulns += [pattern.vulnerability]
        return vulns

    def getPatternByName(self, name):
        for pattern in self.patterns:
            if pattern.vulnerability == name:
                return pattern
        return None

    def getAllVulnerabilitiesBySource(self, source):
        if not isinstance(source, Source):
            raise ValueError("Error: not a Source object")

        vulns = []
        for pattern in self.patterns:
            if pattern.isSource(source.name):
                vulns += [pattern.vulnerability]
        return vulns

    def getAllVulnerabilitiesBySanitizer(self, sanitizer):
        if not isinstance(sanitizer, Sanitizer):
            raise ValueError("Error: not a Sanitizer object")

        vulns = []
        for pattern in self.patterns:
            if pattern.isSanitizer(sanitizer.name):
                vulns += [pattern.vulnerability]
        return vulns

    def getAllVulnerabilitiesBySink(self, sink):
        if not isinstance(sink, Sink):
            raise ValueError("Error: not a Sink object")

        vulns = []
        for pattern in self.patterns:
            if pattern.isSink(sink.name):
                vulns += [pattern.vulnerability]
        return vulns

    def illegalInformationFlow(self, sinkName, multiLabel):
        """
        Returns a MultiLabel object that contains only the labels (source, sanitizers[])
        of the vulnerabilities that are illegal flows to the sink.
        """
        if not isinstance(multiLabel, MultiLabel):
            raise ValueError("Error: not a MultiLabel object")

        newMultiLabel = MultiLabel()
        for pattern in self.patterns:
            if pattern.isSink(sinkName):
                label = multiLabel.getLabel(pattern.vulnerability)
                if label is not None:
                    newMultiLabel.addLabel(pattern.vulnerability, label)

        return newMultiLabel

    def __repr__(self):
        return f"Policy | patterns: {self.patterns}"
