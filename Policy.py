from MultiLabel import MultiLabel
from Pattern import Pattern
from Source import Source
from Sink import Sink
from Sanitizer import Sanitizer

class Policy:
    def __init__(self, patterns):
        for pattern in patterns:
            if (not isinstance(pattern, Pattern)):
                raise ValueError("Invalid pattern")
        self.patterns = patterns
                

    def getVulnerabilities(self):
        vulnerabilities = []
        for pattern in self.patterns:
            vulnerabilities += [pattern.vulnerability]
        return vulnerabilities
    
    
    def getPatternByName(self, name):
        for pattern in self.patterns:
            if (pattern.vulnerability == name):
                return pattern
        return None
    
    def getVulnerabilitiesBySource(self, source):
        if (isinstance(source, Source)):
            vulnerabilities = []
            for pattern in self.patterns:
                if (pattern.isSource(source.name)):
                    vulnerabilities += [pattern.vulnerability]
            return vulnerabilities
        else:
            raise ValueError("Invalid Source")
    
    def getVulnerabilitiesBySanitizer(self, sanitizer):
        if (isinstance(sanitizer, Sanitizer)):
            vulnerabilities = []
            for pattern in self.patterns:
                if (pattern.isSanitizer(sanitizer.name)):
                    vulnerabilities += [pattern.vulnerability]
            return vulnerabilities
        else:
            raise ValueError("Invalid Sanitizer")
    
    def getVulnerabilitiesBySink(self, sink):
        if (isinstance(sink, Sink)):
            vulnerabilities = []
            for pattern in self.patterns:
                if (pattern.isSink(sink.name)):
                    vulnerabilities += [pattern.vulnerability]
            return vulnerabilities
        else:
            raise ValueError("Invalid Sink")
    
    def illegalFlow(self, sinkName, multiLabel):
        """
        Returns the MultiLabel that contains only the labels (source, sanitizers[]) 
        of the vulnerabilities that are illegal flows to the sink
        """
        if(isinstance(multiLabel, MultiLabel)):
            newMultiLabel = MultiLabel()
            for pattern in self.patterns:
                if (pattern.isSink(sinkName)):
                    m = multiLabel.getLabel(pattern.vulnerability)
                    if (m is not None):
                        newMultiLabel.addLabel(pattern.vulnerability, m)
            return newMultiLabel
        else:
            raise ValueError("Invalid multiLabel")