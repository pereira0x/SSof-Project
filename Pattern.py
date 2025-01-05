class Pattern:
    def __init__(self, data):
        self.vulnerability = data["vulnerability"]
        self.sources = data["sources"]
        self.sanitizers = data["sanitizers"]
        self.sinks = data["sinks"]
        self.implicit = data["implicit"]
        
        
    def isSource(self, name):
        return name in self.sources
    
    def isSanitizer(self, name):
        return name in self.sanitizers
    
    def isSink(self, name):
        return name in self.sinks
        
    def isImplicit(self):
        return self.implicit == "yes"
    
    def __repr__(self):
        return f"Pattern | vulnerability: {self.vulnerability}: sources={self.sources} sanitizers={self.sanitizers} s__repr__ink={self.sinks} implicit={self.implicit}"

    def __eq__(self, other):
        return (
            self.vulnerability == other.vulnerability
            and self.sources == other.sources
            and self.sanitizers == other.sanitizers
            and self.sinks == other.sinks
        )
