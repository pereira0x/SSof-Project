import esprima
import MultiLabelling
from Source import Source
from MultiLabel import MultiLabel
from Label import Label
from Sink import Sink
from esprima import nodes
from Policy import Policy
from Sanitizer import Sanitizer


class Analyser(esprima.NodeVisitor):

    def __init__(self, policy, multiLabelling, vulnerabilities):
        self.policy = policy
        self.multiLabelling = multiLabelling
        self.vulnerabilities = vulnerabilities
        self.functions = []

    def visit_Script(self, node: nodes.Script):
        print("I am visiting a script")
        multiLabellings = [self.multiLabelling]
        for op in node.body:

            if isinstance(op, nodes.ExpressionStatement):
                self.visit_ExpressionStatement(op)

            elif isinstance(op, nodes.AssignmentExpression):
                self.visit_AssignmentExpression(op)
            
            elif isinstance(op, nodes.IfStatement):
                new_multiLabellings = []
                for multiLabelling in multiLabellings:
                    if_multiLabelling, else_exists = self.visit_IFStatement(op, multiLabelling)
                    new_multiLabellings += if_multiLabelling
                if else_exists:
                    multiLabellings = new_multiLabellings
                else:
                    multiLabellings += new_multiLabellings

            else:
                print("Woah, what is this?")

    # TODO: if literal is a function call??
    def visit_Identifier(
        self, node: nodes.Identifier, multiLabelling=None, call: bool = False
    ):
        print("I am visiting an identifier")

        if multiLabelling is None:
            multiLabelling = self.multiLabelling

        source = Source(node.name, node.loc.start.line)

        multiLabel = multiLabelling.getMultiLabelByVarName(node.name)

        # this will handle the case where the variable is not initialized
        # because by default, every variable that is not initialized is
        # a source for every vulnerability
        if multiLabel is None:
            multiLabel = MultiLabel()
            if not call:
                for vuln in self.policy.getVulnerabilities(): 
                    label = Label()
                    label.addSource(source)
                    multiLabel.addLabel(vuln, label)
                return multiLabel
        elif call:
            multiLabel = MultiLabel()

        for vuln in self.policy.getVulnerabilitiesBySource(source):
            pattern = self.policy.getPatternByName(vuln)
            label = Label()
            label.addSource(source)
            multiLabel.addLabel(pattern.vulnerability, label)

        multiLabelling.setMultiLabel(node.name, multiLabel)
        return multiLabel

    def visit_simpleNodes(self, node, multiLabelling=None, multiLabel_cond=None):
        if isinstance(node, nodes.CallExpression):
            m = self.visit_CallExpression(node, multiLabelling, multiLabel_cond)
        elif isinstance(node, nodes.Identifier):
            m = self.visit_Identifier(node, multiLabelling)
        elif isinstance(node, nodes.BinaryExpression):
            m = self.visit_BinOp(node, multiLabelling)
        elif isinstance(node, nodes.StaticMemberExpression):
            m = self.visit_StaticMemberExpression(node, multiLabelling)
        else:
            m = MultiLabel()

        return m

    def visit_CallExpression(self, node: nodes.CallExpression, multiLabelling=None, multiLabel_cond=None):
        print("I am visiting a call expression")
        # a(b,1,2,3)
        if isinstance(node.callee, nodes.StaticMemberExpression):
            functionName = node.callee.property
            multiLabel = self.visit_StaticMemberExpression(node.callee, multiLabelling)
        else:
            functionName = node.callee.name
            multiLabel = self.visit_Identifier(node.callee, multiLabelling, call=True)

        for arg in node.arguments:
            multiLabel += self.visit_simpleNodes(arg, multiLabelling=multiLabelling)
        
        if multiLabel_cond is not None:
            for vulnName in multiLabel_cond.labels:
                if self.policy.getPatternByName(vulnName).isImplicit():
                    label = multiLabel_cond.getLabel(vulnName).deepcopy()
                    multiLabel.addLabel(vulnName, label)
                    
        for vuln in multiLabel.labels:
            if self.policy.getPatternByName(vuln).isSanitizer(functionName):
                sanitizer = Sanitizer(functionName, node.callee.loc.start.line)
                multiLabel.getLabel(vuln).addSanitizer(sanitizer)

        sink = Sink(functionName, node.callee.loc.start.line)
        self.detectIllegalFlows(sink, multiLabel)

        return multiLabel

    def visit_BinOp(self, node: nodes.BinaryExpression, multiLabelling=None):
        print("I am visiting a binary operation")
        multiLabel1 = self.visit_simpleNodes(node.left, multiLabelling=multiLabelling)
        multiLabel2 = self.visit_simpleNodes(node.right, multiLabelling=multiLabelling)

        return multiLabel1 + multiLabel2

    def visit_ExpressionStatement(
        self, node: nodes.ExpressionStatement, multiLabelling=None
    ):
        print("I am visiting an expression statement")
        self.visit(node.expression)

    def visit_AssignmentExpression(
        self, node: nodes.AssignmentExpression, multiLabelling=None, multiLabel_cond=None
    ):
        print("I am visiting an assignment expression")
        """ self.visit(node.right)
        self.visit(node.left) """

        if multiLabelling is None:
            multiLabelling = self.multiLabelling

        # visit right side
        multiLabel = self.visit_simpleNodes(node.right, multiLabelling=multiLabelling)
        
        if multiLabel_cond is not None:
            for vulnName in multiLabel_cond.labels:
                if self.policy.getPatternByName(vulnName).isImplicit():
                    label = multiLabel_cond.getLabel(vulnName).deepcopy()
                    multiLabel.addLabel(vulnName, label)
        
        if multiLabel is not None:
            if isinstance(node.left, nodes.StaticMemberExpression):   # a.b() = something
                propertyName = node.left.property.name
                
                multiLabelProperty = self.visit_StaticMemberExpression(node.left, multiLabelling, True)
                
                multiLabelling.setMultiLabel(propertyName, multiLabel)
                sink = Sink(node.left.object.name, node.left.object.loc.start.line)
                self.detectIllegalFlows(sink, multiLabelProperty + multiLabel)
                
                sink = Sink(propertyName, node.left.loc.start.line)
                self.detectIllegalFlows(sink, multiLabel)
            
            else:
                multiLabelling.setMultiLabel(node.left.name, multiLabel)
                sink = Sink(node.left.name, node.loc.start.line)
                self.detectIllegalFlows(sink, multiLabel)

    def visit_Literal(self, node: nodes.Literal, multiLabelling=None):
        print("I am visiting a literal")
    
    
    def visit_StaticMemberExpression(self, node: nodes.StaticMemberExpression, multiLabelling=None, isAssignTarget=False):
        print("I am visiting a Static Member expression")
        # object.property
        # isAssignTarget true when b.m() = something
        # and isAssignTarget false when something = b.m()
        
        varMultiLabel = MultiLabel() if isAssignTarget else self.visit_simpleNodes(node.object, multiLabelling)
        propertyName = node.property.name
        source = Source(propertyName, node.loc.start.line)
        propertyMultiLabel = multiLabelling.getMultiLabelByVarName(propertyName)
        if propertyMultiLabel is None:
            propertyMultiLabel = MultiLabel()
        
        for vuln in self.policy.getVulnerabilitiesBySource(source):
            pattern = self.policy.getPatternByName(vuln)
            label = Label()
            label.addSource(source)
            propertyMultiLabel.addLabel(pattern.vulnerability, label)
        
        multiLabelling.setMultiLabel(propertyName, propertyMultiLabel)
        
        return varMultiLabel + propertyMultiLabel
      
    def visit_IFStatement(self, node: nodes.IfStatement, multiLabelling=None, multiLabel_cond=None):
        print("I am visiting an if statement")
        
        # multiLabelling_cond = multiLabelling.deepcopy()
        if multiLabelling is None:
            multiLabelling = self.multiLabelling
        
        multiLabelling_cond = multiLabelling.deepcopy()
        
        multiLabel = self.visit_simpleNodes(node.test, multiLabelling=multiLabelling_cond)
        
        if multiLabel_cond is not None:
            multiLabel += multiLabel_cond
        
        if_multiLabellings = [multiLabelling_cond.deepcopy()]
        
        for op in node.consequent.body:
            if isinstance(op, nodes.ExpressionStatement):
              if isinstance(op.expression, nodes.AssignmentExpression):
                print("AHJDHAHDKD")
                for multiLabelling_aux in if_multiLabellings:
                    self.visit_AssignmentExpression(op.expression, multiLabelling_aux, multiLabel)
                    
            elif isinstance(op, nodes.AssignmentExpression):
                for multiLabelling_aux in if_multiLabellings:
                    self.visit_AssignmentExpression(op, multiLabelling_aux, multiLabel)
                  
            elif isinstance(op, nodes.IfStatement):
                new_multiLabellings = []
                for multiLabelling_aux in if_multiLabellings:
                    if_multiLabelling, else_exists = self.visit_IFStatement(op, multiLabelling_aux)
                    new_multiLabellings += if_multiLabelling
                '''
                  if there is not an else statement,
                  we need to account for the multilabels from the if-condition
                '''               
                if else_exists:
                    if_multiLabellings = new_multiLabellings
                else:
                    if_multiLabellings += new_multiLabellings
                    
                # TODO: missing while node
                
        else_multiLabellings = [multiLabelling_cond.deepcopy()]
        else_exists = False
        if node.alternate:
            print("I am visiting an else statement")
            else_exists = True

            for op in node.alternate.body:
                print("IM DETECTING AN OP")
                if isinstance(op, nodes.ExpressionStatement):
                    print("LLLLL")
                    if isinstance(op.expression, nodes.CallExpression):
                        for multiLabelling_aux in else_multiLabellings:
                            self.visit_CallExpression(op.expression, multiLabelling_aux)
                    elif isinstance(op.expression, nodes.AssignmentExpression):
                        print("AHJDHAHDKD")
                        for multiLabelling_aux in else_multiLabellings:
                            self.visit_AssignmentExpression(op.expression, multiLabelling_aux, multiLabel)          
                elif isinstance(op, nodes.AssignmentExpression):
                    print("DJDJDJ")
                    for multiLabelling_aux in else_multiLabellings:
                        self.visit_AssignmentExpression(op, multiLabelling_aux, multiLabel)
                elif isinstance(op, nodes.IfStatement):
                    print("DAJDHAK")
                    new_multiLabellings = []
                    for multiLabelling_aux in else_multiLabellings:
                        if_multiLabelling, else_exists = self.visit_IFStatement(op, multiLabelling_aux)
                        new_multiLabellings += if_multiLabelling
                    '''
                      if there is not an else statement,
                      we need to account for the multilabels from the if-condition
                    '''               
                    if else_exists:
                        else_multiLabellings = new_multiLabellings
                    else:
                        else_multiLabellings += new_multiLabellings
                # TODO: missing while node
                else:
                    print("Woah, what is this?")
                
        return if_multiLabellings + else_multiLabellings, else_exists      

    def detectIllegalFlows(self, sink, multiLabel):

        illegal_multiLabel = self.policy.illegalFlow(sink.name, multiLabel)

        if illegal_multiLabel:
            for vulnName in illegal_multiLabel.labels:
                self.vulnerabilities.addIllegalFlow(sink, vulnName, illegal_multiLabel)
