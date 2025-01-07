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

        for op in node.body:

            if isinstance(op, nodes.ExpressionStatement):
                self.visit_ExpressionStatement(op)

            elif isinstance(op, nodes.AssignmentExpression):
                self.visit_AssignmentExpression(op)

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

    def visit_simpleNodes(self, node, multiLabelling=None):
        if isinstance(node, nodes.CallExpression):
            m = self.visit_CallExpression(node, multiLabelling)
        elif isinstance(node, nodes.Identifier):
            m = self.visit_Identifier(node, multiLabelling)
        elif isinstance(node, nodes.BinaryExpression):
            m = self.visit_BinOp(node, multiLabelling)
        else:
            m = MultiLabel()

        return m

    def visit_CallExpression(self, node: nodes.CallExpression, multiLabelling=None):
        print("I am visiting a call expression")
        # a(b,1,2,3)
        functionName = node.callee.name
        multiLabel = self.visit_Identifier(node.callee, multiLabelling, call=True)

        for arg in node.arguments:
            multiLabel += self.visit_simpleNodes(arg, multiLabelling=multiLabelling)

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
        self, node: nodes.AssignmentExpression, multiLabelling=None
    ):
        print("I am visiting an assignment expression")
        """ self.visit(node.right)
        self.visit(node.left) """

        if multiLabelling is None:
            multiLabelling = self.multiLabelling

        # visit right side
        multiLabel = self.visit_simpleNodes(node.right, multiLabelling=multiLabelling)

        if multiLabel is not None:
            multiLabelling.setMultiLabel(node.left.name, multiLabel)
            sink = Sink(node.left.name, node.loc.start.line)
            self.detectIllegalFlows(sink, multiLabel)

    def visit_Literal(self, node: nodes.Literal, multiLabelling=None):
        print("I am visiting a literal")
    

    def detectIllegalFlows(self, sink, multiLabel):

        illegal_multiLabel = self.policy.illegalFlow(sink.name, multiLabel)

        if illegal_multiLabel:
            for vulnName in illegal_multiLabel.labels:
                self.vulnerabilities.addIllegalFlow(sink, vulnName, illegal_multiLabel)
