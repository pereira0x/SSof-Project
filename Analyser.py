import esprima
import MultiLabelling
from esprima import nodes

class Analyser(esprima.NodeVisitor):

    def __init__(self, policy, multiLabelling, vulnerabilities):
        self.policy = policy
        self.multiLabelling = multiLabelling
        self.vulnerabilities = vulnerabilities
        self.functions = []

    # TODO: if literal is a function call??

    def visit_Script(self, node: nodes.Script):
        print("I am visiting a script")

        for op in node.body:

            if isinstance(op, nodes.ExpressionStatement):
                self.visit_ExpressionStatement(op)

            elif isinstance(op, nodes.AssignmentExpression):
                self.visit_AssignmentExpression(op)

            else:
                print("Woah, what is this?")

    def visit_Identifier(self, node: nodes.Identifier):
        print("I am visiting an identifier")

    def visit_simpleNodes(self, node):
        if isinstance(node, nodes.CallExpression):
            self.visit_CallExpression(node)
        elif isinstance(node, nodes.ExpressionStatement):
            self.visit_ExpressionStatement(node)
        elif isinstance(node, nodes.AssignmentExpression):
            self.visit_AssignmentExpression(node)
        elif isinstance(node, nodes.Literal):
            self.visit_Literal(node)
        elif isinstance(node, nodes.Identifier):
            self.visit_Identifier(node)
        else:
            print("Unknown node type: " + str(type(node)))

    def visit_CallExpression(self, node: nodes.CallExpression):
        print("I am visiting a call expression")
        self.visit(node.callee)
        for arg in node.arguments:
            self.visit(arg)

    def visit_ExpressionStatement(self, node: nodes.ExpressionStatement):
        print("I am visiting an expression statement")
        self.visit(node.expression)

    def visit_AssignmentExpression(self, node: nodes.AssignmentExpression):
        print("I am visiting an assignment expression")
        self.visit(node.right)
        self.visit(node.left)

    def visit_Literal(self, node: nodes.Literal):
        print("I am visiting a literal")
