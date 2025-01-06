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

    def visit_Script(self, node):
        print("I am visiting a script")

        for op in node.body:

            if isinstance(op, nodes.ExpressionStatement):
                self.visit_ExpressionStatement(op)

            elif isinstance(op, nodes.AssignmentExpression):
                self.visit_AssignmentExpression(op)

            else:
                print("Woah, what is this?")

    def visit_Identifier(self, node):
        print("I am visiting an identifier")

    def visit_CallExpression(self, node):
        print("I am visiting a call expression")

    def visit_ExpressionStatement(self, node):
        print("I am visiting an expression statement")

    def visit_AssignmentExpression(self, node):
        print("I am visiting an assignment expression")

    def visit_Literal(self, node):
        print("I am visiting a literal")

    def visit_Program(self, node):
        print("I am visiting a program")
