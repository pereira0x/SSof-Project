import esprima
import MultiLabelling


class Analyser(esprima.NodeVisitor):

    def __init__(self, policy, multiLabelling, vulnerabilities):
        self.policy = policy
        self.multiLabelling = multiLabelling
        self.vulnerabilities = vulnerabilities
        self.functions = []

    # TODO: if literal is a function call??
    
    def visit_Program(self, node):
        print("I am visiting a program")
    
    def visit_Identifier(self, node, multilabeling=None):
      print("I am visiting an identifier woooaahhh")
    
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
    
      
        
    def run(self, node):
        print("I am running the analyser")
        self.visit(node)
        return self.vulnerabilities