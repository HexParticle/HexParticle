import ply.yacc as yacc
from .lexer import tokens
from .ast_nodes import Endpoint, FilterStatement, WhereClause, Condition, ConditionList


def p_statement_root(p):
    '''statement : FROM endpoint TO endpoint
                 | FROM endpoint TO endpoint where_clause'''
    if len(p) == 6:
        p[0] = FilterStatement(source=p[2], destination=p[4], where_clause=p[5])
    else:
        p[0] = FilterStatement(source=p[2], destination=p[4])


def p_endpoint_ip_and_port(p):
    '''
    endpoint : IP_ADDRESS COLON NUMBER
    '''
    p[0] = Endpoint(ip=p[1], mac=None, port=p[3])
    

def p_endpoint_ip_and_mac(p):
    '''
    endpoint : IP_ADDRESS AT MAC_ADDRESS
    '''
    p[0] = Endpoint(ip=p[1], mac=p[3], port=None)


def p_endpoint_ip_port_and_mac(p):
    '''
    endpoint : IP_ADDRESS COLON NUMBER AT MAC_ADDRESS
    '''
    p[0] = Endpoint(ip=p[1], port=p[3], mac=p[5])


def p_endpoint_ip_only(p):
    '''
    endpoint : IP_ADDRESS
    '''
    p[0] = Endpoint(ip=p[1], mac=None, port=None)


def p_endpoint_mac_only(p):
    '''
    endpoint : MAC_ADDRESS
    '''
    p[0] = Endpoint(mac=p[1], ip=None, port=None)


def p_condition(p):
    '''
    condition : FIELD OPERATOR VALUE
                | FIELD OPERATOR NUMBER
    '''
    p[0] = Condition(field=p[1], operator=p[2], value=p[3])


def p_condition_list(p):
    '''
    condition_list : condition 
                    | condition_list COMMA condition
    '''
    if len(p) == 4:
        p[0] = ConditionList(conditions=p[1] + [p[3]])
    else:
        p[0] = ConditionList(conditions=[p[1]])


def p_where_clause(p):
    '''
    where_clause : WHERE condition_list
    '''
    p[0] = WhereClause(condition_list=p[2])


def p_error(p):
    if p:
        print(f"Syntax error at token {p.type} (Value: {p.value})")
    else:
        print("Syntax error: Unexpected end of input")


_parser = yacc.yacc()

def parse(input: str):
    return _parser.parse(input)