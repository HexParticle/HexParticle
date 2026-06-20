import ply.lex as lex

tokens = (
    'FROM', 'TO', 'WHERE',
    'IP_ADDRESS', 'NUMBER',
    'FIELD', 'OPERATOR', 'VALUE',
    'COLON', 'DOT', 'COMMA',
    'MAC_ADDRESS', 'AT',
    'AND', 'OR'
)


t_COLON = r':'
t_DOT = r'\.'
t_AT = r'\@'
t_OPERATOR = r'!=|>=|<=|=|<|>'
t_COMMA = r','
t_AND = r'and'
t_OR = r'or'


reserved = {
    'FROM': 'FROM',
    'TO': 'TO',
    'WHERE': 'WHERE'
}


def t_IP_ADDRESS(t):
    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    return t


def t_MAC_ADDRESS(t):
    r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
    return t


def t_NUMBER(t):
    r'\d{1,5}'
    t.value = int(t.value)
    return t


def t_FIELD(t):
    r'[A-Za-z_][A-Za-z0-9_\.]*'
    t.type = reserved.get(t.value, 'FIELD')
    return t


def t_VALUE(t):
    r'\'[^\']*\''
    if t.value.startswith("'") and t.value.endswith("'"):
        t.value = t.value[1:-1]
    return t


t_ignore = ' \t\n\r'


def t_error(t):
    print(f"Illegal character '{t.value[0]}' at position {t.lexpos}")
    t.lexer.skip(1)


# Build the lexer
lexer = lex.lex()