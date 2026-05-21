# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import sys
from typing import List, Optional

from core.netdsl import ast
from core.netdsl import tokenizer

class Parser:
    def __init__(self, tokens: List[tokenizer.Token]):
        self.tokens = tokens
        self.current = 0
        self.total = len(tokens)


    def peek(self) -> tokenizer.Token:
        if self.current >= self.total:
            return tokenizer.Token(tokenizer.TokenType.EOF, "")
        return self.tokens[self.current]


    def consume(self) -> tokenizer.Token:
        if self.current >= self.total:
            return tokenizer.Token(tokenizer.TokenType.EOF, "")
        tok = self.tokens[self.current]
        self.current += 1
        return tok


    def consume_type(self, token_type: tokenizer.TokenType) -> tokenizer.Token:
        if self.current >= self.total:
            return tokenizer.Token(tokenizer.TokenType.EOF, "")
        
        tok = self.tokens[self.current]
        self.current += 1
        
        if tok.type != token_type:
            print("Tokens don't match", file=sys.stderr)
            sys.exit(1)
            
        return tok


    def _ip_addr_from_str(self, ip_str: str) -> ast.IPAddr:
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                raise ValueError()
            return ast.IPAddr([int(p) for p in parts])
        except ValueError:
            print("Invalid IP address", file=sys.stderr)
            sys.exit(1)

	
    def parse_from_stmt(self) -> ast.FromStmt:
        self.consume()
        
        from_node = self.parse_expr()
        
        if self.peek().type == tokenizer.TokenType.TO:
            self.consume()
            
        to_node = self.parse_expr()
        
        return ast.FromStmt(from_expr=from_node, to_expr=to_node)


    def parse_expr(self) -> Optional[ast.Expr]:
        t = self.peek()
        if t.type == tokenizer.TokenType.EOF:
            return None

        if t.type == tokenizer.TokenType.NUMBER:
            self.consume()
            return ast.LitExpr(value=int(t.lexeme))
            
        elif t.type == tokenizer.TokenType.IP:
            return self.parse_ip_expr()
            
        elif t.type == tokenizer.TokenType.PORT:
            return self.parse_port_expr()
            
        else:
            return None


    def parse_ip_expr(self) -> ast.IPExpr:
        self.consume_type(tokenizer.TokenType.IP)
        ip_token = self.consume_type(tokenizer.TokenType.IPADDR)
        addr = self._ip_addr_from_str(ip_token.lexeme)
        return ast.IPExpr(value=addr)


    def parse_port_expr(self) -> ast.PortExpr:
        return ast.PortExpr(value=3333)

	
if __name__ == "__main__":
    tokens_input = [
        tokenizer.Token(tokenizer.TokenType.UNKNOWN, "from"),
        tokenizer.Token(tokenizer.TokenType.IP, "ip"),
        tokenizer.Token(tokenizer.TokenType.IPADDR, "10.0.0.1"),
        tokenizer.Token(tokenizer.TokenType.TO, "to"),
        tokenizer.Token(tokenizer.TokenType.PORT, "port")
    ]
    
    parser = Parser(tokens_input)
    root_stmt = parser.parse_from_stmt()
    
    print("Parsing pass trace complete.")
    print(f"Statement Node Target Type : {root_stmt.type.name}")
    print(f"  ├─ From Expression Class : {type(root_stmt.from_expr).__name__} (Type: {root_stmt.from_expr.type.name})")
    print(f"  │   └─ Value             : {root_stmt.from_expr.value.octets}")
    print(f"  └─ To Expression Class   : {type(root_stmt.to_expr).__name__} (Type: {root_stmt.to_expr.type.name})")
    print(f"      └─ Value             : {root_stmt.to_expr.value}")