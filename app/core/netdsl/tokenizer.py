# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from enum import Enum, auto
import dataclasses

class TokenType(Enum):
    UNKNOWN = 	auto()
    EOF = 		auto()
    ARROW = 	auto()
    MACADDR = 	auto()
    IPADDR = 	auto()
    NUMBER = 	auto()
    FROM = 		auto()
    TO = 		auto()
    AND = 		auto()
    IP = 		auto()
    PORT = 		auto()
    MAC = 		auto()


KEYWORDS = {
    "from": TokenType.FROM,
    "to": TokenType.TO,
    "and": TokenType.AND,
    "ip": TokenType.IP,
    "port": TokenType.PORT,
    "mac": TokenType.MAC
}


@dataclasses.dataclass
class Token:
    type: TokenType = TokenType.UNKNOWN
    lexeme: str = ""


class Tokenizer:
    def __init__(self, input_text: str):
        self.input = input_text
        self.cursor = 0
        self.length = len(input_text)


    def _is_network_char(self, c: str) -> bool:
        return c.isalnum() or c == '.' or c == ':'


    def next_token(self) -> Token:
        while self.cursor < self.length and self.input[self.cursor].isspace():
            self.cursor += 1

        if self.cursor >= self.length:
            return Token(TokenType.EOF, "")

        current_slice = self.input[self.cursor:]

        if current_slice.startswith("->"):
            self.cursor += 2
            return Token(TokenType.ARROW, "->")

        start_char = current_slice[0]
        if self._is_network_char(start_char):
            lexeme_chars = []
            has_dot = False
            has_colon = False
            has_alpha = False

            while (self.cursor < self.length and 
                   self._is_network_char(self.input[self.cursor])):
                char = self.input[self.cursor]
                
                if char == '.': 
                    has_dot = True
                elif char == ':': 
                    has_colon = True
                elif char.isalpha(): 
                    has_alpha = True
                
                lexeme_chars.append(char)
                self.cursor += 1

            lexeme = "".join(lexeme_chars)

            if has_colon:
                token_type = TokenType.MACADDR
            elif has_dot:
                token_type = TokenType.IPADDR
            elif has_alpha:
                token_type = KEYWORDS.get(lexeme, TokenType.UNKNOWN)
            else:
                token_type = TokenType.NUMBER

            return Token(token_type, lexeme)

        unknown_char = self.input[self.cursor]
        self.cursor += 1
        return Token(TokenType.UNKNOWN, unknown_char)
    

    def tokenize(self):
        tokens = []
        while True:
            token = self.next_token()

            if token:
                tokens.append(token)

            if token.type == TokenType.EOF:
                break
        
        return tokens



if __name__ == "__main__":
    source_dsl = "from 192.168.1.1 and mac 00:11:22:33:44:55 -> to port 80"
    
    tokenizer = Tokenizer(source_dsl)
    print(f"Tokenizing string: \"{source_dsl}\"\n" + "-" * 50)
    
    while True:
        token = tokenizer.next_token()
        print(f"[{token.type.name:<8}] -> \"{token.lexeme}\"")
        if token.type == TokenType.EOF:
            break