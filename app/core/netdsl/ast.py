# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Union

class BinExprType(Enum):
    AND = auto()


class ExprType(Enum):
    BIN = auto()
    LIT = auto()
    IP = auto()
    PORT = auto()


class StmtType(Enum):
    FROM = auto()


@dataclass
class IPAddr:
    octets: List[int] = field(default_factory=lambda: [0, 0, 0, 0])

    def __post_init__(self):
        if len(self.octets) != 4 or any(not (0 <= o <= 255) for o in self.octets):
            raise ValueError("IPAddr octets must be exactly 4 elements bounded between 0 and 255.")


class Expr:
    type: ExprType


@dataclass
class IPExpr(Expr):
    value: IPAddr
    type: ExprType = ExprType.IP


@dataclass
class PortExpr(Expr):
    value: int  # Mimics uint16_t
    type: ExprType = ExprType.PORT

    def __post_init__(self):
        if not (0 <= self.value <= 65535):
            raise ValueError("Port value must be a valid uint16_t (0-65535).")


@dataclass
class LitExpr(Expr):
    value: int
    type: ExprType = ExprType.LIT


@dataclass
class BinExpr(Expr):
    lhs: Expr
    rhs: Expr
    bin_type: BinExprType
    type: ExprType = ExprType.BIN


class Stmt:
    type: StmtType


@dataclass
class FromStmt(Stmt):
    from_expr: Union[Expr, None]
    to_expr: Union[Expr, None]
    type: StmtType = StmtType.FROM


if __name__ == "__main__":
    ip_node = IPExpr(value=IPAddr([192, 168, 1, 1]))
    port_node = PortExpr(value=80)
    
    logical_and_tree = BinExpr(
        lhs=ip_node,
        rhs=port_node,
        bin_type=BinExprType.AND
    )
    
    statement_ast = FromStmt(from_expr=logical_and_tree, to_expr=None)
    
    print("AST Generated cleanly with Python 3.9 Types:")
    print(f"Statement Type Tag: {statement_ast.type.name}")
    print(f"LHS Expression Tag : {statement_ast.from_expr.type.name}")
    if isinstance(statement_ast.from_expr, BinExpr):
        print(f"  └─ Binary Operation: {statement_ast.from_expr.bin_type.name}")
        print(f"  └─ LHS Inner Class : {type(statement_ast.from_expr.lhs).__name__}")
        print(f"  └─ RHS Inner Class : {type(statement_ast.from_expr.rhs).__name__}")