#!/usr/bin/env python3
"""
Exonerve :: safe_eval — a tiny boolean/comparison expression evaluator
==========================================================================
A hand-written recursive-descent parser that evaluates the restricted grammar
used by the Sigma and YARA condition engines WITHOUT calling eval().

Why this exists: `eval()` with an emptied __builtins__ is NOT a sandbox — the
`().__class__.__bases__[0].__subclasses__()` trick escapes it. Rather than gate
eval() with a whitelist, we remove eval() entirely so there is no sandbox to
escape and nothing for a scanner to flag. This is elimination, not suppression.

Grammar (precedence low→high):
    expr    := or_expr
    or_expr := and_expr ( 'or' and_expr )*
    and_expr:= not_expr ( 'and' not_expr )*
    not_expr:= 'not' not_expr | comparison
    comparison := sum ( ('<'|'<='|'>'|'>='|'=='|'!=') sum )?
    sum     := term ( ('+'|'-') term )*
    term    := factor ( ('*'|'/'|'%') factor )*
    factor  := NUMBER | 'True' | 'False' | '(' expr ')' | '-' factor

Only booleans and numbers exist. No names, no attributes, no calls, no indexing.
Anything outside the grammar raises SafeEvalError → callers treat as False.
"""
from __future__ import annotations

import re
from typing import List, Tuple, Union

Number = Union[int, float]


class SafeEvalError(ValueError):
    """Raised when the expression is outside the permitted grammar."""


_TOKEN_RE = re.compile(r"""
    \s*(?:
        (?P<num>\d+\.\d+|\d+)
      | (?P<op><=|>=|==|!=|<|>|\+|-|\*|/|%|\(|\))
      | (?P<kw>True|False|and|or|not)
    )
""", re.VERBOSE)


def _tokenize(s: str) -> List[Tuple[str, str]]:
    tokens: List[Tuple[str, str]] = []
    pos = 0
    n = len(s)
    while pos < n:
        if s[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(s, pos)
        if not m:
            raise SafeEvalError(f"illegal token near: {s[pos:pos+16]!r}")
        # advance to end of the matched token (which may include leading ws)
        end = m.end()
        if end == pos:
            raise SafeEvalError(f"no progress at: {s[pos:pos+16]!r}")
        if m.group("num"):
            tokens.append(("num", m.group("num")))
        elif m.group("op"):
            tokens.append(("op", m.group("op")))
        elif m.group("kw"):
            tokens.append(("kw", m.group("kw")))
        else:
            raise SafeEvalError(f"illegal token near: {s[pos:pos+16]!r}")
        pos = end
    return tokens


class _Parser:
    def __init__(self, tokens: List[Tuple[str, str]]):
        self.toks = tokens
        self.i = 0

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def _eat(self, val=None):
        kind, tv = self._peek()
        if kind is None:
            raise SafeEvalError("unexpected end of expression")
        if val is not None and tv != val:
            raise SafeEvalError(f"expected {val!r}, got {tv!r}")
        self.i += 1
        return tv

    def parse(self):
        v = self._or()
        if self.i != len(self.toks):
            raise SafeEvalError("trailing tokens")
        return v

    def _or(self):
        v = self._and()
        while self._peek() == ("kw", "or"):
            self._eat("or")
            r = self._and()
            v = bool(v) or bool(r)
        return v

    def _and(self):
        v = self._not()
        while self._peek() == ("kw", "and"):
            self._eat("and")
            r = self._not()
            v = bool(v) and bool(r)
        return v

    def _not(self):
        if self._peek() == ("kw", "not"):
            self._eat("not")
            return not bool(self._not())
        return self._comparison()

    def _comparison(self):
        left = self._sum()
        kind, tv = self._peek()
        if kind == "op" and tv in ("<", "<=", ">", ">=", "==", "!="):
            self._eat(tv)
            right = self._sum()
            return {"<": left < right, "<=": left <= right, ">": left > right,
                    ">=": left >= right, "==": left == right, "!=": left != right}[tv]
        return left

    def _sum(self):
        v = self._term()
        while True:
            kind, tv = self._peek()
            if kind == "op" and tv in ("+", "-"):
                self._eat(tv)
                r = self._term()
                v = v + r if tv == "+" else v - r
            else:
                return v

    def _term(self):
        v = self._factor()
        while True:
            kind, tv = self._peek()
            if kind == "op" and tv in ("*", "/", "%"):
                self._eat(tv)
                r = self._factor()
                if tv == "*":
                    v = v * r
                elif tv == "/":
                    v = v / r if r != 0 else 0
                else:
                    v = v % r if r != 0 else 0
            else:
                return v

    def _factor(self):
        kind, tv = self._peek()
        if kind == "op" and tv == "-":
            self._eat("-")
            return -self._factor()
        if kind == "op" and tv == "(":
            self._eat("(")
            v = self._or()
            self._eat(")")
            return v
        if kind == "num":
            self._eat()
            return float(tv) if "." in tv else int(tv)
        if kind == "kw" and tv in ("True", "False"):
            self._eat()
            return tv == "True"
        raise SafeEvalError(f"unexpected token {tv!r}")


def safe_eval_bool(expr: str) -> bool:
    """Evaluate a restricted boolean/comparison expression. Returns bool.
    Raises SafeEvalError on anything outside the grammar (callers treat as False)."""
    tokens = _tokenize(expr)
    if not tokens:
        raise SafeEvalError("empty expression")
    return bool(_Parser(tokens).parse())


if __name__ == "__main__":
    ok = [("True and False", False), ("(True or False) and not False", True),
          ("12345 < 1024", False), ("2.5 > 1.0 and True", True),
          ("1 + 2 == 3", True), ("not (True and True)", False)]
    for e, exp in ok:
        got = safe_eval_bool(e)
        print(f"  {e:35} -> {got}  {'OK' if got == exp else 'FAIL'}")
    for bad in ["().__class__", "__import__('os')", "open('x')", "a and b", "1;2"]:
        try:
            safe_eval_bool(bad); print(f"  {bad:35} -> NOT REJECTED (BUG)")
        except SafeEvalError:
            print(f"  {bad:35} -> rejected OK")
