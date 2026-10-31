"""Safe, deterministic expression evaluator for rule conditions.

Rule conditions are parsed with ``ast`` and interpreted against a strict
node whitelist. No attribute access, no arbitrary calls, no ``eval``.
"""

from __future__ import annotations

import ast
import operator
from datetime import datetime, timezone
from typing import Any, Callable

MAX_NODES = 200


class ExpressionError(ValueError):
    """Raised for unsafe, malformed or unevaluable expressions."""


_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}
_CMP = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}


def _to_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    raise ExpressionError(f"cannot interpret {value!r} as a date")


def make_functions(now: datetime) -> dict[str, Callable[..., Any]]:
    def age_days(value: Any) -> float:
        return (now - _to_datetime(value)).total_seconds() / 86400.0

    return {
        "len": len,
        "any": any,
        "all": all,
        "sum": sum,
        "min": min,
        "max": max,
        "abs": abs,
        "exists": lambda v: v is not None and v != "" and v != [],
        "age_days": age_days,
        "split": lambda s, sep: str(s).split(sep),
        "lower": lambda s: str(s).lower(),
        "int": int,
        "get": lambda d, k, default=None: d.get(k, default),
    }


_FUNC_NAMES = frozenset(make_functions(datetime.now(timezone.utc)))


def validate(expression: str) -> ast.Expression:
    try:
        tree = ast.parse(expression.strip(), mode="eval")
    except SyntaxError as exc:
        raise ExpressionError(f"syntax error: {exc.msg}") from exc
    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_NODES:
        raise ExpressionError("expression too complex")
    allowed = (
        ast.Expression,
        ast.BoolOp,
        ast.And,
        ast.Or,
        ast.UnaryOp,
        ast.Not,
        ast.USub,
        ast.BinOp,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Compare,
        ast.Name,
        ast.Load,
        ast.Store,
        ast.Constant,
        ast.Subscript,
        ast.Call,
        ast.List,
        ast.Tuple,
        ast.IfExp,
        ast.ListComp,
        ast.GeneratorExp,
        ast.comprehension,
    ) + tuple(_CMP)
    for node in nodes:
        if not isinstance(node, allowed):
            raise ExpressionError(f"disallowed syntax: {type(node).__name__}")
        if isinstance(node, ast.Call) and (not isinstance(node.func, ast.Name) or node.keywords):
            raise ExpressionError("only plain calls to whitelisted functions are allowed")
        if isinstance(node, ast.Call) and node.func.id not in _FUNC_NAMES:  # type: ignore[attr-defined]
            raise ExpressionError(f"function '{node.func.id}' is not allowed")  # type: ignore[attr-defined]
    return tree


def evaluate(expression: str, variables: dict[str, Any], now: datetime) -> Any:
    tree = validate(expression)
    funcs = make_functions(now)

    def ev(node: ast.AST, env: dict[str, Any]) -> Any:
        if isinstance(node, ast.Expression):
            return ev(node.body, env)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            raise ExpressionError(f"unknown name '{node.id}'")
        if isinstance(node, ast.BoolOp):
            result: Any = isinstance(node.op, ast.And)
            for v in node.values:
                result = ev(v, env)
                if isinstance(node.op, ast.And) and not result:
                    return result
                if isinstance(node.op, ast.Or) and result:
                    return result
            return result
        if isinstance(node, ast.UnaryOp):
            val = ev(node.operand, env)
            return (not val) if isinstance(node.op, ast.Not) else -val
        if isinstance(node, ast.BinOp):
            return _BIN[type(node.op)](ev(node.left, env), ev(node.right, env))
        if isinstance(node, ast.Compare):
            left = ev(node.left, env)
            for op, comp in zip(node.ops, node.comparators):
                right = ev(comp, env)
                if not _CMP[type(op)](left, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.Subscript):
            container, key = ev(node.value, env), ev(node.slice, env)
            try:
                return container[key]
            except (KeyError, IndexError, TypeError) as exc:
                raise ExpressionError(f"cannot index {key!r}") from exc
        if isinstance(node, ast.List):
            return [ev(e, env) for e in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(ev(e, env) for e in node.elts)
        if isinstance(node, ast.IfExp):
            return ev(node.body, env) if ev(node.test, env) else ev(node.orelse, env)
        if isinstance(node, ast.Call):
            name = node.func.id  # type: ignore[attr-defined]
            if name not in funcs:
                raise ExpressionError(f"function '{name}' is not allowed")
            return funcs[name](*[ev(a, env) for a in node.args])
        if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
            if len(node.generators) != 1 or node.generators[0].is_async:
                raise ExpressionError("only single-clause comprehensions are allowed")
            gen = node.generators[0]
            if not isinstance(gen.target, ast.Name):
                raise ExpressionError("comprehension target must be a name")
            out = []
            for item in ev(gen.iter, env):
                inner = {**env, gen.target.id: item}
                if all(ev(cond, inner) for cond in gen.ifs):
                    out.append(ev(node.elt, inner))
            return out
        raise ExpressionError(f"unsupported node {type(node).__name__}")

    try:
        return ev(tree, dict(variables))
    except ExpressionError:
        raise
    except (TypeError, ValueError, ZeroDivisionError, AttributeError, OverflowError, OSError) as exc:
        raise ExpressionError(str(exc)) from exc
