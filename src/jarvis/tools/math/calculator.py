"""Calculator tool — safe math evaluation via ``ast`` module."""

from __future__ import annotations

import ast
import math
import operator
from typing import Any

from jarvis.security.levels import SecurityLevel
from jarvis.tools.base import BaseTool, ToolParameter, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry

# Maximum allowed length and complexity of mathematical expressions
MAX_EXPRESSION_LENGTH = 500
MAX_AST_NODES = 100
MAX_EXPONENT = 1000

# Allowed binary operators
_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

# Allowed unary operators
_UNARYOPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

# Allowed math functions and constants (safe subset)
_MATH_FUNCS = {
    "abs": abs,
    "round": round,
    "min": min,
    "max": max,
    "sqrt": math.sqrt,
    "log": math.log,
    "ln": math.log,  # alias: ln(x) == log(x)
    "log10": math.log10,
    "log2": math.log2,
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "pi": math.pi,
    "e": math.e,
    "ceil": math.ceil,
    "floor": math.floor,
}


def _safe_eval_node(node: ast.AST) -> Any:
    """Recursively evaluate an AST node using only whitelisted operations."""
    if isinstance(node, ast.Expression):
        return _safe_eval_node(node.body)

    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError(f"Tipo de constante no permitido: {type(node.value).__name__}")

    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in _BINOPS:
            raise ValueError(f"Operador binario no admitido: {op_type.__name__}")

        left = _safe_eval_node(node.left)
        right = _safe_eval_node(node.right)

        # Prevenir ataques de denegación de servicio por exponentes gigantes
        if op_type is ast.Pow:
            if abs(right) > MAX_EXPONENT or (abs(left) > 1000 and right > 100):
                raise ValueError("Exponente o base excesivamente grandes para calcular.")

        # Manejo explícito de división por cero
        if op_type in (ast.Div, ast.FloorDiv, ast.Mod) and right == 0:
            raise ZeroDivisionError("División por cero.")

        return _BINOPS[op_type](left, right)

    if isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in _UNARYOPS:
            raise ValueError(f"Operador unario no admitido: {op_type.__name__}")
        operand = _safe_eval_node(node.operand)
        return _UNARYOPS[op_type](operand)

    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ValueError("Solo se permiten llamadas a funciones matemáticas simples.")
        fname = node.func.id
        if fname not in _MATH_FUNCS:
            raise ValueError(f"Función matemática no permitida: '{fname}'.")
        func = _MATH_FUNCS[fname]
        if not callable(func):
            raise ValueError(f"'{fname}' es una constante, no una función.")
        args = [_safe_eval_node(a) for a in node.args]
        return func(*args)

    if isinstance(node, ast.Name):
        name = node.id
        if name in _MATH_FUNCS:
            val = _MATH_FUNCS[name]
            if isinstance(val, (int, float)):
                return val
        raise ValueError(f"Variable o identificador desconocido: '{name}'.")

    raise ValueError(f"Tipo de expresión no admitido: {type(node).__name__}")


def safe_eval(expression: str) -> float:
    """Evaluate a math expression safely using Python AST."""
    if not expression or not expression.strip():
        raise ValueError("La expresión matemática está vacía.")

    raw_expr = expression.strip()
    if len(raw_expr) > MAX_EXPRESSION_LENGTH:
        raise ValueError(f"La expresión excede la longitud máxima ({MAX_EXPRESSION_LENGTH} caracteres).")

    # Reemplazar operador exponencial visual
    parsed_expr = raw_expr.replace("^", "**")

    try:
        tree = ast.parse(parsed_expr, mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"Error de sintaxis en la expresión: {exc}") from exc

    # Limitar complejidad del árbol AST
    node_count = sum(1 for _ in ast.walk(tree))
    if node_count > MAX_AST_NODES:
        raise ValueError(f"La expresión es demasiado compleja ({node_count} nodos AST).")

    raw_result = _safe_eval_node(tree.body)

    if not isinstance(raw_result, (int, float)):
        raise ValueError(f"Resultado no numérico: {type(raw_result).__name__}")

    if math.isnan(raw_result) or math.isinf(raw_result):
        raise ValueError("Resultado matemático no válido (infinito o indefinido).")

    return float(raw_result)


@ToolRegistry.register("calculator")
class CalculatorTool(BaseTool):
    """Calculadora matemática segura utilizando evaluación AST."""

    tool_id = "calculator"
    name = "calculator"
    description = (
        "Evalúa expresiones matemáticas de forma segura. "
        "Soporta aritmética básica (+, -, *, /, //, %, **), funciones trigonométricas/logarítmicas y constantes (pi, e)."
    )
    required_level = SecurityLevel.LEVEL_0

    @property
    def parameters(self) -> list[ToolParameter]:
        return [
            ToolParameter(
                name="expression",
                description="Expresión matemática a evaluar (ej: '2+3*4', 'sqrt(16)').",
                required=True,
                parameter_type="string",
            )
        ]

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.name,
            description=self.description,
            parameters={
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "Expresión matemática a evaluar (ej: '2+3*4', 'sqrt(16)').",
                    },
                },
                "required": ["expression"],
            },
            category="math",
        )

    def execute(self, **params: Any) -> ToolResult:
        expression = params.get("expression", "")
        if not expression or not str(expression).strip():
            return ToolResult(
                tool_name=self.tool_id,
                content="No se proporcionó ninguna expresión.",
                success=False,
            )

        try:
            result = safe_eval(str(expression))
            # Formatear números enteros limpiamente sin sufijo .0 innecesario
            formatted = str(int(result)) if result.is_integer() else str(result)
            return ToolResult(
                tool_name=self.tool_id,
                content=formatted,
                success=True,
                metadata={"expression": expression, "result": result},
            )
        except ZeroDivisionError:
            return ToolResult(
                tool_name=self.tool_id,
                content="Error: división por cero.",
                success=False,
            )
        except (ValueError, SyntaxError, TypeError) as exc:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Error al evaluar la expresión: {exc}",
                success=False,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Error inesperado en cálculo: {exc}",
                success=False,
            )


__all__ = ["CalculatorTool", "safe_eval"]