"""Python `ast` import & call-symbol extractor.

Produces one flat list holding module names (`yaml`) and dotted call symbols
(`yaml.load`), with import aliases resolved (`import numpy as np; np.array()` ->
`numpy.array`). Pure functions, no I/O.
"""
import ast
from typing import Dict, Iterable, List, Optional

_FUNC_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


def _dotted(node: ast.AST) -> Optional[str]:
    """Return 'a.b.c' for a Name/Attribute chain, else None."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def extract_symbols(source: str) -> List[str]:
    """Sorted, de-duplicated modules and dotted call symbols. Unparseable source -> []."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []

    aliases: Dict[str, str] = {}
    found = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                found.add(top)
                aliases[alias.asname or top] = alias.name if alias.asname else top
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue  # relative import: local code, not a third-party package
            found.add(node.module.split(".")[0])
            for alias in node.names:
                if alias.name == "*":
                    continue
                full = f"{node.module}.{alias.name}"
                aliases[alias.asname or alias.name] = full
                found.add(full)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            dotted = _dotted(node.func)
            if not dotted:
                continue
            root, _, rest = dotted.partition(".")
            if root in aliases:
                found.add(aliases[root] + (f".{rest}" if rest else ""))

    return sorted(found)


def merge_symbols(sources: Iterable[str]) -> List[str]:
    """Union of extract_symbols() over several files."""
    merged = set()
    for src in sources:
        merged.update(extract_symbols(src))
    return sorted(merged)


def enclosing_function(source: str, lineno: int) -> Optional[str]:
    """Name of the innermost function containing `lineno` (e.g. a traceback line)."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    best: Optional[ast.AST] = None
    for node in ast.walk(tree):
        if isinstance(node, _FUNC_NODES) and node.lineno <= lineno <= (node.end_lineno or node.lineno):
            if best is None or node.lineno >= best.lineno:
                best = node
    return best.name if best is not None else None
