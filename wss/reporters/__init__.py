"""Reporters — exportadores de resultados de escaneo."""
from __future__ import annotations

from wss.reporters.markdown import generate_individual as markdown_individual
from wss.reporters.json_reporter import generate as json_generate
from wss.reporters.table import print_results as table_print

__all__ = ["markdown_individual", "json_generate", "table_print"]
