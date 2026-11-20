"""Example LogLens plugin: counts the lines that mention an order."""

PLUGIN = {"name": "Orders", "version": "1.0", "api": 1, "description": "Counts lines that mention an order"}


def count_orders(lines):
    total = sum("order" in line.lower() for line in lines)
    return f"{total} lines mention an order"


ANALYZERS = [{"title": "Count order lines", "run": count_orders}]
