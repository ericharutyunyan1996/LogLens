"""Qt-aware application services: non-widget objects that own state and background work.

Layering: ``core`` (pure Python) ← ``services`` (QObject + signals, no widgets) ← ``ui`` (widgets).
"""
