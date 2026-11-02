"""CLI command families extracted from the ``apileaks`` entrypoint.

Each module here defines a cohesive Click command group (and its helpers) that
``apileaks.py`` registers onto the root ``cli`` group via ``cli.add_command``.
These modules do not import ``apileaks`` (no circular dependency).
"""
