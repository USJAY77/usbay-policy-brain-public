"""Runtime package marker.

Keep this module side-effect free so importing a runtime submodule does not
eagerly import the rest of the package and create circular dependencies.
"""

__all__: list[str] = []
