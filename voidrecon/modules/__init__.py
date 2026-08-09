"""VoidRecon recon modules.

Submodules are auto-discovered and registered at runtime by the pipeline
(``load_all_modules``), so simply dropping a new file that defines a
``@register``-decorated :class:`~voidrecon.core.module.Module` subclass anywhere
under this package makes it part of the engine.
"""
