"""VoidRecon — adversary-minded reconnaissance framework.

VoidRecon maps a target's attack surface the way a real intruder would:
organisation-first, passive-before-active, and relentlessly focused on the
forgotten corners that classic checklists skip. It is built for *authorized*
work only — bug bounty programs and sanctioned penetration tests.

Maintained by VoidSec-Hub.
"""

from voidrecon.version import __codename__, __version__

__all__ = ["__version__", "__codename__"]
