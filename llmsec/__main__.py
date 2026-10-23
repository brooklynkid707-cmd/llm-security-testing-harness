"""Entry point for ``python -m llmsec``."""

from __future__ import annotations

import sys

from llmsec.cli import main

if __name__ == "__main__":
    sys.exit(main())
