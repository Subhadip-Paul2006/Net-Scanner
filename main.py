#!/usr/bin/env python3
"""NetSight launcher: forwards to netsight.cli.main."""

import sys

from netsight.cli import main

if __name__ == "__main__":
    sys.exit(main())
