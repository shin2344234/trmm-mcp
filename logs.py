#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wrapper so this keeps working from a clone; the code lives in trmm_mcp.cli_logs."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from trmm_mcp.cli_logs import main  # noqa: E402

main()
