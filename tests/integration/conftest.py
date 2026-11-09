"""Integration test setup.

Point the auth store at a throwaway file BEFORE app.py is imported, so tests
never touch the real data/auth.json and start from a clean (no-users) state.
"""

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="artex-itest-")
os.environ["ARTEX_AUTH_FILE"] = os.path.join(_tmp, "auth.json")
