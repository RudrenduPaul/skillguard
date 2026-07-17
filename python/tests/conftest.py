import tempfile
from pathlib import Path

import pytest

# The repo's shared fixture skills (examples/known-bad-skill, clean-skill,
# clean-skill-python) live at the repo root, one level above python/, and
# are used by both the TypeScript test suite and this Python one -- no
# duplication needed, both suites exercise the exact same fixture content.
REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = REPO_ROOT / "examples"


@pytest.fixture()
def tmp_skill_dir():
    with tempfile.TemporaryDirectory(prefix="skillguard-pytest-") as d:
        yield Path(d)
