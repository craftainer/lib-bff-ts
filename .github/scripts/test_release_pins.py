"""The release build's Node image must be the Node the devcontainer runs.

``release-run.sh`` checks this at release time; this runs on every PR so a
``NODE_VERSION`` bump that leaves ``NODE_IMAGE`` behind (or the reverse) fails
before it reaches a release.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class NodeImagePinTest(unittest.TestCase):
    """``scripts/release-lib.sh``'s ``NODE_IMAGE`` against the Dockerfile's ``NODE_VERSION``."""

    def test_node_image_matches_devcontainer_node_version(self) -> None:
        dockerfile = (ROOT / ".devcontainer/Dockerfile").read_text(encoding="utf-8")
        lib = (ROOT / "scripts/release-lib.sh").read_text(encoding="utf-8")
        version = re.search(r"^ARG NODE_VERSION=(\S+)$", dockerfile, re.MULTILINE)
        image = re.search(r"^NODE_IMAGE=(\S+)$", lib, re.MULTILINE)
        if version is None:
            self.fail("no `ARG NODE_VERSION=` in .devcontainer/Dockerfile")
        if image is None:
            self.fail("no `NODE_IMAGE=` in scripts/release-lib.sh")
        pattern = rf"node:{re.escape(version.group(1))}-trixie-slim@sha256:[a-f0-9]{{64}}"
        self.assertRegex(
            image.group(1),
            rf"^{pattern}$",
            "NODE_IMAGE must be node:<NODE_VERSION>-trixie-slim@sha256:<digest>; "
            "update it and .devcontainer/Dockerfile's NODE_VERSION together",
        )


if __name__ == "__main__":
    unittest.main()
