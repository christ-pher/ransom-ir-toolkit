"""Allow running the VMDK Entropy Analyzer as ``python -m tools.vmdk_entropy_analyzer``."""

import sys

from tools.vmdk_entropy_analyzer.cli import main

sys.exit(main())
