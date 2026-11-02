"""Allow ``python -m phishguard``."""
import sys
from .cli import main

sys.exit(main())
