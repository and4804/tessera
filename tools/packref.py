"""CLI wrapper:  python -m tools.packref [packs_dir]  -> lint + run golden vectors of every pack with the reference interpreter."""
from ulpf.onboard.refengine import *  # noqa: F401,F403
from ulpf.onboard.refengine import main

if __name__ == "__main__":
    raise SystemExit(main())
