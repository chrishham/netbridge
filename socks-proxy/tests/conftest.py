import os

# pystray picks its backend at import time; without a display (CI runners,
# headless dev boxes) the AppIndicator backend fails and the tray tests would
# be skipped. The dummy backend never draws, so they run everywhere and the
# coverage floor means the same thing locally and in CI.
os.environ.setdefault("PYSTRAY_BACKEND", "dummy")
