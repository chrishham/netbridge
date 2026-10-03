import os

# pystray picks its backend at import time; on Linux the AppIndicator backend
# needs Gtk, which CI runners and headless dev boxes lack. The dummy backend
# never draws, so the tests stay platform-neutral.
os.environ.setdefault("PYSTRAY_BACKEND", "dummy")
