"""PyInstaller entry point for NetBridge."""
import os
import sys
import traceback

# Use user's temp dir for crash log
CRASH_LOG = os.path.join(os.environ.get("TEMP", "."), "netbridge_crash.log")

def show_error(msg):
    """Show error - try messagebox on Windows, else print."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, str(msg), "NetBridge Error", 0x10)
    except Exception:
        print(msg, file=sys.stderr)

def run():
    try:
        from netbridge_agent.__main__ import main
        main()
    except Exception as e:
        # Write error to temp directory
        try:
            with open(CRASH_LOG, "w") as f:
                f.write(f"Crash at startup:\n{e}\n\n")
                traceback.print_exc(file=f)
        except Exception:
            pass
        show_error(f"NetBridge crashed:\n{e}\n\nSee: {CRASH_LOG}")
        sys.exit(1)

if __name__ == "__main__":
    run()
