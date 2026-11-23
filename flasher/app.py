"""C3Hole Flasher 2.0 - entry point.  `app.py --selftest` verifies the bundled files without opening a window."""
import sys


def main():
    if "--selftest" in sys.argv:
        from core import selftest
        sys.exit(selftest())
    import tkinter as tk
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)      # crisp text on high-DPI screens
        except Exception:
            pass
    root = tk.Tk()
    from gui import App
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
