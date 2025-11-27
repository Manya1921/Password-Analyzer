import os
import sys

HERE = os.path.dirname(__file__)
SRC = os.path.join(HERE, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from password_analyzer.gui import run_gui

if __name__ == '__main__':
    run_gui()
