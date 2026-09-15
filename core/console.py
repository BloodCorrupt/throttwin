import sys
import ctypes

if sys.platform == "win32":
    try:
        # Set Windows Console CodePage to UTF-8
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass

    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    try:
        # Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004) on stdout & stderr
        kernel32 = ctypes.windll.kernel32
        for handle_id in (-11, -12):
            h = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                kernel32.SetConsoleMode(h, mode.value | 0x0004 | 0x0008)
    except Exception:
        pass

import questionary
from rich.console import Console, Group
from rich.theme import Theme
from rich.table import Table
from rich.live import Live
from rich.rule import Rule
from rich.panel import Panel
from rich import box

custom_style = questionary.Style([
    ("question",    "white nobold"),
    ('answer',      'green'),
    ("selected",    "fg:default bg:default noreverse"),
])

theme = Theme({
    "text":     "not bold white",
    "info":     "bold bright_cyan",
    "success":  "not bold green",
    "warning":  "bold yellow",
    "error":    "not bold red",
    "muted":    "dim white",
    "accent":   "bright_cyan",
    "label":    "bold cyan",
})

console = Console(theme=theme)


def qselect(message, choices, **kwargs):
    return questionary.select(
        message,
        qmark="",
        instruction="",
        choices=choices,
        style=custom_style,
        pointer=">",
        **kwargs
    ).ask(kbi_msg="")
