"""Application bootstrap."""

from __future__ import annotations

import logging
import multiprocessing
import sys
import threading
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from types import TracebackType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PySide6.QtWidgets import QMessageBox

log = logging.getLogger(__name__)
MAX_ERROR_TEXT_CHARS = 300  # of the exception message shown to the user (the full traceback goes to the log file)


@dataclass(slots=True)
class _ReportState:
    reporting: bool = False  # an exception raised while reporting one is only logged (no recursion)
    box: QMessageBox | None = None  # at most one error message on screen at a time

    def box_open(self) -> bool:
        try:
            return self.box is not None and self.box.isVisible()
        except RuntimeError:  # already deleted (it deletes itself on close)
            return False


_state = _ReportState()


def _setup_logging() -> None:
    from .paths import log_file

    handler = RotatingFileHandler(log_file(), maxBytes=2_000_000, backupCount=2, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s - %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)


# ---- unhandled exceptions --------------------------------------------------------------------------------------------
# The windowed build has no console: without these hooks an exception in a slot or a thread vanishes without a trace.
def install_exception_hooks() -> None:
    """Log every unhandled exception with its traceback; on the main thread also tell the user (non-modally)."""
    sys.excepthook = handle_exception
    threading.excepthook = handle_thread_exception


def handle_exception(
    exc_type: type[BaseException], exc: BaseException, traceback: TracebackType | None
) -> QMessageBox | None:
    """``sys.excepthook``: log the full traceback and show a short message. Returns the message box, if one opened."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc, traceback)
        return None
    log.critical("Unhandled exception", exc_info=(exc_type, exc, traceback))
    if _state.reporting or threading.current_thread() is not threading.main_thread():
        return None
    _state.reporting = True
    try:
        return _show_error(exc_type, exc)
    except Exception:  # the hook must never raise: log the failure to report, then carry on
        log.exception("Could not show the error message")
        return None
    finally:
        _state.reporting = False


def handle_thread_exception(args: threading.ExceptHookArgs) -> None:
    """``threading.excepthook``: log the traceback (worker threads never touch widgets)."""
    if args.exc_type is SystemExit:
        return
    name = args.thread.name if args.thread is not None else "?"
    if args.exc_value is None:
        log.critical("Unhandled %s in thread %s", args.exc_type.__name__, name)
    else:
        log.critical("Unhandled exception in thread %s", name, exc_info=args.exc_value)  # with its traceback


def _show_error(exc_type: type[BaseException], exc: BaseException) -> QMessageBox | None:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QMessageBox

    from . import APP_NAME
    from .paths import log_file

    if not isinstance(QApplication.instance(), QApplication):
        return None
    if _state.box_open():
        return None  # one message is enough; the rest are in the log file
    text = str(exc) or exc_type.__name__
    if len(text) > MAX_ERROR_TEXT_CHARS:
        text = text[:MAX_ERROR_TEXT_CHARS] + "…"
    box = QMessageBox(QMessageBox.Icon.Critical, APP_NAME, f"Something went wrong: {exc_type.__name__}: {text}")
    box.setInformativeText(f"LogLens keeps running, but the last action may not have completed.\nDetails: {log_file()}")
    box.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    box.setWindowModality(Qt.WindowModality.NonModal)
    box.finished.connect(_forget_error_box)
    box.show()  # not exec(): a nested event loop inside an exception hook could re-enter the failing code
    _state.box = box
    return box


def _forget_error_box(_result: int = 0) -> None:
    _state.box = None


def main(argv: list[str] | None = None) -> int:
    multiprocessing.freeze_support()  # needed for the search process pool in a frozen (PyInstaller) build
    argv = sys.argv if argv is None else argv
    _setup_logging()
    install_exception_hooks()

    from PySide6.QtWidgets import QApplication

    from . import APP_NAME
    from .core.search import shutdown_pool
    from .services.single_instance import SingleInstance
    from .settings import Settings
    from .ui.icons import logo_icon
    from .ui.main_window import MainWindow
    from .ui.theme import apply_theme

    if sys.platform == "win32":  # own taskbar identity (icon/grouping) instead of python.exe's
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("LogLens.LogLens")
        except (AttributeError, OSError):
            pass

    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_NAME)
    app.setWindowIcon(logo_icon())
    paths = [a for a in argv[1:] if not a.startswith("-")]
    instance = SingleInstance()
    new_window = "--new-window" in argv  # e.g. the elevated relaunch: never hand files over, never serve the pipe
    if not new_window and instance.forward(paths):
        return 0  # an open LogLens window took the files
    if not new_window and not instance.listen() and instance.forward(paths):
        return 0  # another launch won the race to serve the pipe: it took the files
    settings = Settings.load()
    apply_theme(app, settings.theme)
    window = MainWindow(settings)
    instance.filesReceived.connect(window.receive_files)
    window.show()
    window.open_later(paths)
    try:
        return app.exec()
    finally:
        shutdown_pool()


if __name__ == "__main__":
    sys.exit(main())
