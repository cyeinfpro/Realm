from __future__ import annotations

import asyncio
import faulthandler
import logging
import os
import signal
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from ..utils.redact import redact_for_log, redact_log_text
except Exception:
    # Keep runtime bootable even when optional redaction helpers are missing.
    def redact_log_text(value: Any) -> str:
        return str(value or "")

    def redact_for_log(value: Any, *, key_hint: str = "") -> Any:
        return value

_LOG_SETUP_DONE = False
_HOOKS_SETUP_DONE = False
_FAULT_LOG_FH: Optional[Any] = None
_ACTIVE_LOG_FILE: Optional[Path] = None
_ACTIVE_CRASH_LOG_FILE: Optional[Path] = None
_ACTIVE_FAULT_LOG_FILE: Optional[Path] = None


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = str(os.getenv(name, str(default)) or "").strip()
    try:
        v = int(float(raw))
    except Exception:
        v = int(default)
    if v < int(lo):
        v = int(lo)
    if v > int(hi):
        v = int(hi)
    return int(v)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() not in ("0", "false", "off", "no")


def _log_level() -> int:
    raw = str(os.getenv("REALM_PANEL_LOG_LEVEL", "INFO") or "INFO").strip().upper()
    return int(getattr(logging, raw, logging.INFO))


def _log_file() -> Path:
    raw = str(os.getenv("REALM_PANEL_LOG_FILE", "/var/log/realm-panel/panel.log") or "").strip()
    if not raw:
        raw = "/var/log/realm-panel/panel.log"
    return Path(raw)


def _crash_log_file() -> Path:
    raw = str(os.getenv("REALM_PANEL_CRASH_LOG_FILE", "/var/log/realm-panel/crash.log") or "").strip()
    if not raw:
        raw = "/var/log/realm-panel/crash.log"
    return Path(raw)


def _fault_log_file() -> Path:
    raw = str(os.getenv("REALM_PANEL_FAULT_LOG_FILE", "/var/log/realm-panel/fault.log") or "").strip()
    if not raw:
        raw = "/var/log/realm-panel/fault.log"
    return Path(raw)


def _truncate(val: Any, max_len: int = 400) -> str:
    if isinstance(val, str):
        s = val
    else:
        try:
            s = repr(val)
        except Exception:
            s = str(val)
    s = redact_log_text(s)
    if len(s) <= max_len:
        return s
    return s[:max_len] + "…"


def _context_for_log(context: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in context.items():
        if k == "exception":
            continue
        out[str(k)] = _truncate(redact_for_log(v, key_hint=str(k)))
    return out


def _fallback_path(path: Path) -> Path:
    return Path("/tmp/realm-panel") / path.name


def _best_existing_path(primary: Path) -> Path:
    fb = _fallback_path(primary)
    if primary.exists():
        return primary
    if fb.exists():
        return fb
    return primary


def _select_writable_path(primary: Path) -> Optional[Path]:
    selected: Optional[Path] = primary
    try:
        selected.parent.mkdir(parents=True, exist_ok=True)
        return selected
    except Exception:
        selected = _fallback_path(primary)
    try:
        selected.parent.mkdir(parents=True, exist_ok=True)
        return selected
    except Exception:
        return None


def _runtime_formatter() -> logging.Formatter:
    return logging.Formatter("%(asctime)s %(levelname)s %(process)d %(threadName)s %(name)s | %(message)s")


def configure_runtime_logging() -> None:
    global _LOG_SETUP_DONE
    global _ACTIVE_LOG_FILE
    if _LOG_SETUP_DONE:
        return

    level = _log_level()
    root = logging.getLogger()
    root.setLevel(level)

    fmt = _runtime_formatter()

    # Keep stdout logging when root has no handlers (development mode).
    if not root.handlers:
        sh = logging.StreamHandler(sys.stdout)
        sh.setLevel(level)
        sh.setFormatter(fmt)
        setattr(sh, "_realm_panel_handler", "stdout")
        root.addHandler(sh)

    # Always try to persist logs to a rolling file.
    log_path = _log_file()
    selected_log_path = _select_writable_path(log_path)

    try:
        if selected_log_path is None:
            raise RuntimeError("no writable log directory")
        max_bytes = _env_int("REALM_PANEL_LOG_MAX_BYTES", 5 * 1024 * 1024, 256 * 1024, 512 * 1024 * 1024)
        backups = _env_int("REALM_PANEL_LOG_BACKUP_COUNT", 5, 1, 50)
        already = False
        for h in root.handlers:
            if (
                getattr(h, "_realm_panel_handler", "") == "file"
                and getattr(h, "baseFilename", "") == str(selected_log_path)
            ):
                already = True
                break
        if not already:
            fh = RotatingFileHandler(
                str(selected_log_path),
                maxBytes=int(max_bytes),
                backupCount=int(backups),
                encoding="utf-8",
            )
            fh.setLevel(level)
            fh.setFormatter(fmt)
            setattr(fh, "_realm_panel_handler", "file")
            root.addHandler(fh)
        _ACTIVE_LOG_FILE = Path(selected_log_path)
    except Exception:
        logging.getLogger(__name__).exception("failed to setup file logging")

    _LOG_SETUP_DONE = True
    install_crash_hooks()
    logging.getLogger(__name__).info("runtime logging enabled")


def install_crash_hooks() -> None:
    global _HOOKS_SETUP_DONE
    global _FAULT_LOG_FH
    global _ACTIVE_CRASH_LOG_FILE
    global _ACTIVE_FAULT_LOG_FILE
    if _HOOKS_SETUP_DONE:
        return

    logger = logging.getLogger("realm.panel.crash")
    logger.setLevel(logging.ERROR)
    fmt = _runtime_formatter()
    crash_log = _crash_log_file()
    selected_crash_log = _select_writable_path(crash_log)
    try:
        if selected_crash_log is None:
            raise RuntimeError("no writable crash log directory")
        crash_max_bytes = _env_int(
            "REALM_PANEL_CRASH_LOG_MAX_BYTES",
            5 * 1024 * 1024,
            128 * 1024,
            512 * 1024 * 1024,
        )
        crash_backups = _env_int("REALM_PANEL_CRASH_LOG_BACKUP_COUNT", 5, 1, 50)
        already = False
        for h in logger.handlers:
            if (
                getattr(h, "_realm_panel_handler", "") == "crash_file"
                and getattr(h, "baseFilename", "") == str(selected_crash_log)
            ):
                already = True
                break
        if not already:
            ch = RotatingFileHandler(
                str(selected_crash_log),
                maxBytes=int(crash_max_bytes),
                backupCount=int(crash_backups),
                encoding="utf-8",
            )
            ch.setLevel(logging.ERROR)
            ch.setFormatter(fmt)
            setattr(ch, "_realm_panel_handler", "crash_file")
            logger.addHandler(ch)
        _ACTIVE_CRASH_LOG_FILE = Path(selected_crash_log)
    except Exception:
        logger.exception("failed to setup crash file logging")

    old_sys_excepthook = sys.excepthook

    def _sys_excepthook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            try:
                old_sys_excepthook(exc_type, exc, tb)
            except Exception:
                pass
            return
        logger.critical("uncaught exception (sys.excepthook)", exc_info=(exc_type, exc, tb))
        try:
            old_sys_excepthook(exc_type, exc, tb)
        except Exception:
            pass

    sys.excepthook = _sys_excepthook

    if hasattr(sys, "unraisablehook"):
        old_unraisablehook = sys.unraisablehook

        def _unraisablehook(args):
            logger.critical(
                "unraisable exception err_msg=%s object=%s",
                _truncate(getattr(args, "err_msg", "")),
                _truncate(getattr(args, "object", None)),
                exc_info=(
                    getattr(args, "exc_type", Exception),
                    getattr(args, "exc_value", None),
                    getattr(args, "exc_traceback", None),
                ),
            )
            try:
                old_unraisablehook(args)
            except Exception:
                pass

        sys.unraisablehook = _unraisablehook

    if hasattr(threading, "excepthook"):
        old_thread_excepthook = threading.excepthook

        def _thread_excepthook(args: threading.ExceptHookArgs):
            logger.critical(
                "uncaught exception in thread name=%s",
                str(getattr(args, "thread", None).name if getattr(args, "thread", None) else ""),
                exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
            )
            try:
                old_thread_excepthook(args)
            except Exception:
                pass

        threading.excepthook = _thread_excepthook

    if _env_bool("REALM_PANEL_FAULTHANDLER", True):
        fault_log = _fault_log_file()
        selected_fault_log = _select_writable_path(fault_log)
        try:
            if selected_fault_log is None:
                raise RuntimeError("no writable fault log directory")
            _FAULT_LOG_FH = open(selected_fault_log, "a", encoding="utf-8", buffering=1)
            try:
                if faulthandler.is_enabled():
                    faulthandler.disable()
                faulthandler.enable(file=_FAULT_LOG_FH, all_threads=True)
            except Exception:
                pass
            try:
                faulthandler.register(signal.SIGUSR1, file=_FAULT_LOG_FH, all_threads=True, chain=True)
            except Exception:
                pass
            _ACTIVE_FAULT_LOG_FILE = Path(selected_fault_log)
        except Exception:
            logger.exception("failed to setup faulthandler log")

    _HOOKS_SETUP_DONE = True


def install_asyncio_exception_logging() -> None:
    loop = asyncio.get_running_loop()
    if bool(getattr(loop, "_realm_panel_asyncio_handler_installed", False)):
        return
    logger = logging.getLogger("realm.panel.asyncio")
    prev = loop.get_exception_handler()

    def _handler(lp: asyncio.AbstractEventLoop, context: Dict[str, Any]) -> None:
        exc = context.get("exception")
        msg = str(context.get("message") or "unhandled asyncio exception")
        extra = _context_for_log(context if isinstance(context, dict) else {})
        if exc is not None:
            logger.error("%s context=%s", msg, extra, exc_info=exc)
        else:
            logger.error("%s context=%s", msg, extra)

        try:
            if prev is not None:
                prev(lp, context)
            else:
                lp.default_exception_handler(context)
        except Exception:
            logger.exception("asyncio previous exception handler failed")

    loop.set_exception_handler(_handler)
    setattr(loop, "_realm_panel_asyncio_handler_installed", True)


def get_runtime_log_paths() -> Dict[str, Path]:
    panel = _ACTIVE_LOG_FILE or _best_existing_path(_log_file())
    crash = _ACTIVE_CRASH_LOG_FILE or _best_existing_path(_crash_log_file())
    fault = _ACTIVE_FAULT_LOG_FILE or _best_existing_path(_fault_log_file())
    return {"panel": Path(panel), "crash": Path(crash), "fault": Path(fault)}
