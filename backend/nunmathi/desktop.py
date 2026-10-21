"""Entry point of the packaged (PyInstaller) build.

With no arguments - or with a single capture file, as when a .pcap is opened with Nunmathi - it starts the
standalone desktop application (native window, no browser, no network port). With a sub-command it behaves
like the `nunmathi` command-line tool. The data directory (captures, results, model cache) is per user.
"""
from __future__ import annotations

import os
import sys

CLI_COMMANDS = {"analyze", "forge", "scenarios", "testbed", "verify", "schema", "train", "live", "-h", "--help"}
# "gui" is handled below; "serve" (HTTP server for UI development) is not part of the packaged product


def _user_data() -> str:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        new, old = os.path.join(base, "Nunmathi"), os.path.join(base, "VeilScope")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
        new, old = os.path.join(base, "nunmathi"), os.path.join(base, "veilscope")
    # the product was called VeilScope up to 1.1.0: carry its saved analyses over on first start
    if not os.path.exists(new) and os.path.isdir(old):
        try:
            os.replace(old, new)
        except OSError:
            pass
    return new


def main() -> int:
    os.environ.setdefault("NUNMATHI_DATA", _user_data())
    os.makedirs(os.environ["NUNMATHI_DATA"], exist_ok=True)
    args = sys.argv[1:]
    windowed = sys.stdout is None          # Windows GUI executable: there is no console to print to
    if args and args[0] in ("app", "gui"):
        args = args[1:]
    if args == ["--gl-probe"]:
        from nunmathi.gui import gl_probe
        return gl_probe()
    if args and args[0] == "--selftest":
        from nunmathi.gui import selftest
        return selftest()
    if not windowed and args and args[0] in CLI_COMMANDS:
        from nunmathi.cli import main as cli_main
        return cli_main(args)
    if not windowed and args and args[0] == "serve":
        print("This build of Nunmathi is a standalone desktop application and has no web interface.\n"
              "Run 'nunmathi' with no arguments to open it, or 'nunmathi --help' for the command-line tools.",
              file=sys.stderr)
        return 2
    open_path = next((a for a in args if not a.startswith("-") and os.path.isfile(a)), None)
    from nunmathi.gui import run
    if not windowed:
        return run(open_path=open_path, debug="--debug" in args)
    # windowed Windows build: there is no console, so report a crash in a dialog and a log file
    try:
        return run(open_path=open_path, debug="--debug" in args)
    except Exception:
        import traceback
        from nunmathi.gui import message_box
        log = os.path.join(os.environ["NUNMATHI_DATA"], "crash.log")
        with open(log, "a", encoding="utf-8") as f:
            f.write(traceback.format_exc() + "\n")
        message_box(f"Nunmathi stopped because of an unexpected error.\n\nDetails were written to:\n{log}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
