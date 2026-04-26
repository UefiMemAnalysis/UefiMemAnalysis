"""Discover and run plugin-style UEFI memory analysis modules."""

from __future__ import annotations

import argparse
import importlib
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

PluginMap = dict[str, ModuleType]
LoadErrorMap = dict[str, str]


def _get_modules_dir() -> str:
    """Return the absolute path to the plugin module directory."""
    package_dir = Path(__file__).resolve().parent.parent
    return str(package_dir / "modules")


def load_modules() -> tuple[PluginMap, LoadErrorMap]:
    """Load modules from ``modules/`` that expose ``plugin_info`` and ``run``."""
    modules_dir = _get_modules_dir()
    modules: PluginMap = {}
    load_errors: LoadErrorMap = {}
    importlib.invalidate_caches()

    for file_name in sorted(os.listdir(modules_dir)):
        if not file_name.endswith(".py") or file_name == "__init__.py":
            continue

        module_name = file_name[:-3]
        try:
            module = importlib.import_module(f"uefi_dump_analysis.modules.{module_name}")
            if hasattr(module, "plugin_info") and hasattr(module, "run"):
                modules[module_name] = module
        except Exception as exc:  # pragma: no cover - exercised by import failures
            load_errors[module_name] = str(exc)

    return modules, load_errors


def _add_plugin_arguments(
    subparser: argparse.ArgumentParser,
    arguments: list[dict[str, Any]],
) -> None:
    """Register one plugin's declared CLI arguments with ``argparse``."""
    passthrough_keys = ("action", "default", "choices", "metavar", "nargs", "type")

    for argument in arguments:
        kwargs: dict[str, Any] = {
            "help": argument.get("help", "No help provided."),
            "required": argument.get("required", False),
        }
        for key in passthrough_keys:
            if argument.get(key) is not None:
                kwargs[key] = argument[key]
        subparser.add_argument(argument["name"], **kwargs)


def _build_parser(modules: PluginMap) -> argparse.ArgumentParser:
    """Build the top-level CLI parser and register each plugin subcommand."""
    main_parser = argparse.ArgumentParser(
        description=(
            "Plugin-based CLI for analyzing UEFI memory dumps.\n"
            "Run 'uefi-mem-analysis <module> -h', "
            "or 'python -m uefi_dump_analysis <module> -h' for module-specific help."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = main_parser.add_subparsers(
        title="modules",
        dest="module",
        help="Available analysis modules",
    )

    for module_name, module_obj in modules.items():
        plugin_info = getattr(module_obj, "plugin_info", {})
        description = plugin_info.get("description", "No description provided.")
        arguments = plugin_info.get("arguments", [])

        subparser = subparsers.add_parser(
            module_name,
            description=description,
            help=description,
        )
        _add_plugin_arguments(subparser, arguments)
        subparser.set_defaults(func=module_obj.run)

    return main_parser


def main() -> None:
    """Parse the CLI, load plugins, and dispatch to the selected module."""
    modules, load_errors = load_modules()

    if load_errors:
        for module_name, error_message in sorted(load_errors.items()):
            print(f"[warning] Skipping module '{module_name}': {error_message}", file=sys.stderr)

    if not modules:
        print("No loadable modules were found.", file=sys.stderr)
        sys.exit(1)

    main_parser = _build_parser(modules)

    if len(sys.argv) == 1:
        main_parser.print_help()
        sys.exit(0)

    args = main_parser.parse_args()
    if not args.module:
        main_parser.print_help()
        sys.exit(1)

    if hasattr(args, "func"):
        args.func(args)
        return

    main_parser.print_help()


if __name__ == "__main__":
    main()
