"""Concatenate split ``dump*.bin`` files produced by ``UefiMemDump``.

The acquisition code writes multiple sequential dump chunks to FAT32 media.
This helper sorts those chunk files numerically and joins them into a single
binary image on the host.
"""

import argparse
import re
from pathlib import Path
from typing import Optional, Sequence

CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB
FILE_PATTERN = re.compile(r"dump\d+\.bin", re.IGNORECASE)


def extract_number(filename: str) -> int:
    """Extract the numeric suffix used to order ``dump*.bin`` files."""
    numbers = re.findall(r"\d+", filename)
    return int(numbers[0]) if numbers else 0


def concat_dump_files(input_dir: str, output_file: str) -> None:
    """Concatenate numerically ordered ``dump*.bin`` files into one output file."""
    input_path = Path(input_dir)
    if not input_path.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_path}")

    files = [
        path for path in input_path.iterdir()
        if path.is_file() and FILE_PATTERN.fullmatch(path.name)
    ]

    if not files:
        print(f"No dump*.bin files found in '{input_path}'")
        return

    files.sort(key=lambda path: extract_number(path.name))
    output_path = Path(output_file)

    with output_path.open("wb") as out_handle:
        for path in files:
            print(f"Adding {path.name}")
            with path.open("rb") as in_handle:
                while chunk := in_handle.read(CHUNK_SIZE):
                    out_handle.write(chunk)

    print(f"Files concatenated into '{output_path}'")


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the command-line parser for the helper script."""
    parser = argparse.ArgumentParser(
        description="Concatenate split dump*.bin files into one full dump image."
    )
    parser.add_argument("input_dir", help="Directory that contains dump*.bin chunks.")
    parser.add_argument("output_file", help="Path of the concatenated output file.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse CLI arguments, run concatenation, and return a process exit code."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    concat_dump_files(args.input_dir, args.output_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
