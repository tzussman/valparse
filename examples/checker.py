#!/usr/bin/env python3

# Valgrind XML file parsing script

import argparse
import signal
import sys
from pathlib import Path

from termcolor import cprint

from valparse import Parser

"""Signals we expect to see for which a student can still get points"""
ALLOWED_SIGNALS: set[signal.Signals] = {signal.SIGINT, signal.SIGQUIT,
                                        signal.SIGTERM, signal.SIGKILL}

"""
Expected termination signals:
    - SIGABRT: caused by a failed assert() or stack smashing
    - SIGSEGV: caused by a segmentation fault
    - SIGFPE: Floating-point exception, such as divide by zero
    - SIGBUS: Bus error, such as misaligned memory access
    - SIGPIPE: write to broken pipe
"""
EXPECTED_TERM_SIGNALS: set[signal.Signals] = {signal.SIGABRT, signal.SIGSEGV,
                                              signal.SIGFPE, signal.SIGBUS,
                                              signal.SIGPIPE}


def write_values(path: Path, value: str, delimiter: str):
    prev_value = path.read_text().strip()
    value_list = prev_value.split(delimiter) + [value] if prev_value else [value]
    new_value = delimiter.join(value_list) + '\n'
    path.write_text(new_value)


desc = 'Parse Valgrind XML output files'
parser = argparse.ArgumentParser(description=desc)

parser.add_argument('xmlfile',
                    metavar='<xml-file>',
                    type=str,
                    help='the XML file to parse')

parser.add_argument('-f', '--create-files',
                    default=False, action='store_true',
                    help='Create files for errors or leaks found')

parser.add_argument('--error-file',
                    default='.memerr_found', type=str,
                    help='File to create if memory errors are found, if -f is set.',
                    metavar='<filename>')

parser.add_argument('--leak-file',
                    default='.memleak_found', type=str,
                    help='File to create if memory leaks are found, if -f is set.',
                    metavar='<filename>')

parser.add_argument('--fatal-signal-file',
                    default='.memerr_found', type=str,
                    help='File to create if a fatal signal is caught, if -f is set. Defaults to same file as --error-file.',
                    metavar='<filename>')

parser.add_argument('--write-item',
                    default='', type=str,
                    help='Value to append to error or leak files, if -f is set.',
                    metavar='<item>')

parser.add_argument('--write-item-delimiter',
                    default=', ', type=str,
                    help='Delimiter for error/leak file value list, if -f is set.',
                    metavar='<delim>')

parser.add_argument('-q', '--quiet',
                    default=False, action='store_true',
                    help="Don't print leak/error messages.")

args = parser.parse_args()

try:
    valfile = Parser(args.xmlfile)
except FileNotFoundError:
    cprint(f"File '{args.xmlfile}' not found. The tested executable might have failed...", "red")
    sys.exit(1)
except Exception as e:
    cprint(f"Exception raised: {e}. The tested executable might have failed...", "red")
    sys.exit(1)

if valfile.signal and not (valfile.signal.get_signal() in ALLOWED_SIGNALS):
    cprint(f"Fatal signal observed: {valfile.signal.signame}", "red")

    if valfile.signal.get_signal() in EXPECTED_TERM_SIGNALS:
        if not args.quiet:
            cprint("Do not award memory points.", "red")
    else:
        cprint("Unexpected signal: ask for advice.", "red")

    if args.create_files:
        fatal_signal_file = Path(args.fatal_signal_file)
        fatal_signal_file.touch()

        if args.write_item:
            write_values(fatal_signal_file, args.write_item, args.write_item_delimiter)

    sys.exit(1)

if valfile.errcount:
    if not args.quiet:
        cprint(f"[ Errors present ]", "red")

    if args.create_files:
        error_file = Path(args.error_file)
        error_file.touch()

        if args.write_item:
            write_values(error_file, args.write_item, args.write_item_delimiter)
elif not args.quiet:
    cprint("[ No errors ]", "green")

if valfile.leakcount:
    if not args.quiet:
        cprint(f"[ Leaks present ]", "red")

    if args.create_files:
        leak_file = Path(args.leak_file)
        leak_file.touch()

        if args.write_item:
            write_values(leak_file, args.write_item, args.write_item_delimiter)
elif not args.quiet:
    cprint("[ No leaks ]", "green")
