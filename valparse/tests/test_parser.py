'''Integration tests for Valparse.'''

import filecmp
import signal
from pathlib import Path

import valparse
from valparse import Parser, ValgrindErrorKind


def test_Parser():
    """Create an instance of a Parser using data/bad-test.xml and verify the output"""

    filename = Path(__file__).resolve().parent / 'data/bad-test.xml'

    valfile = Parser(filename)

    assert valfile.args.valexe == "/usr/bin/valgrind.bin"
    assert valfile.args.valargs == [
        "--leak-check=full",
        "--xml=yes",
        "--xml-file=bad-test.xml",
        "--gen-suppressions=all",
        "--suppressions=bad.supp",
    ]
    assert valfile.args.exe == "./bad"
    assert valfile.args.exeargs == []

    assert valfile.hasErrors() is True
    assert valfile.hasLeaks() is False
    assert valfile.uniqueErrCount() == 2
    assert valfile.uniqueLeakCount() == 0
    assert valfile.totalBytesLeaked() == 0
    assert valfile.hasFatalSignal() is True

    assert ValgrindErrorKind.UNINIT_VALUE in valfile.errsunique
    assert ValgrindErrorKind.INVALID_READ in valfile.errsunique
    assert valfile.signal.signame == "SIGSEGV"
    assert valfile.signal.get_signal() == signal.SIGSEGV
    assert valfile.pid == 10220
    assert valfile.ppid == 8125
    assert valfile.tool == 'memcheck'

    assert valfile.status.start == "00:00:00:00.047 "
    assert valfile.status.end == "00:00:00:00.694 "

    valfile_str = '''Valgrind executable: /usr/bin/valgrind.bin
Valgrind args: --leak-check=full --xml=yes --xml-file=bad-test.xml --gen-suppressions=all --suppressions=bad.supp
Executable: ./bad


Fatal signal:
Thread ID: 1
Signal number: 11
Name: SIGSEGV
Code: 1
Address: 0x0
Stack:
  Instruction Pointer: 0x108706
  Object: /home/tz2294/valparse/examples/bad
  Function: main
  Directory: /home/tz2294/valparse/examples
  File: bad.c
  Line: 10
Event: Access not within mapped region


Status:
Start time: 00:00:00:00.047 \nEnd time: 00:00:00:00.694 \n

Errors present: 2

Error kind: UninitValue
Error message: Use of uninitialised value of size 8
Stack:
  Instruction Pointer: 0x108706
  Object: /home/tz2294/valparse/examples/bad
  Function: main
  Directory: /home/tz2294/valparse/examples
  File: bad.c
  Line: 10

Error kind: InvalidRead
Error message: Invalid read of size 4
Stack:
  Instruction Pointer: 0x108706
  Object: /home/tz2294/valparse/examples/bad
  Function: main
  Directory: /home/tz2294/valparse/examples
  File: bad.c
  Line: 10


Leaks present: 0


Suppressions:
Suppression kind: Memcheck:Value8
Stack frame:
  Function: main

Suppression kind: Memcheck:Addr4
Stack frame:
  Function: main


Total bytes leaked: 0
'''

    assert str(valfile) == valfile_str


def test_suppression_dump():
    """Create an instance of a Parser using data/bad.xml and dump suppresions"""

    filename = Path(__file__).resolve().parent / 'data/bad-test.xml'

    valfile = Parser(filename)

    assert valfile.hasErrors() is True
    assert valfile.hasLeaks() is False
    assert valfile.uniqueErrCount() == 2
    assert valfile.uniqueLeakCount() == 0
    assert valfile.totalBytesLeaked() == 0
    assert valfile.hasFatalSignal() is True

    test_supp_file = Path(__file__).resolve().parent / 'data/test.supp'
    supp_file = Path(__file__).resolve().parent / 'data/bad.supp'

    print(valfile.suppressions)

    valparse.dumpSuppressions(test_supp_file, [('definite-leak-ignore', valfile.suppressions[0])])
    assert filecmp.cmp(supp_file, test_supp_file, shallow=False)
