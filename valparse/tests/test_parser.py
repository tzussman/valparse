'''Integration tests for Valparse.'''

import filecmp
import signal
from pathlib import Path

import valparse
from valparse import Parser, ValgrindErrorKind


def test_Parser():
    """Create an instance of a Parser using data/bad-test.xml and verify the output"""

    filename = Path(__file__).resolve().parent / 'data/bad-test.xml'

    try:
        valfile = Parser(filename)
    except FileNotFoundError:
        print(f"File '{filename}' not found. The tested executable might have failed...", "red")
        exit(1)
    except Exception as e:
        print(f"Exception raised: {e}. The tested executable might have failed...", "red")
        exit(1)

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


def test_suppression_dump():
    """Create an instance of a Parser using data/bad.xml and dump suppresions"""

    filename = Path(__file__).resolve().parent / 'data/bad-test.xml'

    try:
        valfile = Parser(filename)
    except FileNotFoundError:
        print(f"File '{filename}' not found. The tested executable might have failed...", "red")
        exit(1)
    except Exception as e:
        print(f"Exception raised: {e}. The tested executable might have failed...", "red")
        exit(1)

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
