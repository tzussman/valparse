'''Integration tests for Valparse.'''

import signal
from pathlib import Path

from valparse import Parser
from valparse.vgerror import ValgrindErrorKind


def test_Parser():
    """Create an instance of a Parser using data/bad.xml and verify the output"""

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
