import signal

import valparse


def test_ValgrindError_error():
    """Create an instance of a ValgrindError with an InvalidRead and check its fields."""
    vgerr = valparse.ValgrindError(
        kind=valparse.ValgrindErrorKind("InvalidRead"),
        msg="Invalid read of size 4",
        msg_secondary="Address 0x4 is 4 bytes inside a block of size 8 free'd",
        stack=[
            valparse.Frame(
                ip="0x108706",
                obj="/home/valparse/examples/invalid_read",
                fn="main",
                dir="/home/valparse/examples/",
                file="invalid_read.c",
                line="50",
            ),
        ],
    )

    assert vgerr.kind == valparse.ValgrindErrorKind.INVALID_READ
    assert vgerr.msg == "Invalid read of size 4"
    assert vgerr.msg_secondary == "Address 0x4 is 4 bytes inside a block of size 8 free'd"
    assert len(vgerr.stack) == 1

    assert vgerr.isLeak() is False
    assert vgerr.isError() is True


def test_ValgrindError_leak():
    """Create an instance of a ValgrindError with a leak and check its fields."""
    vgerr = valparse.ValgrindError(
        kind=valparse.ValgrindErrorKind("Leak_DefinitelyLost"),
        msg="Test message",
        stack=[
            valparse.Frame(
                ip="0x108706",
                obj="/home/valparse/examples/fake_file",
                fn="main",
                dir="/home/valparse/examples/",
                file="fake_file.c",
                line="50",
            ),
        ],
    )

    assert vgerr.kind == valparse.ValgrindErrorKind.LEAK_DEFINITELY_LOST
    assert vgerr.msg == "Test message"
    assert len(vgerr.stack) == 1

    assert vgerr.isLeak() is True
    assert vgerr.isError() is False


def test_SFrame():
    """Create an instance of a SFrame and check its fields."""
    sframe = valparse.SFrame(
        obj="0x4",
        fun="main",
    )

    assert sframe.obj == "0x4"
    assert sframe.fun == "main"
    assert str(sframe) == "  Object: 0x4\n  Function: main\n"


def test_FatalSignal():
    """Create an instance of a FatalSignal and check its fields."""
    sig = valparse.FatalSignal(
        tid=5,
        signo=11,
        signame="SIGSEGV",
        sicode=1,
        siaddr="0x0",
        stack=[
            valparse.Frame(
                ip="0x108706",
                obj="/home/valparse/examples/invalid_read",
                fn="main",
                dir="/home/valparse/examples/",
                file="invalid_read.c",
                line="50",
            ),
        ],
    )

    assert sig.tid == 5
    assert sig.signo == 11
    assert sig.signame == "SIGSEGV"
    assert sig.sicode == 1
    assert sig.siaddr == "0x0"
    assert len(sig.stack) == 1

    assert sig.get_signal() == signal.SIGSEGV
    sig_str = '''Thread ID: 5
Signal number: 11
Name: SIGSEGV
Code: 1
Address: 0x0
Stack:
  Instruction Pointer: 0x108706
  Object: /home/valparse/examples/invalid_read
  Function: main
  Directory: /home/valparse/examples/
  File: invalid_read.c
  Line: 50
'''

    assert str(sig) == sig_str


def test_Frame():
    """Create an instance of a Frame and check its fields."""
    frame = valparse.Frame(
        ip="0x108706",
        obj="/home/valparse/examples/invalid_read",
        fn="main",
        dir="/home/valparse/examples/",
        file="invalid_read.c",
        line="50",
    )

    assert frame.ip == "0x108706"
    assert frame.obj == "/home/valparse/examples/invalid_read"
    assert frame.fn == "main"
    assert frame.dir == "/home/valparse/examples/"
    assert frame.file == "invalid_read.c"
    assert frame.line == "50"

    frame_str = '''  Instruction Pointer: 0x108706
  Object: /home/valparse/examples/invalid_read
  Function: main
  Directory: /home/valparse/examples/
  File: invalid_read.c
  Line: 50
'''
    assert str(frame) == frame_str


def test_SuppCount():
    """Create an instance of a SuppCount and check its fields."""
    supp = valparse.SuppCount(
        name="test_supp",
        count=1,
    )

    assert supp.name == "test_supp"
    assert supp.count == 1

    supp_count_str = '''Count: 1
Name: test_supp
'''

    assert str(supp) == supp_count_str


def test_Suppression():
    """Create an instance of a Suppression and check its fields."""
    supp = valparse.Suppression(
        name="test_supp",
        kind="Memcheck:Value8",
        stack=[valparse.SFrame(fun="main")],
    )

    assert supp.name == "test_supp"
    assert supp.kind == "Memcheck:Value8"
    assert len(supp.stack) == 1

    supp_str = '''Suppression kind: Memcheck:Value8
Stack frame:
  Function: main
'''

    assert str(supp) == supp_str
