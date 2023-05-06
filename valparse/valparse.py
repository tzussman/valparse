# Valgrind XML parser for Protocol 4
# https://sourceware.org/git/?p=valgrind.git;a=blob_plain;f=docs/internals/xml-output-protocol4.txt

import signal
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple, Optional

from valparse.util import elem_find_text, elem_find_int, elem_find_all_text


# Errors


class ValgrindFormatError(Exception):
    """Raised when the XML file does not meet Valgrind protocol specifications"""

    pass


class ValgrindVersionError(Exception):
    """Raised when an unsupported Valgrind XML version is passed in"""

    pass


class ValgrindToolError(Exception):
    """Raised when an unsupported Valgrind XML tool is passed in"""

    pass


# Constants

_SUPPORTED_VERSIONS = ['4']
_SUPPORTED_TOOLS = ['memcheck']  # 'helgrind', 'drd', 'exp-ptrcheck'


class ValgrindErrorKind(Enum):
    """Enum representing Valgrind error types"""

    UNINIT_VALUE = 'UninitValue'
    UNINIT_CONDITION = 'UninitCondition'
    CORE_MEM_ERROR = 'CoreMemError'
    INVALID_READ = 'InvalidRead'
    INVALID_WRITE = 'InvalidWrite'
    INVALID_JUMP = 'InvalidJump'
    SYSCALL_PARAM = 'SyscallParam'
    CLIENT_CHECK = 'ClientCheck'
    INVALID_FREE = 'InvalidFree'
    MISMATCHED_FREE = 'MismatchedFree'
    OVERLAP = 'Overlap'
    LEAK_DEFINITELY_LOST = 'Leak_DefinitelyLost'
    LEAK_INDIRECTLY_LOST = 'Leak_IndirectlyLost'
    LEAK_POSSIBLY_LOST = 'Leak_PossiblyLost'
    LEAK_STILL_REACHABLE = 'Leak_StillReachable'
    INVALID_MEM_POOL = 'InvalidMemPool'
    FISHY_VALUE = 'FishyValue'

    def __str__(self):
        return self.value


LEAK_KINDS = [
    ValgrindErrorKind.LEAK_DEFINITELY_LOST,
    ValgrindErrorKind.LEAK_INDIRECTLY_LOST,
    ValgrindErrorKind.LEAK_POSSIBLY_LOST,
    ValgrindErrorKind.LEAK_STILL_REACHABLE,
]


@dataclass
class Arguments:
    """Class to keep track of Valgrind arguments

    Parameters
    ----------
    valexe: str
        Executable corresponding to the Valgrind tool

    valargs: List[str]
        Arguments passed to Valgrind

    exe: str
        Executable corresponding to the program being tested

    exeargs: List[str]
        Arguments passed to the program being tested

    Raises
    ------
    ValgrindFormatError
        If the <args> block does not meet Valgrind protocol specifications
    """

    valexe: str
    valargs: List[str]
    exe: str
    exeargs: List[str]

    @classmethod
    def from_xml_element(cls, el: ET.Element) -> 'Arguments':
        vargv = el.find('./vargv')
        argv = el.find('./argv')

        if not vargv or not argv:
            raise ValgrindFormatError("Invalid <args> format.")

        valexe = elem_find_text(vargv, './exe')
        if not valexe:
            raise ValgrindFormatError("Invalid <vargv> format.")

        valargs = elem_find_all_text(vargv, './arg')

        exe = elem_find_text(argv, './exe')
        if not exe:
            raise ValgrindFormatError("Invalid <argv> format.")

        exeargs = elem_find_all_text(argv, './arg')
        return cls(valexe, valargs, exe, exeargs)

    def __str__(self):
        def value(val):
            return f": {val.__str__()}\n"

        result = "Valgrind executable" + value(self.valexe)
        if self.valargs:
            result += "Valgrind args:"
            for valarg in self.valargs:
                result += " " + valarg

        result += "\nExecutable" + value(self.exe)
        if self.exeargs:
            result += "Args:"
            for exearg in self.exeargs:
                result += " " + exearg

        return result


@dataclass
class Status:
    """Class to keep track of start and end times of Valgrind run

    Parameters
    ----------
    start: str
        Start time of Valgrind run

    end: str
        End time of Valgrind run

    Raises
    ------
    ValgrindFormatError
        If the <status> block does not meet Valgrind protocol specifications
    """

    start: str
    end: str

    @classmethod
    def from_xml_elements(cls, el: List[ET.Element]) -> 'Status':
        """Takes in list of <status> blocks"""
        if len(el) != 2:
            raise ValgrindFormatError("Incorrect number of <status> tags.")

        start, end = None, None

        for s in el:
            if elem_find_text(s, './state') == 'RUNNING':
                start = elem_find_text(s, './time')
            elif elem_find_text(s, './state') == 'FINISHED':
                end = elem_find_text(s, './time')

        return cls(start, end)

    def __str__(self):
        def value(val):
            return f": {val.__str__()}\n"

        result = "Start time" + value(self.start)
        result += "End time" + value(self.end)

        return result


@dataclass
class Frame:
    """Class to keep track of Valgrind stack frame

    Parameters
    ----------
    ip: str
        Instruction pointer

    obj: Optional[str]
        Object name

    fn: Optional[str]
        Function name

    dir: Optional[str]
        Directory name

    file: Optional[str]
        File name

    line: Optional[int]
        Line number
    """

    ip: str  # instruction pointer
    obj: Optional[str] = None
    fn: Optional[str] = None
    dir: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None

    @classmethod
    def from_xml_element(cls, el: ET.Element) -> 'Frame':
        fields = {field: elem_find_text(el, field) for field in ['ip', 'obj', 'fn', 'dir', 'file']}
        fields['line'] = elem_find_int(el, 'line')
        return cls(**fields)

    def __str__(self):
        def indent(name):
            return f"  {name}"

        def value(val):
            return f": {val.__str__()}\n"

        result = indent("Instruction Pointer") + value(self.ip)

        if self.obj is not None:
            result += indent("Object") + value(self.obj)

        if self.fn is not None:
            result += indent("Function") + value(self.fn)

        if self.dir is not None:
            result += indent("Directory") + value(self.dir)

        if self.file is not None:
            result += indent("File") + value(self.file)

        if self.line is not None:
            result += indent("Line") + value(self.line)

        return result


@dataclass
class SFrame:
    """Class to keep track of Valgrind suppression frame

    Parameters
    ----------
    obj: Optional[str]
        Object name

    fun: Optional[str]
        Function name
    """

    obj: Optional[str] = None
    fun: Optional[str] = None

    @classmethod
    def from_xml_element(cls, el: ET.Element) -> 'SFrame':
        fields = {field: elem_find_text(el, field) for field in ['obj', 'fun']}
        return cls(**fields)

    def __str__(self):
        def indent(name):
            return f"  {name}"

        def value(val):
            return f": {val.__str__()}\n"

        result = ""

        if self.obj is not None:
            result += indent("Object") + value(self.obj)

        if self.fun is not None:
            result += indent("Function") + value(self.fun)

        return result


@dataclass
class ValgrindError:
    """Class to keep track of Valgrind error

    Parameters
    ----------
    kind: ValgrindErrorKind
        Kind of Valgrind error

    msg: str
        Error message

    stack: List[Frame]
        Stack trace

    msg_secondary: Optional[str]
        Secondary error message

    bytes_leaked: Optional[int]
        Number of bytes leaked

    blocks_leaked: Optional[int]
        Number of blocks leaked

    Methods
    -------
    isLeak() -> bool
        Returns True if error is a leak, False otherwise
    isError() -> bool
        Returns True if error is an error, False otherwise
    """

    kind: ValgrindErrorKind
    msg: str
    stack: List[Frame]
    msg_secondary: Optional[str] = None
    bytes_leaked: Optional[int] = None
    blocks_leaked: Optional[int] = None

    @classmethod
    def from_xml_element(cls, el: ET.Element) -> 'ValgrindError':
        kind = ValgrindErrorKind(elem_find_text(el, 'kind'))
        msg = elem_find_text(el, 'what') or elem_find_text(el, 'xwhat/text')
        msg_secondary = elem_find_text(el, 'auxwhat') or elem_find_text(el, 'xauxwhat/text')
        stack = [Frame.from_xml_element(frame) for frame in el.findall('stack/frame')]
        bytes_leaked = elem_find_int(el, 'xwhat/leakedbytes')
        blocks_leaked = elem_find_int(el, 'xwhat/leakedblocks')

        if bytes_leaked is None:
            bytes_leaked = 0

        if blocks_leaked is None:
            bytes_leaked = 0

        return cls(kind, msg, stack, msg_secondary, bytes_leaked, blocks_leaked)

    def isLeak(self) -> bool:
        return self.kind in LEAK_KINDS

    def isError(self) -> bool:
        return self.kind not in LEAK_KINDS

    def __str__(self):
        def value(val):
            return f": {val.__str__()}\n"

        if self.isLeak():
            result = "Leak kind" + value(self.kind)
            result += "Leak message" + value(self.msg)
        else:
            result = "Error kind" + value(self.kind)
            result += "Error message" + value(self.msg)

        for frame in self.stack:
            result += f"Stack:\n{frame.__str__()}"

        return result


@dataclass
class SuppCount:
    """Class to keep track of Valgrind suppression count

    Parameters
    ----------
    count: int
        Number of times suppression was applied

    name: str
        Name of suppression
    """

    count: int
    name: str

    @classmethod
    def from_xml_element(cls, el: ET.Element) -> 'SuppCount':
        count = elem_find_int(el, 'count')
        name = elem_find_text(el, 'name')
        return cls(count, name)

    def __str__(self):
        def value(val):
            return f": {val.__str__()}\n"

        result = "Count" + value(self.count)
        result += "Name" + value(self.name)

        return result


@dataclass
class Suppression:
    """Class to keep track of Valgrind suppression

    Parameters
    ----------
    name: str
        Name of suppression

    kind: str
        Kind of suppression

    stack: List[SFrame]
        Suppression stack trace

    auxkind: Optional[str]
        Auxiliary kind of suppression

    Methods
    -------
    createRawText(name: str)
        Creates raw text for suppression
    """

    name: str
    kind: str
    stack: List[SFrame]
    auxkind: Optional[str] = None

    @classmethod
    def from_xml_element(cls, el: ET.Element) -> 'Suppression':
        name = elem_find_text(el, 'sname')
        kind = elem_find_text(el, 'skind')
        stack = [SFrame.from_xml_element(sframe) for sframe in el.findall('sframe')]
        auxkind = elem_find_text(el, 'skaux')
        return cls(name, kind, stack, auxkind)

    def createRawText(self, name: str):
        def line(string):
            return f"   {string}\n"

        rawtext = "{\n" + line(f"<{name}>") + line(self.kind)

        if self.auxkind is not None:
            rawtext += line(self.auxkind)

        for el in self.stack:
            if el.fun is not None:
                rawtext += line(f"fun:{el.fun}")
            if el.obj is not None:
                rawtext += line(f"obj:{el.obj}")

        return rawtext + "}\n"

    def __str__(self):
        def value(val):
            return f": {val.__str__()}\n"

        result = "Suppression kind" + value(self.kind)

        for sframe in self.stack:
            result += f"Stack frame:\n{sframe.__str__()}"

        if self.auxkind is not None:
            result += "Aux kind" + value(self.auxkind)

        return result


@dataclass
class FatalSignal:
    """Class to keep track of fatal signal

    Parameters
    ----------
    tid: int
        Thread ID

    signo: int
        Signal number

    signame: str
        Signal name

    sicode: int
        Signal code

    siaddr: str
        Signal address

    stack: List[Frame]
        Stack trace

    event: Optional[str]
        Event

    threadname: Optional[str]
        Thread name

    Methods
    -------
    get_signal() -> signal.Signals
        Returns signal object from signal name
    """

    tid: int
    signo: int
    signame: str
    sicode: int
    siaddr: str
    stack: List[Frame]
    event: Optional[str] = None
    threadname: Optional[str] = None

    @classmethod
    def from_xml_element(cls, el: ET.Element) -> 'FatalSignal':
        tid = elem_find_int(el, './tid')
        signo = elem_find_int(el, './signo')
        signame = elem_find_text(el, './signame')
        sicode = elem_find_int(el, './sicode')
        siaddr = elem_find_text(el, './siaddr')
        stack = [Frame.from_xml_element(frame) for frame in el.findall('./stack/frame')]
        event = elem_find_text(el, './event')
        threadname = elem_find_text(el, './threadname')
        return cls(tid, signo, signame, sicode, siaddr, stack, event, threadname)

    def get_signal(self) -> signal.Signals:
        return signal.Signals[self.signame]

    def __str__(self):
        def value(val):
            return f": {val.__str__()}\n"

        result = "Thread ID" + value(self.tid)
        result += "Signal number" + value(self.signo)
        result += "Name" + value(self.signame)
        result += "Code" + value(self.sicode)
        result += "Address" + value(self.siaddr)
        for frame in self.stack:
            result += f"Stack:\n{frame.__str__()}"

        if self.event is not None:
            result += "Event" + value(self.event)

        if self.threadname is not None:
            result += "Thread name" + value(self.threadname)

        return result


class Parser:
    """Class to parse Valgrind XML output

    Parameters
    ----------
    xmlfile : str
        XML file to parse

    Raises
    ------
    ValgrindFormatError
        Raised if XML file is not properly formatted
    ValgrindVersionError
        Raised if XML file is for a schema that is not supported
    ValgrindToolError
        Raised if XML file is for a tool that is not supported
    """

    def __init__(self, xmlfile: str) -> None:
        self.tree = ET.parse(xmlfile)
        root = self.tree.getroot()
        if root.tag != 'valgrindoutput':
            raise ValgrindFormatError("No valgrindoutput tag at top level.")

        # Check version
        if root[0].tag != 'protocolversion':
            raise ValgrindFormatError("Nonexistent or incorrect protocolversion tag.")

        if root[0].text not in _SUPPORTED_VERSIONS:
            raise ValgrindVersionError(f"Unsupported version: {root[0].text}")

        # Assuming protocol version 4

        # Check tool
        if root[1].tag != 'protocoltool':
            raise ValgrindFormatError("Nonexistent or incorrect protocoltool tag.")

        if root[1].text not in _SUPPORTED_TOOLS:
            raise ValgrindToolError(f"Unsupported tool: {root[1].text}")

        # Check preamble
        if root[2].tag != 'preamble':
            raise ValgrindFormatError("No preamble tag.")

        # Check pid
        if root[3].tag != 'pid':
            raise ValgrindFormatError("No pid tag.")
        self.pid = int(root[3].text)

        # Check ppid
        if root[4].tag != 'ppid':
            raise ValgrindFormatError("No ppid tag.")
        self.ppid = int(root[4].text)

        # Check tool
        if root[5].tag != 'tool':
            raise ValgrindFormatError("No tool tag.")
        self.tool = root[5].text

        # Check args
        args = root.find('./args')
        if not args:
            raise ValgrindFormatError("No args tag.")
        self.args = Arguments.from_xml_element(args)

        self.errs = []
        self.leaks = []

        for el in root.findall('error'):
            curr = ValgrindError.from_xml_element(el)
            if curr.isError():
                self.errs.append(curr)
            else:
                self.leaks.append(curr)

        self.errsunique = {curr.kind for curr in self.errs}
        self.leaksunique = {curr.kind for curr in self.leaks}
        self.errcount = len(self.errs)
        self.leakcount = len(self.leaks)

        self.suppcounts = [SuppCount.from_xml_element(el) for el in root.find('./suppcounts')]

        self.suppressions = [Suppression.from_xml_element(el) for el in root.findall('./suppression')]

        self.signal = None
        signal = root.find('./fatal_signal')
        if signal:
            self.signal = FatalSignal.from_xml_element(signal)

        self.status = Status.from_xml_elements(root.findall('./status'))

    def hasErrors(self) -> bool:
        """
        Returns
        -------
        bool
            True if there are errors, False otherwise
        """
        return bool(self.errcount)

    def hasLeaks(self) -> bool:
        """
        Returns
        -------
        bool
            True if there are leaks, False otherwise
        """
        return bool(self.leakcount)

    def uniqueErrCount(self) -> int:
        """
        Returns
        -------
        int
            Number of unique errors
        """
        return len(self.errsunique)

    def uniqueLeakCount(self) -> int:
        """
        Returns
        -------
        int
            Number of unique leaks
        """
        return len(self.leaksunique)

    def totalBytesLeaked(self) -> int:
        """
        Returns
        -------
        int
            Total number of bytes leaked
        """
        count = 0
        for el in self.leaks:
            count += el.bytes_leaked
        return count

    def hasFatalSignal(self) -> bool:
        """
        Returns
        -------
        bool
            True if there is a fatal signal, False otherwise
        """
        return bool(self.signal)

    def __str__(self):
        result = self.args.__str__() + "\n\n"

        if self.hasFatalSignal():
            result += "Fatal signal:\n" + self.signal.__str__() + "\n\n"

        result += "Status:\n" + self.status.__str__() + "\n\n"

        result += "Errors present: " + self.errcount.__str__() + "\n\n"
        for err in self.errs:
            result += err.__str__() + "\n"

        result += "\nLeaks present: " + self.leakcount.__str__() + "\n\n"
        for leak in self.leaks:
            result += leak.__str__() + "\n"

        result += "\nSuppressions:\n"

        if len(self.suppressions) == 0:
            result += "none\n"
        for supp in self.suppressions:
            result += supp.__str__() + "\n"

        result += "\nTotal bytes leaked: " + self.totalBytesLeaked().__str__() + "\n"

        return result


def dumpSuppressions(filename: str, supps: List[Tuple[str, Suppression]], append: Optional[bool] = False):
    """Dumps the raw suppression text to file with filename specified.

    Parameters
    ----------
    filename : str
        File to write to
    supps : List[Tuple[str, Suppression]]
        List of tuples of the form (name, Suppression)
    append : Optional[bool], optional
        If True, the file is opened in append mode, by default False
    """
    mode = 'a' if append else 'w'

    contents = ""
    with open(filename, mode) as file:
        for name, supp in supps:
            contents += supp.createRawText(name)
        file.write(contents)
