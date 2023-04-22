import signal
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List
from xml.etree.ElementTree import Element

from valparse.util import elem_find_text, elem_find_int


class ValgrindErrorKind(Enum):
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
class Frame:
    ip: str  # instruction pointer
    obj: Optional[str] = None
    fn: Optional[str] = None
    dir: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None

    @classmethod
    def from_xml_element(cls, el: Element) -> 'Frame':
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
    obj: Optional[str] = None
    fun: Optional[str] = None

    @classmethod
    def from_xml_element(cls, el: Element) -> 'SFrame':
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
    kind: ValgrindErrorKind
    msg: str
    stack: List[Frame]
    msg_secondary: Optional[str] = None
    bytes_leaked: Optional[int] = None
    blocks_leaked: Optional[int] = None

    @classmethod
    def from_xml_element(cls, el: Element) -> 'ValgrindError':
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
    count: int
    name: str

    @classmethod
    def from_xml_element(cls, el: Element) -> 'SuppCount':
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
    name: str
    kind: str
    stack: List[SFrame]
    auxkind: Optional[str] = None

    @classmethod
    def from_xml_element(cls, el: Element) -> 'Suppression':
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
            elif el.obj is not None:
                rawtext += line(f"obj:{el.obj}")

        return rawtext + "}\n"

    def __str__(self):
        def value(val):
            return f": {val.__str__()}\n"

        result = "Suppression kind" + value(self.kind)

        for sframe in self.stack:
            result += f"Stack frame:\n{sframe.__str__()}"

        if self.auxkind is not None:
            result = "Aux kind" + value(self.auxkind)

        return result


@dataclass
class FatalSignal:
    tid: int
    signo: int
    signame: str
    sicode: int
    siaddr: str
    stack: List[Frame]
    event: Optional[str] = None
    threadname: Optional[str] = None

    @classmethod
    def from_xml_element(cls, el: Element) -> 'FatalSignal':
        tid = elem_find_int(el, './tid')
        signo = elem_find_int(el, './signo')
        signame = elem_find_text(el, './signame')
        sicode = elem_find_int(el, './sicode')
        siaddr = elem_find_text(el, './siaddr')
        stack = [Frame.from_xml_element(frame) for frame in el.findall('./stack/frame')]
        event = elem_find_text(el, './event')
        threadname = elem_find_text(el, './threadname')
        return cls(tid, signo, signame, sicode, siaddr, stack, event, threadname)

    def get_signal(self):
        """OS-specific (I think)"""
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
