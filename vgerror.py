from xml.etree.ElementTree import Element
from dataclasses import dataclass
from typing import Optional, List
from enum import Enum
from util import elem_find_text, elem_find_int

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
        fields = {
            field: elem_find_text(el, field)
            for field in ['ip', 'obj', 'fn', 'dir', 'file']
        }
        fields['line'] = elem_find_int(el, 'line')
        return cls(**fields)

@dataclass
class SFrame:
    obj: Optional[str] = None
    fun: Optional[str] = None 

    @classmethod
    def from_xml_element(cls, el: Element) -> 'SFrame':
        fields = {
            field: elem_find_text(el, field)
            for field in ['obj', 'fun']
        }
        return cls(**fields)

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
        stack = [Frame.from_xml_element(frame) for frame in el.findall('stack/frame') ]
        bytes_leaked = elem_find_int(el, 'xwhat/leakedbytes')
        blocks_leaked = elem_find_int(el, 'xwhat/leakedblocks')
        return cls(kind, msg, stack, msg_secondary, bytes_leaked, blocks_leaked)

@dataclass
class SuppCount:
    count: int
    name: str

    @classmethod
    def from_xml_element(cls, el: Element) -> 'SuppCount':
        count = elem_find_int(el, 'count')
        name = elem_find_text(el, 'name')
        return cls(count, name)

@dataclass
class Suppression:
    name: str
    kind: str
    stack: List[SFrame]
    raw: str
    auxkind: Optional[str] = None

    @classmethod
    def from_xml_element(cls, el: Element) -> 'Suppression':
        name = elem_find_text(el, 'sname')
        kind = elem_find_text(el, 'skind')
        stack = [SFrame.from_xml_element(sframe) for sframe in el.findall('sframe') ]
        raw = elem_find_text(el, 'rawtext')
        auxkind = elem_find_text(el, 'skaux')
        return cls(name, kind, stack, raw, auxkind)