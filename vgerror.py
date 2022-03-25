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
class StackFrame:
    ip: str  # instruction pointer
    obj: Optional[str] = None
    fn: Optional[str] = None 
    dir: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None

    @classmethod
    def from_xml_element(cls, el: Element) -> 'StackFrame':
        fields = {
            field: elem_find_text(el, field)
            for field in ['ip', 'obj', 'fn', 'dir', 'file']
        }
        fields['line'] = elem_find_int(el, 'line')
        return cls(**fields)


@dataclass
class ValgrindError:
    kind: ValgrindErrorKind
    msg: str
    stack: List[StackFrame]
    msg_secondary: Optional[str] = None
    bytes_leaked: Optional[int] = None
    blocks_leaked: Optional[int] = None

    @classmethod
    def from_xml_element(cls, el: Element) -> 'ValgrindError':
        kind = ValgrindErrorKind(elem_find_text(el, 'kind'))
        msg = elem_find_text(el, 'what') or elem_find_text(el, 'xwhat/text')
        msg_secondary = elem_find_text(el, 'auxwhat') or elem_find_text(el, 'xauxwhat/text')
        stack = [StackFrame.from_xml_element(frame) for frame in el.findall('stack/frame') ]
        bytes_leaked = elem_find_int(el, 'xwhat/leakedbytes')
        blocks_leaked = elem_find_int(el, 'xwhat/leakedblocks')
        return cls(kind, msg, stack, msg_secondary, bytes_leaked, blocks_leaked)
