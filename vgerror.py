from xml.etree.ElementTree import Element
from dataclasses import dataclass
from typing import Optional, List
from enum import Enum


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
        args = {'ip': el.find('ip').text}
        for arg in ['obj', 'fn', 'dir', 'file']:
            if el.find(arg) is not None:
                args[arg] = el.find(arg).text
        if el.find('line') is not None:
            args['line'] = int(el.find('line').text)
        return cls(**args)


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
        kind = ValgrindErrorKind(el.find('kind').text)

        if el.find('what') is not None:
            msg = el.find('what').text
        elif el.find('xwhat') is not None:
            msg = el.find('xwhat/text').text
        else:
            raise ValueError('No message found in error element')

        if el.find('auxwhat') is not None:
            msg_secondary = el.find('auxwhat').text
        elif el.find('xauxwhat') is not None:
            msg_secondary = el.find('xauxwhat/text').text
        else:
            msg_secondary = None

        stack = [
            StackFrame.from_xml_element(frame)
            for frame in el.findall('stack/frame')
        ]
        
        bytes_leaked = None
        blocks_leaked = None
        if kind in LEAK_KINDS:
            bytes_leaked = int(el.find('xwhat/leakedbytes').text)
            blocks_leaked = int(el.find('xwhat/leakedblocks').text)
        
        return cls(kind, msg, stack, msg_secondary, bytes_leaked, blocks_leaked)
