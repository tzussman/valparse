# Valgrind XML parser for Protocol 4
# https://sourceware.org/git/?p=valgrind.git;a=blob_plain;f=docs/internals/xml-output-protocol4.txt

import xml.etree.ElementTree as ET
from typing import List, Tuple, Optional
from dataclasses import dataclass
from vgerror import ValgrindError, SuppCount, Suppression, FatalSignal
from util import elem_find_text, elem_find_all_text

class ValgrindFormatError(Exception):
    """Raised when the XML file does not meet Valgrind protocol specifications"""
    pass

class ValgrindVersionError(Exception):
    """Raised when an unsupported Valgrind XML version is passed in"""
    pass

class ValgrindToolError(Exception):
    """Raised when an unsupported Valgrind XML tool is passed in"""
    pass

_SUPPORTED_VERSIONS = ['4']
_SUPPORTED_TOOLS = ['memcheck'] # 'helgrind', 'drd', 'exp-ptrcheck'

# dumps the raw suppression text to file with filename specified
# if mode is specified as True, the file is opened in append mode.
# if mode is unspecified or specified as False, the file is opened in write mode.
def dumpSuppressions(filename: str, supps: List[Tuple[str, Suppression]], append: Optional[bool] = False):
    mode = 'w'
    if append:
        mode = 'a'

    contents = ""
    with open(filename, mode) as file:
        for name, supp in supps:
            contents += supp.createRawText(name)
        file.write(contents)

@dataclass
class Arguments():
    """Class to keep track of Valgrind arguments"""
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

@dataclass
class Status():
    """Class to keep track of start and end time"""
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


class Parser():

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
        
        self.errsunique = { curr.kind for curr in self.errs }
        self.leaksunique = { curr.kind for curr in self.leaks }
        self.errcount = len(self.errs)
        self.leakcount = len(self.leaks)

        self.suppcounts = [
            SuppCount.from_xml_element(el)
            for el in root.find('./suppcounts')
        ]

        self.suppressions = [
            Suppression.from_xml_element(el)
            for el in root.findall('./suppression')
        ]

        self.signal = None
        signal = root.find('./fatal_signal')
        if signal:
            self.signal = FatalSignal.from_xml_element(signal)

        self.status = Status.from_xml_elements(root.findall('./status'))

    def hasErrors(self) -> bool:
        return bool(self.errcount)

    def hasLeaks(self) -> bool:
        return bool(self.leakcount)

    def uniqueErrCount(self) -> int:
        return len(self.errsunique)

    def uniqueLeakCount(self) -> int:
        return len(self.leaksunique)

    def totalBytesLeaked(self) -> int:
        count = 0
        for el in self.leaks:
            count += el.bytes_leaked
        return count

    def hasFatalSignal(self) -> bool:
        return bool(self.signal)

    def __str__(self):
        result = "Errors present: " + self.errcount.__str__() + "\n\n"
        for err in self.errs:
            result += err.__str__() + "\n"

        result += "\nLeaks present: " + self.leakcount.__str__() + "\n\n"
        for leak in self.leaks:
            result += leak.__str__() + "\n"
        
        result += "\nSuppressions: \n" 
        
        if len(self.suppressions) == 0:
            result += "none\n"
        for supp in self.suppressions:
            result += supp.__str__() + "\n"

        result += "\nTotal bytes leaked: " + self.totalBytesLeaked().__str__() + "\n"

        return result

a = Parser('examples/bad-test.xml')
# print(a.__str__())

b = Parser('examples/bad.xml')
print(b.__str__())