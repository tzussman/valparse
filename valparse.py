# Valgrind XML parser for Protocol 4
# https://sourceware.org/git/?p=valgrind.git;a=blob_plain;f=docs/internals/xml-output-protocol4.txt

import xml.etree.ElementTree as ET
from typing import List
from dataclasses import dataclass

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


@dataclass
class Arguments():
    """Class to keep track of Valgrind arguments"""
    valexe: str
    valargs: List[str]
    exe: str
    exeargs: List[str]


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
           raise ValgrindFormatError(f"Nonexistent or incorrect protocoltool tag.")

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

        

        for x in root:
            print(x.tag, x.text)


# Check initial xml string prolog - later
# Check valgrind output tag
# Check protocol version and protocol tool
# Check for preamble


a = Parser('../vlctest/bad.xml')
print(a.tree.getroot().tag)





