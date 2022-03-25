# Valgrind XML parser for Protocol 4
# https://sourceware.org/git/?p=valgrind.git;a=blob_plain;f=docs/internals/xml-output-protocol4.txt

import xml.etree.ElementTree as ET

class Parser():

    def __init__(self, xmlfile: str) -> None:
        self.tree = ET.parse(xmlfile)


# Check initial xml string
# Check valgrind output tag
# Check protocol version and protocol tool
# Check for preamble









