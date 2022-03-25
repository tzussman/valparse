from xml.etree.ElementTree import Element
from typing import Optional

def elem_find_text(el: Element, match: str) -> Optional[str]:
    return el.find(match).text if el.find(match) is not None else None

def elem_find_int(el: Element, match: str) -> Optional[int]:
    return int(el.find(match).text) if el.find(match) is not None else None
