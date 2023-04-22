from typing import Optional, List
from xml.etree.ElementTree import Element


def elem_find_text(el: Element, match: str) -> Optional[str]:
    m = el.find(match)
    return m.text if m is not None else None


def elem_find_int(el: Element, match: str) -> Optional[int]:
    m = el.find(match)
    return int(m.text) if m is not None else None


def elem_find_all_text(el: Element, match: str) -> Optional[List[str]]:
    m = el.findall(match)
    return [match.text for match in m] if m is not None else None
