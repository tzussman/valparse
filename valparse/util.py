from typing import Optional, List
from xml.etree.ElementTree import Element


def elem_find_text(el: Element, match: str) -> Optional[str]:
    """Find text in an XML element.

    Parameters
    ----------
    el : Element
        XML element to search
    match : str
        XML tag to search for

    Returns
    -------
    Optional[str]
        Text of the first matching tag, or None if no match is found
    """
    m = el.find(match)
    return m.text if m is not None else None


def elem_find_int(el: Element, match: str) -> Optional[int]:
    """Find an integer in an XML element.

    Parameters
    ----------
    el : Element
        XML element to search
    match : str
        XML tag to search for

    Returns
    -------
    Optional[int]
        Integer value of the first matching tag, or None if no match is found
    """
    m = el.find(match)
    return int(m.text) if m is not None else None


def elem_find_all_text(el: Element, match: str) -> Optional[List[str]]:
    """Find all text in an XML element.

    Parameters
    ----------
    el : Element
        XML element to search
    match : str
        XML tag to search for

    Returns
    -------
    Optional[List[str]]
        List of text values of all matching tags, or None if no match is found
    """
    m = el.findall(match)
    return [match.text for match in m] if m is not None else None
