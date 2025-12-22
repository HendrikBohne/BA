"""
DOM XSS Trigger Strategies - DOM Utilities
Hilfsfunktionen für DOM-Operationen
"""
import re
from typing import List, Dict, Optional


def create_element_selector(element: Dict) -> str:
    """
    Erstellt einen CSS-Selector für ein Element.
    
    Args:
        element: Dictionary mit Element-Informationen
        
    Returns:
        CSS-Selector String
    """
    tag = element.get('tag', 'div').lower()
    
    # ID hat höchste Priorität
    if element.get('id'):
        return f"{tag}#{element['id']}"
    
    # Name-Attribut
    if element.get('name'):
        return f"{tag}[name=\"{element['name']}\"]"
    
    # Klassen
    if element.get('class'):
        classes = element['class'].split() if isinstance(element['class'], str) else element['class']
        if classes:
            # Nur erste Klasse verwenden (spezifischer)
            return f"{tag}.{classes[0]}"
    
    # Fallback auf Tag
    return tag


def normalize_text(text: str, max_length: int = 100) -> str:
    """
    Normalisiert Text für Vergleiche und Anzeige.
    
    Args:
        text: Zu normalisierender Text
        max_length: Maximale Länge
        
    Returns:
        Normalisierter Text
    """
    if not text:
        return ""
    
    # Whitespace normalisieren
    text = ' '.join(text.split())
    
    # Kürzen
    if len(text) > max_length:
        text = text[:max_length - 3] + "..."
    
    return text


def is_interactive_element(tag: str, attributes: Dict) -> bool:
    """
    Prüft ob ein Element interaktiv ist.
    
    Args:
        tag: HTML-Tag
        attributes: Element-Attribute
        
    Returns:
        True wenn interaktiv
    """
    # Native interaktive Elemente
    interactive_tags = {
        'a', 'button', 'input', 'select', 'textarea',
        'details', 'summary', 'dialog'
    }
    
    if tag.lower() in interactive_tags:
        return True
    
    # ARIA Roles
    role = attributes.get('role', '').lower()
    interactive_roles = {'button', 'link', 'tab', 'menuitem', 'checkbox', 'radio'}
    
    if role in interactive_roles:
        return True
    
    # Event Handler
    event_attrs = ['onclick', 'onsubmit', 'onchange', 'oninput']
    if any(attr in attributes for attr in event_attrs):
        return True
    
    # Tabindex macht Element fokussierbar/interaktiv
    if 'tabindex' in attributes:
        return True
    
    return False


def extract_text_content(html: str) -> str:
    """
    Extrahiert Text-Content aus HTML.
    
    Args:
        html: HTML-String
        
    Returns:
        Extrahierter Text
    """
    # Entferne Script und Style Tags
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
    
    # Entferne alle HTML-Tags
    text = re.sub(r'<[^>]+>', ' ', html)
    
    # Decode HTML-Entities
    text = text.replace('&nbsp;', ' ')
    text = text.replace('&amp;', '&')
    text = text.replace('&lt;', '<')
    text = text.replace('&gt;', '>')
    text = text.replace('&quot;', '"')
    
    # Whitespace normalisieren
    text = ' '.join(text.split())
    
    return text


def find_form_inputs(form_html: str) -> List[Dict]:
    """
    Findet alle Input-Felder in einem Formular.
    
    Args:
        form_html: HTML des Formulars
        
    Returns:
        Liste von Input-Definitionen
    """
    inputs = []
    
    # Input-Tags finden
    input_pattern = r'<input\s+([^>]*)>'
    for match in re.finditer(input_pattern, form_html, re.IGNORECASE):
        attrs_str = match.group(1)
        attrs = _parse_attributes(attrs_str)
        
        if attrs.get('type', 'text').lower() != 'hidden':
            inputs.append({
                'type': 'input',
                'input_type': attrs.get('type', 'text'),
                'name': attrs.get('name', ''),
                'id': attrs.get('id', ''),
                'placeholder': attrs.get('placeholder', '')
            })
    
    # Textarea finden
    textarea_pattern = r'<textarea\s+([^>]*)>'
    for match in re.finditer(textarea_pattern, form_html, re.IGNORECASE):
        attrs_str = match.group(1)
        attrs = _parse_attributes(attrs_str)
        
        inputs.append({
            'type': 'textarea',
            'name': attrs.get('name', ''),
            'id': attrs.get('id', '')
        })
    
    # Select finden
    select_pattern = r'<select\s+([^>]*)>'
    for match in re.finditer(select_pattern, form_html, re.IGNORECASE):
        attrs_str = match.group(1)
        attrs = _parse_attributes(attrs_str)
        
        inputs.append({
            'type': 'select',
            'name': attrs.get('name', ''),
            'id': attrs.get('id', '')
        })
    
    return inputs


def _parse_attributes(attrs_str: str) -> Dict[str, str]:
    """Parst HTML-Attribute aus String"""
    attrs = {}
    
    # Pattern für Attribute: name="value" oder name='value' oder name=value
    pattern = r'(\w+)(?:=(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+)))?'
    
    for match in re.finditer(pattern, attrs_str):
        name = match.group(1).lower()
        value = match.group(2) or match.group(3) or match.group(4) or ''
        attrs[name] = value
    
    return attrs


def calculate_dom_depth(page_evaluate_result: List[Dict]) -> int:
    """
    Berechnet die maximale DOM-Tiefe.
    
    Args:
        page_evaluate_result: Ergebnis von page.evaluate() mit Element-Tiefen
        
    Returns:
        Maximale Tiefe
    """
    if not page_evaluate_result:
        return 0
    
    max_depth = 0
    for item in page_evaluate_result:
        depth = item.get('depth', 0)
        if depth > max_depth:
            max_depth = depth
    
    return max_depth


def get_element_path(element: Dict) -> str:
    """
    Erstellt einen lesbaren Pfad zu einem Element.
    
    Args:
        element: Element-Dictionary
        
    Returns:
        Pfad wie "body > div#main > form > input"
    """
    path_parts = element.get('path', [])
    
    if not path_parts:
        return create_element_selector(element)
    
    return ' > '.join(path_parts)
