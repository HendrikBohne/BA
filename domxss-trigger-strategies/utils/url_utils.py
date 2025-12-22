"""
DOM XSS Trigger Strategies - URL Utilities
Hilfsfunktionen für URL-Operationen
"""
import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, urljoin
from typing import Dict, Optional, List, Tuple


def is_same_origin(url1: str, url2: str) -> bool:
    """
    Prüft ob zwei URLs den gleichen Origin haben.
    
    Args:
        url1: Erste URL
        url2: Zweite URL
        
    Returns:
        True wenn gleicher Origin (scheme + host + port)
    """
    parsed1 = urlparse(url1)
    parsed2 = urlparse(url2)
    
    return (
        parsed1.scheme == parsed2.scheme and
        parsed1.netloc == parsed2.netloc
    )


def is_internal_link(href: str, base_url: str) -> bool:
    """
    Prüft ob ein Link intern ist (gleiche Domain).
    
    Args:
        href: Link-Href
        base_url: Basis-URL der Seite
        
    Returns:
        True wenn interner Link
    """
    if not href:
        return False
    
    # Offensichtlich interne Links
    if href.startswith('#'):
        return True
    if href.startswith('/') and not href.startswith('//'):
        return True
    
    # Offensichtlich externe/ungültige Links
    if href.startswith('mailto:') or href.startswith('tel:'):
        return False
    if href.startswith('javascript:'):
        return False
    if href.startswith('data:'):
        return False
    
    # Vollständige URLs vergleichen
    try:
        base_parsed = urlparse(base_url)
        href_parsed = urlparse(urljoin(base_url, href))
        
        return base_parsed.netloc == href_parsed.netloc
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """
    Normalisiert eine URL für Vergleiche.
    
    - Entfernt Fragment
    - Sortiert Query-Parameter
    - Lowercase für Scheme und Host
    
    Args:
        url: Zu normalisierende URL
        
    Returns:
        Normalisierte URL
    """
    try:
        parsed = urlparse(url)
        
        # Query-Parameter sortieren
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(query_dict.items()), doseq=True)
        
        # URL neu zusammensetzen (ohne Fragment)
        normalized = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            sorted_query,
            ''  # Kein Fragment
        ))
        
        return normalized
    except Exception:
        return url


def extract_url_parameters(url: str) -> Dict[str, List[str]]:
    """
    Extrahiert alle Parameter aus einer URL.
    
    Args:
        url: URL mit Parametern
        
    Returns:
        Dictionary der Parameter
    """
    parsed = urlparse(url)
    
    params = {}
    
    # Query-Parameter
    if parsed.query:
        params.update(parse_qs(parsed.query))
    
    # Hash-Parameter (oft bei SPAs)
    if parsed.fragment:
        # Versuche Hash als Query-String zu parsen
        if '=' in parsed.fragment:
            # Format: #param=value
            fragment_clean = parsed.fragment.lstrip('#')
            try:
                params.update(parse_qs(fragment_clean))
            except Exception:
                params['hash'] = [parsed.fragment]
        else:
            params['hash'] = [parsed.fragment]
    
    return params


def build_xss_test_url(base_url: str, payload: str, injection_point: str = 'hash') -> str:
    """
    Erstellt eine Test-URL mit XSS-Payload.
    
    Args:
        base_url: Basis-URL
        payload: XSS-Payload
        injection_point: Wo der Payload eingefügt wird ('hash', 'query', 'path')
        
    Returns:
        URL mit Payload
    """
    parsed = urlparse(base_url)
    
    if injection_point == 'hash':
        return f"{base_url.split('#')[0]}#{payload}"
    
    elif injection_point == 'query':
        # Füge als Parameter hinzu
        query_params = parse_qs(parsed.query)
        query_params['xss'] = [payload]
        new_query = urlencode(query_params, doseq=True)
        
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    
    elif injection_point == 'path':
        # Hänge an Pfad an
        new_path = parsed.path.rstrip('/') + '/' + payload
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            new_path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
    
    return base_url


def get_domain(url: str) -> str:
    """
    Extrahiert die Domain aus einer URL.
    
    Args:
        url: URL
        
    Returns:
        Domain (z.B. "example.com")
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def url_to_safe_filename(url: str, max_length: int = 50) -> str:
    """
    Konvertiert URL zu einem sicheren Dateinamen.
    
    Args:
        url: URL
        max_length: Maximale Länge
        
    Returns:
        Sicherer Dateiname
    """
    # Entferne Protokoll
    name = re.sub(r'^https?://', '', url)
    
    # Ersetze unsichere Zeichen
    name = re.sub(r'[^\w\-.]', '_', name)
    
    # Entferne mehrfache Unterstriche
    name = re.sub(r'_+', '_', name)
    
    # Kürze
    if len(name) > max_length:
        name = name[:max_length]
    
    return name.strip('_')


def parse_spa_routes(urls: List[str]) -> List[Tuple[str, str]]:
    """
    Analysiert SPA-Routen aus einer Liste von URLs.
    
    Args:
        urls: Liste von URLs
        
    Returns:
        Liste von (route, full_url) Tupeln
    """
    routes = []
    
    for url in urls:
        parsed = urlparse(url)
        
        # Hash-Route (React Router etc.)
        if parsed.fragment:
            route = '#' + parsed.fragment.split('?')[0]
            routes.append((route, url))
        
        # Path-Route
        elif parsed.path and parsed.path != '/':
            route = parsed.path
            routes.append((route, url))
    
    return routes
