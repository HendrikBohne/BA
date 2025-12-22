"""
DOM XSS Trigger Strategies - Utils Package
Hilfsfunktionen und Utilities
"""

from .logging_config import setup_logging, get_logger, create_run_logger, LogContext
from .dom_utils import (
    create_element_selector,
    normalize_text,
    is_interactive_element,
    extract_text_content,
    find_form_inputs,
    calculate_dom_depth,
    get_element_path
)
from .url_utils import (
    is_same_origin,
    is_internal_link,
    normalize_url,
    extract_url_parameters,
    build_xss_test_url,
    get_domain,
    url_to_safe_filename,
    parse_spa_routes
)

__all__ = [
    # Logging
    'setup_logging',
    'get_logger',
    'create_run_logger',
    'LogContext',
    
    # DOM Utils
    'create_element_selector',
    'normalize_text',
    'is_interactive_element',
    'extract_text_content',
    'find_form_inputs',
    'calculate_dom_depth',
    'get_element_path',
    
    # URL Utils
    'is_same_origin',
    'is_internal_link',
    'normalize_url',
    'extract_url_parameters',
    'build_xss_test_url',
    'get_domain',
    'url_to_safe_filename',
    'parse_spa_routes',
]
