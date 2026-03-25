"""
Detection module - XSS and SQLi scanners
"""
from .xss_scanner import XSSScanner
from .sqli_scanner import SQLiScanner
from .reflected import ReflectedDetector
from .blind import BlindDetector

__all__ = ['XSSScanner', 'SQLiScanner', 'ReflectedDetector', 'BlindDetector']