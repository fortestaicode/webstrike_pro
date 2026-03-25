"""
Integrations module - Nuclei and FFUF
"""
from .nuclei import NucleiIntegration
from .ffuf_bridge import FFUFBridge

__all__ = ['NucleiIntegration', 'FFUFBridge']