# Package initializer
#!/usr/bin/env python3
"""
Paquete de analizadores de vulnerabilidades modulares
Exporta las clases principales para uso externo
"""

# Importar clases base
from .vulnerability_analyzer_base import (
    VulnerabilityAnalyzerBase,
    VulnerabilityType,
    Severity,
    Vulnerability
)

# Importar analyzers específicos por dominio
from .vulnerability_analyzer_iam import IAMVulnerabilityAnalyzer
from .vulnerability_analyzer_network import NetworkVulnerabilityAnalyzer

# Importar el coordinador de módulos
from .vulnerability_analyzer_modules import ModuleVulnerabilityAnalyzer

# Para compatibilidad con código existente que importa IAMNetworkVulnerabilityAnalyzer
# Crear un alias para mantener la retrocompatibilidad


class IAMNetworkVulnerabilityAnalyzer(ModuleVulnerabilityAnalyzer):
    """
    Clase de compatibilidad para código existente.
    Redirige al nuevo ModuleVulnerabilityAnalyzer
    """

    def __init__(self, logger=None):
        super().__init__(logger)
        self.logger.info(
            "Usando ModuleVulnerabilityAnalyzer con compatibilidad IAMNetwork")


# Definir qué se exporta cuando se hace "from analyzers import *"
__all__ = [
    # Clases base
    'VulnerabilityAnalyzerBase',
    'VulnerabilityType',
    'Severity',
    'Vulnerability',

    # Analyzers específicos
    'IAMVulnerabilityAnalyzer',
    'NetworkVulnerabilityAnalyzer',

    # Coordinador principal
    'ModuleVulnerabilityAnalyzer',

    # Compatibilidad
    'IAMNetworkVulnerabilityAnalyzer'
]

# Información del paquete
__version__ = '2.0.0'
__author__ = 'Security Assessment Team'
__description__ = 'Modular vulnerability analyzers for Huawei Cloud Security Assessment'
