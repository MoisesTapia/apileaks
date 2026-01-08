"""
OWASP Testing Modules Package
Specialized testing modules for OWASP API Security Top 10
"""

from .registry import OWASPModuleRegistry, OWASPModule
from .bola_testing import BOLATestingModule
from .auth_testing import AuthenticationTestingModule
from .property_level_auth import PropertyLevelAuthModule
from .function_level_auth import FunctionLevelAuthModule
from .resource_consumption import ResourceConsumptionModule

__all__ = ["OWASPModuleRegistry", "OWASPModule", "BOLATestingModule", "AuthenticationTestingModule", "PropertyLevelAuthModule", "FunctionLevelAuthModule", "ResourceConsumptionModule"]