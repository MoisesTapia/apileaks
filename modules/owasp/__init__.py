"""
OWASP Testing Modules Package
Specialized testing modules for OWASP API Security Top 10
"""

from .auth_testing import AuthenticationTestingModule
from .bola_testing import BOLATestingModule
from .business_flows import BusinessFlowsTestingModule
from .function_level_auth import FunctionLevelAuthModule
from .inventory_management import InventoryManagementModule
from .parameter_pollution import ParameterPollutionModule
from .property_level_auth import PropertyLevelAuthModule
from .registry import OWASPModule, OWASPModuleRegistry
from .resource_consumption import ResourceConsumptionModule
from .security_misconfiguration import SecurityMisconfigModule
from .spec_driven_testing import SpecDrivenTestingModule
from .ssrf_testing import SSRFTestingModule
from .unsafe_consumption import UnsafeConsumptionModule

__all__ = [
    "OWASPModuleRegistry",
    "OWASPModule",
    "BOLATestingModule",
    "AuthenticationTestingModule",
    "PropertyLevelAuthModule",
    "FunctionLevelAuthModule",
    "ResourceConsumptionModule",
    "SSRFTestingModule",
    "BusinessFlowsTestingModule",
    "SecurityMisconfigModule",
    "InventoryManagementModule",
    "UnsafeConsumptionModule",
    "ParameterPollutionModule",
    "SpecDrivenTestingModule",
]
