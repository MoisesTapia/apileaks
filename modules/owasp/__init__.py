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
from .ssrf_testing import SSRFTestingModule
from .business_flows import BusinessFlowsTestingModule
from .security_misconfiguration import SecurityMisconfigModule
from .inventory_management import InventoryManagementModule
from .unsafe_consumption import UnsafeConsumptionModule

__all__ = ["OWASPModuleRegistry", "OWASPModule", "BOLATestingModule", "AuthenticationTestingModule", "PropertyLevelAuthModule", "FunctionLevelAuthModule", "ResourceConsumptionModule", "SSRFTestingModule", "BusinessFlowsTestingModule", "SecurityMisconfigModule", "InventoryManagementModule", "UnsafeConsumptionModule"]