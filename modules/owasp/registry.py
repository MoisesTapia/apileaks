"""
OWASP Module Registry
Registry for OWASP API Security testing modules
"""

from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod

from core.logging import get_logger


class OWASPModule(ABC):
    """Base class for OWASP testing modules"""
    
    def __init__(self, config: Any):
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
    
    @abstractmethod
    async def execute_tests(self, endpoints: List[Any]) -> List[Any]:
        """Execute OWASP tests on endpoints"""
        pass
    
    @abstractmethod
    def get_module_name(self) -> str:
        """Get module name"""
        pass


class OWASPModuleRegistry:
    """
    Registry for OWASP testing modules
    
    Manages registration and execution of OWASP API Security testing modules
    """
    
    def __init__(self):
        self.modules: Dict[str, OWASPModule] = {}
        self.logger = get_logger(__name__)
        
        self.logger.info("OWASP Module Registry initialized")
    
    def register_module(self, module: OWASPModule) -> None:
        """
        Register an OWASP testing module
        
        Args:
            module: OWASP module instance
        """
        module_name = module.get_module_name()
        self.modules[module_name] = module
        
        self.logger.info("OWASP module registered", module=module_name)
    
    def get_module(self, module_name: str) -> Optional[OWASPModule]:
        """
        Get registered OWASP module
        
        Args:
            module_name: Name of the module
            
        Returns:
            OWASP module instance or None if not found
        """
        return self.modules.get(module_name)
    
    def get_registered_modules(self) -> List[str]:
        """
        Get list of registered module names
        
        Returns:
            List of registered module names
        """
        return list(self.modules.keys())
    
    async def execute_module(self, module_name: str, endpoints: List[Any]) -> List[Any]:
        """
        Execute specific OWASP module
        
        Args:
            module_name: Name of the module to execute
            endpoints: List of endpoints to test
            
        Returns:
            List of findings from the module
            
        Raises:
            ValueError: If module is not registered
        """
        module = self.get_module(module_name)
        if not module:
            raise ValueError(f"OWASP module not registered: {module_name}")
        
        self.logger.info("Executing OWASP module", module=module_name)
        
        try:
            findings = await module.execute_tests(endpoints)
            
            self.logger.info("OWASP module execution completed",
                           module=module_name,
                           findings_count=len(findings))
            
            return findings
            
        except Exception as e:
            self.logger.error("OWASP module execution failed",
                            module=module_name,
                            error=str(e))
            raise
    
    async def execute_all_modules(self, enabled_modules: List[str], 
                                endpoints: List[Any]) -> Dict[str, List[Any]]:
        """
        Execute all enabled OWASP modules
        
        Args:
            enabled_modules: List of enabled module names
            endpoints: List of endpoints to test
            
        Returns:
            Dictionary mapping module names to their findings
        """
        results = {}
        
        for module_name in enabled_modules:
            if module_name in self.modules:
                try:
                    findings = await self.execute_module(module_name, endpoints)
                    results[module_name] = findings
                except Exception as e:
                    self.logger.error("Failed to execute OWASP module",
                                    module=module_name,
                                    error=str(e))
                    results[module_name] = []
            else:
                self.logger.warning("OWASP module not registered",
                                  module=module_name)
                results[module_name] = []
        
        return results