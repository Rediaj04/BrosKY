import pymem
import pymem.process
from typing import Optional, Dict, Any
import os
import sys
import time
from ..utils.logger import Logger
from ..injection.memory import MemoryManager

class GameExecutor:
    def __init__(self):
        self.logger = Logger()
        self.memory_manager = MemoryManager()
        self.process: Optional[pymem.Pymem] = None
        self.scripts: Dict[str, str] = {}
        
    def attach_to_game(self) -> bool:
        """Intenta conectarse al proceso del juego"""
        try:
            self.process = self.memory_manager.attach_to_game()
            if self.process:
                self.logger.info(f"Conectado exitosamente al juego")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Error al conectar: {str(e)}")
            return False
            
    def execute_script(self, script: str, script_name: str = "unnamed") -> bool:
        """Ejecuta un script en el proceso del juego"""
        try:
            if not self.process:
                raise Exception("No hay proceso conectado")
                
            # Guardar el script
            self.scripts[script_name] = script
            
            # Ejecutar el script
            if self.memory_manager.execute_script(self.process, script):
                self.logger.info(f"Script '{script_name}' ejecutado exitosamente")
                return True
            else:
                self.logger.error(f"Error al ejecutar el script '{script_name}'")
                return False
                
        except Exception as e:
            self.logger.error(f"Error al ejecutar script: {str(e)}")
            return False
            
    def save_script(self, script_name: str, script_content: str) -> None:
        """Guarda un script en el directorio de scripts"""
        script_path = os.path.join("scripts", f"{script_name}.lua")
        with open(script_path, "w") as f:
            f.write(script_content)
        self.logger.info(f"Script guardado como {script_path}")
        
    def load_script(self, script_name: str) -> Optional[str]:
        """Carga un script desde el directorio de scripts"""
        script_path = os.path.join("scripts", f"{script_name}.lua")
        try:
            with open(script_path, "r") as f:
                content = f.read()
            self.logger.info(f"Script {script_name} cargado exitosamente")
            return content
        except Exception as e:
            self.logger.error(f"Error al cargar script: {str(e)}")
            return None 