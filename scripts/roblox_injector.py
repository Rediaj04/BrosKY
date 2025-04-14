import sys
import os
import ctypes
from ctypes import wintypes
import win32api
import win32process
import psutil
import traceback

# Obtener la ruta absoluta al directorio raíz del proyecto
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT_DIR)

# Importar los módulos del proyecto
from src.core.lua_detector import LuaDetector
from src.core.lua_injector import LuaInjector

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Reejecuta el script como administrador"""
    try:
        if not is_admin():
            print("Reejecutando como administrador...")
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable, 
                " ".join(sys.argv), 
                None, 
                1
            )
            sys.exit()
    except Exception as e:
        print(f"Error al reejecutar como administrador: {str(e)}")
        return False
    return True

class RobloxInjector:
    def __init__(self):
        self.process_name = "RobloxPlayerBeta.exe"
        self.process_handle = None
        self.process_id = None
        self.lua_detector = None
        self.lua_injector = None

    def find_roblox_process(self):
        """Busca el proceso de Roblox en ejecución"""
        print("Buscando proceso de Roblox...")
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] == self.process_name:
                        self.process_id = proc.info['pid']
                        print(f"Proceso encontrado con PID: {self.process_id}")
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            print("No se encontró el proceso de Roblox")
            print("Asegúrate de que Roblox esté en ejecución")
            return False
        except Exception as e:
            print(f"Error al buscar proceso: {str(e)}")
            traceback.print_exc()
            return False

    def open_process(self):
        """Abre un handle al proceso de Roblox"""
        if not self.process_id:
            print("No hay PID de proceso disponible")
            return False
        
        try:
            print(f"Intentando abrir proceso con PID: {self.process_id}")
            self.process_handle = win32api.OpenProcess(
                0x1F0FFF,  # PROCESS_ALL_ACCESS
                False,
                self.process_id
            )
            if self.process_handle:
                print(f"Handle del proceso abierto: {self.process_handle}")
                return True
            else:
                error = ctypes.get_last_error()
                print(f"Error al abrir proceso: {error}")
                print("Asegúrate de ejecutar como administrador")
                return False
        except Exception as e:
            print(f"Error al abrir el proceso: {str(e)}")
            traceback.print_exc()
            return False

    def initialize(self):
        """Inicializa el inyector"""
        print("\nIniciando inicialización...")
        
        if not self.find_roblox_process():
            return False
            
        if not self.open_process():
            return False
            
        print("\nInicializando detector de Lua...")
        # Inicializar el detector de Lua
        self.lua_detector = LuaDetector(self.process_handle)
        
        # Buscar el estado de Lua
        if not self.lua_detector.find_lua_state():
            print("No se pudo encontrar el estado de Lua")
            return False
            
        # Verificar que el estado de Lua es válido
        if not self.lua_detector.verify_lua_state():
            print("El estado de Lua encontrado no es válido")
            return False
            
        print("\nInicializando inyector de Lua...")
        # Inicializar el inyector de Lua
        self.lua_injector = LuaInjector(
            self.process_handle,
            self.lua_detector.lua_state
        )
            
        print("Inicialización completada exitosamente")
        return True
        
    def inject_script(self, script):
        """Inyecta un script Lua en el proceso"""
        if not self.lua_injector:
            print("El inyector no está inicializado")
            return False
            
        return self.lua_injector.inject_script(script)

    def cleanup(self):
        """Limpia los recursos"""
        print("\nLimpiando recursos...")
        if self.lua_injector:
            self.lua_injector.cleanup()
            
        if self.process_handle:
            try:
                win32api.CloseHandle(self.process_handle)
                print("Handle del proceso cerrado")
            except Exception as e:
                print(f"Error al cerrar handle: {str(e)}")

def main():
    print("Iniciando BrosKY Injector...")
    
    # Reejecutar como administrador si es necesario
    if not is_admin():
        run_as_admin()
        return

    injector = RobloxInjector()
    try:
        if injector.initialize():
            print("\nListo para inyectar scripts")
            
            # Ejemplo de script para inyectar
            test_script = """
            print("¡Hola desde BrosKY!")
            game:GetService("Players").LocalPlayer.Character.Humanoid.WalkSpeed = 50
            """
            
            print("\nInyectando script de prueba...")
            # Inyectar el script
            if injector.inject_script(test_script):
                print("Script inyectado exitosamente")
            else:
                print("Error al inyectar script")
        else:
            print("Error durante la inicialización")
    except Exception as e:
        print(f"Error general: {str(e)}")
        traceback.print_exc()
    finally:
        injector.cleanup()

if __name__ == "__main__":
    main() 