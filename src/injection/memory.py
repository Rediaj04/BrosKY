import pymem
import pymem.process
from typing import Optional
import ctypes
from ctypes import wintypes
import os
import json
import psutil

class MemoryManager:
    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
        self._setup_functions()
        self._load_config()
        
    def _load_config(self):
        with open('config/config.json', 'r') as f:
            self.config = json.load(f)
            
    def _setup_functions(self):
        """Configura las funciones de Windows API necesarias"""
        self.kernel32.VirtualAllocEx.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, wintypes.SIZE_T,
            wintypes.DWORD, wintypes.DWORD
        ]
        self.kernel32.VirtualAllocEx.restype = wintypes.LPVOID
        
        self.kernel32.WriteProcessMemory.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID,
            wintypes.SIZE_T, ctypes.POINTER(wintypes.SIZE_T)
        ]
        self.kernel32.WriteProcessMemory.restype = wintypes.BOOL
        
        self.kernel32.CreateRemoteThread.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, wintypes.SIZE_T,
            wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
            wintypes.LPVOID
        ]
        self.kernel32.CreateRemoteThread.restype = wintypes.HANDLE
        
    def _find_process(self) -> Optional[int]:
        """Busca el proceso específico de Roblox"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == self.config['process_name']:
                    # Verificar que la ventana tenga el título correcto
                    try:
                        import win32gui
                        def callback(hwnd, pid):
                            if win32gui.IsWindowVisible(hwnd):
                                title = win32gui.GetWindowText(hwnd)
                                if self.config['window_title'] in title:
                                    return hwnd
                            return None
                            
                        hwnd = win32gui.EnumWindows(callback, proc.info['pid'])
                        if hwnd:
                            return proc.info['pid']
                    except:
                        return proc.info['pid']
            return None
        except Exception as e:
            print(f"Error al buscar proceso: {str(e)}")
            return None
            
    def attach_to_game(self) -> Optional[pymem.Pymem]:
        """Intenta conectarse al proceso del juego"""
        try:
            pid = self._find_process()
            if not pid:
                print(f"No se encontró el proceso {self.config['process_name']}")
                return None
                
            process = pymem.Pymem(pid)
            print(f"Conectado exitosamente a {self.config['process_name']} (PID: {pid})")
            return process
        except pymem.exception.ProcessNotFound:
            print(f"No se encontró el proceso {self.config['process_name']}")
            return None
        except Exception as e:
            print(f"Error al conectar: {str(e)}")
            return None
            
    def execute_script(self, process: pymem.Pymem, script: str) -> bool:
        """Ejecuta un script Lua en el proceso del juego"""
        try:
            # Convertir el script a bytes
            script_bytes = script.encode('utf-8')
            
            # Asignar memoria para el script
            script_address = self.kernel32.VirtualAllocEx(
                process.process_handle,
                None,
                len(script_bytes) + 1,
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x40     # PAGE_EXECUTE_READWRITE
            )
            
            if not script_address:
                raise Exception("Error al asignar memoria para el script")
                
            # Escribir el script en memoria
            bytes_written = wintypes.SIZE_T()
            if not self.kernel32.WriteProcessMemory(
                process.process_handle,
                script_address,
                script_bytes,
                len(script_bytes) + 1,
                ctypes.byref(bytes_written)
            ):
                raise Exception("Error al escribir el script en memoria")
                
            # Encontrar la función de ejecución de Lua
            lua_state = self._find_lua_state(process)
            if not lua_state:
                raise Exception("No se pudo encontrar el estado de Lua")
                
            # Ejecutar el script
            self._execute_lua_script(process, lua_state, script_address)
            
            return True
            
        except Exception as e:
            print(f"Error al ejecutar script: {str(e)}")
            return False
            
    def _find_lua_state(self, process: pymem.Pymem) -> Optional[int]:
        """Encuentra el estado de Lua en el proceso"""
        try:
            # Buscar en la memoria del proceso
            memory_info = process.memory_info()
            
            # Buscar patrones específicos de Lua
            for address in range(memory_info.BaseAddress, memory_info.BaseAddress + memory_info.RegionSize, 4):
                try:
                    value = process.read_int(address)
                    if self._is_lua_state(value):
                        return address
                except:
                    continue
                    
            return None
            
        except Exception as e:
            print(f"Error al buscar estado de Lua: {str(e)}")
            return None
            
    def _is_lua_state(self, address: int) -> bool:
        """Verifica si una dirección es un estado de Lua válido"""
        # Implementar verificación del estado de Lua
        return True
        
    def _execute_lua_script(self, process: pymem.Pymem, lua_state: int, script_address: int):
        """Ejecuta un script en el estado de Lua especificado"""
        # Implementar ejecución del script
        pass 