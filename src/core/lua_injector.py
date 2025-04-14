import ctypes
from ctypes import wintypes
import win32api
import win32process
import traceback

class LuaInjector:
    def __init__(self, process_handle, lua_state_address):
        self.process_handle = process_handle
        self.lua_state_address = lua_state_address
        self.allocated_memory = []
        
        # Definir constantes de Lua
        self.LUA_TNONE = -1
        self.LUA_TNIL = 0
        self.LUA_TBOOLEAN = 1
        self.LUA_TLIGHTUSERDATA = 2
        self.LUA_TNUMBER = 3
        self.LUA_TSTRING = 4
        self.LUA_TTABLE = 5
        self.LUA_TFUNCTION = 6
        self.LUA_TUSERDATA = 7
        self.LUA_TTHREAD = 8
        
        # Definir funciones de Lua
        self._define_lua_functions()
        
    def _define_lua_functions(self):
        """Define las funciones de Lua que necesitamos"""
        # Obtener la base de RobloxPlayerBeta.exe
        process = win32process.GetProcessId(self.process_handle)
        modules = win32process.EnumProcessModules(self.process_handle)
        base_address = modules[0]
        
        # Definir las funciones de Lua
        self.luaL_loadstring = ctypes.CFUNCTYPE(
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_char_p
        )(base_address + 0x1234567)  # Necesitamos la dirección correcta
        
        self.lua_pcall = ctypes.CFUNCTYPE(
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int
        )(base_address + 0x2345678)  # Necesitamos la dirección correcta
        
    def allocate_memory(self, size):
        """Asigna memoria en el proceso de Roblox"""
        try:
            # Convertir el handle a un entero para usarlo con ctypes
            handle_int = int(self.process_handle)
            
            # Asignar memoria
            address = ctypes.windll.kernel32.VirtualAllocEx(
                handle_int,
                None,
                size,
                0x1000,  # MEM_COMMIT
                0x40     # PAGE_EXECUTE_READWRITE
            )
            
            if address:
                self.allocated_memory.append(address)
                return address
            else:
                error = ctypes.get_last_error()
                print(f"Error al asignar memoria: {error}")
                return None
                
        except Exception as e:
            print(f"Error al asignar memoria: {str(e)}")
            return None
            
    def write_memory(self, address, data):
        """Escribe datos en la memoria del proceso"""
        try:
            # Convertir el handle a un entero para usarlo con ctypes
            handle_int = int(self.process_handle)
            
            # Crear buffer con los datos
            buffer = ctypes.create_string_buffer(data)
            bytes_written = ctypes.c_size_t()
            
            # Escribir en memoria
            result = ctypes.windll.kernel32.WriteProcessMemory(
                handle_int,
                address,
                buffer,
                len(buffer),
                ctypes.byref(bytes_written)
            )
            
            if result:
                return True
            else:
                error = ctypes.get_last_error()
                print(f"Error al escribir memoria: {error}")
                return False
                
        except Exception as e:
            print(f"Error al escribir memoria: {str(e)}")
            return False
            
    def inject_script(self, script):
        """Inyecta y ejecuta un script Lua"""
        try:
            print(f"Inyectando script: {script[:50]}...")
            
            # Asignar memoria para el script
            script_address = self.allocate_memory(len(script) + 1)
            if not script_address:
                return False
                
            # Escribir el script en memoria
            if not self.write_memory(script_address, script):
                return False
                
            # Cargar el script en Lua
            result = self.luaL_loadstring(
                self.lua_state_address,
                script_address
            )
            
            if result != 0:
                print(f"Error al cargar script: {result}")
                return False
                
            # Ejecutar el script
            result = self.lua_pcall(
                self.lua_state_address,
                0,  # número de argumentos
                0,  # número de resultados
                0   # índice del mensaje de error
            )
            
            if result != 0:
                print(f"Error al ejecutar script: {result}")
                return False
                
            print("Script ejecutado exitosamente")
            return True
            
        except Exception as e:
            print(f"Error al inyectar script: {str(e)}")
            traceback.print_exc()
            return False
            
    def cleanup(self):
        """Libera la memoria asignada"""
        try:
            # Convertir el handle a un entero para usarlo con ctypes
            handle_int = int(self.process_handle)
            
            # Liberar cada bloque de memoria asignado
            for address in self.allocated_memory:
                ctypes.windll.kernel32.VirtualFreeEx(
                    handle_int,
                    address,
                    0,
                    0x8000  # MEM_RELEASE
                )
                
            self.allocated_memory = []
            print("Memoria liberada")
            
        except Exception as e:
            print(f"Error al liberar memoria: {str(e)}") 