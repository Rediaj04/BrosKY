import ctypes
from ctypes import wintypes
import win32api
import win32process
import win32gui
import win32con
import psutil
import struct
import traceback
import os
import time

# Definir la estructura MEMORY_BASIC_INFORMATION
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

class LuaDetector:
    def __init__(self, process_handle):
        self.process_handle = process_handle
        self.lua_state = None
        self.lua_state_address = None
        self.lua_version = None
        
        # Constantes para la búsqueda de memoria
        self.MEM_COMMIT = 0x1000
        self.PAGE_READWRITE = 0x04
        self.PAGE_EXECUTE_READ = 0x20
        self.PAGE_EXECUTE_READWRITE = 0x40
        self.PROCESS_ALL_ACCESS = 0x1F0FFF
        
        # DLLs específicas de Roblox que podrían contener el estado de Lua
        self.ROBLOX_DLLS = [
            "RobloxPlayerBeta.exe",
            "lua51.dll",
            "lua5.1.dll",
            "luabase.dll",
            "rbxlua.dll",
            "rbxmain.dll",
            "RobloxScript.dll",
            "RobloxEngine.dll"
        ]
        
        # Patrones de firma para diferentes versiones de Lua y Roblox
        self.LUA_SIGNATURES = [
            # Lua 5.1 (usado por Roblox)
            b"\x1B\x4C\x75\x61\x51",  # "\x1BLuaQ"
            # Patrones específicos de Roblox
            b"RobloxLuaVM",
            b"RobloxLuaState",
            b"RobloxScriptContext",
            b"ScriptContext",
            b"Lua VM",
            # Funciones comunes de Lua
            b"lua_newstate",
            b"lua_State",
            b"luaL_newstate",
            b"luaopen_base",
            # Patrones adicionales específicos de Roblox
            b"Roblox Lua VM",
            b"RobloxGame",
            b"RobloxStudio",
            b"RobloxPlayer",
            b"ScriptingEngine",
            b"DataModel",
            b"Workspace",
            b"Players",
            b"Game",
            # Patrones de funciones Lua específicas de Roblox
            b"rbx_lua_newstate",
            b"rbx_lua_getstate",
            b"rbx_lua_pushvalue",
            b"rbx_lua_pcall",
            b"rbx_lua_load"
        ]
        
        # Direcciones conocidas de regiones de memoria en Roblox
        self.KNOWN_REGIONS = [
            0x7ffe0000,  # Región encontrada por el escáner
            0x7ffef000,  # Región encontrada por el escáner
        ]
        
        # Funciones de Lua para hookear
        self.LUA_FUNCTIONS = [
            "luaL_newstate",
            "lua_pcall",
            "lua_load",
            "luaL_loadstring",
            "luaL_loadfile",
            "luaL_loadbuffer",
            "luaL_loadbufferx",
            "luaL_loadstringx",
            "luaL_loadfilex",
            # Funciones específicas de Roblox
            "rbx_lua_newstate",
            "rbx_lua_getstate",
            "rbx_lua_pushvalue",
            "rbx_lua_pcall",
            "rbx_lua_load"
        ]
        
        # Direcciones de funciones hookeadas
        self.hooked_functions = {}
        
        # Buffer para almacenar el estado de Lua encontrado
        self.lua_state_buffer = None

    def _convert_address(self, address):
        """Convierte una dirección de memoria a ctypes.c_void_p"""
        try:
            # Si la dirección es None o 0, retornar None
            if address is None or address == 0:
                return None
                
            # Si ya es c_void_p, retornarlo directamente
            if isinstance(address, ctypes.c_void_p):
                return address
                
            # Si es un entero, convertirlo directamente
            if isinstance(address, int):
                return ctypes.c_void_p(address)
                
            # Si es una cadena hexadecimal
            if isinstance(address, str):
                if address.startswith('0x'):
                    return ctypes.c_void_p(int(address, 16))
                return ctypes.c_void_p(int(address))
                
            # Para otros tipos, intentar convertir a entero
            return ctypes.c_void_p(int(address))
            
        except (ValueError, TypeError, OverflowError):
            return None

    def find_lua_state(self):
        """Busca el estado de Lua en la memoria del proceso"""
        print("Buscando estado de Lua...")
        try:
            # Obtener información de memoria del proceso
            memory_info = win32process.GetProcessMemoryInfo(self.process_handle)
            print(f"Memoria total del proceso: {memory_info['WorkingSetSize'] / 1024 / 1024:.2f} MB")
            
            # Buscar en DLLs específicas de Roblox
            print("Buscando en DLLs específicas de Roblox...")
            if self._search_roblox_dlls():
                return True
            
            # Buscar ventanas de Roblox
            print("Buscando ventanas de Roblox...")
            windows = self._find_roblox_windows()
            if windows:
                print(f"Se encontraron {len(windows)} ventanas de Roblox")
                for hwnd in windows:
                    print(f"Analizando ventana: {hwnd}")
                    # Intentar obtener el estado de Lua a través de la ventana
                    if self._get_lua_state_from_window(hwnd):
                        return True
            
            # Obtener módulos cargados
            process = psutil.Process(win32process.GetProcessId(self.process_handle))
            modules = process.memory_maps()
            
            print("Buscando en módulos cargados...")
            for module in modules:
                if "RobloxPlayerBeta.exe" in module.path:
                    base_address = int(module.addr.split('-')[0], 16)
                    print(f"Módulo base encontrado en: 0x{base_address:08X}")
                    
                    # Buscar en el módulo principal
                    if self._scan_module(base_address, module.size):
                        return True
                        
                    # Buscar en las regiones conocidas
                    for region_addr in self.KNOWN_REGIONS:
                        print(f"Buscando en región conocida: 0x{region_addr:08X}")
                        mbi = self._get_memory_basic_information(region_addr)
                        if mbi and mbi.State == self.MEM_COMMIT:
                            print(f"Analizando región conocida: 0x{mbi.BaseAddress:08X} - {mbi.RegionSize} bytes")
                            if self._scan_region(mbi.BaseAddress, mbi.RegionSize):
                                return True
                                
                    # Buscar funciones de Lua para hookear
                    print("Buscando funciones de Lua para hookear...")
                    for func_name in self.LUA_FUNCTIONS:
                        func_addr = self._find_function_address(base_address, module.size, func_name)
                        if func_addr:
                            print(f"Función {func_name} encontrada en: 0x{func_addr:08X}")
                            # Intentar obtener el estado de Lua a través de la función
                            if self._get_lua_state_from_function(func_addr):
                                return True
            
            # Si no se encuentra en los módulos, buscar en todas las regiones
            print("Buscando en todas las regiones de memoria...")
            # Comenzar desde una dirección válida (0x1000)
            address = 0x1000
            # Establecer un límite de búsqueda para evitar bucles infinitos
            max_address = 0x7FFFFFFF  # 2GB
            iterations = 0
            max_iterations = 1000  # Límite de iteraciones
            
            while address < max_address and iterations < max_iterations:
                try:
                    iterations += 1
                    # Obtener información de la región de memoria
                    mbi = self._get_memory_basic_information(address)
                    if not mbi:
                        # Si no se encuentra región, avanzar 4KB
                        address += 0x1000
                        continue
                        
                    # Verificar si la región es accesible
                    if (mbi.State == self.MEM_COMMIT and 
                        mbi.Protect == self.PAGE_READWRITE and
                        mbi.RegionSize > 0):
                        
                        print(f"Analizando región: 0x{mbi.BaseAddress:08X} - {mbi.RegionSize} bytes")
                        if self._scan_region(mbi.BaseAddress, mbi.RegionSize):
                            return True
                    
                    # Avanzar a la siguiente región
                    address = mbi.BaseAddress + mbi.RegionSize
                    
                except Exception as e:
                    print(f"Error al analizar región 0x{address:08X}: {str(e)}")
                    address += 0x1000  # Avanzar 4KB en caso de error
                    continue
            
            if iterations >= max_iterations:
                print(f"Se alcanzó el límite de iteraciones ({max_iterations})")
            
            print("No se encontró el estado de Lua")
            return False
            
        except Exception as e:
            print(f"Error al buscar estado de Lua: {str(e)}")
            traceback.print_exc()
            return False

    def _get_memory_basic_information(self, address):
        """Obtiene información básica de memoria para una dirección"""
        try:
            # Si la dirección es 0, retornar None
            if address == 0:
                return None
                
            # Convertir la dirección a ctypes.c_void_p
            address_ptr = self._convert_address(address)
            if not address_ptr:
                return None
                
            # Crear una estructura MEMORY_BASIC_INFORMATION
            mbi = MEMORY_BASIC_INFORMATION()
            
            # Llamar a VirtualQueryEx con la dirección convertida
            result = ctypes.windll.kernel32.VirtualQueryEx(
                self.process_handle,
                ctypes.c_void_p(address_ptr.value),  # Asegurarnos de que sea un c_void_p válido
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            )
            
            if result == 0:
                return None
                
            return mbi
            
        except Exception as e:
            print(f"Error al obtener información de memoria: {str(e)}")
            return None

    def _scan_region(self, base_address, region_size):
        """Escanea una región de memoria buscando el estado de Lua"""
        try:
            print(f"Escaneando región en 0x{base_address:08X} con tamaño {region_size} bytes")
            
            # Leer la región de memoria
            buffer = (ctypes.c_byte * region_size)()
            bytes_read = ctypes.c_size_t()
            
            # Convertir la dirección base a un entero de 64 bits
            base_address_int = self._convert_address(base_address)
            if base_address_int is None:
                print(f"No se pudo convertir la dirección base 0x{base_address:08X}")
                return False
            
            print(f"Leyendo memoria en 0x{base_address:08X}")
            if not ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle,
                base_address_int,
                ctypes.byref(buffer),
                region_size,
                ctypes.byref(bytes_read)
            ):
                print(f"No se pudo leer memoria en 0x{base_address:08X}")
                return False
            
            print(f"Memoria leída: {bytes_read.value} bytes")
            
            # Buscar patrones de firma
            for signature in self.LUA_SIGNATURES:
                print(f"Buscando firma: {signature}")
                offset = 0
                while True:
                    offset = self._find_signature(buffer, signature, offset)
                    if offset == -1:
                        break
                    
                    print(f"Firma encontrada en offset 0x{offset:08X}")
                    
                    # Verificar si el estado de Lua es válido
                    if self._verify_lua_state(base_address + offset):
                        print(f"¡Estado de Lua encontrado en 0x{base_address + offset:08X}!")
                        self.lua_state_address = base_address + offset
                        self.lua_state = buffer[offset:offset + 0x1000]  # Guardar 4KB del estado
                        return True
                    
                    offset += len(signature)
            
            print("No se encontraron firmas válidas en esta región")
            return False
            
        except Exception as e:
            print(f"Error al escanear región 0x{base_address:08X}: {str(e)}")
            return False

    def _find_signature(self, buffer, signature, start_offset=0):
        """Encuentra una firma en un buffer de memoria"""
        try:
            buffer_len = len(buffer)
            sig_len = len(signature)
            
            for i in range(start_offset, buffer_len - sig_len + 1):
                match = True
                for j in range(sig_len):
                    if buffer[i + j] != signature[j]:
                        match = False
                        break
                if match:
                    return i
            return -1
            
        except Exception as e:
            print(f"Error al buscar firma: {str(e)}")
            return -1

    def _verify_lua_state(self, address):
        """Verifica si una dirección contiene un estado de Lua válido"""
        try:
            # Leer 4KB de memoria alrededor de la dirección
            buffer = (ctypes.c_byte * 0x1000)()
            bytes_read = ctypes.c_size_t()
            
            # Convertir la dirección a un entero de 64 bits
            address_int = self._convert_address(address - 0x800)
            if address_int is None:
                return False
            
            if not ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle,
                address_int,
                ctypes.byref(buffer),
                0x1000,
                ctypes.byref(bytes_read)
            ):
                return False
            
            # Verificar si contiene un puntero válido a la tabla global
            global_table_ptr = struct.unpack("<Q", buffer[0x800:0x808])[0]
            if not (0x10000 <= global_table_ptr <= 0x7FFFFFFFFFFF):
                return False
            
            # Verificar si contiene punteros válidos a otras estructuras de Lua
            for offset in range(0x808, 0x818, 8):
                ptr = struct.unpack("<Q", buffer[offset:offset + 8])[0]
                if not (0x10000 <= ptr <= 0x7FFFFFFFFFFF):
                    return False
            
            return True
            
        except Exception as e:
            print(f"Error al verificar estado de Lua en 0x{address:08X}: {str(e)}")
            return False

    def _find_roblox_windows(self):
        """Encuentra ventanas de Roblox"""
        windows = []
        
        def enum_windows_callback(hwnd, _):
            if win32gui.IsWindowVisible(hwnd):
                title = win32gui.GetWindowText(hwnd)
                if "Roblox" in title:
                    windows.append(hwnd)
            return True
        
        win32gui.EnumWindows(enum_windows_callback, None)
        return windows

    def _get_lua_state_from_window(self, hwnd):
        """Intenta obtener el estado de Lua a través de una ventana"""
        try:
            # Obtener el ID del proceso de la ventana
            _, process_id = win32process.GetWindowThreadProcessId(hwnd)
            if process_id != win32process.GetProcessId(self.process_handle):
                return False
            
            # Obtener el handle del proceso
            process_handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, process_id)
            if not process_handle:
                return False
            
            try:
                # Buscar en la memoria del proceso
                address = 0
                while True:
                    mbi = self._get_memory_basic_information(address)
                    if not mbi:
                        break
                    
                    if (mbi.State == self.MEM_COMMIT and 
                        mbi.Protect == self.PAGE_READWRITE and
                        mbi.RegionSize > 0):
                        
                        if self._scan_region(mbi.BaseAddress, mbi.RegionSize):
                            return True
                    
                    address = mbi.BaseAddress + mbi.RegionSize
                
                return False
                
            finally:
                win32api.CloseHandle(process_handle)
                
        except Exception as e:
            print(f"Error al obtener estado de Lua desde ventana: {str(e)}")
            return False

    def _search_roblox_dlls(self):
        """Busca el estado de Lua en DLLs específicas de Roblox"""
        try:
            # Obtener módulos cargados
            process = psutil.Process(win32process.GetProcessId(self.process_handle))
            modules = process.memory_maps()
            
            # Buscar módulos de Roblox
            for module in modules:
                if any(dll.lower() in module.path.lower() for dll in self.ROBLOX_DLLS):
                    base_address = int(module.addr.split('-')[0], 16)
                    print(f"Analizando DLL: {os.path.basename(module.path)} en 0x{base_address:08X}")
                    
                    # Buscar en el módulo
                    if self._scan_module(base_address, module.size):
                        return True
            
            return False
            
        except Exception as e:
            print(f"Error al buscar en DLLs de Roblox: {str(e)}")
            return False

    def _scan_module(self, base_address, module_size):
        """Escanea un módulo buscando el estado de Lua"""
        try:
            # Leer el módulo
            buffer = (ctypes.c_byte * module_size)()
            bytes_read = ctypes.c_size_t()
            
            if not ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle,
                base_address,
                ctypes.byref(buffer),
                module_size,
                ctypes.byref(bytes_read)
            ):
                return False
            
            # Buscar patrones de firma
            for signature in self.LUA_SIGNATURES:
                offset = 0
                while True:
                    offset = self._find_signature(buffer, signature, offset)
                    if offset == -1:
                        break
                    
                    # Verificar si el estado de Lua es válido
                    if self._verify_lua_state(base_address + offset):
                        self.lua_state_address = base_address + offset
                        self.lua_state = buffer[offset:offset + 0x1000]  # Guardar 4KB del estado
                        return True
                    
                    offset += len(signature)
            
            return False
            
        except Exception as e:
            print(f"Error al escanear módulo en 0x{base_address:08X}: {str(e)}")
            return False

    def _find_function_address(self, base_address, module_size, function_name):
        """Encuentra la dirección de una función en un módulo"""
        try:
            # Leer el módulo
            buffer = (ctypes.c_byte * module_size)()
            bytes_read = ctypes.c_size_t()
            
            if not ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle,
                base_address,
                ctypes.byref(buffer),
                module_size,
                ctypes.byref(bytes_read)
            ):
                return None
            
            # Buscar la función por nombre
            function_bytes = function_name.encode()
            offset = 0
            while True:
                offset = self._find_signature(buffer, function_bytes, offset)
                if offset == -1:
                    break
                
                # Verificar si es una dirección de función válida
                if self._verify_function_address(base_address + offset):
                    return base_address + offset
                
                offset += len(function_bytes)
            
            return None
            
        except Exception as e:
            print(f"Error al buscar función {function_name}: {str(e)}")
            return None

    def _verify_function_address(self, address):
        """Verifica si una dirección contiene una función válida"""
        try:
            # Leer los primeros bytes de la función
            buffer = (ctypes.c_byte * 16)()
            bytes_read = ctypes.c_size_t()
            
            if not ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle,
                address,
                ctypes.byref(buffer),
                16,
                ctypes.byref(bytes_read)
            ):
                return False
            
            # Verificar si comienza con un prólogo de función común
            prologues = [
                bytes([0x55, 0x8B, 0xEC]),  # push ebp; mov ebp, esp
                bytes([0x48, 0x89, 0x5C, 0x24]),  # mov [rsp+...], rbx
                bytes([0x48, 0x83, 0xEC])  # sub rsp, ...
            ]
            
            return any(buffer[:len(p)] == p for p in prologues)
            
        except Exception as e:
            print(f"Error al verificar dirección de función 0x{address:08X}: {str(e)}")
            return False

    def _get_lua_state_from_function(self, function_address):
        """Intenta obtener el estado de Lua a través de una función"""
        try:
            # Leer la función
            buffer = (ctypes.c_byte * 0x100)()
            bytes_read = ctypes.c_size_t()
            
            if not ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle,
                function_address,
                ctypes.byref(buffer),
                0x100,
                ctypes.byref(bytes_read)
            ):
                return False
            
            # Buscar referencias al estado de Lua
            for i in range(0, 0x100 - 8, 4):
                # Leer un puntero potencial
                ptr = struct.unpack("<Q", buffer[i:i + 8])[0]
                if 0x10000 <= ptr <= 0x7FFFFFFFFFFF:
                    # Verificar si el puntero apunta a un estado de Lua válido
                    if self._verify_lua_state(ptr):
                        self.lua_state_address = ptr
                        # Leer el estado de Lua
                        state_buffer = (ctypes.c_byte * 0x1000)()
                        if ctypes.windll.kernel32.ReadProcessMemory(
                            self.process_handle,
                            ptr,
                            ctypes.byref(state_buffer),
                            0x1000,
                            ctypes.byref(bytes_read)
                        ):
                            self.lua_state = state_buffer
                            return True
            
            return False
            
        except Exception as e:
            print(f"Error al obtener estado de Lua desde función 0x{function_address:08X}: {str(e)}")
            return False

    def get_lua_version(self):
        """Obtiene la versión de Lua"""
        if not self.lua_state:
            return None
            
        try:
            # Leer el byte de versión
            buffer = self._read_process_memory(self.lua_state + 4, 1)
            if buffer:
                version = ord(buffer)
                self.lua_version = f"5.{version - 0x30}"  # Convertir ASCII a número
                return self.lua_version
        except:
            pass
        return None

    def _read_process_memory(self, address, size):
        """Lee memoria del proceso"""
        try:
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            if ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle,
                address,
                buffer,
                size,
                ctypes.byref(bytes_read)
            ):
                return buffer.raw[:bytes_read.value]
        except:
            pass
        return None 