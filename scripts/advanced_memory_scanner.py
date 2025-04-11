import ctypes
import sys
import os
import win32gui
import win32process
import win32security
import win32con
import win32api
import struct
from ctypes import wintypes, windll, create_string_buffer, Structure, sizeof, POINTER, c_void_p, c_ulong, c_ulonglong, c_size_t, c_uint32
import psutil
import time

# Constantes
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_DUP_HANDLE = 0x0040

# Permisos necesarios para leer memoria
PROCESS_ACCESS = (
    PROCESS_VM_READ | 
    PROCESS_QUERY_INFORMATION | 
    PROCESS_QUERY_LIMITED_INFORMATION |
    PROCESS_DUP_HANDLE
)

class SYSTEM_INFO(Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", c_void_p),
        ("lpMaximumApplicationAddress", c_void_p),
        ("dwActiveProcessorMask", c_ulong),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD)
    ]

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", c_uint32),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD)
    ]

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_process_handle(pid):
    try:
        # Obtener privilegios de depuración
        token = win32security.OpenProcessToken(
            win32process.GetCurrentProcess(),
            win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
        )
        priv_id = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
        win32security.AdjustTokenPrivileges(
            token, 0, [(priv_id, win32con.SE_PRIVILEGE_ENABLED)]
        )
        
        # Abrir proceso con permisos específicos
        handle = windll.kernel32.OpenProcess(
            PROCESS_ACCESS,
            False,
            pid
        )
        
        if handle:
            return handle
        else:
            error = windll.kernel32.GetLastError()
            print(f"Error al obtener handle: {error}")
    except Exception as e:
        print(f"Error al obtener handle: {e}")
    return None

def read_memory(handle, address, size):
    buffer = create_string_buffer(size)
    bytes_read = c_size_t()
    
    if windll.kernel32.ReadProcessMemory(
        handle, 
        address, 
        buffer, 
        size, 
        ctypes.byref(bytes_read)
    ):
        return buffer.raw[:bytes_read.value]
    return None

def find_lua_patterns(process_handle):
    """Busca patrones de Lua en la memoria del proceso."""
    try:
        # Patrones comunes de Lua y Roblox
        patterns = [
            b"Lua 5.1",
            b"LuaQ",
            b"luaL_loadbuffer",
            b"lua_pcall",
            b"lua_getfield",
            b"lua_setfield",
            b"lua_getglobal",
            b"lua_setglobal",
            b"ROBLOX",
            b"RobloxPlayer",
            b"RobloxGame",
            b"rbxasset://",
            b"game:",
            b"workspace",
            b"Players",
            b"LocalPlayer",
            b"Character",
            b"Instance.new",
            b"GetService",
            b"FireServer",
            b"InvokeServer",
            b"RemoteEvent",
            b"RemoteFunction",
            b"ReplicatedStorage",
            b"ServerScriptService",
            b"LocalScript",
            b"Script",
            b"ModuleScript"
        ]
        
        # Obtener información de memoria
        mbi = MEMORY_BASIC_INFORMATION()
        current_address = 0
        total_regions = 0
        scanned_regions = 0
        found_patterns = 0
        
        print("Escaneando memoria en busca de patrones de Lua...")
        
        # Obtener información del sistema
        system_info = SYSTEM_INFO()
        windll.kernel32.GetSystemInfo(ctypes.byref(system_info))
        
        # Establecer rango de direcciones a escanear
        min_address = system_info.lpMinimumApplicationAddress
        max_address = system_info.lpMaximumApplicationAddress
        
        print(f"Rango de direcciones a escanear: 0x{min_address:X} - 0x{max_address:X}")
        
        # Primero contar las regiones totales
        current_address = min_address
        while current_address < max_address:
            if windll.kernel32.VirtualQueryEx(
                process_handle,
                current_address,
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            ):
                if mbi.State == win32con.MEM_COMMIT:
                    total_regions += 1
                current_address = mbi.BaseAddress + mbi.RegionSize
            else:
                break
        
        print(f"Total de regiones de memoria a escanear: {total_regions}")
        current_address = min_address
        
        while current_address < max_address:
            if windll.kernel32.VirtualQueryEx(
                process_handle,
                current_address,
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            ):
                if (mbi.State == win32con.MEM_COMMIT and 
                    mbi.Type == win32con.MEM_PRIVATE and 
                    (mbi.Protect & win32con.PAGE_READWRITE or 
                     mbi.Protect & win32con.PAGE_READONLY or
                     mbi.Protect & win32con.PAGE_EXECUTE_READ or
                     mbi.Protect & win32con.PAGE_EXECUTE_READWRITE)):
                    
                    scanned_regions += 1
                    if scanned_regions % 10 == 0:
                        print(f"Progreso: {scanned_regions}/{total_regions} regiones escaneadas")
                        print(f"Escaneando región: 0x{mbi.BaseAddress:X} - 0x{mbi.BaseAddress + mbi.RegionSize:X}")
                    
                    try:
                        # Leer la región de memoria en bloques más pequeños
                        block_size = 0x1000  # 4KB por bloque
                        for offset in range(0, mbi.RegionSize, block_size):
                            mem = read_memory(process_handle, mbi.BaseAddress + offset, block_size)
                            if mem:
                                # Buscar patrones
                                for pattern in patterns:
                                    pos = 0
                                    while True:
                                        pos = mem.find(pattern, pos)
                                        if pos == -1:
                                            break
                                        
                                        addr = mbi.BaseAddress + offset + pos
                                        found_patterns += 1
                                        print(f"\nPatrón encontrado ({found_patterns}): {pattern.decode(errors='ignore')}")
                                        print(f"Dirección: 0x{addr:X}")
                                        print(f"Región: 0x{mbi.BaseAddress:X} - 0x{mbi.BaseAddress + mbi.RegionSize:X}")
                                        print(f"Protección: 0x{mbi.Protect:X}")
                                        
                                        # Intentar leer contexto
                                        context = read_memory(process_handle, addr - 32, 64)
                                        if context:
                                            try:
                                                context_str = context.decode('utf-8', errors='ignore')
                                                print(f"Contexto: {context_str}")
                                            except:
                                                print(f"Contexto (hex): {context.hex()}")
                                        
                                        pos += len(pattern)
                    except Exception as e:
                        print(f"Error al leer región 0x{mbi.BaseAddress:X}: {str(e)}")
                
                current_address = mbi.BaseAddress + mbi.RegionSize
            else:
                break
        
        print(f"\nEscaneo completado:")
        print(f"Regiones totales: {total_regions}")
        print(f"Regiones escaneadas: {scanned_regions}")
        print(f"Patrones encontrados: {found_patterns}")
                
    except Exception as e:
        print(f"Error al escanear memoria: {str(e)}")

def main():
    if not is_admin():
        print("ADVERTENCIA: El script no se está ejecutando como administrador")
        print("Para mejor acceso a la memoria, ejecuta el script como administrador")
        if sys.platform == 'win32':
            print("Intentando reiniciar con privilegios de administrador...")
            try:
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
                sys.exit()
            except:
                print("No se pudo obtener privilegios de administrador")
                return
    
    print("Iniciando escáner de memoria avanzado...")
    print("Por favor, asegúrate de que Roblox esté abierto y en un juego.")
    time.sleep(2)
    
    # Buscar proceso de Roblox
    roblox_process = None
    for proc in psutil.process_iter(['pid', 'name']):
        if "Windows10Universal.exe" in proc.info['name']:
            roblox_process = proc
            break
    
    if not roblox_process:
        print("No se encontró el proceso de Roblox")
        return
    
    print(f"\nProceso de Roblox encontrado (PID: {roblox_process.info['pid']})")
    
    # Obtener handle del proceso
    process_handle = get_process_handle(roblox_process.info['pid'])
    if not process_handle:
        print("No se pudo obtener acceso al proceso")
        return
    
    try:
        # Buscar patrones de Lua
        find_lua_patterns(process_handle)
        
    except KeyboardInterrupt:
        print("\nDeteniendo escaneo...")
    finally:
        if process_handle:
            windll.kernel32.CloseHandle(process_handle)

if __name__ == "__main__":
    main() 