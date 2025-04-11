import pymem
import psutil
import time
import os
import ctypes
import sys
from ctypes import wintypes, windll, create_string_buffer, Structure, sizeof, POINTER, c_void_p, c_ulong, c_ulonglong, c_size_t, c_uint64, c_uint32
import win32gui
import win32process
import win32con
import win32security

PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

def ptr_to_int(ptr):
    """Convierte un puntero a entero."""
    if isinstance(ptr, int):
        return ptr
    if ptr is None:
        return 0
    try:
        return c_uint32.from_buffer(ctypes.cast(ptr, POINTER(c_uint32))).value
    except:
        return 0

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

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_process_handle(pid):
    try:
        # Obtener el token actual
        token = win32security.OpenProcessToken(
            win32process.GetCurrentProcess(),
            win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
        )
        
        # Habilitar el privilegio de depuración
        priv_id = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")
        win32security.AdjustTokenPrivileges(
            token, 0, [(priv_id, win32con.SE_PRIVILEGE_ENABLED)]
        )
        
        # Intentar obtener el handle con privilegios mínimos necesarios
        handle = windll.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
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

def enum_windows_callback(hwnd, results):
    if win32gui.IsWindowVisible(hwnd):
        title = win32gui.GetWindowText(hwnd)
        if "roblox" in title.lower():
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                results.append({
                    'hwnd': hwnd,
                    'title': title,
                    'pid': pid
                })
                print(f"Ventana de Roblox encontrada: {title}")
                print(f"HWND: {hwnd}")
                print(f"PID: {pid}")
            except Exception as e:
                print(f"Error al obtener información de la ventana: {e}")
    return True

def find_roblox_processes():
    print("Buscando procesos de Roblox...")
    roblox_processes = []
    
    # Buscar ventanas de Roblox
    print("\nBuscando ventanas de Roblox:")
    window_results = []
    win32gui.EnumWindows(enum_windows_callback, window_results)
    
    # Buscar procesos por nombre y ruta
    print("\nBuscando procesos de Roblox:")
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            # Forzar actualización del uso de CPU
            cpu = proc.cpu_percent(interval=0.1)
            
            if ("Windows10Universal" in proc.name() or 
                "Roblox" in proc.name() or 
                (proc.exe() and ("roblox" in proc.exe().lower() or "windows10universal" in proc.exe().lower()))):
                
                print(f"\nProceso encontrado: {proc.name()} (PID: {proc.pid})")
                print(f"Ejecutable: {proc.exe()}")
                print(f"CPU: {cpu}%")
                print(f"Memoria: {proc.memory_info().rss / 1024 / 1024:.2f} MB")
                
                if proc.pid not in [p['pid'] for p in roblox_processes]:
                    handle = get_process_handle(proc.pid)
                    if handle:
                        roblox_processes.append({
                            'pid': proc.pid,
                            'name': proc.name(),
                            'exe': proc.exe(),
                            'cpu': cpu,
                            'handle': handle
                        })
                    else:
                        print("No se pudo obtener acceso al proceso")
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            continue
    
    return roblox_processes

def read_memory(handle, address, size):
    buffer = create_string_buffer(size)
    bytes_read = c_size_t()
    
    # Convertir la dirección a entero si es necesario
    if not isinstance(address, int):
        address = ptr_to_int(address)
    
    # Asegurarse de que el tamaño no sea demasiado grande
    size = min(size, 0x1000)  # Limitar a 4KB por lectura
    
    if windll.kernel32.ReadProcessMemory(
        handle, 
        address, 
        buffer, 
        size, 
        ctypes.byref(bytes_read)
    ):
        return buffer.raw[:bytes_read.value]
    return None

def scan_memory(process_info):
    pid = process_info['pid']
    handle = process_info['handle']
    
    print(f"\nEscaneando memoria del proceso {process_info['name']} (PID: {pid})...")
    
    if not handle:
        print("No se pudo obtener acceso al proceso")
        return
    
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
            b"Character"
        ]
        
        # Obtener información del sistema
        sys_info = SYSTEM_INFO()
        windll.kernel32.GetSystemInfo(ctypes.byref(sys_info))
        
        # Información de memoria
        mbi = MEMORY_BASIC_INFORMATION()
        current_address = 0
        max_address = ptr_to_int(sys_info.lpMaximumApplicationAddress)
        
        print("Escaneando regiones de memoria...")
        while current_address < max_address:
            if windll.kernel32.VirtualQueryEx(
                handle,
                current_address,
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            ):
                base_address = ptr_to_int(mbi.BaseAddress)
                region_size = mbi.RegionSize
                
                if (mbi.State == win32con.MEM_COMMIT and 
                    mbi.Type == win32con.MEM_PRIVATE and 
                    mbi.Protect & win32con.PAGE_READWRITE):
                    
                    try:
                        # Leer la región de memoria en bloques más pequeños
                        block_size = 0x1000  # 4KB por bloque
                        for offset in range(0, region_size, block_size):
                            mem = read_memory(handle, base_address + offset, block_size)
                            if mem:
                                # Buscar patrones
                                for pattern in patterns:
                                    pos = 0
                                    while True:
                                        pos = mem.find(pattern, pos)
                                        if pos == -1:
                                            break
                                            
                                        addr = base_address + offset + pos
                                        print(f"Patrón encontrado: {pattern.decode(errors='ignore')} en 0x{addr:X}")
                                        
                                        # Intentar leer contexto
                                        context = read_memory(handle, addr - 16, 64)
                                        if context:
                                            print(f"Contexto: {context.hex()}")
                                        
                                        pos += len(pattern)
                    except Exception as e:
                        print(f"Error al leer región 0x{base_address:X}: {str(e)}")
                
                current_address = base_address + region_size
            else:
                current_address += 4096  # Página por defecto
                
    except Exception as e:
        print(f"Error al escanear memoria: {str(e)}")
    finally:
        if handle:
            windll.kernel32.CloseHandle(handle)

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
    
    print("Iniciando escáner de memoria...")
    print("Por favor, asegúrate de que Roblox esté abierto y en un juego.")
    time.sleep(2)
    
    # Buscar procesos de Roblox
    processes = find_roblox_processes()
    
    if processes:
        print(f"\nEncontrados {len(processes)} procesos relacionados con Roblox")
        # Escanear memoria de cada proceso
        for proc in processes:
            scan_memory(proc)
    else:
        print("\nNo se pudo encontrar ningún proceso de Roblox")
        print("Asegúrate de que Roblox esté abierto y en un juego")
        print("\nSugerencias:")
        print("1. Abre Roblox y únete a un juego")
        print("2. Espera a que el juego cargue completamente")
        print("3. Ejecuta este script como administrador")
        print("4. Si usas la versión de Microsoft Store, considera usar la versión del sitio web")

if __name__ == "__main__":
    main() 