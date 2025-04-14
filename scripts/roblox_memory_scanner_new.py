import psutil
import time
import win32process
import win32api
import win32con
import ctypes
from ctypes import wintypes
import sys
import traceback
import os
import win32gui

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Definir estructuras y constantes necesarias para VirtualQueryEx
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

# Definir constantes
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PROCESS_ALL_ACCESS = 0x1F0FFF

# Definir la función VirtualQueryEx con los tipos correctos
VirtualQueryEx = ctypes.windll.kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t
]
VirtualQueryEx.restype = ctypes.c_size_t

# Definir la función ReadProcessMemory con los tipos correctos
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
]
ReadProcessMemory.restype = wintypes.BOOL

class RobloxMemoryScanner:
    def __init__(self):
        # Bloxstrap ejecuta RobloxPlayerBeta.exe
        self.process_name = "RobloxPlayerBeta.exe"
        self.process_handle = None
        self.process_id = None
        self.windows = []

    def find_roblox_process(self):
        """Busca el proceso de Roblox en ejecución"""
        print("Buscando proceso de Roblox (ejecutado por Bloxstrap)...")
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] == self.process_name:
                        self.process_id = proc.info['pid']
                        print(f"Proceso encontrado con PID: {self.process_id}")
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            print("No se encontró el proceso de Roblox. Asegúrate de que Bloxstrap haya iniciado el juego.")
            return False
        except Exception as e:
            print(f"Error al buscar proceso: {str(e)}")
            return False

    def open_process(self):
        """Abre un handle al proceso de Roblox"""
        if not self.process_id:
            print("No hay PID de proceso disponible")
            return False
        
        try:
            # En Windows 11, necesitamos permisos elevados
            self.process_handle = win32api.OpenProcess(
                PROCESS_ALL_ACCESS,
                False,
                self.process_id
            )
            if self.process_handle:
                print(f"Handle del proceso abierto: {self.process_handle}")
                return True
            else:
                error = ctypes.get_last_error()
                print(f"Error al abrir proceso: {error}")
                print("Asegúrate de ejecutar este script como administrador")
                return False
        except Exception as e:
            print(f"Error al abrir el proceso: {str(e)}")
            return False

    def scan_memory_region(self, address, size):
        """Escanea una región de memoria específica"""
        try:
            # Limitar el tamaño de la región para evitar problemas de memoria
            max_size = 1024 * 1024  # 1MB máximo por región
            if size > max_size:
                size = max_size
                
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            
            # Convertir el handle a un entero para usarlo con ctypes
            handle_int = int(self.process_handle)
            
            result = ReadProcessMemory(
                handle_int,
                address,
                buffer,
                size,
                ctypes.byref(bytes_read)
            )
            
            if result:
                return buffer.raw
            else:
                error = ctypes.get_last_error()
                print(f"Error al leer memoria en {hex(address)}: {error}")
                return None
        except Exception as e:
            print(f"Excepción al escanear región {hex(address)}: {str(e)}")
            return None

    def virtual_query_ex(self, address):
        """Implementación directa de VirtualQueryEx usando ctypes"""
        try:
            mbi = MEMORY_BASIC_INFORMATION()
            
            # Convertir el handle a un entero para usarlo con ctypes
            handle_int = int(self.process_handle)
            
            result = VirtualQueryEx(
                handle_int,
                address,
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            )
            
            if result == 0:
                error = ctypes.get_last_error()
                if error == 0x1F:  # ERROR_INVALID_PARAMETER
                    print(f"Dirección {hex(address)} no es válida")
                    return None
                print(f"Error en VirtualQueryEx para dirección {hex(address)}: {error}")
                return None
            
            # Verificar que los valores sean válidos
            if not hasattr(mbi, 'BaseAddress') or not hasattr(mbi, 'RegionSize'):
                print(f"Error: Estructura MBI inválida para dirección {hex(address)}")
                return None
            
            # Verificar que los valores no sean None
            if mbi.BaseAddress is None or mbi.RegionSize is None:
                print(f"Error: Valores None en MBI para dirección {hex(address)}")
                return None
                
            return mbi
        except Exception as e:
            print(f"Error en virtual_query_ex para dirección {hex(address)}: {str(e)}")
            return None

    def get_memory_regions(self):
        """Obtiene las regiones de memoria del proceso"""
        regions = []
        address = 0
        
        try:
            print("Iniciando búsqueda de regiones de memoria...")
            while True:
                print(f"Consultando dirección: {hex(address)}")
                mbi = self.virtual_query_ex(address)
                
                if mbi is None:
                    # Si es la primera iteración y falla, intentar con una dirección diferente
                    if address == 0:
                        print("Intentando con dirección alternativa 0x1000...")
                        address = 0x1000
                        continue
                    print("No se pudo obtener información de memoria, finalizando búsqueda")
                    break
                
                # Verificar que los valores sean válidos antes de usarlos
                if not hasattr(mbi, 'BaseAddress') or not hasattr(mbi, 'RegionSize'):
                    print(f"Error: Valores inválidos en MBI para dirección {hex(address)}")
                    break
                
                # Imprimir información de la región
                print(f"Región encontrada en {hex(mbi.BaseAddress)}:")
                print(f"  Tamaño: {mbi.RegionSize} bytes")
                print(f"  Estado: {hex(mbi.State)}")
                print(f"  Protección: {hex(mbi.Protect)}")
                print(f"  Tipo: {hex(mbi.Type)}")
                
                # Buscar regiones con diferentes permisos
                if mbi.State == MEM_COMMIT and (
                    mbi.Protect & PAGE_READWRITE or
                    mbi.Protect & PAGE_READONLY or
                    mbi.Protect & PAGE_EXECUTE_READ or
                    mbi.Protect & PAGE_EXECUTE_READWRITE
                ):
                    regions.append((mbi.BaseAddress, mbi.RegionSize))
                    print(f"  ¡Región válida encontrada!")
                
                # Avanzar al siguiente bloque de memoria
                try:
                    if mbi.BaseAddress is None or mbi.RegionSize is None:
                        print(f"Error: Valores None en MBI para dirección {hex(address)}")
                        break
                        
                    next_address = mbi.BaseAddress + mbi.RegionSize
                    print(f"Siguiente dirección calculada: {hex(next_address)}")
                    
                    if next_address <= address:  # Evitar bucle infinito
                        print(f"Error: Dirección siguiente ({hex(next_address)}) menor o igual a la actual ({hex(address)})")
                        break
                        
                    address = next_address
                    if address >= 0x7FFFFFFF:
                        print("Alcanzado límite máximo de direcciones")
                        break
                except Exception as e:
                    print(f"Error al calcular siguiente dirección: {str(e)}")
                    print(f"Valores actuales - BaseAddress: {mbi.BaseAddress}, RegionSize: {mbi.RegionSize}")
                    break
                    
            return regions
        except Exception as e:
            print(f"Error al obtener regiones de memoria: {str(e)}")
            traceback.print_exc()
            return []

    def find_windows(self):
        """Encuentra todas las ventanas asociadas al proceso de Roblox"""
        def callback(hwnd, extra):
            if win32gui.IsWindowVisible(hwnd):
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid == self.process_id:
                    title = win32gui.GetWindowText(hwnd)
                    if title:  # Solo añadir ventanas con título
                        self.windows.append({
                            'hwnd': hwnd,
                            'title': title,
                            'rect': win32gui.GetWindowRect(hwnd)
                        })
            return True

        win32gui.EnumWindows(callback, None)
        return self.windows

    def scan_process_memory(self):
        """Escanea toda la memoria del proceso"""
        if not self.find_roblox_process():
            return
        
        if not self.open_process():
            return

        print(f"Escaneando memoria del proceso {self.process_name} (PID: {self.process_id})")
        
        # Primero encontrar las ventanas
        print("\nBuscando ventanas de Roblox...")
        windows = self.find_windows()
        if windows:
            print(f"Se encontraron {len(windows)} ventanas:")
            for i, window in enumerate(windows, 1):
                print(f"{i}. Título: {window['title']}")
                print(f"   Posición: {window['rect']}")
        else:
            print("No se encontraron ventanas visibles")
        
        print("\nEscaneando regiones de memoria...")
        regions = self.get_memory_regions()
        print(f"Total de regiones encontradas: {len(regions)}")
        
        for base_address, size in regions:
            try:
                data = self.scan_memory_region(base_address, size)
                if data:
                    print(f"Región escaneada en {hex(base_address)} con tamaño {size} bytes")
            except Exception as e:
                print(f"Error al escanear región {hex(base_address)}: {str(e)}")

    def cleanup(self):
        """Limpia los recursos"""
        if self.process_handle:
            try:
                win32api.CloseHandle(self.process_handle)
                print("Handle del proceso cerrado")
            except Exception as e:
                print(f"Error al cerrar handle: {str(e)}")

def main():
    print("Iniciando escáner de memoria para Roblox (ejecutado por Bloxstrap)...")
    print("Asegúrate de que Bloxstrap haya iniciado el juego antes de ejecutar este script.")
    
    if not is_admin():
        print("Este script requiere permisos de administrador para acceder a la memoria del proceso.")
        print("Por favor, ejecuta el script como administrador.")
        return

    scanner = RobloxMemoryScanner()
    try:
        scanner.scan_process_memory()
    except Exception as e:
        print(f"Error general: {str(e)}")
        traceback.print_exc()
    finally:
        scanner.cleanup()

if __name__ == "__main__":
    main() 