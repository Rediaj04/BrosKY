import pymem
import pymem.process
import psutil
import struct
import time
import json

def find_lua_patterns():
    print("Buscando patrones de Lua...")
    
    # Patrones comunes de Lua 5.1
    LUA_PATTERNS = [
        b"Lua 5.1",
        b"LuaQ",
        b"luaL_loadbuffer",
        b"lua_pcall"
    ]
    
    try:
        # Buscar el proceso de Roblox
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] in ["RobloxPlayerBeta.exe", "ROBLOXCORPORATION.ROBLOX_2.667.665.0_x64__55nm5eh3cm0pr"]:
                print(f"Proceso encontrado: {proc.info['name']} (PID: {proc.info['pid']})")
                
                # Conectar al proceso
                pm = pymem.Pymem(proc.info['pid'])
                
                # Resultados
                results = {
                    "lua_addresses": [],
                    "potential_states": [],
                    "memory_regions": []
                }
                
                # Escanear la memoria
                print("Escaneando memoria...")
                current_address = 0
                while True:
                    try:
                        # Leer memoria en bloques
                        mem = pm.read_bytes(current_address, 4096)
                        
                        # Buscar patrones
                        for pattern in LUA_PATTERNS:
                            if pattern in mem:
                                offset = mem.index(pattern)
                                addr = current_address + offset
                                print(f"Patrón encontrado: {pattern} en 0x{addr:X}")
                                results["lua_addresses"].append({
                                    "address": hex(addr),
                                    "pattern": pattern.decode('utf-8', errors='ignore')
                                })
                                
                        # Buscar posibles estados de Lua
                        for i in range(0, len(mem) - 8, 4):
                            value = struct.unpack("Q", mem[i:i+8])[0]
                            if 0x100000000 <= value <= 0x7FFFFFFFFFFF:
                                results["potential_states"].append(hex(current_address + i))
                                
                        current_address += 4096
                        
                    except (pymem.exception.MemoryReadError, ValueError):
                        # Guardar región de memoria
                        if len(results["lua_addresses"]) > 0:
                            results["memory_regions"].append({
                                "start": hex(current_address - 4096),
                                "end": hex(current_address)
                            })
                        current_address += 4096
                        
                    except Exception as e:
                        print(f"Error: {str(e)}")
                        break
                        
                # Guardar resultados
                with open("memory_scan_results.json", "w") as f:
                    json.dump(results, f, indent=4)
                    
                print("\nResultados guardados en memory_scan_results.json")
                return results
                
        print("Proceso de Roblox no encontrado")
        return None
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return None

def main():
    print("Iniciando escáner de memoria...")
    print("Por favor, asegúrate de que el juego esté abierto.")
    time.sleep(2)
    
    results = find_lua_patterns()
    
    if results and len(results["lua_addresses"]) > 0:
        print("\nPatrones encontrados:")
        for addr in results["lua_addresses"]:
            print(f"- {addr['pattern']} en {addr['address']}")
            
        print("\nPosibles estados de Lua:", len(results["potential_states"]))
        print("Regiones de memoria escaneadas:", len(results["memory_regions"]))
    else:
        print("No se encontraron patrones de Lua")

if __name__ == "__main__":
    main() 