import pymem
import pymem.process
import json
import time
import os

def test_injection():
    print("Iniciando prueba de inyección...")
    
    # Cargar resultados del escaneo
    try:
        with open("memory_scan_results.json", "r") as f:
            scan_results = json.load(f)
    except FileNotFoundError:
        print("Error: Primero debes ejecutar memory_scanner.py")
        return
        
    # Conectar al proceso
    try:
        pm = pymem.Pymem("RobloxPlayerBeta.exe")
        print(f"Conectado al proceso (PID: {pm.process_id})")
    except Exception as e:
        print(f"Error al conectar: {str(e)}")
        return
        
    # Script de prueba simple
    test_script = """
    print("Test de inyección exitoso!")
    game.StarterGui:SetCore("SendNotification", {
        Title = "Test",
        Text = "Inyección exitosa!",
        Duration = 5
    })
    """
    
    # Probar cada dirección encontrada
    for addr_info in scan_results["lua_addresses"]:
        addr = int(addr_info["address"], 16)
        pattern = addr_info["pattern"]
        
        print(f"\nProbando dirección: {hex(addr)} (Patrón: {pattern})")
        
        try:
            # Asignar memoria para el script
            script_addr = pm.allocate(len(test_script) + 1)
            print(f"Memoria asignada en: {hex(script_addr)}")
            
            # Escribir el script
            pm.write_bytes(script_addr, test_script.encode('utf-8') + b'\0')
            print("Script escrito en memoria")
            
            # Intentar ejecutar
            print("Intentando ejecutar...")
            time.sleep(1)  # Esperar un poco
            
            # Leer resultado
            try:
                result = pm.read_bytes(script_addr, 32)
                print(f"Resultado: {result}")
            except:
                print("No se pudo leer el resultado")
                
        except Exception as e:
            print(f"Error en esta dirección: {str(e)}")
            continue
            
        print("Esperando 5 segundos antes de la siguiente prueba...")
        time.sleep(5)
        
def main():
    print("=== Test de Inyección de Scripts ===")
    print("Asegúrate de que el juego esté abierto")
    print("ADVERTENCIA: Este es un test experimental")
    input("Presiona Enter para continuar...")
    
    test_injection()

if __name__ == "__main__":
    main() 