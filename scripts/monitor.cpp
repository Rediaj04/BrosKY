#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <TlHelp32.h>

// Estructura para almacenar información de hooks
struct HookInfo {
    void* originalFunction;
    void* hookFunction;
    BYTE originalBytes[5];
    BYTE hookBytes[5];
};

// Vector para almacenar los hooks
std::vector<HookInfo> hooks;

// Función para escribir en el archivo de log
void Log(const char* message) {
    std::ofstream logFile("lua_monitor.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.close();
    }
}

// Función para instalar un hook
bool InstallHook(void* targetFunction, void* hookFunction) {
    HookInfo hook;
    hook.originalFunction = targetFunction;
    hook.hookFunction = hookFunction;
    
    // Guardar bytes originales
    memcpy(hook.originalBytes, targetFunction, 5);
    
    // Crear bytes del hook
    hook.hookBytes[0] = 0xE9; // JMP
    DWORD relativeAddress = (DWORD)hookFunction - (DWORD)targetFunction - 5;
    memcpy(&hook.hookBytes[1], &relativeAddress, 4);
    
    // Aplicar el hook
    DWORD oldProtect;
    if (VirtualProtect(targetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(targetFunction, hook.hookBytes, 5);
        VirtualProtect(targetFunction, 5, oldProtect, &oldProtect);
        hooks.push_back(hook);
        return true;
    }
    
    return false;
}

// Función para remover todos los hooks
void RemoveHooks() {
    for (const auto& hook : hooks) {
        DWORD oldProtect;
        if (VirtualProtect(hook.originalFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy(hook.originalFunction, hook.originalBytes, 5);
            VirtualProtect(hook.originalFunction, 5, oldProtect, &oldProtect);
        }
    }
    hooks.clear();
}

// Hook para luaL_loadbuffer
int __stdcall Hook_luaL_loadbuffer(void* L, const char* buff, size_t sz, const char* name) {
    Log("luaL_loadbuffer llamado");
    Log(buff); // Log del código Lua
    
    // Llamar a la función original
    typedef int(__stdcall* Original_luaL_loadbuffer)(void*, const char*, size_t, const char*);
    Original_luaL_loadbuffer original = (Original_luaL_loadbuffer)hooks[0].originalFunction;
    return original(L, buff, sz, name);
}

// Hook para lua_pcall
int __stdcall Hook_lua_pcall(void* L, int nargs, int nresults, int errfunc) {
    Log("lua_pcall llamado");
    
    // Llamar a la función original
    typedef int(__stdcall* Original_lua_pcall)(void*, int, int, int);
    Original_lua_pcall original = (Original_lua_pcall)hooks[1].originalFunction;
    return original(L, nargs, nresults, errfunc);
}

// Función principal de la DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            // Inicializar hooks
            Log("DLL cargada");
            
            // Aquí iría el código para encontrar las direcciones de las funciones
            // y establecer los hooks
            // Por ejemplo:
            // InstallHook((void*)0x12345678, Hook_luaL_loadbuffer);
            // InstallHook((void*)0x87654321, Hook_lua_pcall);
            
            break;
            
        case DLL_PROCESS_DETACH:
            // Remover hooks
            RemoveHooks();
            Log("DLL descargada");
            break;
 