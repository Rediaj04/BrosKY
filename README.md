# Roblox Script Executor

Este proyecto es un ejecutor de scripts para juegos basados en Roblox. Permite inyectar y ejecutar scripts Lua en tiempo real en el juego.

## Características

- Interfaz gráfica moderna y fácil de usar
- Editor de scripts con resaltado de sintaxis para Lua
- Sistema de gestión de scripts (guardar/cargar)
- Conexión automática al proceso del juego
- Ejecución de scripts en tiempo real
- Sistema de logging para depuración

## Estructura del Proyecto

```
RobloxExecutor/
├── config/           # Archivos de configuración
├── scripts/          # Scripts guardados
├── src/              # Código fuente
│   ├── core/         # Núcleo del ejecutor
│   ├── injection/    # Sistema de inyección
│   ├── ui/           # Interfaz de usuario
│   └── utils/        # Utilidades
└── requirements.txt  # Dependencias
```

## Requisitos

- Python 3.7 o superior
- Windows 10/11
- Acceso administrativo
- Las dependencias listadas en `requirements.txt`

## Instalación

1. Clona este repositorio
2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

## Uso

1. Inicia el juego
2. Ejecuta el ejecutor:
```bash
python src/main.py
```
3. Conecta al juego usando el botón "Conectar al Juego"
4. Escribe o carga un script
5. Haz clic en "Ejecutar Script"

## Notas Importantes

- Este ejecutor está diseñado para uso con juegos específicos
- Requiere configuración específica para cada versión del juego
- El uso de este software es bajo tu propia responsabilidad

## Contribución

Las contribuciones son bienvenidas. Por favor, lee el archivo TODO.md para ver las tareas pendientes. 