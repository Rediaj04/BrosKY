# BrosKY

Herramienta para inyectar y ejecutar scripts en Roblox.

## Requisitos

- Python 3.8 o superior
- Windows 10/11
- Bloxstrap instalado
- Permisos de administrador

## Instalación

1. Clona el repositorio:
```bash
git clone https://github.com/tu-usuario/BrosKY.git
cd BrosKY
```

2. Crea un entorno virtual:
```bash
python -m venv venv
```

3. Activa el entorno virtual:
- Windows:
```bash
venv\Scripts\activate
```
- Linux/Mac:
```bash
source venv/bin/activate
```

4. Instala las dependencias:
```bash
pip install -r requirements.txt
```

## Uso

1. Asegúrate de que Bloxstrap haya iniciado Roblox

2. Ejecuta el script como administrador:
```bash
python scripts/roblox_memory_scanner_new.py
```

## Estructura del Proyecto

```
BrosKY/
├── scripts/           # Scripts de utilidad
├── src/              # Código fuente principal
├── config/           # Archivos de configuración
├── requirements.txt  # Dependencias de Python
└── README.md         # Este archivo
```

## Desarrollo

1. Asegúrate de tener todas las dependencias instaladas
2. Ejecuta los scripts como administrador
3. Sigue las convenciones de código establecidas

## Contribución

1. Fork el repositorio
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

## Notas de Seguridad

- Este proyecto requiere permisos de administrador para funcionar
- Úsalo de manera responsable y ética
- No uses para actividades maliciosas o que violen los términos de servicio 