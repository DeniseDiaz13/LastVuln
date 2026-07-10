[English](roadmap.md)

# Mejoras futuras

## Soporte para más archivos de dependencias

Agregar soporte para nuevos formatos como:
- `yarn.lock` (Node.js)
- `Cargo.lock` (Rust)
- `go.mod` (Go)

## Mejoras de rendimiento

- Para escaneo masivo agregar otro caché por ghsa_id para ganar todavía más tiempo de respuesta
en la búsqueda por paquetes y el escaneo.

## Integración continua

- Ejecutar validaciones de calidad de código en cada cambio.
- Generar reportes automáticos de pruebas.
- Agregar tipado con mypy (detectar errores de tipos en Python)
- Agregar linter con ruff (mantener código limpio y consistente)

## Distribución

- Crear un paquete instalable mediante PyPI.
- Crear release binaries.
- Empaquetar para su instalación en ArchLinux con un AUR helper.

