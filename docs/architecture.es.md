[English](architecture.md)

# Arquitectura

Lastvuln CLI está diseñado con una arquitectura modular, separación de responsabilidades, 
validación de entradas, manejo de errores y pruebas automatizadas para las funciones críticas.

![Architecture diagram](docs/architecture_diagram.png)

Diagrama de casos de uso:

![Case use diagram](docs/case_use_diagram.png)

## CLI

La interfaz está construida a partir de Typer y Rich para ofrecer una experiencia de uso más 
clara y agradable para el usuario. Typer facilita la implementación de comandos y parámetros 
durante el desarrollo, además de proporcionar una interfaz intuitiva para el usuario final. 
En conjunto con Rich, permite representar la información en forma de tablas facilitando su 
consulta desde la terminal.

## Parseo

Para el modo de escaneo de archivos de dependencias, el ecosistema se identifica automáticamente 
mediante el nombre del archivo. De esta manera, el usuario únicamente debe proporcionar la ruta 
del archivo para iniciar el escaneo.
Además, según el tipo de archivo se identifica su estructura y se extrae la información relevante
para posteriormente consultar las APIs encargadas de obtener las vulnerabilidades reportadas para 
los paquetes y sus versiones.

## APIs

La búsqueda por ecosistema utiliza GitHub Advisory Database API, una API que proporciona acceso a 
una amplia base de vulnerabilidades reportadas y utiliza identificadores CVE ampliamente adoptados 
en la industria de seguridad.
Para la búsqueda por paquete se integró OSV API, ya que está orientada a la consulta de vulnerabilidades 
por paquete y versión específicos. Además, cuenta con integración con múltiples fuentes de vulnerabilidades, 
incluyendo GitHub Advisory Database y CVE.

## Caché

SQLite permite mejorar la velocidad de respuesta en consultas realizadas por el usuario. Si se ejecuta
el mismo comando varias veces, en lugar de realizar nuevamente una petición externa que puede tomar 
algunos segundos, la caché permite recuperar la información almacenada previamente.

## Formateador

Entre toda la información proporcionada por ambas APIs, únicamente se seleccionan los datos relevantes 
para construir el objeto final que posteriormente se utiliza para generar la tabla mostrada mediante Rich 
o para crear archivos de exportación en los formatos soportados (HTML, JSON, CSV y Excel).


