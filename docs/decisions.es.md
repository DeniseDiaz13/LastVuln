[English](decisions.md)

# Decisiones técnicas

## OSV API

Decidí utilizar esta API debido a que soporta una amplia variedad de ecosistemas de paquetes, 
incluyendo varios de los utilizados por GitHub Advisory Database, lo que facilita la integración 
de ambas fuentes de información.
OSV API utiliza identificadores GHSA entre otros identificadores de vulnerabilidades, permitiendo 
relacionar los resultados obtenidos con GitHub Advisory Database. Esto se adaptaba a los requerimientos 
del proyecto para realizar búsquedas por paquete y versión, además del escaneo de archivos de dependencias.

## SQLite

La caché almacenada mediante SQLite evita realizar múltiples llamadas a las APIs cuando el usuario 
ejecuta consultas repetidas. Esto permite mejorar los tiempos de respuesta y reducir solicitudes 
innecesarias a las APIs.
Aunque la ganancia individual de tiempo puede parecer pequeña, este tipo de optimizaciones resulta 
importante en herramientas de línea de comandos donde la rapidez de respuesta influye directamente 
en la experiencia de uso.

## ThreadPoolExecutor

Además del almacenamiento en caché, implementé consultas múltiples independientes mediante 
`ThreadPoolExecutor` para reducir el tiempo de ejecución durante el proceso de escaneo.
Este proceso representa la operación más costosa de la aplicación debido a la cantidad de paquetes 
que pueden existir en un archivo de dependencias, por lo que la ejecución concurrente permite mejorar 
el rendimiento y deja abierta la posibilidad de futuras optimizaciones.

