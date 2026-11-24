# Decisiones de diseño

Notas breves sobre por qué `devops-cli` está hecho como está. Cada punto indica la
alternativa descartada, para poder revisarla si cambian las circunstancias.

## 1. Cero dependencias de runtime

Todo se resuelve con la biblioteca estándar (`argparse`, `shutil`, `ssl`, `socket`, `re`,
`json`, `gzip`). Una herramienta de operaciones se copia a servidores donde no siempre hay
`pip` ni acceso a internet; con cero dependencias, `pip install .` basta y no hay cadena de
suministro que vigilar. Las dependencias de desarrollo (pytest, pytest-cov, ruff) van en el
extra opcional `dev`.

*Descartado:* `click`/`typer` (más cómodos, pero una dependencia más), `rich` (tablas
bonitas, pero la salida se redirige a ficheros y a otros programas), `cryptography` (ver 4).

## 2. Códigos de salida estilo Nagios

`0` OK, `1` WARNING, `2` CRITICAL, `3` UNKNOWN y `64` para uso incorrecto (`EX_USAGE` de
`sysexits.h`). Así cualquier `cron`, script o sistema de monitorización (Nagios, Icinga,
Zabbix con UserParameter, healthchecks) puede consumir la herramienta sin parsear texto. El
repositorio hermano `bash-sysadmin-toolkit` usa la misma convención.

- Con varios resultados (varios montajes o varios hosts) el código es el del **peor**, con
  este orden de gravedad: CRITICAL > WARNING > UNKNOWN > OK. Un UNKNOWN nunca oculta un
  WARNING real, pero tampoco se da por bueno un OK si algo no se pudo comprobar.
- UNKNOWN (3) significa «no pude comprobarlo» (host inalcanzable, fichero ilegible); no es lo
  mismo que un problema detectado.
- `argparse` usa `2` por defecto para errores de uso, que colisionaría con CRITICAL; por eso
  se sobreescribe `ArgumentParser.error` para devolver `64`.

## 3. Primera línea al estilo plugin de Nagios

`disk` y `tls-expiry` empiezan por una línea resumen (`DISK WARNING - /var 85.0% usado ...`)
y debajo muestran la tabla completa. La primera línea es la que recoge Nagios; la tabla es
para quien lo ejecuta a mano. `--json` ofrece la misma información estructurada.

## 4. TLS: leer la caducidad sin validar la cadena, y sin `cryptography`

`ssl.getpeercert()` solo devuelve el diccionario con fechas cuando la cadena de confianza se
valida con éxito; con certificados caducados, autofirmados o de una CA interna devuelve `{}`
o falla antes de dar datos. Justo esos son los casos que interesan a un comprobador de
caducidad.

Decisión: conectar con `CERT_NONE`, pedir el certificado en DER (`getpeercert(binary_form=True)`)
y leer a mano los campos de validez, sujeto y emisor (`x509.py`, unas 100 líneas, con tests
sobre certificados reales generados con `openssl` y sobre estructuras mal formadas).

- **Consecuencia importante:** `tls-expiry` mide *cuánto le queda* al certificado; no
  comprueba que la cadena sea de confianza ni que el nombre coincida. Está documentado en
  el README. Es la misma semántica que `check_http -C` de Nagios.
- *Descartado:* depender de `cryptography` (rompe el punto 1) o usar `ssl._ssl._test_decode_cert`
  (API privada que puede desaparecer sin aviso).

## 5. Umbrales

- `disk`: `-w`/`-c` son porcentaje de **uso**; se alcanza el estado cuando `uso >= umbral`. El
  porcentaje se calcula como `df` (`usado / (usado + disponible)`), que descuenta el espacio
  reservado para root; de lo contrario no coincidiría con lo que ve el administrador.
- `tls-expiry`: `-w`/`-c` son **días restantes**; se alcanza cuando `días <= umbral`. Un
  certificado caducado es siempre CRITICAL, y uno que todavía no es válido también.
- Se exige que el umbral de aviso sea más estricto que el crítico (error de uso `64` si no),
  porque dos umbrales invertidos casi siempre son un error de quien lo configura.

## 6. `disk`: qué montajes se vigilan

Por defecto se leen de `/proc/mounts` y se descartan los sistemas de ficheros virtuales
(`tmpfs`, `proc`, `sysfs`, `cgroup`, `squashfs`...) y los montajes repetidos del mismo
dispositivo (los *bind mounts* y los subvolúmenes de btrfs mostrarían la misma cifra varias
veces). `--all` desactiva el filtro y `--path` comprueba rutas concretas.

En el descubrimiento automático, un montaje ilegible (típico: capas de overlay de Docker sin
permiso) se **ignora con un aviso por stderr** en vez de convertir todo el resultado en
UNKNOWN. Con `--path` el mismo fallo sí es UNKNOWN, porque el usuario pidió esa ruta
expresamente. Si ningún montaje es legible, el resultado es UNKNOWN.

## 7. `logs`: streaming y formatos

- El fichero se recorre **una sola vez, línea a línea**; la memoria depende del número de
  IPs/rutas distintas, no del tamaño del log. Acepta `.gz` y `-` (entrada estándar).
- Formatos: access log *combined/common* (nginx y Apache comparten formato) y syslog, tanto
  clásico (`Nov 24 09:13:01 host prog[pid]: ...`) como con fecha ISO 8601 (rsyslog moderno).
  `--format auto` mira las primeras 20 líneas no vacías y elige el formato que más
  reconoce.
- Syslog no tiene nivel de severidad en el fichero, así que se **infiere por palabras clave**
  (`critical`, `error`, `failed`, `denied`, `warning`...). Es una heurística, y está
  documentada como tal; la alternativa (parsear `journalctl -o json`) queda para el futuro.
- Syslog clásico no trae año: se asume el actual y, si la fecha resultara más de un día en el
  futuro, el anterior (un `Dec 31` leído en enero).
- «Errores más frecuentes» agrupa: en access logs por `(estado, ruta sin query string)` para
  `>= 400`; en syslog por mensaje normalizado (IPs y números sustituidos por `<IP>`/`<N>`),
  de modo que 500 intentos de `Failed password ... port 51234` cuentan como un solo error
  repetido y no como 500 distintos.
- Las líneas que no encajan se **cuentan** (`sin reconocer`), no se descartan en silencio ni
  abortan. Solo se falla si no se reconoce ninguna.
- `logs` devuelve `0` si genera el informe: es un resumen, no una comprobación con umbrales.

## 8. Errores esperados sin traza

Todo fallo previsible (fichero inexistente, host inalcanzable, `/proc` ausente, umbral
inválido) se representa con `CliError` o con un resultado `UNKNOWN`, y `main()` lo convierte en
un mensaje de una línea en stderr (`devops-cli: error: ...`) más el código de salida.
Un traceback solo debería aparecer ante un bug real.

Los datos que vienen de fuera (CN de un certificado, rutas y mensajes de un log, puntos de
montaje) pueden contener caracteres de control; se sustituyen por `?` al leerlos para que no
puedan falsear líneas de salida (p. ej. una primera línea de plugin de Nagios) ni mover el
cursor del terminal. `--timeout` se limita a una hora y rechaza `nan`/`inf`.

Limitación conocida: algunos mensajes internos de `argparse` (p. ej. «the following
arguments are required») salen en inglés porque Python no los traduce; la ayuda, las
descripciones y todos los mensajes propios están en español.

## 9. Testabilidad

- Las llamadas al sistema van detrás de parámetros inyectables: `usage_fn` y `mounts_reader`
  (disco), `fetcher` y `now` (TLS), `lines`, `now` y `since` (logs).
- Los tests de TLS no usan internet: levantan un servidor TLS en `127.0.0.1` con un
  certificado autofirmado generado al vuelo con `openssl` (se omiten si no está instalado),
  y para los estados «caducado» o «aún no válido» se inyecta la hora en vez de esperar.
- La zona horaria se fija a UTC en los tests para que los de fechas sean deterministas.

## 10. Fuera de alcance (por ahora)

Comprobaciones concurrentes de muchos hosts (hoy son secuenciales con timeout por host),
validación de cadena y *hostname* en TLS, `inodes` en `disk`, lectura directa de `journald` y
salida en formato de perfdata de Nagios.
