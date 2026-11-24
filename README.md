# python-devops-cli

[![CI](https://github.com/dgr-devops/python-devops-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/dgr-devops/python-devops-cli/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Dependencias](https://img.shields.io/badge/dependencias-0-brightgreen)
![Licencia](https://img.shields.io/badge/licencia-MIT-lightgrey)

Herramienta de línea de comandos para tareas habituales de administración de sistemas, con
**códigos de salida estilo Nagios** para poder usarla desde `cron`, scripts o un sistema de
monitorización:

| Comando      | Qué hace                                                                           |
|--------------|------------------------------------------------------------------------------------|
| `disk`       | Uso de disco por punto de montaje, con umbrales de aviso y crítico.                |
| `tls-expiry` | Días que le quedan al certificado TLS de uno o varios servidores.                  |
| `logs`       | Resumen de un log de acceso (nginx/Apache) o de syslog: códigos, IPs y errores.   |

Sin dependencias de runtime (solo biblioteca estándar de Python), mensajes en español y
salida opcional en JSON.

## Instalación

Requiere Python 3.11 o superior y Linux (`disk` lee `/proc/mounts`).

```bash
git clone https://github.com/dgr-devops/python-devops-cli.git
cd python-devops-cli
python3 -m venv .venv
source .venv/bin/activate
pip install .
devops-cli --version
```

También se puede ejecutar sin instalar el script: `python -m devops_cli ...`.

## Uso

```
$ devops-cli --help
uso: devops-cli [-h] [--version] COMANDO ...

Utilidades de operaciones: disco, caducidad TLS y resumen de logs.

argumentos:
  COMANDO
    disk        uso de disco por punto de montaje
    tls-expiry  días hasta la caducidad de certificados TLS
    logs        resumen de un log de acceso o de syslog

opciones:
  -h, --help    muestra esta ayuda y termina
  --version     muestra la versión y termina

Códigos de salida: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN (error de
ejecución), 64 uso incorrecto.
```

Los ejemplos de abajo son salida real, capturada el 2026-11-24.

### `disk`: uso de disco

```
devops-cli disk [-w PCT] [-c PCT] [-p RUTA]... [-a] [--json]
```

Sin opciones recorre todos los montajes reales (los de `/proc/mounts`, sin `tmpfs`, `proc`,
`squashfs`...). `-w` y `-c` son el porcentaje de **uso** a partir del cual se avisa
(por defecto 80) o es crítico (por defecto 90).

```
$ devops-cli disk -p / -p /boot
DISK OK - 2 puntos de montaje por debajo del umbral (aviso >= 80%, crítico >= 90%)

MONTAJE  DISPOSITIVO     TIPO       TOTAL      USADO      LIBRE    USO  ESTADO
-------  --------------  -----  ---------  ---------  ---------  -----  ------
/        /dev/nvme0n1p2  btrfs  927.5 GiB  282.5 GiB  642.6 GiB  30.5%  OK
/boot    /dev/nvme0n1p1  vfat     4.0 GiB  389.4 MiB    3.6 GiB   9.5%  OK
[exit=0]

$ devops-cli disk -p / -w 20 -c 30
DISK CRITICAL - / 30.5% usado (aviso >= 20%, crítico >= 30%)

MONTAJE  DISPOSITIVO     TIPO       TOTAL      USADO      LIBRE    USO  ESTADO
-------  --------------  -----  ---------  ---------  ---------  -----  --------
/        /dev/nvme0n1p2  btrfs  927.5 GiB  282.5 GiB  642.6 GiB  30.5%  CRITICAL
[exit=2]
```

Con `--json`:

```
$ devops-cli disk -p / --json
{
  "check": "disk",
  "status": "OK",
  "exit_code": 0,
  "thresholds": {
    "warning": 80.0,
    "critical": 90.0
  },
  "mounts": [
    {
      "mountpoint": "/",
      "device": "/dev/nvme0n1p2",
      "fstype": "btrfs",
      "total_bytes": 995907784704,
      "used_bytes": 303375802368,
      "free_bytes": 689945321472,
      "used_percent": 30.5,
      "status": "OK",
      "error": null
    }
  ],
  "skipped": []
}
```

Los umbrales incoherentes son un error de uso:

```
$ devops-cli disk -w 90 -c 80
devops-cli: error: el umbral de aviso (-w 90) debe ser menor que el crítico (-c 80)
[exit=64]
```

### `tls-expiry`: caducidad de certificados

```
devops-cli tls-expiry HOST[:PUERTO]... [-w DIAS] [-c DIAS] [-t SEG] [--json]
```

Se conecta a cada destino (puerto 443 por defecto; acepta `[IPv6]:puerto`) y calcula los
días que le quedan al certificado. `-w` (por defecto 30) y `-c` (por defecto 14) son los
días restantes a partir de los cuales hay aviso o es crítico; un certificado caducado es
siempre CRITICAL. `-t` fija el tiempo máximo por conexión (por defecto 10 s).

```
$ devops-cli tls-expiry github.com example.com:443
TLS OK - 2 certificados con vigencia suficiente

DESTINO          SUJETO (CN)  EMISOR (CN)                                     CADUCA      DÍAS  ESTADO
---------------  -----------  ----------------------------------------------  ----------  ----  ------
github.com:443   github.com   Sectigo Public Server Authentication CA DV E36  2027-01-27    64  OK
example.com:443  example.com  Cloudflare TLS Issuing ECC CA 3                 2026-12-25    31  OK
[exit=0]
```

Contra un servidor local con un certificado autofirmado de 20 días (aviso) y otro de 5 días
(crítico):

```
$ devops-cli tls-expiry 127.0.0.1:8443
TLS WARNING - 127.0.0.1:8443 caduca en 19 días (2026-12-14)

DESTINO         SUJETO (CN)         EMISOR (CN)         CADUCA      DÍAS  ESTADO
--------------  ------------------  ------------------  ----------  ----  -------
127.0.0.1:8443  intranet.lab.local  intranet.lab.local  2026-12-14    19  WARNING
[exit=1]

$ devops-cli tls-expiry 127.0.0.1:8444
TLS CRITICAL - 127.0.0.1:8444 caduca en 4 días (2026-11-29)

DESTINO         SUJETO (CN)         EMISOR (CN)         CADUCA      DÍAS  ESTADO
--------------  ------------------  ------------------  ----------  ----  --------
127.0.0.1:8444  intranet.lab.local  intranet.lab.local  2026-11-29     4  CRITICAL
[exit=2]
```

Los fallos de conexión se explican sin trazas y no impiden comprobar el resto de destinos:

```
$ devops-cli tls-expiry 127.0.0.1:8443 127.0.0.1:9 no-existe.invalid -t 3
TLS WARNING - 127.0.0.1:8443 caduca en 19 días (2026-12-14); 127.0.0.1:9 conexión rechazada en el puerto 9; no-existe.invalid:443 no se pudo resolver el host 'no-existe.invalid'

DESTINO                SUJETO (CN)         EMISOR (CN)         CADUCA      DÍAS  ESTADO
---------------------  ------------------  ------------------  ----------  ----  -------
127.0.0.1:8443         intranet.lab.local  intranet.lab.local  2026-12-14    19  WARNING
127.0.0.1:9            -                   -                   -              -  UNKNOWN
no-existe.invalid:443  -                   -                   -              -  UNKNOWN
[exit=1]
```

> **Alcance:** mide *cuánto le queda* al certificado; **no valida** la cadena de confianza ni
> que el nombre coincida (así funciona también con certificados autofirmados o de una CA
> interna). Las razones están en [docs/decisiones.md](docs/decisiones.md#4-tls-leer-la-caducidad-sin-validar-la-cadena-y-sin-cryptography).

### `logs`: resumen de logs

```
devops-cli logs FICHERO [-f auto|access|syslog] [-s DESDE] [-n N] [--json]
```

Resume un log de acceso nginx/Apache (formato *combined* o *common*) o un syslog (clásico o
con fecha ISO 8601). Admite ficheros `.gz` y `-` para leer de la entrada estándar. El formato
se detecta solo salvo que se indique con `-f`. `--since` acepta duraciones (`30m`, `2h`,
`7d`, `1w`) o una fecha ISO (`2026-11-24T08:00`); `-n` fija el tamaño de los rankings
(10 por defecto). En `examples/` hay dos logs sintéticos con los que reproducir lo siguiente.

```
$ devops-cli logs examples/access.log -n 3
Fichero: examples/access.log  (formato: access)
Líneas: 121 totales, 120 reconocidas, 1 sin reconocer, 120 en el rango
Periodo: 2026-11-24T08:01:26+01:00 -> 2026-11-24T09:36:40+01:00

Códigos de estado
CÓDIGO  PETICIONES
------  ----------
200             57
201              7
304             12
403             11
404             23
500              7
502              3

Clases: 2xx=64  3xx=12  4xx=34  5xx=10

IPs más activas
IP             PETICIONES
-------------  ----------
203.0.113.7            53
198.51.100.23          20
203.0.113.99           15

Errores más frecuentes (HTTP >= 400)
ESTADO  RUTA           VECES
------  -------------  -----
404     /wp-login.php     17
403     /admin            11
500     /api/orders        7
[exit=0]
```

En syslog no hay nivel de severidad en el fichero, así que se **infiere** por palabras clave
(`error`, `failed`, `denied`, `warning`, `critical`...). Los mensajes se agrupan sustituyendo
IPs y números, de modo que los intentos repetidos de un mismo ataque cuentan como un solo
error frecuente:

```
$ devops-cli logs examples/syslog.log -n 3 --since 2026-11-24T10:00
Fichero: examples/syslog.log  (formato: syslog)
Líneas: 60 totales, 60 reconocidas, 0 sin reconocer, 28 en el rango
Desde: 2026-11-24T10:00:00+01:00
Periodo: 2026-11-24T10:03:00+01:00 -> 2026-11-24T13:23:00+01:00

Niveles
NIVEL     LÍNEAS
--------  ------
critical       0
error         14
warning        3
info          11

Programas más activos
PROGRAMA  LÍNEAS
--------  ------
systemd        8
CRON           5
nginx          5

IPs en mensajes de error
IP             VECES
-------------  -----
198.51.100.23      3
203.0.113.7        1

Errores más frecuentes
VECES  MENSAJE
-----  -----------------------------------------------------------------------
    5  connect() failed (<N>: Connection refused) while connecting to upstream
    3  Failed password for invalid user admin from <IP> port <N> ssh2
    3  nginx.service: Main process exited, code=exited, status=<N>/FAILURE
[exit=0]
```

Con `--json` el mismo resumen es procesable con `jq` u otras herramientas:

```
$ devops-cli logs examples/access.log -n 2 --json
{
  "file": "examples/access.log",
  "format": "access",
  "since": null,
  "lines": {
    "total": 121,
    "parsed": 120,
    "unparsed": 1,
    "in_range": 120
  },
  "period": {
    "first": "2026-11-24T08:01:26+01:00",
    "last": "2026-11-24T09:36:40+01:00"
  },
  "status_codes": {
    "200": 57,
    "201": 7,
    "304": 12,
    "403": 11,
    "404": 23,
    "500": 7,
    "502": 3
  },
  "status_classes": {
    "2xx": 64,
    "3xx": 12,
    "4xx": 34,
    "5xx": 10
  },
  "top_ips": [
    {
      "ip": "203.0.113.7",
      "count": 53
    },
    {
      "ip": "198.51.100.23",
      "count": 20
    }
  ],
  "top_errors": [
    {
      "status": 404,
      "path": "/wp-login.php",
      "count": 17
    },
    {
      "status": 403,
      "path": "/admin",
      "count": 11
    }
  ]
}
```

```
$ devops-cli logs /var/log/no-existe.log
devops-cli: error: no existe el fichero: /var/log/no-existe.log
[exit=3]
```

## Códigos de salida

| Código | Significado                                                                      |
|-------:|----------------------------------------------------------------------------------|
| `0`    | **OK**: todo por debajo de los umbrales (o informe de `logs` generado).          |
| `1`    | **WARNING**: se alcanzó el umbral de aviso.                                      |
| `2`    | **CRITICAL**: se alcanzó el umbral crítico, o el certificado está caducado.      |
| `3`    | **UNKNOWN**: no se pudo comprobar (host inalcanzable, fichero ilegible...).      |
| `64`   | Uso incorrecto de la línea de comandos (opción inválida, umbrales incoherentes). |

Con varios resultados (varios montajes o varios hosts) el código es el del peor, con el orden
CRITICAL > WARNING > UNKNOWN > OK. Los errores esperados se muestran en una línea por
`stderr` (`devops-cli: error: ...`), nunca como traza de Python.

### Integración

Desde `cron`, dejando constancia en el log del sistema cuando no es OK:

```cron
*/15 * * * * devops-cli disk -w 80 -c 90 >/dev/null || logger -t devops-cli "disk: código $?"
0 7 * * *    devops-cli tls-expiry web.ejemplo.com api.ejemplo.com || logger -t devops-cli "tls: código $?"
```

Como comprobación de Nagios/Icinga vía NRPE (el código y la primera línea de la salida son
justo lo que espera el servidor):

```
command[check_disk]=/opt/devops-cli/.venv/bin/devops-cli disk -w 80 -c 90
command[check_tls]=/opt/devops-cli/.venv/bin/devops-cli tls-expiry web.ejemplo.com -w 30 -c 14
```

## Desarrollo

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

ruff check .                 # lint
ruff format --check .        # formato
pytest --cov                 # tests con cobertura (falla por debajo del 80 %)
```

- Los tests no usan internet: los de TLS levantan un servidor local con un certificado
  autofirmado generado con `openssl` (se omiten si no está instalado), y las llamadas al
  sistema (`/proc/mounts`, `shutil.disk_usage`, la conexión TLS) se pueden sustituir.
- La cobertura exigida es del 80 %; ahora mismo ronda el 99 %.
- La CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) ejecuta ruff y pytest con
  cobertura en Python 3.11, 3.12 y 3.13.

Estructura:

```
src/devops_cli/
  cli.py        parser, enrutado de subcomandos y gestión de errores
  common.py     estados Nagios, errores, tablas y utilidades compartidas
  disk.py       subcomando disk
  tls.py        subcomando tls-expiry
  x509.py       lector mínimo de certificados DER (sin dependencias)
  logs.py       subcomando logs (resumen y salida)
  logparse.py   parsers de access log y syslog
tests/          pytest (219 tests)
examples/       logs sintéticos para probar logs
docs/decisiones.md   por qué está hecho así
```

Las decisiones de diseño y sus alternativas descartadas están en
[docs/decisiones.md](docs/decisiones.md).

## Licencia

MIT. Ver [LICENSE](LICENSE).
