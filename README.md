# RFID Student Box

Sistema de control de acceso y gestión de billetes para transporte universitario basado en tarjetas RFID (MIFARE DESFire EV1/EV3). Incluye un **lector** que simula la validación en torno, un **servidor** que centraliza los datos y un **panel web** de administración.

> Proyecto desarrollado como Trabajo de Fin de Grado (TFG) de **Álvaro Hugo Hernández Triana**.

---

## Componentes

| Archivo | Descripción |
|---|---|
| `server_rfid.py` | Servidor Flask. Autentica a los lectores, gestiona usuarios, billetes, blacklist y logfile. |
| `lector_rfid.py` | Cliente de consola que emula el lector: valida y recarga billetes. |
| `webclient_rfid_v6.html` | Panel de administración web (single-file, sin dependencias de build). |
| `data/` | Bases de datos JSON del servidor (`users.json`, `blacklist.json`, `logfile.json`). |
| `blacklist_local.json` | Copia local de la blacklist que usa el lector cuando no hay conexión. |

---

## Arquitectura

```
┌────────────────┐    HTTP + AES-CMAC     ┌─────────────────┐
│ lector_rfid.py │ ─────────────────────▶ │ server_rfid.py  │
│  (lector)      │ ◀───────────────────── │ (Flask :5000)   │
└────────────────┘                        └────────┬────────┘
                                                   │
┌────────────────┐    HTTP + AES-CMAC              │
│ webclient_v6   │ ────────────────────────────────┘
│ (navegador)    │
└────────────────┘
```

El servidor es la única fuente de verdad. Los lectores y el panel web sólo se comunican con él.

---

## Protocolo de seguridad

Toda la comunicación se basa en **AES-CMAC** (RFC 4493) con una clave maestra compartida `KM` de 128 bits.

### 1. Autenticación mutua (`/auth/challenge` y `/auth/verify`)

1. El cliente genera un desafío aleatorio `Nr` (16 bytes) y lo envía.
2. El servidor genera `Ns` (16 bytes) y responde con `mac_server = CMAC_KM(Nr || Ns)`.
3. El cliente verifica `mac_server`, lo que autentica al servidor. Después envía `mac_client = CMAC_KM(Ns || Nr)`.
4. El servidor verifica `mac_client`, lo que autentica al cliente.
5. Ambos derivan la clave de sesión `KS = CMAC_KM(Nr || Ns)`.

La sesión caduca a los **5 minutos** sin actividad.

### 2. Firma de peticiones

Todas las operaciones posteriores (`/ticket/validate`, `/users/update`, `/logfile`, etc.) van firmadas:

- Se añaden `reader_id` y `ts` (UNIX time).
- El payload se serializa en JSON con claves ordenadas y sin espacios.
- Se calcula `mac = CMAC_KS(payload)` y se envía junto a la petición.
- El servidor rechaza peticiones con `ts` fuera de ±60 s (protección contra *replay*) o con MAC inválido.

---

## API del servidor

| Método | Ruta | Descripción | Firmada |
|---|---|---|---|
| POST | `/auth/challenge` | Inicio de autenticación mutua | No |
| POST | `/auth/verify` | Confirmación y establecimiento de sesión | No |
| POST | `/users/register` | Registra una tarjeta nueva | Sí |
| POST | `/users/update` | Actualiza datos o billete de un usuario | Sí |
| GET | `/users/query` | Consulta un UID (o `__all__`) | Sí |
| POST | `/ticket/validate` | Valida un billete y descuenta un uso si procede | Sí |
| POST | `/logfile` | Sube eventos del lector al logfile | Sí |
| GET | `/blacklist` | Descarga la blacklist (`step=date` o `step=full`) | Sí |
| POST | `/blacklist/add` | Añade un UID a la blacklist | Sí |
| POST | `/blacklist/remove` | Elimina un UID de la blacklist | Sí |
| GET | `/data/users`, `/data/logfile`, `/data/blacklist` | Volcado completo de las bases de datos (uso del panel) | Sí |

### Validación de billetes

`validar_billete()` devuelve uno de estos resultados:

- `banned`: el UID está en la blacklist.
- `expired`: ha pasado la fecha de caducidad.
- `void`: está bloqueado manualmente o se han agotado los usos.
- `valid`: acceso concedido. Se actualizan `lastusedateunix32`, `inout` y, si el billete tiene usos limitados, `realuses`.

Un billete con `maximumuses = 255` se considera **ilimitado**.

---

## Tipos de billete

Definidos en `RECARGA_OPCIONES` del lector:

| Tipo | Usos | Validez |
|---|---|---|
| single ride | 1 | 1 día |
| 10 rides | 10 | 30 días |
| day pass | ilimitados | 1 día |
| tourist pass | 10 | 3 días |
| week pass | ilimitados | 7 días |
| monthly pass | ilimitados | 30 días |
| staff pass | ilimitados | 1 año |

---

## Instalación

Requisitos: **Python 3.9+**.

```bash
pip install flask flask-cors cryptography requests
```

### Servidor

```bash
python3 server_rfid.py
```

Al arrancar pide la clave maestra `KM` (32 caracteres hexadecimales) y escucha en `0.0.0.0:5000`. Si no existen, crea los ficheros de `data/` automáticamente.

### Lector

```bash
python3 lector_rfid.py
```

Solicita al inicio la URL del servidor, el `READER_ID` y la clave `KM`. Pulsando Enter se usan los valores por defecto del código. Al autenticarse descarga la blacklist; si no hay conexión, trabaja con `blacklist_local.json`.

Menú del lector:

- **1**: validar billete.
- **2**: recargar billete.
- **R**: refrescar blacklist.
- **Q**: salir.

### Panel web

Abre `webclient_rfid_v6.html` directamente en el navegador. En la pantalla de conexión indica la URL del servidor, la clave `KM` y el `Reader ID`. Los datos se guardan en `localStorage`.

> El panel usa Google Fonts, por lo que necesita conexión a internet para cargar la tipografía. El resto funciona sin ella.

---

## Configuración

> **Aviso de seguridad.** Este repositorio contiene una clave maestra de prueba en el código. No la uses en un entorno real.

| Dónde | Variable | Valor por defecto |
|---|---|---|
| `server_rfid.py` | `KM` | `0123456789ABCDEF0123456789ABCDEF` (se sobrescribe al arrancar) |
| `lector_rfid.py` | `SERVER_URL` | `http://192.168.1.157:5000` |
| `lector_rfid.py` | `READER_ID` | `00001A23` |
| `lector_rfid.py` | `KM` | `AABBCCDDEEFF11223344556677889900` |
| `webclient_rfid_v6.html` | formulario inicial | valores de ejemplo prerrellenados |

Antes de desplegar:

1. Genera una `KM` nueva y no la guardes en el código.
2. Asegúrate de que `KM` del lector y del servidor coincidan.
3. Ajusta `SERVER_URL` a la IP real del servidor.

---

## Estructura de datos

**`users.json`**: usuarios y sus billetes.

```json
{
  "uid": "0123456U",
  "lastreaderid": "LECTORMAC",
  "cardtype": { "manufacturer": "NXP", "chiptype": "MIFARE DESFire EV3", "...": "..." },
  "ticketdata": {
    "tickettype": "monthly pass",
    "expirationdateunix32": 1785349890,
    "maximumuses": 255,
    "realuses": 0,
    "status": "valid",
    "inout": "in"
  },
  "userdata": { "...": "..." }
}
```

**`blacklist.json`**: UIDs bloqueados con su motivo (`LOSTORSTOLEN`, `MALFUNCTION`, `CLONINGSUSPECTED`).

**`logfile.json`**: eventos de cada operación (`tap`, `reload`), con timestamp, UID, resultado y descripción.

Si los ficheros no existen, el servidor los crea vacíos al arrancar. También se pueden dar de alta usuarios desde el panel web.

---

## Limitaciones conocidas

- El panel web implementa AES-CMAC sobre Web Crypto con AES-CBC, siguiendo el algoritmo de RFC 4493. Está pensado para la demostración del TFG y no ha sido auditado.
- El panel registra en consola cada cuerpo firmado (`signedPost → …`) para depuración. Conviene quitarlo en producción.
- El servidor usa el servidor de desarrollo de Flask (`app.run`). Para producción, usar un WSGI como gunicorn detrás de un proxy.
- La persistencia es en ficheros JSON, sin control de concurrencia.
- El lector simula el hardware: no hay comunicación real con un lector RFID.

---

## Licencia

Proyecto académico. Consulta con el autor antes de reutilizarlo.
