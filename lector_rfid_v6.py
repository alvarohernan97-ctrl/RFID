# lector_rfid_v6.py  —  RFID Student Box · lector operacional
# Autenticación mutua AES-CMAC + firma de mensajes con KS
# Funciones: validar billete, recargar billete
# Ejecutar: python3 lector_rfid_v5.py
# Requiere: pip3 install requests cryptography

import requests
import json
import time
import random
import string
import secrets
import hmac
import os
import sys
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend


SERVER_URL     = "http://192.168.1.157:5000"
READER_ID      = "00001A23"
KM             = bytes.fromhex("AABBCCDDEEFF11223344556677889900")
BLACKLIST_FILE = "blacklist_local.json"

sesion = {"KS": None, "Nr": None, "Ns": None, "active": False}
blacklist_local = []


# ── Criptografía ──────────────────────────────────────────────────────────────

def aes_cmac(key: bytes, message: bytes) -> bytes:
    c = CMAC(algorithms.AES(key), backend=default_backend())
    c.update(message)
    return c.finalize()

def derive_session_key(KM: bytes, Nr: bytes, Ns: bytes) -> bytes:
    # KS = AES-CMAC_KM(Nr || Ns)  según el protocolo acordado
    return aes_cmac(KM, Nr + Ns)

def calcular_mac(payload: dict) -> str:
    # el payload se serializa con sort_keys para que lector y servidor firmen exactamente lo mismo
    if not sesion["active"] or sesion["KS"] is None:
        raise RuntimeError("No hay sesión activa.")
    payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
    return aes_cmac(sesion["KS"], payload_bytes).hex()

def post_firmado(url, payload: dict, timeout=5):
    payload["ts"] = unix_now()
    payload["mac"] = calcular_mac(payload)
    return requests.post(url, json=payload, timeout=timeout)

def get_firmado(url, params: dict, timeout=5):
    if not sesion["active"] or sesion["KS"] is None:
        raise RuntimeError("No hay sesión activa.")
    params["ts"] = unix_now()
    params["mac"] = calcular_mac(params)
    return requests.get(url, params=params, timeout=timeout)


# ── Helpers ───────────────────────────────────────────────────────────────────

def rand_hex(n=8):
    return "".join(random.choices("0123456789ABCDEF", k=n))

def rand_digits(n=8):
    return "".join(random.choices(string.digits, k=n))

def unix_now():
    return int(time.time())

def unix_a_str(ts):
    if ts is None:
        return "sin fecha"
    try:
        return time.strftime("%d/%m/%Y %H:%M", time.localtime(int(ts)))
    except Exception:
        return str(ts)

def separador(titulo):
    print(f"\n{'═'*54}")
    print(f"  {titulo}")
    print(f"{'═'*54}")


# ── Blacklist local ───────────────────────────────────────────────────────────

def cargar_blacklist():
    global blacklist_local
    if os.path.isfile(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, "r") as f:
                data = json.load(f)
            records = data.get("blacklistrecords", [])
            blacklist_local = [r["uid"] for r in records if "uid" in r]
            print(f"  [OK] Blacklist local cargada: {len(blacklist_local)} UIDs bloqueados")
        except Exception as e:
            print(f"  [AVISO] No pude leer la blacklist local: {e}")
            blacklist_local = []
    else:
        print(f"  [INFO] Sin blacklist local previa ({BLACKLIST_FILE} no encontrado)")
        blacklist_local = []

def guardar_blacklist(bl_data: dict):
    try:
        with open(BLACKLIST_FILE, "w") as f:
            json.dump(bl_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"  [AVISO] No pude guardar la blacklist local: {e}")

def refresh_blacklist():
    """
    Descarga la blacklist del servidor y actualiza la copia local.
    Se llama al arrancar y desde el menú con R.
    Devuelve True si se actualizó, False si falló (se sigue usando la local).
    """
    global blacklist_local
    separador("REFRESCO DE BLACKLIST")
    try:
        r1 = get_firmado(f"{SERVER_URL}/blacklist", {"reader_id": READER_ID, "step": "date"})
        if r1.status_code != 200:
            print(f"  [AVISO] El servidor no devolvió la fecha de blacklist (HTTP {r1.status_code})")
            return False
        fecha_servidor = r1.json().get("blacklistdate", 0)
        print(f"  -> Fecha blacklist en servidor: {unix_a_str(fecha_servidor)}")

        r2 = get_firmado(f"{SERVER_URL}/blacklist", {"reader_id": READER_ID, "step": "full"})
        if r2.status_code != 200:
            print(f"  [AVISO] No pude descargar la blacklist completa (HTTP {r2.status_code})")
            return False

        bl = r2.json().get("blacklist", {})
        blacklist_local = [rec["uid"] for rec in bl.get("blacklistrecords", []) if "uid" in rec]
        guardar_blacklist(bl)
        print(f"  [OK] Blacklist actualizada: {len(blacklist_local)} UIDs bloqueados")
        return True

    except RuntimeError as e:
        print(f"  [ERROR] {e}")
        return False
    except requests.exceptions.ConnectionError:
        print(f"  [AVISO] Sin conexión — se usará la blacklist local ({len(blacklist_local)} UIDs)")
        return False

def en_blacklist(uid: str) -> bool:
    return uid.upper() in [u.upper() for u in blacklist_local]


# ── Log automático ────────────────────────────────────────────────────────────

def subir_log(uid: str, tickettype: str, eventtype: str, result: str,
              description: str, realuses: int = 0):
    # se llama tras cada operación; si falla no bloquea el flujo principal
    evento = {
        "timestampunix32": unix_now(),
        "uid":             uid,
        "cardtype":        "MIFARE DESFire EV1",
        "tickettype":      tickettype,
        "realuses":        realuses,
        "eventtype":       eventtype,
        "result":          result,
        "description":     description
    }
    payload = {
        "reader_id": READER_ID,
        "logfile": {
            "logfileversion":  "1.0",
            "logfiledate":     unix_now(),
            "logfilereaderid": READER_ID,
            "logfilerecords":  [evento]
        }
    }
    try:
        r = post_firmado(f"{SERVER_URL}/logfile", payload)
        if r.status_code in (200, 201):
            print(f"  [LOG] Log subido al servidor  [resultado={result}]")
        else:
            print(f"  [AVISO] Log no aceptado por el servidor (HTTP {r.status_code})")
    except requests.exceptions.ConnectionError:
        print(f"  [AVISO] Sin conexión — log NO subido al servidor")
    except Exception as e:
        print(f"  [AVISO] Error al subir log: {e}")


# ── Autenticación mutua ───────────────────────────────────────────────────────

def auth_session() -> bool:
    separador("AUTENTICACIÓN MUTUA AES-CMAC")

    Nr_bytes = secrets.token_bytes(16)
    Nr_hex   = Nr_bytes.hex()
    print(f"  -> READER_ID={READER_ID}")
    print(f"  -> Nr generado: {Nr_hex[:16]}...")

    try:
        r1 = requests.post(f"{SERVER_URL}/auth/challenge",
                           json={"reader_id": READER_ID, "Nr": Nr_hex}, timeout=5)
    except requests.exceptions.ConnectionError:
        print(f"  [ERROR] No puedo conectar al servidor en {SERVER_URL}")
        return False

    if r1.status_code != 200:
        print(f"  [ERROR] [AUTH/CHALLENGE] HTTP {r1.status_code}")
        try:
            print(f"  {json.dumps(r1.json(), indent=4, ensure_ascii=False)}")
        except Exception:
            pass
        return False

    data           = r1.json()
    Ns_hex         = data.get("Ns")
    mac_server_hex = data.get("mac_server")

    if not Ns_hex or not mac_server_hex:
        print("  [ERROR] Respuesta incompleta del servidor")
        return False

    Ns_bytes = bytes.fromhex(Ns_hex)
    print(f"  <- Ns recibido:  {Ns_hex[:16]}...")
    print(f"  <- mac_server:   {mac_server_hex[:16]}...")

    # compare_digest evita timing attacks al comparar el MAC
    if not hmac.compare_digest(aes_cmac(KM, Nr_bytes + Ns_bytes), bytes.fromhex(mac_server_hex)):
        print("  [ERROR] MAC del servidor INVALIDO — servidor no autenticado. Abortando.")
        return False
    print("  [OK] mac_server verificado — servidor autenticado")

    mac_client = aes_cmac(KM, Ns_bytes + Nr_bytes)
    print(f"  -> mac_client:   {mac_client.hex()[:16]}...")

    try:
        r2 = requests.post(f"{SERVER_URL}/auth/verify", json={
            "reader_id":  READER_ID,
            "Nr":         Nr_hex,
            "Ns":         Ns_hex,
            "mac_client": mac_client.hex()
        }, timeout=5)
    except requests.exceptions.ConnectionError:
        print(f"  [ERROR] No puedo conectar al servidor en {SERVER_URL}")
        return False

    if r2.status_code != 200:
        print(f"  [ERROR] [AUTH/VERIFY] HTTP {r2.status_code}")
        try:
            print(f"  {json.dumps(r2.json(), indent=4, ensure_ascii=False)}")
        except Exception:
            pass
        return False

    KS = derive_session_key(KM, Nr_bytes, Ns_bytes)
    sesion.update({"KS": KS, "Nr": Nr_bytes, "Ns": Ns_bytes, "active": True})

    print(f"\n  [OK] Autenticacion completada  |  KS: {KS.hex()[:16]}...")
    return True


# ── Validación de billete ─────────────────────────────────────────────────────

def mostrar_estado_billete(uid: str, td: dict):
    print(f"\n  {'─'*50}")
    print(f"  UID          : {uid}")
    tickettype = td.get("tickettype", "desconocido")
    status     = td.get("status", "?")
    max_uses   = td.get("maximumuses", 255)
    real_uses  = td.get("realuses", 0)
    expiry_ts  = td.get("expirationdateunix32")

    print(f"  Tipo billete : {tickettype}")
    print(f"  Estado       : {status.upper()}")

    if max_uses == 255:  # 255 = ilimitado por convenio del protocolo
        print(f"  Usos         : ILIMITADOS")
    else:
        restantes = max(0, max_uses - real_uses)
        print(f"  Usos         : {real_uses} / {max_uses}  ->  {restantes} viaje(s) restante(s)")
        if restantes == 0:
            print(f"  [AVISO] No quedan viajes disponibles")
        elif restantes <= 2:
            print(f"  [AVISO] Quedan pocos viajes ({restantes})")

    if expiry_ts is not None:
        dias_rest = (int(expiry_ts) - unix_now()) // 86400
        print(f"  Caduca       : {unix_a_str(expiry_ts)}", end="")
        if dias_rest < 0:
            print(f"  <- [AVISO] CADUCADO")
        elif dias_rest == 0:
            print(f"  <- [AVISO] CADUCA HOY")
        elif dias_rest <= 7:
            print(f"  <- [AVISO] Caduca en {dias_rest} dia(s)")
        else:
            print(f"  <- en {dias_rest} dia(s)")
    else:
        print(f"  Caduca       : sin fecha de caducidad")

    print(f"  {'─'*50}")


def ticket_validate():
    separador("PROCESO 1 — Validación de billete")

    uid   = _input("  UID de la tarjeta: ")
    inout = _input("  Dirección (in/out) [in]: ") or "in"

    if en_blacklist(uid):
        print(f"\n  [BLOQUEADA] TARJETA EN BLACKLIST LOCAL  UID={uid}")
        subir_log(uid, "unknown", "tap", "banned", "Tarjeta bloqueada detectada en blacklist local")
        return

    if inout == "out":
        print(f"\n  -> UID={uid}  inout=out  (salida -- no descuenta viaje)")
        print(f"\n  SALIDA REGISTRADA")
        subir_log(uid, "unknown", "tap", "out", "Salida registrada — sin descuento de viaje")
        return

    payload = {"reader_id": READER_ID, "uid": uid, "inout": inout}
    print(f"\n  -> UID={uid}  inout={inout}")
    try:
        r      = post_firmado(f"{SERVER_URL}/ticket/validate", payload)
        data   = r.json()
        result = data.get("result", "error")
        td     = data.get("ticketdata") or {}

        if r.status_code == 200:
            if result == "valid":
                print(f"\n  [OK] ACCESO CONCEDIDO")
            elif result == "banned":
                print(f"\n  [DENEGADO] TARJETA BLOQUEADA")
            elif result == "expired":
                print(f"\n  [DENEGADO] BILLETE CADUCADO")
            elif result == "void":
                print(f"\n  [DENEGADO] BILLETE SIN USOS DISPONIBLES")
            else:
                print(f"\n  [DENEGADO] ACCESO DENEGADO  [{result}]")

            mostrar_estado_billete(uid, td)
        else:
            print(f"\n  [ERROR] Error del servidor (HTTP {r.status_code}): {data.get('error', '')}")

        subir_log(uid, td.get("tickettype", "unknown"), "tap", result,
                  f"Validación billete: {result}  dirección={inout}",
                  realuses=td.get("realuses", 0))

    except RuntimeError as e:
        print(f"  [ERROR] {e}")
    except requests.exceptions.ConnectionError:
        print(f"  [ERROR] Sin conexión con el servidor")


# ── Recarga de billete ────────────────────────────────────────────────────────

RECARGA_OPCIONES = {
    "1": ("single ride",   1,   86400),
    "2": ("10 rides",      10,  2592000),
    "3": ("day pass",      255, 86400),
    "4": ("tourist pass",  10,  259200),
    "5": ("week pass",     255, 604800),
    "6": ("monthly pass",  255, 2592000),
    "7": ("staff pass",    255, 31536000),
}

VALIDEZ_DESC = {
    "1": "1 día", "2": "30 días", "3": "1 día",
    "4": "3 días", "5": "7 días", "6": "30 días", "7": "1 año",
}

def ticket_reload():
    separador("PROCESO 2 — Recarga de billete")

    uid = _input("  UID de la tarjeta: ")

    if en_blacklist(uid):
        print(f"\n  [BLOQUEADA] TARJETA EN BLACKLIST — recarga no permitida")
        return

    print("\n  Tipos de billete disponibles:")
    print("  ┌────┬──────────────────┬──────────┬──────────────────┐")
    print("  │    │ Tipo             │ Usos máx │ Validez          │")
    print("  ├────┼──────────────────┼──────────┼──────────────────┤")
    for k, (nombre, usos, _) in RECARGA_OPCIONES.items():
        usos_str = "Ilimitados" if usos == 255 else str(usos)
        print(f"  │ {k}  │ {nombre:<16} │ {usos_str:<8} │ {VALIDEZ_DESC[k]:<16} │")
    print("  └────┴──────────────────┴──────────┴──────────────────┘")

    opcion = _input("\n  Elige tipo de billete (1-7): ")
    if opcion not in RECARGA_OPCIONES:
        print("  [ERROR] Opcion no valida")
        return

    tickettype, max_uses, validez_seg = RECARGA_OPCIONES[opcion]
    now        = unix_now()
    new_expiry = now + validez_seg

    nuevo_ticket = {
        "tickettype":             tickettype,
        "registrationdateunix32": now,
        "expirationdateunix32":   new_expiry,
        "lastusedateunix32":      now,
        "maximumuses":            max_uses,
        "realuses":               0,
        "status":                 "valid",
        "inout":                  "out"
    }

    payload = {
        "reader_id": READER_ID,
        "uid":       uid,
        "new_data":  {"ticketdata": nuevo_ticket}
    }

    print(f"\n  -> UID={uid}  nuevo billete={tickettype}  caduca={unix_a_str(new_expiry)}")
    try:
        r    = post_firmado(f"{SERVER_URL}/users/update", payload)
        data = r.json()

        if r.status_code in (200, 201):
            usos_str = "Ilimitados" if max_uses == 255 else str(max_uses)
            print(f"\n  [OK] RECARGA COMPLETADA")
            print(f"  {'─'*50}")
            print(f"  UID          : {uid}")
            print(f"  Tipo billete : {tickettype}")
            print(f"  Usos maximos : {usos_str}")
            print(f"  Caduca       : {unix_a_str(new_expiry)}")
            print(f"  {'─'*50}")
        else:
            print(f"\n  [ERROR] Error del servidor (HTTP {r.status_code}): {data.get('error', '')}")

        result_log = "reloaded" if r.status_code in (200, 201) else "reload_error"
        subir_log(uid, tickettype, "reload", result_log,
                  f"Recarga de billete: {tickettype}  caduca={unix_a_str(new_expiry)}")

    except RuntimeError as e:
        print(f"  [ERROR] {e}")
    except requests.exceptions.ConnectionError:
        print(f"  [ERROR] Sin conexión con el servidor")


# ── Menú principal ────────────────────────────────────────────────────────────

MENU = """
╔══════════════════════════════════════════════════════╗
║    RFID Student Box · Lector v5  (AES-CMAC)         ║
╠══════════════════════════════════════════════════════╣
║  1.  Validar billete                                ║
║  2.  Recargar billete                               ║
║  ──────────────────────────────────────────────     ║
║  R.  Refrescar blacklist                            ║
║  Q.  Salir                                          ║
╚══════════════════════════════════════════════════════╝
Elige: """


def _input(prompt):
    # flush forzado para que el prompt aparezca antes de readline en algunos terminales
    sys.stdout.write(prompt)
    sys.stdout.flush()
    return sys.stdin.readline().rstrip("\n").strip()


def main():
    global SERVER_URL, READER_ID, KM

    print(f"\n{'='*54}", flush=True)
    print(f"  RFID Student Box · Lector v5", flush=True)
    print(f"{'='*54}", flush=True)
    print(f"  Pulsa Enter para aceptar el valor por defecto.\n", flush=True)

    entrada = _input(f"  Servidor   [{SERVER_URL}]: ")
    if entrada:
        SERVER_URL = entrada

    entrada = _input(f"  Reader ID  [{READER_ID}]: ")
    if entrada:
        READER_ID = entrada

    while True:
        entrada = _input(f"  KM (hex 32 chars)  [{KM.hex()[:8]}...]: ")
        if not entrada:
            break
        if len(entrada) != 32:
            print(f"  [ERROR] Debe tener 32 caracteres hex. Se recibieron {len(entrada)}.", flush=True)
            continue
        try:
            KM = bytes.fromhex(entrada)
            break
        except ValueError:
            print("  [ERROR] Contiene caracteres no hexadecimales.", flush=True)

    print(f"\n  Servidor : {SERVER_URL}", flush=True)
    print(f"  Lector   : {READER_ID}", flush=True)
    print(f"  KM       : {KM.hex()[:8]}...{KM.hex()[-8:]}", flush=True)

    cargar_blacklist()

    print()
    ok = auth_session()
    if not ok:
        print("\n  [AVISO] Autenticación fallida. El lector funcionará en modo OFFLINE.")
        print(f"  [INFO] Se usará la blacklist local ({len(blacklist_local)} UIDs).")
        print(f"  [AVISO] Las operaciones de validar/recargar requieren conexión con el servidor.")
    else:
        print()
        refresh_blacklist()

    while True:
        opcion = _input(MENU).lower()
        try:
            if   opcion == "1":  ticket_validate()
            elif opcion == "2":  ticket_reload()
            elif opcion == "r":
                if not sesion["active"]:
                    print("  [AVISO] Sin sesión activa. No se puede refrescar la blacklist.")
                else:
                    refresh_blacklist()
            elif opcion == "q":
                print("  Saliendo...")
                break
            else:
                print("  [AVISO] Opcion no valida")
        except requests.exceptions.ConnectionError:
            print(f"\n  [ERROR] Sin conexión con {SERVER_URL}")
        except Exception as e:
            print(f"\n  [ERROR] Error inesperado: {e}")
        print()


if __name__ == "__main__":
    main()