# server_rfid_v5.py  —  RFID Student Box · servidor Flask
# Autenticación mutua AES-CMAC + clave de sesión KS derivada de KM
# Ejecutar: python3 server_rfid_v5.py
# Requiere: pip install flask cryptography flask-cors

from flask import Flask, request, jsonify
from flask_cors import CORS
import json, os, time, secrets, hmac
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
CORS(app)

DATA_DIR  = "data"
USERS_DB  = os.path.join(DATA_DIR, "users.json")
BLACKLIST = os.path.join(DATA_DIR, "blacklist.json")
LOGFILE   = os.path.join(DATA_DIR, "logfile.json")

# se sobreescribe en main() con la clave que introduzca el operador
KM = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")

sessions = {}
SESSION_TIMEOUT = 300  # 5 minutos


# ── Criptografía ──────────────────────────────────────────────────────────────

def aes_cmac(key: bytes, message: bytes) -> bytes:
    c = CMAC(algorithms.AES(key), backend=default_backend())
    c.update(message)
    return c.finalize()


def derive_session_key(KM: bytes, Nr: bytes, Ns: bytes) -> bytes:
    # KS = AES-CMAC_KM(Nr || Ns)  según el protocolo acordado
    return aes_cmac(KM, Nr + Ns)


def verify_mac(key: bytes, message: bytes, mac_recibido: bytes) -> bool:
    # compare_digest evita timing attacks, no cambiar por ==
    return hmac.compare_digest(aes_cmac(key, message), mac_recibido)


def sesion_valida(reader_id: str) -> bool:
    s = sessions.get(reader_id)
    if not s:
        return False
    if time.time() - s["timestamp"] > SESSION_TIMEOUT:
        sessions.pop(reader_id, None)
        print(f"[AUTH] Sesión expirada — lector {reader_id}")
        return False
    return True


def clave_sesion(reader_id: str) -> bytes | None:
    s = sessions.get(reader_id)
    return s["KS"] if s else None


# ── Base de datos ─────────────────────────────────────────────────────────────

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def init_databases():
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"[INIT] Carpeta '{DATA_DIR}/' lista")

    if not os.path.exists(USERS_DB):
        save_json(USERS_DB, {"fileversion": "1.0", "filedate": int(time.time()), "filerecords": []})
        print(f"[INIT] {USERS_DB} creado")
    else:
        print(f"[INIT] {USERS_DB} ya existe ({len(load_json(USERS_DB)['filerecords'])} usuarios)")

    if not os.path.exists(BLACKLIST):
        save_json(BLACKLIST, {
            "blacklistversion": "1.0", "blacklistdate": int(time.time()),
            "blacklistissuer": "RFIDStudentBox", "blacklistrecords": []
        })
        print(f"[INIT] {BLACKLIST} creado")
    else:
        print(f"[INIT] {BLACKLIST} ya existe ({len(load_json(BLACKLIST)['blacklistrecords'])} entradas)")

    if not os.path.exists(LOGFILE):
        save_json(LOGFILE, {
            "logfileversion": "1.0", "logfiledate": int(time.time()),
            "logfilereaderid": None, "logfilerecords": []
        })
        print(f"[INIT] {LOGFILE} creado")
    else:
        print(f"[INIT] {LOGFILE} ya existe ({len(load_json(LOGFILE)['logfilerecords'])} eventos)")


def uid_en_blacklist(uid):
    bl = load_json(BLACKLIST)
    for r in bl["blacklistrecords"]:
        if r["uid"] == uid:
            return r
    return None


def validar_billete(ticketdata):
    now = int(time.time())
    if ticketdata.get("status") == "blocked":
        return "void", "Ticket manually blocked"
    expiracion = ticketdata.get("expirationdateunix32", 0)
    if expiracion and now > expiracion:
        return "expired", f"Ticket expired on {expiracion}"
    max_usos  = ticketdata.get("maximumuses", 255)
    usos_real = ticketdata.get("realuses", 0)
    if max_usos != 255 and usos_real >= max_usos:
        return "void", f"No uses left ({usos_real}/{max_usos})"
    return "valid", "Ticket OK"


# ── Decorador de sesión ───────────────────────────────────────────────────────

def require_session(f):
    """
    Verifica sesión activa y MAC antes de entrar al endpoint.
    GET  → parámetros en query string
    POST → parámetros en body JSON

    Campos obligatorios: reader_id, ts (UNIX ±60s anti-replay), mac (hex AES-CMAC_KS)
    """
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method == 'GET':
            raw = request.args.to_dict()
            if 'ts' in raw:
                try:
                    raw['ts'] = int(raw['ts'])
                except ValueError:
                    pass
        else:
            raw = request.json or {}

        reader_id = raw.get("reader_id")
        mac_hex   = raw.get("mac")
        ts        = raw.get("ts")

        if not reader_id or not mac_hex or ts is None:
            return jsonify({"status": "error", "reason": "Faltan reader_id, mac o ts"}), 400

        if abs(time.time() - int(ts)) > 60:
            return jsonify({"status": "error", "reason": "Timestamp fuera de rango (posible replay)"}), 401

        if not sesion_valida(reader_id):
            return jsonify({"status": "error", "reason": "Sesión no válida o expirada. Re-autentícate en /auth"}), 401

        KS = clave_sesion(reader_id)

        # reconstruimos el payload exactamente igual que el lector para comparar el MAC
        payload_verificar = {k: v for k, v in sorted(raw.items()) if k != "mac"}
        payload_bytes = json.dumps(
            payload_verificar,
            separators=(',', ':'),
            sort_keys=True,
            ensure_ascii=False
        ).encode()

        try:
            mac_recibido = bytes.fromhex(mac_hex)
        except ValueError:
            return jsonify({"status": "error", "reason": "MAC con formato inválido"}), 400

        if not verify_mac(KS, payload_bytes, mac_recibido):
            print(f"[SEC] MAC inválido — lector={reader_id}  payload={payload_bytes.decode()}")
            return jsonify({"status": "error", "reason": "MAC inválido — integridad comprometida"}), 403

        sessions[reader_id]["timestamp"] = time.time()
        return f(*args, **kwargs)

    return wrapper


# ── Autenticación mutua ───────────────────────────────────────────────────────

@app.route("/auth/challenge", methods=["POST"])
def auth_challenge():
    data      = request.json or {}
    reader_id = data.get("reader_id")
    Nr_hex    = data.get("Nr")

    if not reader_id or not Nr_hex:
        return jsonify({"status": "error", "reason": "Faltan reader_id o Nr"}), 400

    try:
        Nr = bytes.fromhex(Nr_hex)
        if len(Nr) != 16:
            raise ValueError
    except ValueError:
        return jsonify({"status": "error", "reason": "Nr debe ser 16 bytes en hex (32 chars)"}), 400

    Ns         = secrets.token_bytes(16)
    mac_server = aes_cmac(KM, Nr + Ns)

    sessions[reader_id] = {
        "Nr": Nr, "Ns": Ns, "KS": None,
        "timestamp": time.time(), "verified": False
    }

    print(f"[AUTH] Challenge  | lector={reader_id}  Nr={Nr_hex[:8]}…  Ns={Ns.hex()[:8]}…")
    return jsonify({
        "status":     "ok",
        "Ns":         Ns.hex(),
        "mac_server": mac_server.hex()
    }), 200


@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    data           = request.json or {}
    reader_id      = data.get("reader_id")
    Nr_hex         = data.get("Nr")
    Ns_hex         = data.get("Ns")
    mac_client_hex = data.get("mac_client")

    if not all([reader_id, Nr_hex, Ns_hex, mac_client_hex]):
        return jsonify({"status": "error", "reason": "Faltan campos en la petición"}), 400

    sesion = sessions.get(reader_id)
    if not sesion:
        return jsonify({"status": "error", "reason": "Sin sesión pendiente. Llama primero a /auth/challenge"}), 401

    try:
        Nr         = bytes.fromhex(Nr_hex)
        Ns         = bytes.fromhex(Ns_hex)
        mac_client = bytes.fromhex(mac_client_hex)
    except ValueError:
        return jsonify({"status": "error", "reason": "Formato hex inválido"}), 400

    if Nr != sesion["Nr"] or Ns != sesion["Ns"]:
        print(f"[AUTH] FALLO — Nr/Ns no coinciden  | lector={reader_id}")
        sessions.pop(reader_id, None)
        return jsonify({"status": "error", "reason": "Nr o Ns no coinciden con el challenge"}), 403

    if not verify_mac(KM, Ns + Nr, mac_client):
        print(f"[AUTH] FALLO — MAC del lector inválido  | lector={reader_id}")
        sessions.pop(reader_id, None)
        return jsonify({"status": "error", "reason": "Autenticación fallida — MAC inválido"}), 403

    KS = derive_session_key(KM, Nr, Ns)
    sessions[reader_id].update({"KS": KS, "verified": True, "timestamp": time.time()})

    print(f"[AUTH] OK  | lector={reader_id}  KS={KS.hex()[:8]}…")
    return jsonify({
        "status":             "ok",
        "message":            f"Sesión establecida para lector {reader_id}.",
        "session_expires_in": SESSION_TIMEOUT
    }), 200


# ── Registro de usuario ───────────────────────────────────────────────────────

@app.route("/users/register", methods=["POST"])
@require_session
def register_user():
    data      = request.json
    reader_id = data.get("reader_id")
    uid       = data.get("uid")
    card_data = data.get("card_data")

    if not uid or not card_data:
        return jsonify({"status": "error", "reason": "Faltan uid o card_data"}), 400

    bloqueado = uid_en_blacklist(uid)
    if bloqueado:
        print(f"[REGISTER] RECHAZADO — UID {uid} en blacklist")
        return jsonify({"status": "reject", "reason": "UID en blacklist", "detail": bloqueado.get("reasoncode")}), 403

    db = load_json(USERS_DB)
    for r in db["filerecords"]:
        if r["uid"] == uid:
            return jsonify({"status": "reject", "reason": "UID ya registrado"}), 409

    nuevo = {
        "uid":          uid,
        "lastreaderid": reader_id,
        "cardtype":     card_data.get("cardtype",   {}),
        "ticketdata":   card_data.get("ticketdata", {}),
        "userdata":     card_data.get("userdata",   {})
    }
    db["filerecords"].append(nuevo)
    db["filedate"] = int(time.time())
    save_json(USERS_DB, db)

    print(f"[REGISTER] Nuevo usuario  | UID={uid}  lector={reader_id}")
    return jsonify({"status": "ok", "message": "Usuario registrado", "user": nuevo}), 201


# ── Actualización de usuario ──────────────────────────────────────────────────

@app.route("/users/update", methods=["POST"])
@require_session
def update_user():
    data      = request.json
    reader_id = data.get("reader_id")
    uid       = data.get("uid")
    new_data  = data.get("new_data")

    if not uid or not new_data:
        return jsonify({"status": "error", "reason": "Faltan uid o new_data"}), 400

    db = load_json(USERS_DB)
    for r in db["filerecords"]:
        if r["uid"] == uid:
            r.update(new_data)
            r["lastreaderid"] = reader_id
            db["filedate"] = int(time.time())
            save_json(USERS_DB, db)
            print(f"[UPDATE] Actualizado  | UID={uid}  lector={reader_id}")
            return jsonify({"status": "ok", "message": "Usuario actualizado", "user": r}), 200

    return jsonify({"status": "reject", "reason": "UID no encontrado"}), 404


# ── Validación de billete ─────────────────────────────────────────────────────

@app.route("/ticket/validate", methods=["POST"])
@require_session
def ticket_validate():
    data      = request.json
    reader_id = data.get("reader_id")
    uid       = data.get("uid")
    inout     = data.get("inout", "in")

    if not uid:
        return jsonify({"status": "error", "reason": "Falta uid"}), 400

    bloqueado = uid_en_blacklist(uid)
    if bloqueado:
        print(f"[VALIDATE] BANNED  | UID={uid}  motivo={bloqueado.get('reasoncode')}")
        return jsonify({
            "status": "ok", "result": "banned",
            "description": f"UID en blacklist: {bloqueado.get('reasoncode')}",
            "ticketdata": None
        }), 200

    db = load_json(USERS_DB)
    registro = next((r for r in db["filerecords"] if r["uid"] == uid), None)

    if not registro:
        return jsonify({"status": "reject", "reason": "UID no registrado"}), 404

    ticketdata = registro.get("ticketdata", {})
    resultado, descripcion = validar_billete(ticketdata)

    if resultado != "valid":
        print(f"[VALIDATE] {resultado.upper()}  | UID={uid}  {descripcion}")
        return jsonify({"status": "ok", "result": resultado, "description": descripcion, "ticketdata": ticketdata}), 200

    now = int(time.time())
    ticketdata["lastusedateunix32"] = now
    ticketdata["inout"] = inout
    if ticketdata.get("maximumuses", 255) != 255:
        ticketdata["realuses"] = ticketdata.get("realuses", 0) + 1

    registro["lastreaderid"] = reader_id
    db["filedate"] = now
    save_json(USERS_DB, db)

    print(f"[VALIDATE] VALID  | UID={uid}  inout={inout}  lector={reader_id}")
    return jsonify({"status": "ok", "result": "valid", "description": descripcion, "ticketdata": ticketdata}), 200


# ── Subida de logfile ─────────────────────────────────────────────────────────

@app.route("/logfile", methods=["POST"])
@require_session
def upload_logfile():
    data      = request.json
    reader_id = data.get("reader_id")
    entrante  = data.get("logfile", {})
    records   = entrante.get("logfilerecords", [])

    if not reader_id:
        return jsonify({"status": "error", "reason": "Falta reader_id"}), 400

    lf = load_json(LOGFILE)
    lf["logfilerecords"].extend(records)
    lf["logfiledate"]     = int(time.time())
    lf["logfilereaderid"] = reader_id
    save_json(LOGFILE, lf)

    print(f"[LOGFILE] {len(records)} eventos recibidos  | lector={reader_id}")
    return jsonify({"status": "ok", "saved": len(records)}), 200


# ── Blacklist ─────────────────────────────────────────────────────────────────

@app.route("/blacklist", methods=["GET"])
@require_session
def download_blacklist():
    reader_id = request.args.get("reader_id")
    step      = request.args.get("step", "full")

    bl = load_json(BLACKLIST)

    if step == "date":
        print(f"[BLACKLIST] Consulta fecha  | lector={reader_id}")
        return jsonify({"status": "ok", "blacklistdate": bl["blacklistdate"]}), 200

    print(f"[BLACKLIST] Descarga  | lector={reader_id}  {len(bl.get('blacklistrecords', []))} entradas")
    return jsonify({"status": "ok", "blacklist": bl}), 200


@app.route("/blacklist/add", methods=["POST"])
@require_session
def add_to_blacklist():
    data   = request.json
    record = data.get("record")

    if not record or not record.get("uid"):
        return jsonify({"status": "error", "reason": "Falta uid en el registro"}), 400

    bl = load_json(BLACKLIST)
    for r in bl["blacklistrecords"]:
        if r["uid"] == record["uid"]:
            return jsonify({"status": "reject", "reason": "UID ya está en la blacklist"}), 409

    bl["blacklistrecords"].append(record)
    bl["blacklistdate"] = int(time.time())
    save_json(BLACKLIST, bl)

    print(f"[BLACKLIST] Bloqueado  | UID={record['uid']}  motivo={record.get('reasoncode')}")
    return jsonify({"status": "ok", "message": f"UID {record['uid']} añadido a la blacklist"}), 201


@app.route("/blacklist/remove", methods=["POST"])
@require_session
def remove_from_blacklist():
    data      = request.json
    uid       = data.get("uid")
    reader_id = data.get("reader_id")

    if not uid:
        return jsonify({"status": "error", "reason": "Falta uid"}), 400

    bl     = load_json(BLACKLIST)
    antes  = len(bl["blacklistrecords"])
    bl["blacklistrecords"] = [r for r in bl["blacklistrecords"] if r["uid"] != uid]

    if len(bl["blacklistrecords"]) == antes:
        return jsonify({"status": "reject", "reason": f"UID {uid} no encontrado en la blacklist"}), 404

    bl["blacklistdate"] = int(time.time())
    save_json(BLACKLIST, bl)

    print(f"[BLACKLIST] Desbloqueado  | UID={uid}  lector={reader_id}")
    return jsonify({"status": "ok", "message": f"UID {uid} eliminado de la blacklist"}), 200


# ── Consulta de usuarios ──────────────────────────────────────────────────────

@app.route("/users/query", methods=["GET"])
@require_session
def query_user():
    uid       = request.args.get("uid")
    reader_id = request.args.get("reader_id")

    if not uid or not reader_id:
        return jsonify({"status": "error", "reason": "Faltan uid o reader_id"}), 400

    bloqueado = uid_en_blacklist(uid)
    db = load_json(USERS_DB)

    if uid == "__all__":
        return jsonify({"status": "ok", "users": db["filerecords"]}), 200

    for r in db["filerecords"]:
        if r["uid"] == uid:
            print(f"[QUERY] UID={uid}  blacklisted={bloqueado is not None}  lector={reader_id}")
            return jsonify({
                "status":           "ok",
                "blacklisted":      bloqueado is not None,
                "blacklist_reason": bloqueado.get("reasoncode") if bloqueado else None,
                "user":             r
            }), 200

    return jsonify({"status": "not_found", "reason": "UID no encontrado"}), 404


# ── Endpoints directos para el cliente web ────────────────────────────────────

@app.route("/data/users", methods=["GET"])
@require_session
def get_users_db():
    try:
        return jsonify({"status": "ok", "data": load_json(USERS_DB)}), 200
    except Exception as e:
        return jsonify({"status": "error", "reason": str(e)}), 500


@app.route("/data/logfile", methods=["GET"])
@require_session
def get_logfile_db():
    try:
        return jsonify({"status": "ok", "data": load_json(LOGFILE)}), 200
    except Exception as e:
        return jsonify({"status": "error", "reason": str(e)}), 500


@app.route("/data/blacklist", methods=["GET"])
@require_session
def get_blacklist_db():
    try:
        return jsonify({"status": "ok", "data": load_json(BLACKLIST)}), 200
    except Exception as e:
        return jsonify({"status": "error", "reason": str(e)}), 500


# ── Arranque ──────────────────────────────────────────────────────────────────

def pedir_clave_maestra() -> bytes:
    print("=" * 55)
    print("  RFID Student Box · Configuración de arranque")
    print("=" * 55)
    print("  Introduce la clave maestra KM (AES-128).")
    print("  Formato: 32 caracteres hex (ej: 0123456789ABCDEF0123456789ABCDEF)")
    print()
    while True:
        try:
            entrada = input("  KM > ").strip().upper().replace(" ", "")
        except (EOFError, KeyboardInterrupt):
            print("\n  Arranque cancelado.")
            raise SystemExit(0)

        if len(entrada) != 32:
            print(f"  ✗ Longitud incorrecta ({len(entrada)} chars). Debe tener exactamente 32.")
            continue
        try:
            clave = bytes.fromhex(entrada)
            print(f"  ✓ KM aceptada: {entrada[:8]}…{entrada[-8:]}")
            print()
            return clave
        except ValueError:
            print("  ✗ Caracteres no hexadecimales. Usa solo 0-9 y A-F.")


if __name__ == "__main__":
    KM = pedir_clave_maestra()
    init_databases()
    print("=" * 55)
    print("  RFID Student Box · Servidor Flask")
    print("  Escuchando en 0.0.0.0:5000  (AES-CMAC activo)")
    print("  KM activa:", KM.hex()[:8] + "…" + KM.hex()[-8:])
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=False)