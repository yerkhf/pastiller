import base64
import hashlib
import json
import math
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, date, time, timedelta
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import streamlit as st

# ============================================================
# CONFIGURACIÓN GENERAL
# ============================================================

APP_TITLE = "CUTSA - Pastillero Inteligente"
DB_PATH = Path(__file__).with_name("pastillero.db")

st.set_page_config(
    page_title=APP_TITLE,
    page_icon="💊",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# ESTILOS
# ============================================================

st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        margin-bottom: 0.2rem;
    }
    .subtle {
        color: #6b7280;
        font-size: 0.95rem;
    }
    .card {
        padding: 1rem;
        border: 1px solid #e5e7eb;
        border-radius: 14px;
        background: #ffffff;
        box-shadow: 0 2px 12px rgba(0,0,0,0.04);
        margin-bottom: 0.75rem;
    }
    .badge-pending {
        background: #fff3cd;
        color: #7a5a00;
        padding: 0.2rem 0.5rem;
        border-radius: 999px;
        font-size: 0.8rem;
        font-weight: 700;
    }
    .badge-answered {
        background: #dcfce7;
        color: #166534;
        padding: 0.2rem 0.5rem;
        border-radius: 999px;
        font-size: 0.8rem;
        font-weight: 700;
    }
    .danger-text { color: #b91c1c; font-weight: 700; }
    .ok-text { color: #166534; font-weight: 700; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# BASE DE DATOS
# ============================================================

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rut TEXT NOT NULL,
                nombre TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                telefono TEXT,
                direccion TEXT,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                rol TEXT NOT NULL DEFAULT 'cliente',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS medications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                nombre TEXT NOT NULL,
                descripcion TEXT NOT NULL,
                foto_url TEXT,
                foto_data TEXT,
                dosis_mg REAL NOT NULL,
                total_dosis INTEGER NOT NULL,
                dosis_dia INTEGER NOT NULL,
                vida_media_horas REAL NOT NULL,
                nivel_minimo_pct REAL NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                medication_id INTEGER NOT NULL,
                paciente TEXT,
                primer_horario TEXT NOT NULL,
                intervalo_horas REAL NOT NULL,
                dosis_dia INTEGER NOT NULL,
                horarios_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(medication_id) REFERENCES medications(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                usuario_email TEXT NOT NULL,
                texto TEXT NOT NULL,
                estado TEXT NOT NULL DEFAULT 'pendiente',
                respuesta TEXT,
                created_at TEXT NOT NULL,
                responded_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dose_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                schedule_id INTEGER NOT NULL,
                medication_id INTEGER NOT NULL,
                fecha TEXT NOT NULL,
                hora TEXT NOT NULL,
                estado TEXT NOT NULL DEFAULT 'tomada',
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(schedule_id) REFERENCES schedules(id),
                FOREIGN KEY(medication_id) REFERENCES medications(id)
            )
            """
        )
        conn.commit()


# ============================================================
# SEGURIDAD LOCAL: REGISTRO Y LOGIN SIN FIREBASE
# ============================================================

def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120_000,
    ).hex()


def create_user(rut, nombre, email, telefono, direccion, password):
    salt = secrets.token_hex(16)
    pwd_hash = hash_password(password, salt)
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO users (rut, nombre, email, telefono, direccion, password_hash, salt, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (rut, nombre, email.lower(), telefono, direccion, pwd_hash, salt, now_text(), now_text()),
        )
        conn.commit()
        return cur.lastrowid


def get_user_by_email(email):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower(),)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def verify_login(email, password):
    user = get_user_by_email(email)
    if not user:
        return None
    expected = hash_password(password, user["salt"])
    if secrets.compare_digest(expected, user["password_hash"]):
        return user
    return None


def update_profile(user_id, nombre, telefono, direccion):
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET nombre=?, telefono=?, direccion=?, updated_at=? WHERE id=?",
            (nombre, telefono, direccion, now_text(), user_id),
        )
        conn.commit()


# ============================================================
# CRUD MEDICAMENTOS
# ============================================================

def create_medication(user_id, data):
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO medications (
                user_id, nombre, descripcion, foto_url, foto_data,
                dosis_mg, total_dosis, dosis_dia, vida_media_horas,
                nivel_minimo_pct, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                data["nombre"],
                data["descripcion"],
                data.get("foto_url"),
                data.get("foto_data"),
                data["dosis_mg"],
                data["total_dosis"],
                data["dosis_dia"],
                data["vida_media_horas"],
                data["nivel_minimo_pct"],
                now_text(),
                now_text(),
            ),
        )
        conn.commit()
        return cur.lastrowid


def update_medication(user_id, med_id, data):
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE medications
            SET nombre=?, descripcion=?, foto_url=?, foto_data=?, dosis_mg=?, total_dosis=?,
                dosis_dia=?, vida_media_horas=?, nivel_minimo_pct=?, updated_at=?
            WHERE id=? AND user_id=?
            """,
            (
                data["nombre"],
                data["descripcion"],
                data.get("foto_url"),
                data.get("foto_data"),
                data["dosis_mg"],
                data["total_dosis"],
                data["dosis_dia"],
                data["vida_media_horas"],
                data["nivel_minimo_pct"],
                now_text(),
                med_id,
                user_id,
            ),
        )
        conn.commit()


def delete_medication(user_id, med_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM schedules WHERE medication_id=? AND user_id=?", (med_id, user_id))
        conn.execute("DELETE FROM medications WHERE id=? AND user_id=?", (med_id, user_id))
        conn.commit()


def list_medications(user_id):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM medications WHERE user_id=? ORDER BY id DESC", (user_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_medication(user_id, med_id):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM medications WHERE id=? AND user_id=?", (med_id, user_id)
        ).fetchone()
        return dict(row) if row else None


# ============================================================
# CRUD HORARIOS
# ============================================================

def generar_horarios(primer_horario: str, intervalo_horas: float, dosis_dia: int):
    h, m = map(int, primer_horario.split(":"))
    base = datetime.combine(date.today(), time(hour=h, minute=m))
    horarios = []
    for i in range(int(dosis_dia)):
        d = base + timedelta(hours=float(intervalo_horas) * i)
        etiqueta = d.strftime("%H:%M")
        if d.date() > date.today():
            etiqueta += " (+1 día)"
        horarios.append(etiqueta)
    return horarios


def calcular_dias_tratamiento(total_dosis, dosis_dia):
    if not total_dosis or not dosis_dia:
        return 0
    return math.floor(total_dosis / dosis_dia)


def create_schedule(user_id, data):
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO schedules (
                user_id, medication_id, paciente, primer_horario,
                intervalo_horas, dosis_dia, horarios_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                data["medication_id"],
                data.get("paciente"),
                data["primer_horario"],
                data["intervalo_horas"],
                data["dosis_dia"],
                json.dumps(data["horarios"], ensure_ascii=False),
                now_text(),
                now_text(),
            ),
        )
        conn.commit()
        return cur.lastrowid


def update_schedule(user_id, schedule_id, data):
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE schedules
            SET medication_id=?, paciente=?, primer_horario=?, intervalo_horas=?,
                dosis_dia=?, horarios_json=?, updated_at=?
            WHERE id=? AND user_id=?
            """,
            (
                data["medication_id"],
                data.get("paciente"),
                data["primer_horario"],
                data["intervalo_horas"],
                data["dosis_dia"],
                json.dumps(data["horarios"], ensure_ascii=False),
                now_text(),
                schedule_id,
                user_id,
            ),
        )
        conn.commit()


def delete_schedule(user_id, schedule_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM schedules WHERE id=? AND user_id=?", (schedule_id, user_id))
        conn.commit()


def list_schedules(user_id):
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT s.*, m.nombre AS medicamento
            FROM schedules s
            JOIN medications m ON m.id = s.medication_id
            WHERE s.user_id=?
            ORDER BY s.id DESC
            """,
            (user_id,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["horarios"] = json.loads(d.get("horarios_json") or "[]")
            result.append(d)
        return result


# ============================================================
# MENSAJES Y RESPUESTAS
# ============================================================

def create_message(user_id, usuario_email, texto):
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO messages (user_id, usuario_email, texto, estado, created_at)
            VALUES (?, ?, ?, 'pendiente', ?)
            """,
            (user_id, usuario_email, texto, now_text()),
        )
        conn.commit()
        return cur.lastrowid


def list_messages(user_id):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM messages WHERE user_id=? ORDER BY id DESC", (user_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def reply_message(user_id, msg_id, respuesta):
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE messages
            SET estado='respondido', respuesta=?, responded_at=?
            WHERE id=? AND user_id=?
            """,
            (respuesta, now_text(), msg_id, user_id),
        )
        conn.commit()


def delete_message(user_id, msg_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM messages WHERE id=? AND user_id=?", (msg_id, user_id))
        conn.commit()


# ============================================================
# REGISTRO DE DOSIS TOMADAS / OMITIDAS
# ============================================================

def create_dose_log(user_id, schedule_id, medication_id, estado, fecha=None, hora=None):
    now = datetime.now()
    fecha_text = fecha or now.strftime("%Y-%m-%d")
    hora_text = hora or now.strftime("%H:%M")
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO dose_logs (user_id, schedule_id, medication_id, fecha, hora, estado, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, schedule_id, medication_id, fecha_text, hora_text, estado, now_text()),
        )
        conn.commit()
        return cur.lastrowid


def list_dose_logs(user_id):
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT dl.*, m.nombre AS medicamento
            FROM dose_logs dl
            JOIN medications m ON m.id = dl.medication_id
            WHERE dl.user_id=?
            ORDER BY dl.id DESC
            """,
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_latest_dose_log(user_id, medication_id):
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM dose_logs
            WHERE user_id=? AND medication_id=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (user_id, medication_id),
        ).fetchone()
        return dict(row) if row else None


# ============================================================
# CÁLCULO DIFERENCIAL
# ============================================================

def constante_eliminacion(vida_media_horas: float) -> float:
    return math.log(2) / float(vida_media_horas)


def concentracion(t, c0, k):
    return c0 * np.exp(-k * t)


def derivada_concentracion(t, c0, k):
    return -k * c0 * np.exp(-k * t)


def tiempo_hasta_nivel(nivel_minimo_pct, k):
    proporcion = float(nivel_minimo_pct) / 100
    if proporcion <= 0 or proporcion >= 1:
        return None
    return -math.log(proporcion) / k


# ============================================================
# UTILIDADES UI
# ============================================================

def valid_email(value):
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value or ""))


def file_to_data_url(uploaded_file):
    if not uploaded_file:
        return None
    data = uploaded_file.read()
    encoded = base64.b64encode(data).decode("utf-8")
    mime = uploaded_file.type or "image/png"
    return f"data:{mime};base64,{encoded}"


def medication_dataframe(meds):
    if not meds:
        return pd.DataFrame()
    df = pd.DataFrame(meds)
    keep = [
        "id",
        "nombre",
        "descripcion",
        "dosis_mg",
        "total_dosis",
        "dosis_dia",
        "vida_media_horas",
        "nivel_minimo_pct",
        "updated_at",
    ]
    return df[keep].rename(
        columns={
            "id": "ID",
            "nombre": "Medicamento",
            "descripcion": "Uso / descripción",
            "dosis_mg": "Dosis por toma (mg)",
            "total_dosis": "Dosis totales",
            "dosis_dia": "Dosis por día",
            "vida_media_horas": "Vida media (h)",
            "nivel_minimo_pct": "Nivel mínimo (%)",
            "updated_at": "Actualizado",
        }
    )


def schedules_dataframe(schedules):
    if not schedules:
        return pd.DataFrame()
    df = pd.DataFrame(schedules)
    df["horarios"] = df["horarios"].apply(lambda x: ", ".join(x))
    keep = [
        "id",
        "paciente",
        "medicamento",
        "primer_horario",
        "intervalo_horas",
        "dosis_dia",
        "horarios",
        "updated_at",
    ]
    return df[keep].rename(
        columns={
            "id": "ID",
            "paciente": "Paciente",
            "medicamento": "Medicamento",
            "primer_horario": "Primer horario",
            "intervalo_horas": "Intervalo (h)",
            "dosis_dia": "Dosis/día",
            "horarios": "Horarios generados",
            "updated_at": "Actualizado",
        }
    )


def messages_dataframe(messages):
    if not messages:
        return pd.DataFrame()
    df = pd.DataFrame(messages)
    keep = ["id", "usuario_email", "texto", "estado", "respuesta", "created_at", "responded_at"]
    return df[keep].rename(
        columns={
            "id": "ID",
            "usuario_email": "Correo paciente",
            "texto": "Mensaje",
            "estado": "Estado",
            "respuesta": "Respuesta",
            "created_at": "Creado",
            "responded_at": "Respondido",
        }
    )


def dose_logs_dataframe(dose_logs):
    if not dose_logs:
        return pd.DataFrame()
    df = pd.DataFrame(dose_logs)
    keep = ["id", "medicamento", "fecha", "hora", "estado", "created_at"]
    return df[keep].rename(
        columns={
            "id": "ID",
            "medicamento": "Medicamento",
            "fecha": "Fecha",
            "hora": "Hora",
            "estado": "Estado",
            "created_at": "Registrado",
        }
    )


def parse_schedule_horarios(horarios):
    parsed = []
    for item in horarios or []:
        text = str(item).strip()
        if not text:
            continue
        if text.endswith("(+1 día)"):
            text = text.replace(" (+1 día)", "")
        parsed.append(text)
    return parsed


def next_dose_summary(schedule):
    try:
        horarios = parse_schedule_horarios(schedule.get("horarios") or [])
    except Exception:
        horarios = []
    if not horarios:
        return "Sin horarios"

    now = datetime.now()
    today = now.date()
    for entry in horarios:
        try:
            hour_text = entry.split(" ", 1)[0]
            hh, mm = map(int, hour_text.split(":"))
            candidate_dt = datetime.combine(today, time(hour=hh, minute=mm))
            if candidate_dt >= now:
                label = "Hoy" if candidate_dt.date() == today else "Mañana"
                return f"{label} a las {candidate_dt.strftime('%H:%M')}"
        except ValueError:
            continue

    if horarios:
        try:
            hh, mm = map(int, horarios[0].split(":"))
            candidate_dt = datetime.combine(today + timedelta(days=1), time(hour=hh, minute=mm))
            return f"Mañana a las {candidate_dt.strftime('%H:%M')}"
        except ValueError:
            return horarios[0]
    return "Sin horarios"


# ============================================================
# PÁGINA DE AUTENTICACIÓN
# ============================================================

def auth_page():
    st.markdown(f"<div class='main-title'>💊 {APP_TITLE}</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='subtle'>Versión local con Streamlit + SQLite. No usa Firebase, Vercel ni servicios externos.</div>",
        unsafe_allow_html=True,
    )
    st.info(
        "Prototipo educativo: permite registrar farmacias, medicamentos, horarios, mensajes y simular concentración usando derivadas."
    )

    tab_login, tab_register = st.tabs(["Iniciar sesión", "Crear cuenta"])

    with tab_login:
        with st.form("login_form"):
            email = st.text_input("Correo", placeholder="farmacia@ejemplo.cl", key="login_email")
            password = st.text_input("Contraseña", type="password", key="login_password")
            submitted = st.form_submit_button("Entrar")

        if submitted:
            user = verify_login(email, password)
            if user:
                st.session_state["user_id"] = user["id"]
                st.session_state["user_name"] = user["nombre"]
                st.success("Inicio de sesión correcto.")
                st.rerun()
            else:
                st.error("Credenciales no válidas.")

        with st.expander("Usuario de prueba"):
            st.write("Puedes crear una cuenta propia. Si quieres una rápida, usa el botón de abajo.")
            if st.button("Crear usuario demo", key="create_demo_user"):
                demo_email = "demo@farmacia.cl"
                if not get_user_by_email(demo_email):
                    create_user(
                        rut="11.111.111-1",
                        nombre="Farmacia Demo",
                        email=demo_email,
                        telefono="+56 9 1234 5678",
                        direccion="Concepción, Chile",
                        password="12345678",
                    )
                st.success("Usuario demo listo. Correo: demo@farmacia.cl / Contraseña: 12345678")

    with tab_register:
        with st.form("register_form"):
            rut = st.text_input("RUT", placeholder="12.345.678-9", key="register_rut")
            nombre = st.text_input("Nombre farmacia o usuario", placeholder="Farmacia Central", key="register_name")
            email = st.text_input("Correo", placeholder="farmacia@correo.cl", key="register_email")
            telefono = st.text_input("Teléfono", placeholder="+56 9 0000 0000", key="register_phone")
            direccion = st.text_input("Dirección", placeholder="Dirección de la farmacia", key="register_address")
            password = st.text_input("Contraseña", type="password", key="register_password")
            submitted = st.form_submit_button("Crear cuenta")

        if submitted:
            if len(rut.strip()) < 3:
                st.error("El RUT no es válido.")
            elif not nombre.strip():
                st.error("Ingresa un nombre.")
            elif not valid_email(email):
                st.error("El correo no tiene formato válido.")
            elif len(password) < 8:
                st.error("La contraseña debe tener al menos 8 caracteres.")
            elif get_user_by_email(email):
                st.error("Ese correo ya está registrado.")
            else:
                user_id = create_user(rut, nombre, email, telefono, direccion, password)
                st.session_state["user_id"] = user_id
                st.session_state["user_name"] = nombre
                st.success("Cuenta creada correctamente.")
                st.rerun()


# ============================================================
# SECCIONES DEL PANEL
# ============================================================

def page_dashboard(user):
    meds = list_medications(user["id"])
    schedules = list_schedules(user["id"])
    messages = list_messages(user["id"])
    pending = [m for m in messages if m["estado"] == "pendiente"]

    st.header("Panel principal")
    st.caption("Resumen general del sistema")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Medicamentos", len(meds))
    c2.metric("Horarios", len(schedules))
    c3.metric("Mensajes", len(messages))
    c4.metric("Pendientes", len(pending))

    st.divider()
    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Próximas dosis")
        if schedules:
            for sch in schedules[:5]:
                st.markdown(
                    f"""
                    <div class='card'>
                    <b>{sch['medicamento']}</b><br>
                    Paciente: {sch.get('paciente') or '-'}<br>
                    <span class='badge-pending'>Próxima dosis: {next_dose_summary(sch)}</span><br>
                    Horarios: {', '.join(sch['horarios'])}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.info("No hay horarios registrados.")

    with col_b:
        st.subheader("Mensajes pendientes")
        if pending:
            for msg in pending[:5]:
                st.markdown(
                    f"""
                    <div class='card'>
                    <b>{msg['usuario_email']}</b> <span class='badge-pending'>Pendiente</span><br>
                    {msg['texto']}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.success("No hay mensajes pendientes.")


def page_profile(user):
    st.header("Perfil")
    st.caption("Datos del cliente/farmacia guardados localmente")

    with st.form("profile_form"):
        nombre = st.text_input("Nombre", value=user.get("nombre", ""), key="profile_name")
        email = st.text_input("Correo", value=user.get("email", ""), disabled=True, key="profile_email")
        telefono = st.text_input("Teléfono", value=user.get("telefono", "") or "", key="profile_phone")
        direccion = st.text_input("Dirección", value=user.get("direccion", "") or "", key="profile_address")
        submitted = st.form_submit_button("Actualizar perfil")

    if submitted:
        if not nombre.strip() or not telefono.strip() or not direccion.strip():
            st.error("Completa nombre, teléfono y dirección.")
        else:
            update_profile(user["id"], nombre.strip(), telefono.strip(), direccion.strip())
            st.session_state["user_name"] = nombre.strip()
            st.success("Perfil actualizado.")
            st.rerun()


def medication_form(default=None, prefix="med"):
    default = default or {}
    nombre = st.text_input(
        "Nombre del medicamento",
        value=default.get("nombre", ""),
        key=f"{prefix}_name",
    )
    descripcion = st.text_area(
        "Descripción / uso",
        value=default.get("descripcion", ""),
        height=90,
        key=f"{prefix}_description",
    )

    c1, c2 = st.columns(2)
    with c1:
        dosis_mg = st.number_input(
            "Dosis por toma (mg)",
            min_value=1.0,
            value=float(default.get("dosis_mg", 500.0)),
            step=50.0,
            key=f"{prefix}_dosis_mg",
        )
        total_dosis = st.number_input(
            "Dosis totales disponibles",
            min_value=1,
            value=int(default.get("total_dosis", 20)),
            step=1,
            key=f"{prefix}_total_dosis",
        )
        dosis_dia = st.number_input(
            "Dosis por día",
            min_value=1,
            max_value=24,
            value=int(default.get("dosis_dia", 3)),
            step=1,
            key=f"{prefix}_dosis_dia",
        )
    with c2:
        vida_media_horas = st.number_input(
            "Vida media (horas)",
            min_value=0.1,
            value=float(default.get("vida_media_horas", 4.0)),
            step=0.5,
            key=f"{prefix}_vida_media",
        )
        nivel_minimo_pct = st.slider(
            "Nivel mínimo de concentración (%)",
            min_value=5,
            max_value=90,
            value=int(default.get("nivel_minimo_pct", 25)),
            step=5,
            key=f"{prefix}_nivel_minimo",
        )
        foto_url = st.text_input(
            "URL de foto (opcional)",
            value=default.get("foto_url", "") or "",
            key=f"{prefix}_foto_url",
        )

    uploaded = st.file_uploader(
        "Subir foto local opcional",
        type=["png", "jpg", "jpeg"],
        key=f"{prefix}_upload",
    )
    foto_data = default.get("foto_data")
    if uploaded:
        foto_data = file_to_data_url(uploaded)

    return {
        "nombre": nombre.strip(),
        "descripcion": descripcion.strip(),
        "foto_url": foto_url.strip(),
        "foto_data": foto_data,
        "dosis_mg": dosis_mg,
        "total_dosis": int(total_dosis),
        "dosis_dia": int(dosis_dia),
        "vida_media_horas": vida_media_horas,
        "nivel_minimo_pct": nivel_minimo_pct,
    }


def validate_medication(data):
    if not data["nombre"] or not data["descripcion"]:
        return "Completa nombre y descripción."
    if data["total_dosis"] < data["dosis_dia"]:
        return "Las dosis totales deben ser mayores o iguales a las dosis por día."
    if data["foto_url"] and not data["foto_url"].startswith(("http://", "https://")):
        return "La URL de foto debe comenzar con http:// o https://."
    return None


def page_medications(user):
    st.header("Medicamentos")
    st.caption("CRUD de medicamentos equivalente al panel original, pero guardado en SQLite")

    meds = list_medications(user["id"])
    df = medication_dataframe(meds)
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No hay medicamentos registrados.")

    tab_create, tab_edit, tab_delete = st.tabs(["Crear", "Editar", "Eliminar"])

    with tab_create:
        with st.form("create_med_form"):
            data = medication_form(prefix="create_med")
            submitted = st.form_submit_button("Guardar medicamento")
        if submitted:
            error = validate_medication(data)
            if error:
                st.error(error)
            else:
                create_medication(user["id"], data)
                st.success("Medicamento guardado correctamente.")
                st.rerun()

    with tab_edit:
        if not meds:
            st.info("Primero debes crear un medicamento.")
        else:
            options = {f"{m['id']} - {m['nombre']}": m["id"] for m in meds}
            selected_label = st.selectbox("Selecciona medicamento", list(options.keys()), key="edit_med_select")
            selected = get_medication(user["id"], options[selected_label])
            with st.form("edit_med_form"):
                data = medication_form(selected, prefix="edit_med")
                submitted = st.form_submit_button("Actualizar medicamento")
            if submitted:
                error = validate_medication(data)
                if error:
                    st.error(error)
                else:
                    update_medication(user["id"], selected["id"], data)
                    st.success("Medicamento actualizado.")
                    st.rerun()

    with tab_delete:
        if not meds:
            st.info("No hay medicamentos para eliminar.")
        else:
            options = {f"{m['id']} - {m['nombre']}": m["id"] for m in meds}
            selected_label = st.selectbox("Medicamento a eliminar", list(options.keys()), key="del_med")
            st.warning("Al eliminar un medicamento también se eliminan sus horarios asociados.")
            if st.button("Eliminar medicamento", type="primary"):
                delete_medication(user["id"], options[selected_label])
                st.success("Medicamento eliminado.")
                st.rerun()


def page_schedules(user):
    st.header("Horarios")
    st.caption("Calcula horarios diarios a partir de un primer horario, intervalo y dosis por día")

    meds = list_medications(user["id"])
    schedules = list_schedules(user["id"])

    df = schedules_dataframe(schedules)
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No hay horarios registrados.")

    if schedules:
        st.subheader("Próxima dosis")
        cols = st.columns(min(3, len(schedules)))
        for col, sch in zip(cols, schedules[:3]):
            col.metric(sch["medicamento"], next_dose_summary(sch), delta=sch.get("paciente") or "Sin paciente")

    dose_logs = list_dose_logs(user["id"])
    if dose_logs:
        st.subheader("Historial de dosis")
        st.dataframe(dose_logs_dataframe(dose_logs[:10]), use_container_width=True, hide_index=True)

    tab_create, tab_edit, tab_delete = st.tabs(["Crear", "Editar", "Eliminar"])

    st.subheader("Registro rápido de dosis")
    if schedules:
        dose_options = {f"{s['id']} - {s['medicamento']} - {s.get('paciente') or 'Sin paciente'}": s for s in schedules}
        selected_dose_label = st.selectbox("Selecciona un horario para registrar", list(dose_options.keys()), key="dose_log_schedule")
        col_t, col_o = st.columns(2)
        with col_t:
            if st.button("Marcar dosis como tomada", key="mark_taken"):
                selected_schedule = dose_options[selected_dose_label]
                create_dose_log(user["id"], selected_schedule["id"], selected_schedule["medication_id"], "tomada")
                st.success("Dosis registrada como tomada.")
        with col_o:
            if st.button("Marcar dosis como omitida", key="mark_omitted"):
                selected_schedule = dose_options[selected_dose_label]
                create_dose_log(user["id"], selected_schedule["id"], selected_schedule["medication_id"], "omitida")
                st.success("Dosis registrada como omitida.")
        st.caption("Se guarda localmente en SQLite con fecha y hora del sistema.")
    else:
        st.info("No hay horarios disponibles para registrar dosis.")

    st.divider()

    def schedule_inputs(default=None, prefix="schedule"):
        default = default or {}
        med_options = {f"{m['id']} - {m['nombre']}": m for m in meds}
        default_med_label = None
        if default.get("medication_id"):
            for label, med in med_options.items():
                if med["id"] == default["medication_id"]:
                    default_med_label = label
        labels = list(med_options.keys())
        index = labels.index(default_med_label) if default_med_label in labels else 0
        selected_label = st.selectbox("Medicamento", labels, index=index, key=f"{prefix}_medication")
        med = med_options[selected_label]
        paciente = st.text_input(
            "Paciente o correo del paciente",
            value=default.get("paciente", "") or "",
            key=f"{prefix}_patient",
        )
        c1, c2 = st.columns(2)
        with c1:
            primer = st.time_input(
                "Primer horario",
                value=datetime.strptime(default.get("primer_horario", "08:00"), "%H:%M").time()
                if default.get("primer_horario")
                else time(8, 0),
                key=f"{prefix}_first_time",
            )
        with c2:
            intervalo = st.number_input(
                "Intervalo entre dosis (horas)",
                min_value=1.0,
                max_value=24.0,
                value=float(default.get("intervalo_horas", 8.0)),
                step=1.0,
                key=f"{prefix}_interval",
            )
        primer_text = primer.strftime("%H:%M")
        horarios = generar_horarios(primer_text, intervalo, med["dosis_dia"])
        st.write("Horarios generados:", ", ".join(horarios))
        st.write(
            f"Duración estimada del tratamiento: {calcular_dias_tratamiento(med['total_dosis'], med['dosis_dia'])} días."
        )
        return {
            "medication_id": med["id"],
            "paciente": paciente.strip(),
            "primer_horario": primer_text,
            "intervalo_horas": intervalo,
            "dosis_dia": med["dosis_dia"],
            "horarios": horarios,
        }

    with tab_create:
        if not meds:
            st.info("Primero debes crear medicamentos.")
        else:
            with st.form("create_schedule_form"):
                data = schedule_inputs(prefix="create_schedule")
                submitted = st.form_submit_button("Calcular y guardar horarios")
            if submitted:
                create_schedule(user["id"], data)
                st.success("Horario guardado correctamente.")
                st.rerun()

    with tab_edit:
        if not schedules:
            st.info("No hay horarios para editar.")
        else:
            options = {f"{s['id']} - {s['paciente'] or 'Sin paciente'} - {s['medicamento']}": s for s in schedules}
            selected_label = st.selectbox("Selecciona horario", list(options.keys()), key="edit_schedule_select")
            selected = options[selected_label]
            with st.form("edit_schedule_form"):
                data = schedule_inputs(selected, prefix="edit_schedule")
                submitted = st.form_submit_button("Actualizar horario")
            if submitted:
                update_schedule(user["id"], selected["id"], data)
                st.success("Horario actualizado.")
                st.rerun()

    with tab_delete:
        if not schedules:
            st.info("No hay horarios para eliminar.")
        else:
            options = {f"{s['id']} - {s['paciente'] or 'Sin paciente'} - {s['medicamento']}": s["id"] for s in schedules}
            selected_label = st.selectbox("Horario a eliminar", list(options.keys()), key="del_schedule")
            if st.button("Eliminar horario", type="primary"):
                delete_schedule(user["id"], options[selected_label])
                st.success("Horario eliminado.")
                st.rerun()


def page_messages(user):
    st.header("Mensajes y respuestas")
    st.caption("Gestión local de mensajes. La respuesta queda guardada; no se envía correo externo.")

    messages = list_messages(user["id"])

    c1, c2 = st.columns([2, 1])
    with c1:
        st.subheader("Mensajes registrados")
    with c2:
        if st.button("Crear mensaje demo", key="create_message_demo"):
            create_message(user["id"], "paciente.demo@correo.cl", "Hola, ¿puedo tomar el medicamento después de comer?")
            st.success("Mensaje demo creado.")
            st.rerun()

    df = messages_dataframe(messages)
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No hay mensajes registrados.")

    tab_create, tab_reply, tab_delete = st.tabs(["Crear mensaje", "Responder", "Eliminar"])

    with tab_create:
        with st.form("create_message_form"):
            email = st.text_input("Correo del paciente", placeholder="paciente@correo.cl", key="message_email")
            texto = st.text_area("Mensaje", placeholder="Escribe una consulta o mensaje", height=100, key="message_text")
            submitted = st.form_submit_button("Guardar mensaje")
        if submitted:
            if not valid_email(email):
                st.error("Correo no válido.")
            elif not texto.strip():
                st.error("Escribe un mensaje.")
            else:
                create_message(user["id"], email.strip(), texto.strip())
                st.success("Mensaje guardado.")
                st.rerun()

    with tab_reply:
        pending = [m for m in messages if m["estado"] != "respondido"]
        if not pending:
            st.info("No hay mensajes pendientes.")
        else:
            options = {f"{m['id']} - {m['usuario_email']}: {m['texto'][:50]}": m for m in pending}
            selected_label = st.selectbox("Mensaje pendiente", list(options.keys()), key="pending_message_select")
            selected = options[selected_label]
            st.write(f"**Mensaje:** {selected['texto']}")
            with st.form("reply_form"):
                respuesta = st.text_area("Respuesta", height=120, key="reply_text")
                submitted = st.form_submit_button("Guardar respuesta")
            if submitted:
                if not respuesta.strip():
                    st.error("Escribe una respuesta.")
                else:
                    reply_message(user["id"], selected["id"], respuesta.strip())
                    st.success("Respuesta registrada.")
                    st.rerun()

    with tab_delete:
        if not messages:
            st.info("No hay mensajes para eliminar.")
        else:
            options = {f"{m['id']} - {m['usuario_email']}": m["id"] for m in messages}
            selected_label = st.selectbox("Mensaje a eliminar", list(options.keys()), key="del_msg")
            if st.button("Eliminar mensaje", type="primary"):
                delete_message(user["id"], options[selected_label])
                st.success("Mensaje eliminado.")
                st.rerun()


def page_calculus(user):
    st.header("Cálculo diferencial")
    st.caption("Simulación de concentración del medicamento y su derivada")

    meds = list_medications(user["id"])
    if not meds:
        st.info("Primero registra un medicamento para simular su concentración.")
        return

    med_options = {f"{m['id']} - {m['nombre']}": m for m in meds}
    selected_label = st.selectbox("Medicamento", list(med_options.keys()), key="calc_medication")
    med = med_options[selected_label]

    st.latex(r"C(t)=C_0 e^{-kt}")
    st.latex(r"C'(t)=-kC_0e^{-kt}")

    c1, c2, c3 = st.columns(3)
    with c1:
        c0 = st.number_input("Concentración inicial / dosis (mg)", min_value=1.0, value=float(med["dosis_mg"]), step=50.0, key="calc_c0")
    with c2:
        vida_media = st.number_input("Vida media (h)", min_value=0.1, value=float(med["vida_media_horas"]), step=0.5, key="calc_vida_media")
    with c3:
        horas_totales = st.number_input("Horas a simular", min_value=1, value=24, step=1, key="calc_horas")

    nivel = st.slider("Nivel mínimo de concentración (%)", 5, 90, int(med["nivel_minimo_pct"]), step=5, key="calc_nivel")

    k = constante_eliminacion(vida_media)
    tiempos = np.linspace(0, horas_totales, 200)
    conc = concentracion(tiempos, c0, k)
    der = derivada_concentracion(tiempos, c0, k)
    t_min = tiempo_hasta_nivel(nivel, k)

    last_log = get_latest_dose_log(user["id"], med["id"])
    if last_log:
        try:
            last_dt = datetime.fromisoformat(last_log["created_at"])
            elapsed_h = max(0.0, (datetime.now() - last_dt).total_seconds() / 3600)
            current_concentration = concentracion(elapsed_h, c0, k)
        except ValueError:
            current_concentration = None
    else:
        current_concentration = None

    m1, m2, m3 = st.columns(3)
    m1.metric("Constante k", f"{k:.4f}")
    m2.metric("Vida media", f"{vida_media:.2f} h")
    m3.metric("Tiempo hasta nivel mínimo", f"{t_min:.2f} h" if t_min else "No calculable")
    if current_concentration is not None:
        st.metric("Concentración actual estimada", f"{current_concentration:.2f} mg")
        st.caption(f"Basada en la última dosis registrada hace {elapsed_h:.1f} horas.")
    else:
        st.info("Registra una dosis tomada para usar esa referencia en la simulación actual.")

    st.subheader("Gráfico de concentración")
    fig1, ax1 = plt.subplots()
    ax1.plot(tiempos, conc)
    ax1.axhline(c0 * nivel / 100, linestyle="--")
    ax1.set_xlabel("Tiempo (horas)")
    ax1.set_ylabel("Concentración estimada (mg)")
    ax1.set_title("Disminución de la concentración")
    ax1.grid(True)
    st.pyplot(fig1)

    st.subheader("Gráfico de la derivada")
    fig2, ax2 = plt.subplots()
    ax2.plot(tiempos, der)
    ax2.set_xlabel("Tiempo (horas)")
    ax2.set_ylabel("C'(t)")
    ax2.set_title("Velocidad de disminución")
    ax2.grid(True)
    st.pyplot(fig2)

    df = pd.DataFrame({
        "Tiempo (horas)": tiempos,
        "Concentración estimada": conc,
        "Derivada C'(t)": der,
    })
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.download_button(
        "Descargar simulación CSV",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="simulacion_concentracion.csv",
        mime="text/csv",
    )

    st.warning(
        "Esta simulación es educativa. No reemplaza indicaciones médicas reales ni ajusta tratamientos clínicos."
    )


def page_about():
    st.header("Acerca del proyecto")
    st.markdown(
        """
        Esta aplicación replica las funciones principales de una plataforma web para farmacias, pero en una versión local y simple de levantar.

        **Funciones incluidas:**
        - Registro e inicio de sesión local.
        - Perfil del cliente/farmacia.
        - CRUD de medicamentos.
        - CRUD de horarios de toma.
        - Gestión de mensajes y respuestas.
        - Simulación matemática con derivadas para el proyecto de Cálculo Diferencial.

        **Tecnologías usadas:**
        - Streamlit para la interfaz.
        - SQLite para guardar datos.
        - Pandas, NumPy y Matplotlib para tablas, cálculos y gráficos.

        **Modelo matemático:**
        """
    )
    st.latex(r"C(t)=C_0e^{-kt}")
    st.latex(r"C'(t)=-kC_0e^{-kt}")
    st.markdown(
        "La derivada representa la velocidad de disminución de la concentración del medicamento en el tiempo."
    )


# ============================================================
# BOOTSTRAP
# ============================================================

def main():
    init_db()

    if "user_id" not in st.session_state:
        auth_page()
        return

    user = get_user_by_id(st.session_state["user_id"])
    if not user:
        st.session_state.clear()
        st.rerun()

    st.sidebar.title("💊 CUTSA Local")
    st.sidebar.write(f"**Usuario:** {user['nombre']}")
    st.sidebar.caption(user["email"])

    menu = st.sidebar.radio(
        "Menú",
        [
            "Panel principal",
            "Perfil",
            "Medicamentos",
            "Horarios",
            "Mensajes",
            "Cálculo diferencial",
            "Acerca del proyecto",
        ],
    )

    if st.sidebar.button("Cerrar sesión"):
        st.session_state.clear()
        st.rerun()

    if menu == "Panel principal":
        page_dashboard(user)
    elif menu == "Perfil":
        page_profile(user)
    elif menu == "Medicamentos":
        page_medications(user)
    elif menu == "Horarios":
        page_schedules(user)
    elif menu == "Mensajes":
        page_messages(user)
    elif menu == "Cálculo diferencial":
        page_calculus(user)
    elif menu == "Acerca del proyecto":
        page_about()


if __name__ == "__main__":
    main()
