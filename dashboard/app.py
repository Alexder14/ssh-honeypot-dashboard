import os
import sqlite3
import pandas as pd
import streamlit as st

DB_PATH = os.environ.get("DB_PATH", "honeypot.db")

st.set_page_config(
    page_title="ShadowSSH - SOC Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Estilos CSS para apariencia de Centro de Operaciones de Seguridad (SOC)
st.markdown("""
<style>
    .metric-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 15px;
        border-left: 5px solid #38bdf8;
    }
    .stAlert {
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

def load_data():
    """Carga los datos forenses desde SQLite."""
    if not os.path.exists(DB_PATH):
        return pd.DataFrame(), pd.DataFrame()
    
    conn = sqlite3.connect(DB_PATH)
    try:
        df_auth = pd.read_sql_query("SELECT * FROM auth_attempts ORDER BY id DESC", conn)
    except Exception:
        df_auth = pd.DataFrame()
    
    try:
        df_cmds = pd.read_sql_query("SELECT * FROM session_commands ORDER BY id DESC", conn)
    except Exception:
        df_cmds = pd.DataFrame()
        
    conn.close()
    return df_auth, df_cmds

# --- SIDEBAR ---
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/security-shield-green.png", width=70)
    st.title("ShadowSSH SOC")
    st.caption("Blue Team Telemetry & Threat Intel")
    st.markdown("---")
    
    auto_refresh = st.checkbox("Auto-recargar datos", value=False)
    if st.button("🔄 Actualizar Manualmente"):
        st.rerun()

    st.markdown("---")
    st.markdown("""
    **Métricas del Sistema:**
    * **Protocolo:** SSH-2.0
    * **Modo:** High-Interaction Emulated
    * **Defensa:** Sandboxed in-memory
    """)

# --- MAIN CONTENT ---
st.title("🛡️ Centro de Operaciones de Seguridad (SOC) - ShadowSSH")
st.markdown("Monitoreo de ataques en tiempo real, fuerza bruta y análisis de comportamiento de atacantes.")

df_auth, df_cmds = load_data()

if df_auth.empty:
    st.warning("⚠️ No se han registrado ataques aún. Ejecuta `python simulate_attacks.py` o conecta un cliente SSH al puerto 2222 para generar eventos.")
else:
    # --- KPI METRICS ---
    total_attacks = len(df_auth)
    unique_ips = df_auth["ip"].nunique()
    unique_countries = df_auth[df_auth["country"] != "Unknown"]["country"].nunique()
    compromised_sessions = len(df_auth[df_auth["status"] == "SUCCESS"])

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🚨 Total Intentos", f"{total_attacks:,}")
    with col2:
        st.metric("🌐 IPs Atacantes Únicas", f"{unique_ips:,}")
    with col3:
        st.metric("🌍 Países de Origen", f"{unique_countries}")
    with col4:
        st.metric("🔓 Sesiones Accedidas (Trap)", f"{compromised_sessions}")

    st.markdown("---")

    # --- MAPA DE AMENAZAS ---
    st.subheader("🗺️ Mapa Global de Origen de Ataques")
    geo_df = df_auth[(df_auth["latitude"] != 0.0) & (df_auth["longitude"] != 0.0)]
    if not geo_df.empty:
        map_data = geo_df.rename(columns={"latitude": "lat", "longitude": "lon"})
        st.map(map_data[["lat", "lon"]], zoom=1, size=20)
    else:
        st.info("Sin coordenadas disponibles aún.")

    st.markdown("---")

    # --- ESTADISTICAS Y GRAFICOS ---
    st.subheader("📊 Análisis de Patrones de Ataque (Diccionarios y Fuerza Bruta)")
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.write("**Top 10 Contraseñas Más Probadas por Bots:**")
        top_pass = df_auth["password"].value_counts().head(10)
        st.bar_chart(top_pass)

    with col_chart2:
        st.write("**Top 10 Nombres de Usuario Atacados:**")
        top_users = df_auth["username"].value_counts().head(10)
        st.bar_chart(top_users)

    st.markdown("---")

    # --- COMANDOS FORENSES DE SESIONES ---
    st.subheader("🕵️ Comandos Capturados en la Fake Shell (IoCs)")
    if not df_cmds.empty:
        st.dataframe(
            df_cmds[["timestamp", "ip", "username", "command"]].head(25),
            use_container_width=True
        )
    else:
        st.info("Aún no se han capturado comandos en sesiones interactivas.")

    st.markdown("---")

    # --- TABLA DE REGISTROS FORENSES ---
    st.subheader("📋 Registro de Últimos Ataques")
    st.dataframe(
        df_auth[["timestamp", "ip", "country", "city", "isp", "username", "password", "status"]].head(20),
        use_container_width=True
    )
