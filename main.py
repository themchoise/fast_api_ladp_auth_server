
from fastapi import FastAPI, HTTPException, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from dotenv import load_dotenv
from login import LoginRequest
from itsdangerous import URLSafeTimedSerializer
import os
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
LADP_SERVER_IP = os.getenv("LADP_SERVER_IP")
LDAP_DOMAIN = os.getenv("MIDOMINIO")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN")
SECRET_KEY = os.getenv("SECRET_KEY")

server = Server(f'ldap://{LADP_SERVER_IP}',port=389, get_info=ALL) 
serializer = URLSafeTimedSerializer(SECRET_KEY)

app = FastAPI()
templates = Jinja2Templates(directory="templates")

def get_session_data(request: Request):
    """Obtiene los datos de la sesión desde la cookie"""
    session_cookie = request.cookies.get("session")
    if not session_cookie:
        return None
    try:
        return serializer.loads(session_cookie, max_age=3600) 
    except:
        return None

def extract_group_name(group_dn: str) -> str:
    """Extrae el nombre del grupo desde el DN completo"""
    if group_dn.startswith("CN="):
        return group_dn.split(",")[0].replace("CN=", "")
    return group_dn

def get_user_permissions(groups: list) -> dict:
    """Determina los permisos del usuario basado en sus grupos de AD"""
    permissions = {
        "is_admin": False,
        "is_manager": False,
        "is_user": True,
        "roles": [],
        "permissions": []
    }
    
    group_names = [extract_group_name(g).lower() for g in groups]
    
    logger.info("="*60)
    logger.info("🔍 ANALIZANDO PERMISOS DEL USUARIO")
    logger.info(f"📋 Grupos completos (DN): {json.dumps(groups, indent=2)}")
    logger.info(f"📝 Nombres de grupos extraídos: {group_names}")
    
    admin_groups = ["domain admins", "administrators", "enterprise admins"]
    logger.info(f"🔎 Buscando coincidencias con grupos admin: {admin_groups}")
    if any(admin in group_names for admin in admin_groups):
        permissions["is_admin"] = True
        permissions["roles"].append("admin")
        permissions["permissions"].extend(["read", "write", "delete", "manage_users", "view_reports"])
        logger.info("✅ Usuario identificado como ADMIN")
    
    manager_groups = ["managers", "supervisors", "gerencia"]
    logger.info(f"🔎 Buscando coincidencias con grupos manager: {manager_groups}")
    if any(manager in group_names for manager in manager_groups):
        permissions["is_manager"] = True
        permissions["roles"].append("manager")
        if "read" not in permissions["permissions"]:
            permissions["permissions"].extend(["read", "write", "view_reports"])
        logger.info("✅ Usuario identificado como MANAGER")
    
    if not permissions["is_admin"] and not permissions["is_manager"]:
        permissions["roles"].append("user")
        permissions["permissions"].append("read")
        logger.info("ℹ️ Usuario identificado como USER básico")
    
    logger.info(f"🎯 PERMISOS FINALES: {json.dumps(permissions, indent=2)}")
    logger.info("="*60)
    
    return permissions

def authenticate_ldap(username: str, password: str):
    logger.info("\n" + "🔐 INICIO DE AUTENTICACIÓN LDAP " + "="*40)
    logger.info(f"👤 Usuario intentando autenticar: {username}")
    
    user = f"{LDAP_DOMAIN}\\{username}"
    
    try:
        conn = Connection(server, user=user, password=password, authentication=NTLM)
    except Exception as e:
        logger.error(f"❌ Error al conectar con LDAP: {e}")
        return None
    
    if not conn.bind():
        logger.warning(f"⚠️ Credenciales inválidas para usuario: {username}")
        return None
    
    logger.info(f"✅ Conexión LDAP exitosa para: {username}")
    
    search_filter = f"(sAMAccountName={username})"
    conn.search(
        search_base=LDAP_BASE_DN,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=['cn', 'mail', 'memberOf', 'displayName', 'department', 'title', 'userAccountControl']
    )
    
    user_data = {}
    if conn.entries:
        entry = conn.entries[0]
        logger.info(f"📄 Datos encontrados en AD para: {username}")
        
        groups = [str(group) for group in entry.memberOf] if hasattr(entry, 'memberOf') else []
        logger.info(f"👥 Usuario pertenece a {len(groups)} grupo(s)")
        
        user_permissions = get_user_permissions(groups)
        
        user_data = {
            "username": username,
            "displayName": str(entry.displayName) if hasattr(entry, 'displayName') else None,
            "email": str(entry.mail) if hasattr(entry, 'mail') else None,
            "department": str(entry.department) if hasattr(entry, 'department') else None,
            "title": str(entry.title) if hasattr(entry, 'title') else None,
            "groups": groups,
            "group_names": [extract_group_name(g) for g in groups],
            "accountStatus": str(entry.userAccountControl) if hasattr(entry, 'userAccountControl') else None,
            "permissions": user_permissions
        }
        
        logger.info("\n" + "📦 DATOS COMPLETOS DEL USUARIO " + "="*40)
        logger.info(json.dumps(user_data, indent=2, ensure_ascii=False))
        logger.info("="*70 + "\n")
    
    conn.unbind()
    return user_data

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Redirige a /login o /dashboard según el estado de autenticación"""
    session_data = get_session_data(request)
    if session_data:
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Muestra la página de login"""
    session_data = get_session_data(request)
    if session_data:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    """Procesa el login del usuario"""
    user_data = authenticate_ldap(username, password)
    
    if not user_data:
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Credenciales inválidas"}
        )
    
    
    session_token = serializer.dumps(user_data)
    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie(
        key="session",
        value=session_token,
        httponly=True,
        max_age=3600,  
        samesite="lax"
    )
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Muestra el dashboard para usuarios autenticados"""
    session_data = get_session_data(request)
    if not session_data:
        return RedirectResponse(url="/login", status_code=302)
    
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": session_data}
    )

@app.get("/logout")
async def logout():
    """Cierra la sesión del usuario"""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session")
    return response

@app.post("/api/login")
def api_login(credentials: LoginRequest):
    """Endpoint API original para login (JSON)"""
    user_data = authenticate_ldap(credentials.username, credentials.password)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    
    return {"ok": True, "user": user_data}
   