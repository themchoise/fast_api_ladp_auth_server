
from fastapi import FastAPI, HTTPException
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from dotenv import load_dotenv
from login import LoginRequest
import os

load_dotenv()
LADP_SERVER_IP = os.getenv("LADP_SERVER_IP")
LDAP_DOMAIN = os.getenv("MIDOMINIO")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN")

server = Server(f'ldap://{LADP_SERVER_IP}',port=389, get_info=ALL) 

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Api LADP Funcionando"}

@app.post("/login")
def login(credentials: LoginRequest):
    username = credentials.username
    password = credentials.password
    user = f"{LDAP_DOMAIN}\\{username}"

    conn = None
    try:
        conn = Connection(server, user=user, password=password, authentication=NTLM)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error al conectar con el servidor LDAP")

    if not conn.bind():
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

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
        user_data = {
            "username": username,
            "displayName": str(entry.displayName) if hasattr(entry, 'displayName') else None,
            "email": str(entry.mail) if hasattr(entry, 'mail') else None,
            "department": str(entry.department) if hasattr(entry, 'department') else None,
            "title": str(entry.title) if hasattr(entry, 'title') else None,
            "groups": [str(group) for group in entry.memberOf] if hasattr(entry, 'memberOf') else [],
            "accountStatus": str(entry.userAccountControl) if hasattr(entry, 'userAccountControl') else None
        }

    conn.unbind()
    return {"ok": True, "user": user_data}
    
   