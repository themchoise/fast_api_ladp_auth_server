from fastapi import FastAPI
import ldap3 
from dotenv import load_dotenv
import os

load_dotenv()
LADP_SERVER_IP = os.getenv("LADP_SERVER_IP")
LDAP_DOMAIN = os.getenv("MIDOMINIO")


server = ldap3.Server(f'ldap://{LADP_SERVER_IP}',port=389, get_info=ALL) 


  

app = FastAPI()


@app.get("/")
def read_root():
    return {"message": "Hello World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: str = None):
    return {"item_id": item_id, "q": q}

@app.post("/login")
def login(credentials: LoginRequest):
    username = credentials.username
    password = credentials.password
    user = f"{LDAP_DOMAIN}\\{username}"
    conn = ldap3.Connection(server, user=user, password=password, authentication=NTLM)

    if not conn.bind():
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    conn.unbind()
    return {"ok": True, "user": username}
    
   