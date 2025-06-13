from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import datetime
import uvicorn

app = FastAPI()

SECRET_KEY = "supersecret"
REFRESH_SECRET = "refreshsupersecret"

# Fake DB
users = {
    "rubin": {
        "password": "123456"
    }
}

security = HTTPBearer()  # This will make Swagger show "Authorize" button

def create_access_token(username):
    payload = {
        "sub": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def create_refresh_token(username):
    payload = {
        "sub": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    }
    return jwt.encode(payload, REFRESH_SECRET, algorithm="HS256")

def decode_token(token, refresh=False):
    key = REFRESH_SECRET if refresh else SECRET_KEY
    try:
        return jwt.decode(token, key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/login")
def login(username: str, password: str):
    if username in users and users[username]["password"] == password:
        access = create_access_token(username)
        refresh = create_refresh_token(username)
        return {"access_token": access, "refresh_token": refresh}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/logout")
@app.post("/protected")
def protected(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    decoded = decode_token(token)
    return {"message": f"Welcome, {decoded['sub']}!"}

@app.post("/refresh")
def refresh_token(refresh_token: str):
    decoded = decode_token(refresh_token, refresh=True)
    new_access = create_access_token(decoded["sub"])
    return {"access_token": new_access}

@app.get("/")
def home():
    return {"message": "Welcome to JWT single file API"}

if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)
