from fastapi import FastAPI
from routers import auth, users

app = FastAPI(title="Auth API demo")

app.include_router(auth.router)
app.include_router(users.router)

@app.get('/ping')
def check_server():
    return "Pong"