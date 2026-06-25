from fastapi import FastAPI
from routers import auth, users
from database import engine, Base
from models.model import User, Ref_token

Base.metadata.create_all(bind=engine)
app = FastAPI(title="Auth API demo")

app.include_router(auth.router)
app.include_router(users.router)

@app.get('/ping')
def check_server():
    return "Pong"