from sqlalchemy import create_engine
from sqlalchemy.orm import  DeclarativeBase, sessionmaker
from dotenv import load_dotenv
import os

load_dotenv()

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")


engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    # connect_args={'check_same_thread': False}
)

SessionLocal = sessionmaker(autoflush=False, autocommit=False, bind = engine)

class Base(DeclarativeBase):
    pass

def get_db():
    with SessionLocal() as db:
        yield db