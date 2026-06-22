from pwdlib import PasswordHash

hasher = PasswordHash.recommended()

def hash_password(password: str) -> str:
    hashed_password = hasher.hash(password=password)
    return hashed_password

def verify_password(password: str, hashed_password: str) -> bool:
    return hasher.verify(password=password, hash=hashed_password)