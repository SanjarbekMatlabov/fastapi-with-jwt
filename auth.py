from jose import JWTError,jwt
from datetime import datetime, timedelta
SECRET_KEY = "12"
ALGORITHM = "HS256"
def create_access_token(data:dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt