from fastapi import FastAPI, Depends,HTTPException
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
from auth import *
app = FastAPI()
@app.post("/login")
def login(form_data:OAuth2PasswordRequestForm,form = Depends()):
    if form_data.username != "admin":
        raise HTTPException(status_code=401, detail="Notog'ri malumot")
    access_token =  create_access_token({"sub":form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

oauth2_schema = OAuth2PasswordBearer(tokenUrl="/login")


