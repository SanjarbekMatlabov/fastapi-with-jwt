# from fastapi import FastAPI, Depends,HTTPException
# from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
# from auth import *
# app = FastAPI()
# @app.post("/login")
# def login(form_data:OAuth2PasswordRequestForm,form = Depends()):
#     if form_data.username != "admin":
#         raise HTTPException(status_code=401, detail="Notog'ri malumot")
#     access_token =  create_access_token({"sub":form_data.username})
#     return {"access_token": access_token, "token_type": "bearer"}

# oauth2_schema = OAuth2PasswordBearer(tokenUrl="/login")
# @app.get("/users/me")
# def read_users_me(token:str = Depends(oauth2_schema)):
#     if not user:
#         raise HTTPException(status_code=401, detail="Token xato")
#     return {"user": user}

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import Column, Integer, String, Float, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List, Optional

# --- Configuration ---
SECRET_KEY = "sss"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
Base = declarative_base()
engine = create_engine("sqlite:///./test.db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI()

# --- Database Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Integer, default=0)

class Product(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    price = Column(Float)
    description = Column(String)

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String, default="Pending")
    details = relationship("OrderDetail", back_populates="order")

class OrderDetail(Base):
    __tablename__ = "order_details"
    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey("orders.id"))
    product_id = Column(Integer, ForeignKey("products.id"))
    quantity = Column(Integer)
    order = relationship("Order", back_populates="details")

Base.metadata.create_all(bind=engine)

# --- Pydantic Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: Optional[int] = 0

class ProductCreate(BaseModel):
    name: str
    price: float
    description: str

class OrderCreate(BaseModel):
    customer_id: int
    products: List[dict]  # [{"product_id": 1, "quantity": 2}]

# --- Utility Functions ---
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(db, username: str):
    return db.query(User).filter(User.username == username).first()

# --- Dependencies ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

def get_current_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return current_user

# --- Routes ---
@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)):
    user = get_user(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}
@app.post("/signup", response_model=dict)
def sign_up(user: UserCreate, db: SessionLocal = Depends(get_db)):
    # Foydalanuvchi avvaldan mavjudligini tekshirish
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Parolni xeshlash va yangi foydalanuvchini saqlash
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_password, is_admin=user.is_admin)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User successfully registered"}

@app.post("/api/products", dependencies=[Depends(get_current_admin_user)])
def create_product(product: ProductCreate, db: SessionLocal = Depends(get_db)):
    db_product = Product(**product.dict())
    db.add(db_product)
    db.commit()
    db.refresh(db_product)
    return db_product

@app.get("/api/products/{id}")
def get_product(id: int, db: SessionLocal = Depends(get_db)):
    product = db.query(Product).filter(Product.id == id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@app.put("/api/products/{id}", dependencies=[Depends(get_current_admin_user)])
def update_product(id: int, product: ProductCreate, db: SessionLocal = Depends(get_db)):
    db_product = db.query(Product).filter(Product.id == id).first()
    if not db_product:
        raise HTTPException(status_code=404, detail="Product not found")
    for key, value in product.dict().items():
        setattr(db_product, key, value)
    db.commit()
    return db_product

@app.delete("/api/products/{id}", dependencies=[Depends(get_current_admin_user)])
def delete_product(id: int, db: SessionLocal = Depends(get_db)):
    db_product = db.query(Product).filter(Product.id == id).first()
    if not db_product:
        raise HTTPException(status_code=404, detail="Product not found")
    db.delete(db_product)
    db.commit()
    return {"detail": "Product deleted"}

@app.post("/api/orders")
def create_order(order: OrderCreate, db: SessionLocal = Depends(get_db)):
    db_order = Order(customer_id=order.customer_id)
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    for item in order.products:
        db_order_detail = OrderDetail(order_id=db_order.id, **item)
        db.add(db_order_detail)
    db.commit()
    return db_order

@app.get("/api/orders/{customer_id}")
def get_orders_by_customer(customer_id: int, db: SessionLocal = Depends(get_db)):
    return db.query(Order).filter(Order.customer_id == customer_id).all()

@app.get("/api/orders/{order_id}/status")
def get_order_status(order_id: int, db: SessionLocal = Depends(get_db)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"status": order.status}
