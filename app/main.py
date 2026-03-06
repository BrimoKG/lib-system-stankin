from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from . import models, schemas, auth, database
from typing import List

# Tier 2: Initialize the Application Server
app = FastAPI(title="Library System API")

# Tier 3: Create the tables in the Database if they don't exist
models.Base.metadata.create_all(bind=database.engine)

@app.get("/")
def read_root():
    return {"message": "Library System API is online"}

# --- AUTHENTICATION SECTION ---

@app.post("/register", response_model=schemas.UserResponse)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    # 1. Check if user already exists in Tier 3
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # 2. Hash the password (Security requirement)
    hashed_pwd = auth.get_password_hash(user.password)
    
    # 3. Save the new user with their assigned role (admin, moderator, or viewer)
    new_user = models.User(
        username=user.username, 
        hashed_password=hashed_pwd, 
        role=user.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from .auth import verify_password, create_access_token

# Define where the client should go to get a token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@app.post("/login", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    # 1. Look for user in Tier 3
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    
    # 2. Verify existence and password
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Create the token (The "Badge") including the username and role
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

from jose import jwt, JWTError
import os

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Role checker dependency
def check_role(allowed_roles: list):
    def role_checker(current_user: models.User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="You do not have enough permissions"
            )
        return current_user
    return role_checker

@app.get("/books")
def get_books(current_user: models.User = Depends(check_role(["viewer", "moderator", "admin"]))):
    return {"message": f"Hello {current_user.username}, here are the books!"}

@app.post("/books/add")
def add_book(current_user: models.User = Depends(check_role(["moderator", "admin"]))):
    return {"message": f"Book added successfully by {current_user.username}"}

@app.get("/admin/users", response_model=List[schemas.UserResponse], tags=["Admin Operations"])
def get_all_users(
    db: Session = Depends(database.get_db), 
    current_user: models.User = Depends(check_role(["admin"]))
):
    """
    This endpoint is ONLY visible/accessible to users with the 'admin' role.
    It fulfills the Tier 2 administrative requirement.
    """
    return db.query(models.User).all()

# --- LIBRARY MANAGEMENT (Tier 2 Logic) ---

# VIEW ALL BOOKS (Available to: Viewer, Moderator, Admin)
@app.get("/books", response_model=List[schemas.BookResponse], tags=["Library"])
def get_books(
    db: Session = Depends(database.get_db), 
    current_user: models.User = Depends(check_role(["viewer", "moderator", "admin"]))
):
    return db.query(models.Book).all()

# ADD A BOOK (Available to: Moderator, Admin)
@app.post("/books", response_model=schemas.BookResponse, tags=["Library"])
def create_book(
    book: schemas.BookCreate, 
    db: Session = Depends(database.get_db), 
    current_user: models.User = Depends(check_role(["moderator", "admin"]))
):
    new_book = models.Book(**book.model_dump())
    db.add(new_book)
    db.commit()
    db.refresh(new_book)
    return new_book

# DELETE A BOOK (Available to: Admin ONLY)
@app.delete("/books/{book_id}", tags=["Library"])
def delete_book(
    book_id: int, 
    db: Session = Depends(database.get_db), 
    current_user: models.User = Depends(check_role(["admin"]))
):
    target_book = db.query(models.Book).filter(models.Book.id == book_id).first()
    if not target_book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    db.delete(target_book)
    db.commit()
    return {"message": f"Book {book_id} deleted by Admin {current_user.username}"}

@app.post("/books", response_model=schemas.BookResponse, tags=["Library"])
def create_book(book: schemas.BookCreate, db: Session = Depends(database.get_db), current_user: models.User = Depends(check_role(["moderator", "admin"]))):
    # Check if ISBN already exists
    existing = db.query(models.Book).filter(models.Book.isbn == book.isbn).first()
    if existing:
        raise HTTPException(status_code=400, detail="A book with this ISBN already exists")
    
    new_book = models.Book(**book.model_dump())
    db.add(new_book)
    db.commit()
    db.refresh(new_book)
    return new_book
