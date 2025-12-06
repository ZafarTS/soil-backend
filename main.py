"""
Backend API - FastAPI
Authentication va Model Management
"""

from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
import sqlite3
from pathlib import Path
import json
import os

# ========== Configuration ==========

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 kun

# ========== FastAPI App ==========

app = FastAPI(title="Tuproq Tahlili API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Production'da o'zgartiring!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== Security ==========

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ========== Database ==========

DB_PATH = "soil_app.db"

def init_db():
    """Ma'lumotlar bazasini yaratish"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users jadvali
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            region TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            free_credits INTEGER DEFAULT 5,
            is_premium BOOLEAN DEFAULT 0
        )
    ''')
    
    # Analyses jadvali
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            image_path TEXT NOT NULL,
            soil_type INTEGER NOT NULL,
            moisture_level INTEGER NOT NULL,
            vegetation_index REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Model versions jadvali
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT UNIQUE NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            release_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            description TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✓ Database initialized")

# ========== Models ==========

class UserRegister(BaseModel):
    phone: str = Field(..., min_length=9, max_length=20)
    first_name: str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    region: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    phone: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserProfile(BaseModel):
    id: int
    phone: str
    first_name: str
    last_name: str
    region: str
    free_credits: int
    is_premium: bool
    created_at: str

class ModelVersion(BaseModel):
    version: str
    file_url: str
    file_size: int
    release_date: str
    description: Optional[str] = None

# ========== Helper Functions ==========

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_from_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Token'dan foydalanuvchini olish"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )
        return user_id
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

# ========== API Endpoints ==========

@app.on_event("startup")
async def startup():
    init_db()

@app.get("/")
async def root():
    return {
        "message": "Tuproq Tahlili API",
        "version": "1.0.0",
        "status": "active"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# ========== Authentication ==========

@app.post("/auth/register", response_model=Token)
async def register(user: UserRegister):
    """Ro'yxatdan o'tish"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Tekshirish: telefon raqami mavjudmi
    cursor.execute("SELECT id FROM users WHERE phone = ?", (user.phone,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bu telefon raqami allaqachon ro'yxatdan o'tgan"
        )
    
    # Parolni hash qilish
    hashed_password = get_password_hash(user.password)
    
    # Foydalanuvchini saqlash
    cursor.execute('''
        INSERT INTO users (phone, first_name, last_name, region, password_hash)
        VALUES (?, ?, ?, ?, ?)
    ''', (user.phone, user.first_name, user.last_name, user.region, hashed_password))
    
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Token yaratish
    access_token = create_access_token(data={"user_id": user_id})
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/login", response_model=Token)
async def login(credentials: UserLogin):
    """Kirish"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Foydalanuvchini topish
    cursor.execute(
        "SELECT id, password_hash FROM users WHERE phone = ?", 
        (credentials.phone,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if not user or not verify_password(credentials.password, user[1]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Telefon raqam yoki parol noto'g'ri"
        )
    
    # Token yaratish
    access_token = create_access_token(data={"user_id": user[0]})
    
    return {"access_token": access_token, "token_type": "bearer"}

# ========== User Profile ==========

@app.get("/user/profile", response_model=UserProfile)
async def get_profile(user_id: int = Depends(get_user_from_token)):
    """Foydalanuvchi profilini olish"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, phone, first_name, last_name, region, free_credits, is_premium, created_at
        FROM users WHERE id = ?
    ''', (user_id,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi")
    
    return {
        "id": user[0],
        "phone": user[1],
        "first_name": user[2],
        "last_name": user[3],
        "region": user[4],
        "free_credits": user[5],
        "is_premium": bool(user[6]),
        "created_at": user[7]
    }

@app.post("/user/use-credit")
async def use_credit(user_id: int = Depends(get_user_from_token)):
    """Kredit ishlatish"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Foydalanuvchi ma'lumotlarini olish
    cursor.execute(
        "SELECT free_credits, is_premium FROM users WHERE id = ?", 
        (user_id,)
    )
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi")
    
    free_credits, is_premium = user
    
    # Premium foydalanuvchilar uchun cheksiz
    if is_premium:
        conn.close()
        return {"success": True, "credits_remaining": -1}  # -1 = cheksiz
    
    # Kredit tekshirish
    if free_credits <= 0:
        conn.close()
        return {"success": False, "message": "Kredit tugagan"}
    
    # Kreditni kamaytirish
    cursor.execute(
        "UPDATE users SET free_credits = free_credits - 1 WHERE id = ?",
        (user_id,)
    )
    conn.commit()
    conn.close()
    
    return {"success": True, "credits_remaining": free_credits - 1}

# ========== Model Management ==========

@app.get("/model/latest", response_model=ModelVersion)
async def get_latest_model():
    """Eng oxirgi model versiyasini olish"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT version, file_path, file_size, release_date, description
        FROM model_versions
        WHERE is_active = 1
        ORDER BY release_date DESC
        LIMIT 1
    ''')
    
    model = cursor.fetchone()
    conn.close()
    
    if not model:
        # Default model
        return {
            "version": "1.0.0",
            "file_url": "/models/soil_model_mobile_v1.0.0.pt",
            "file_size": 0,
            "release_date": datetime.now().isoformat(),
            "description": "Initial model"
        }
    
    return {
        "version": model[0],
        "file_url": f"/models/{model[1]}",
        "file_size": model[2],
        "release_date": model[3],
        "description": model[4]
    }

@app.get("/model/check-update")
async def check_model_update(current_version: str):
    """Model yangilanishini tekshirish"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT version, file_path, file_size, release_date, description
        FROM model_versions
        WHERE is_active = 1 AND version > ?
        ORDER BY release_date DESC
        LIMIT 1
    ''', (current_version,))
    
    model = cursor.fetchone()
    conn.close()
    
    if not model:
        return {"update_available": False}
    
    return {
        "update_available": True,
        "version": model[0],
        "file_url": f"/models/{model[1]}",
        "file_size": model[2],
        "release_date": model[3],
        "description": model[4]
    }

# ========== Statistics ==========

@app.get("/user/statistics")
async def get_user_statistics(user_id: int = Depends(get_user_from_token)):
    """Foydalanuvchi statistikasi"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Jami tahlillar
    cursor.execute(
        "SELECT COUNT(*) FROM analyses WHERE user_id = ?",
        (user_id,)
    )
    total_analyses = cursor.fetchone()[0]
    
    # Oxirgi tahlil
    cursor.execute('''
        SELECT created_at FROM analyses 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 1
    ''', (user_id,))
    last_analysis = cursor.fetchone()
    
    conn.close()
    
    return {
        "total_analyses": total_analyses,
        "last_analysis_date": last_analysis[0] if last_analysis else None
    }


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
