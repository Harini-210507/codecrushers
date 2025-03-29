from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from bson import ObjectId
import boto3
import os

client = MongoClient("mongodb://localhost:27017")
db = client.resume_builder
users_collection = db.users


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

app = FastAPI()

AWS_ACCESS_KEY_ID = "your_aws_access_key"
AWS_SECRET_ACCESS_KEY = "your_aws_secret_key"
AWS_BUCKET_NAME = "your_s3_bucket_name"

s3_client = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

class UserSignup(BaseModel):
    username: str
    email: str
    password: str

class UserResponse(BaseModel):
    username: str
    email: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserProfile(BaseModel):
    name: str
    phone: str
    address: str
    education: str
    experience: str
    skills: list[str]
    job_target: str
    certificates: list[str] = []  # List of certificate URLs

class EvaluationResponse(BaseModel):
    overall_score: int
    communication: int
    core_knowledge: int
    practical_knowledge: int
    experience: int
    improvement_tips: list[str]

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = users_collection.find_one({"email": user_email})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/signup", response_model=UserResponse)
def signup(user: UserSignup):
    existing_user = users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password),
        "profile": {}  
    }
    users_collection.insert_one(user_data)
    return UserResponse(username=user.username, email=user.email)

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    access_token = create_access_token({"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}


@app.put("/profile/update")
def update_profile(profile: UserProfile, current_user: dict = Depends(get_current_user)):
    users_collection.update_one({"email": current_user["email"]}, {"$set": {"profile": profile.dict()}})
    return {"message": "Profile updated successfully"}

@app.get("/profile/me", response_model=UserProfile)
def get_profile(current_user: dict = Depends(get_current_user)):
    user = users_collection.find_one({"email": current_user["email"]})
    if "profile" not in user or not user["profile"]:
        raise HTTPException(status_code=404, detail="Profile not found")
    return user["profile"]

@app.post("/profile/upload_certificate")
def upload_certificate(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    s3_file_key = f"certificates/{current_user['email']}/{file.filename}"
    s3_client.upload_fileobj(file.file, AWS_BUCKET_NAME, s3_file_key)
    
    file_url = f"https://{AWS_BUCKET_NAME}.s3.amazonaws.com/{s3_file_key}"
    users_collection.update_one(
        {"email": current_user["email"]},
        {"$push": {"profile.certificates": file_url}}
    )
    return {"message": "Certificate uploaded successfully", "file_url": file_url}

@app.get("/profile/certificates")
def list_certificates(current_user: dict = Depends(get_current_user)):
    user = users_collection.find_one({"email": current_user["email"]})
    return {"certificates": user.get("profile", {}).get("certificates", [])}

@app.get("/profile/evaluate_resume", response_model=EvaluationResponse)
def evaluate_resume(current_user: dict = Depends(get_current_user)):
    profile = current_user.get("profile", {})
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    experience_score = min(30, len(profile.get("experience", "")) * 3)
    skills_score = min(30, len(profile.get("skills", [])) * 5)
    certificate_score = min(20, len(profile.get("certificates", [])) * 5)
    communication_score = min(20, 10 if "communication" in profile.get("skills", []) else 5)
    
    overall_score = experience_score + skills_score + certificate_score + communication_score
    
    tips = []
    if overall_score < 100:
        tips.append("Consider gaining more experience or certifications to improve your score.")
        tips.append("Improve your communication and practical knowledge for better job readiness.")
    
    return EvaluationResponse(
        overall_score=overall_score,
        communication=communication_score,
        core_knowledge=skills_score,
        practical_knowledge=certificate_score,
        experience=experience_score,
        improvement_tips=tips
    )
