import os
from fastapi import FastAPI, Body, HTTPException, Depends, status, APIRouter, File, UploadFile, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr, validator
from pydantic.functional_validators import BeforeValidator
from bson import ObjectId
from typing import Optional, List, Annotated, Dict, Any
from datetime import datetime, timedelta
import motor.motor_asyncio
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND
import secrets

# --- Configuration ---
MONGO_DETAILS = os.environ.get("MONGO_DETAILS", "mongodb://localhost:27017")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Database Setup ---
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_DETAILS)
db = client.StudentAttendanceDB

# --- Security & Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# --- Pydantic Models & Helpers ---
PyObjectId = Annotated[str, BeforeValidator(str)]

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Base Models for Collections
class User(BaseModel):
    id: PyObjectId = Field(alias="_id", default=None)
    first_name: str
    last_name: str
    email: EmailStr
    password_hash: str
    status: str
    roles: List[str]
    student_profile_id: Optional[PyObjectId] = None
    student_ids: Optional[List[PyObjectId]] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserInDB(User):
    password_hash: str

# API Specific Models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class LoginResponse(BaseModel):
    access_token: str
    user_id: str
    roles: List[str]

class UserProfile(BaseModel):
    user_id: str
    first_name: str
    last_name: str
    email: EmailStr
    roles: List[str]

class CreateUser(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str
    roles: List[str]

class UpdateUser(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    status: Optional[str] = None
    roles: Optional[List[str]] = None

class TeacherClass(BaseModel):
    class_period_id: str
    course_name: str
    course_code: str
    period_name: str

class RosterStudent(BaseModel):
    student_id: str
    first_name: str
    last_name: str

class AttendanceRecordInput(BaseModel):
    student_id: str
    status_id: str

class SubmitAttendancePayload(BaseModel):
    attendance_date: datetime
    records: List[AttendanceRecordInput]

class AttendanceHistoryRecord(BaseModel):
    record_id: str
    student_id: str
    student_name: str
    status_name: str
    attendance_date: datetime

class CorrectionRequest(BaseModel):
    record_id: str
    new_status_id: str
    reason: str

class ParentChild(BaseModel):
    student_id: str
    first_name: str
    last_name: str
    grade_level: int

class ChildAttendanceRecord(BaseModel):
    record_id: str
    course_name: str
    attendance_date: datetime
    status_name: str

class StudentAttendanceRecord(ChildAttendanceRecord):
    pass

class AbsenceExcusePayload(BaseModel):
    start_date: datetime
    end_date: datetime
    reason: str

class CalendarEntry(BaseModel):
    school_date: datetime
    day_type: str
    description: Optional[str] = None

# --- Authentication & Authorization ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = await db.users.find_one({"email": token_data.email})
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("status") != "active":
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user

async def role_checker(required_roles: List[str], current_user: dict = Depends(get_current_active_user)):
    user_roles = current_user.get("roles", [])
    if not any(role in user_roles for role in required_roles):
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail=f"User does not have the required roles: {required_roles}"
        )
    return current_user

# Role-specific dependencies
def get_current_teacher(current_user: dict = Depends(lambda user: role_checker(["teacher"]))): return current_user
def get_current_parent(current_user: dict = Depends(lambda user: role_checker(["parent"]))): return current_user
def get_current_student(current_user: dict = Depends(lambda user: role_checker(["student"]))): return current_user
def get_current_admin(current_user: dict = Depends(lambda user: role_checker(["admin"]))): return current_user


# --- FastAPI Application & Routers ---
app = FastAPI(title="Student Attendance Management API")

auth_router = APIRouter(prefix="/api/auth", tags=["Authentication"])
teacher_router = APIRouter(prefix="/api/teacher", tags=["Teacher"], dependencies=[Depends(get_current_teacher)])
parent_router = APIRouter(prefix="/api/parent", tags=["Parent"], dependencies=[Depends(get_current_parent)])
student_router = APIRouter(prefix="/api/student", tags=["Student"], dependencies=[Depends(get_current_student)])
admin_router = APIRouter(prefix="/api/admin", tags=["Admin"], dependencies=[Depends(get_current_admin)])

# --- Auth Routes ---
@auth_router.post("/login", response_model=LoginResponse)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "user_id": str(user["_id"]), "roles": user["roles"]}

@auth_router.get("/me", response_model=UserProfile)
async def read_users_me(current_user: dict = Depends(get_current_active_user)):
    return {
        "user_id": str(current_user["_id"]),
        "first_name": current_user["first_name"],
        "last_name": current_user["last_name"],
        "email": current_user["email"],
        "roles": current_user["roles"]
    }

@auth_router.post("/logout")
async def logout():
    # In a real app, this might involve blacklisting the token.
    return {"message": "Successfully logged out"}

# --- Teacher Routes ---
@teacher_router.get("/classes", response_model=List[TeacherClass])
async def get_teacher_classes(current_user: dict = Depends(get_current_teacher)):
    teacher_id = current_user["_id"]
    pipeline = [
        {"$match": {"teacher_id": teacher_id}},
        {
            "$lookup": {
                "from": "courses",
                "localField": "course_id",
                "foreignField": "_id",
                "as": "course_info"
            }
        },
        {"$unwind": "$course_info"},
        {
            "$project": {
                "class_period_id": {"$toString": "$_id"},
                "course_name": "$course_info.course_name",
                "course_code": "$course_info.course_code",
                "period_name": "$period_name"
            }
        }
    ]
    classes = await db.classes.aggregate(pipeline).to_list(100)
    return classes

@teacher_router.get("/classes/{class_period_id}/roster", response_model=List[RosterStudent])
async def get_class_roster(class_period_id: str, current_user: dict = Depends(get_current_teacher)):
    try:
        class_obj_id = ObjectId(class_period_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid class_period_id format")

    class_info = await db.classes.find_one({"_id": class_obj_id, "teacher_id": current_user["_id"]})
    if not class_info:
        raise HTTPException(status_code=404, detail="Class not found or not assigned to this teacher")

    student_ids = class_info.get("enrolled_student_ids", [])
    if not student_ids:
        return []

    students = await db.students.find({"_id": {"$in": student_ids}}).to_list(length=None)
    return [
        {
            "student_id": str(s["_id"]),
            "first_name": s["first_name"],
            "last_name": s["last_name"]
        } for s in students
    ]

@teacher_router.post("/classes/{class_period_id}/attendance")
async def submit_class_attendance(class_period_id: str, payload: SubmitAttendancePayload, current_user: dict = Depends(get_current_teacher)):
    try:
        class_obj_id = ObjectId(class_period_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid class_period_id format")

    # Verify class belongs to teacher
    class_info = await db.classes.find_one({"_id": class_obj_id, "teacher_id": current_user["_id"]})
    if not class_info:
        raise HTTPException(status_code=404, detail="Class not found or not assigned to this teacher")

    records_to_insert = []
    for record in payload.records:
        records_to_insert.append({
            "student_id": ObjectId(record.student_id),
            "class_id": class_obj_id,
            "status_id": ObjectId(record.status_id),
            "attendance_date": payload.attendance_date,
            "recorded_by_user_id": current_user["_id"],
            "recorded_at": datetime.utcnow()
        })

    if not records_to_insert:
        return {"message": "No attendance records submitted", "submitted_count": 0}
    
    result = await db.attendance.insert_many(records_to_insert)
    return {"message": "Attendance submitted successfully", "submitted_count": len(result.inserted_ids)}

# --- Parent Routes ---
@parent_router.get("/children", response_model=List[ParentChild])
async def get_parent_children(current_user: dict = Depends(get_current_parent)):
    student_ids = current_user.get("student_ids", [])
    if not student_ids:
        return []
    
    children_cursor = db.students.find({"_id": {"$in": student_ids}})
    children = await children_cursor.to_list(length=None)
    return [
        {
            "student_id": str(child["_id"]),
            "first_name": child["first_name"],
            "last_name": child["last_name"],
            "grade_level": child["grade_level"]
        } for child in children
    ]

@parent_router.get("/children/{student_id}/attendance", response_model=List[ChildAttendanceRecord])
async def get_child_attendance(
    student_id: str,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: dict = Depends(get_current_parent)
):
    try:
        student_obj_id = ObjectId(student_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid student_id format")

    # Security check: Ensure the student_id is one of the parent's children
    if student_obj_id not in current_user.get("student_ids", []):
        raise HTTPException(status_code=403, detail="Access denied to this student's records")

    match_query = {"student_id": student_obj_id}
    if start_date and end_date:
        match_query["attendance_date"] = {"$gte": start_date, "$lte": end_date}
    elif start_date:
        match_query["attendance_date"] = {"$gte": start_date}
    elif end_date:
        match_query["attendance_date"] = {"$lte": end_date}

    pipeline = [
        {"$match": match_query},
        {"$lookup": {"from": "classes", "localField": "class_id", "foreignField": "_id", "as": "class_info"}},
        {"$unwind": "$class_info"},
        {"$lookup": {"from": "courses", "localField": "class_info.course_id", "foreignField": "_id", "as": "course_info"}},
        {"$unwind": "$course_info"},
        {"$lookup": {"from": "attendance_statuses", "localField": "status_id", "foreignField": "_id", "as": "status_info"}},
        {"$unwind": "$status_info"},
        {"$sort": {"attendance_date": -1}},
        {
            "$project": {
                "record_id": {"$toString": "$_id"},
                "course_name": "$course_info.course_name",
                "attendance_date": "$attendance_date",
                "status_name": "$status_info.status_name"
            }
        }
    ]
    records = await db.attendance.aggregate(pipeline).to_list(length=None)
    return records

@parent_router.post("/children/{student_id}/absences/excuses")
async def submit_absence_excuse(
    student_id: str,
    start_date: datetime = Form(...),
    end_date: datetime = Form(...),
    reason: str = Form(...),
    document: Optional[UploadFile] = File(None),
    current_user: dict = Depends(get_current_parent)
):
    try:
        student_obj_id = ObjectId(student_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid student_id format")

    if student_obj_id not in current_user.get("student_ids", []):
        raise HTTPException(status_code=403, detail="Cannot submit excuse for this student")
    
    # In a real app, handle file upload to a cloud storage like S3
    document_url = f"uploads/{document.filename}" if document else None

    excuse_data = {
        "student_id": student_obj_id,
        "submitted_by_user_id": current_user["_id"],
        "start_date": start_date,
        "end_date": end_date,
        "reason": reason,
        "document_url": document_url,
        "status": "pending",
        "submitted_at": datetime.utcnow()
    }
    result = await db.excuses.insert_one(excuse_data)
    return {
        "excuse_id": str(result.inserted_id),
        "status": "pending",
        "message": "Absence excuse submitted successfully."
    }

# --- Student Routes ---
@student_router.get("/attendance", response_model=List[StudentAttendanceRecord])
async def get_student_attendance(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: dict = Depends(get_current_student)
):
    student_profile = await db.students.find_one({"user_id": current_user["_id"]})
    if not student_profile:
        raise HTTPException(status_code=404, detail="Student profile not found")

    # Re-use parent's attendance logic with the student's own ID
    # This requires a temporary modification to the current_user dict for the dependency
    # or creating a shared utility function.
    # For simplicity, we'll duplicate the logic here.
    student_obj_id = student_profile["_id"]
    match_query = {"student_id": student_obj_id}
    if start_date and end_date:
        match_query["attendance_date"] = {"$gte": start_date, "$lte": end_date}
    
    pipeline = [
        {"$match": match_query},
        {"$lookup": {"from": "classes", "localField": "class_id", "foreignField": "_id", "as": "class_info"}},
        {"$unwind": "$class_info"},
        {"$lookup": {"from": "courses", "localField": "class_info.course_id", "foreignField": "_id", "as": "course_info"}},
        {"$unwind": "$course_info"},
        {"$lookup": {"from": "attendance_statuses", "localField": "status_id", "foreignField": "_id", "as": "status_info"}},
        {"$unwind": "$status_info"},
        {"$sort": {"attendance_date": -1}},
        {
            "$project": {
                "record_id": {"$toString": "$_id"},
                "course_name": "$course_info.course_name",
                "attendance_date": "$attendance_date",
                "status_name": "$status_info.status_name"
            }
        }
    ]
    records = await db.attendance.aggregate(pipeline).to_list(length=None)
    return records

# --- Admin Routes ---
@admin_router.get("/users")
async def get_all_users(role: Optional[str] = None, status: Optional[str] = None):
    query = {}
    if role:
        query["roles"] = role
    if status:
        query["status"] = status
    
    users_cursor = db.users.find(query)
    users = await users_cursor.to_list(length=None)
    return [
        {
            "user_id": str(user["_id"]),
            "first_name": user["first_name"],
            "last_name": user["last_name"],
            "email": user["email"],
            "status": user["status"],
            "roles": user["roles"]
        } for user in users
    ]

@admin_router.post("/users", status_code=HTTP_201_CREATED)
async def create_new_user(user_data: CreateUser):
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user_data.password)
    new_user = {
        "first_name": user_data.first_name,
        "last_name": user_data.last_name,
        "email": user_data.email,
        "password_hash": hashed_password,
        "status": "active",
        "roles": user_data.roles,
        "created_at": datetime.utcnow()
    }
    result = await db.users.insert_one(new_user)
    return {
        "user_id": str(result.inserted_id),
        "email": user_data.email,
        "status": "active",
        "created_at": new_user["created_at"]
    }

@admin_router.put("/users/{user_id}")
async def update_user_info(user_id: str, update_data: UpdateUser):
    try:
        user_obj_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user_id format")

    update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not update_dict:
        raise HTTPException(status_code=400, detail="No update data provided")

    result = await db.users.update_one({"_id": user_obj_id}, {"$set": update_dict})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"user_id": user_id, "message": "User updated successfully"}

@admin_router.get("/absences/excuses/pending")
async def get_pending_excuses():
    pipeline = [
        {"$match": {"status": "pending"}},
        {"$lookup": {"from": "students", "localField": "student_id", "foreignField": "_id", "as": "student_info"}},
        {"$unwind": "$student_info"},
        {"$lookup": {"from": "users", "localField": "submitted_by_user_id", "foreignField": "_id", "as": "user_info"}},
        {"$unwind": "$user_info"},
        {
            "$project": {
                "excuse_id": {"$toString": "$_id"},
                "student_name": {"$concat": ["$student_info.first_name", " ", "$student_info.last_name"]},
                "submitted_by_name": {"$concat": ["$user_info.first_name", " ", "$user_info.last_name"]},
                "start_date": "$start_date",
                "end_date": "$end_date",
                "submitted_at": "$submitted_at"
            }
        }
    ]
    excuses = await db.excuses.aggregate(pipeline).to_list(length=None)
    return excuses

@admin_router.put("/absences/excuses/{excuse_id}/status")
async def update_excuse_status(
    excuse_id: str,
    new_status: str, # Should be 'approved' or 'rejected'
    current_user: dict = Depends(get_current_admin)
):
    if new_status not in ["approved", "rejected"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be 'approved' or 'rejected'.")

    try:
        excuse_obj_id = ObjectId(excuse_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid excuse_id format")

    update_result = await db.excuses.update_one(
        {"_id": excuse_obj_id, "status": "pending"},
        {"$set": {"status": new_status, "reviewed_by_user_id": current_user["_id"]}}
    )

    if update_result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Pending excuse not found")
    
    return {"excuse_id": excuse_id, "status": new_status, "message": f"Excuse has been {new_status}."}

@admin_router.post("/settings/calendar")
async def add_calendar_day(entry: CalendarEntry):
    # Using update_one with upsert=True to add or update a date
    result = await db.school_calendar.update_one(
        {"school_date": entry.school_date},
        {"$set": entry.model_dump()},
        upsert=True
    )
    message = "Calendar day updated successfully." if result.matched_count > 0 else "Calendar day added successfully."
    return {"school_date": entry.school_date, "message": message}

# --- Main Application Setup ---
@app.get("/")
def read_root():
    return {"message": "Welcome to the Student Attendance API"}

app.include_router(auth_router)
app.include_router(teacher_router)
app.include_router(parent_router)
app.include_router(student_router)
app.include_router(admin_router)

# To run this app: uvicorn filename:app --reload