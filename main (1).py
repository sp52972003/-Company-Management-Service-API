import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import jwt
import re
from fastapi import FastAPI, HTTPException, Depends, Header, status
from pydantic import BaseModel, EmailStr, Field
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from passlib.context import CryptContext
from bson import ObjectId


# CONFIGURATION MANAGEMENT 
class Settings:
    """Application settings loaded from environment variables"""
    DATABASE_URL: str = os.getenv("DATABASE_URL", "mongodb://localhost:27017")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "saas_platform_db")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key-change-in-production")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))


settings = Settings()


# DATABASE INITIALIZATION 
class MongoDBConnection:
    """Handles MongoDB connection and database access"""
    
    def __init__(self, connection_string: str, database_name: str):
        self.connection_string = connection_string
        self.database_name = database_name
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
    
    async def connect(self):
        """Establish connection to MongoDB"""
        self.client = AsyncIOMotorClient(self.connection_string)
        self.db = self.client[self.database_name]
    
    async def disconnect(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
    
    def get_db(self) -> AsyncIOMotorDatabase:
        """Get database instance"""
        return self.db


mongo_db = MongoDBConnection(settings.DATABASE_URL, settings.DATABASE_NAME)


#  PYDANTIC VALIDATION MODELS 
class CompanyCreationInput(BaseModel):
    """Input validation for company creation"""
    company_name: str = Field(..., min_length=3, max_length=100)
    admin_email: EmailStr
    admin_password: str = Field(..., min_length=8)


class CompanyUpdateInput(BaseModel):
    """Input validation for company updates"""
    company_name: str = Field(..., min_length=3, max_length=100)
    admin_email: EmailStr
    admin_password: str = Field(..., min_length=8)


class CompanyDeletionInput(BaseModel):
    """Input validation for company deletion"""
    company_name: str = Field(..., min_length=3, max_length=100)


class AdminLoginInput(BaseModel):
    """Input validation for admin login"""
    admin_email: EmailStr
    admin_password: str = Field(..., min_length=8)


class CompanyDetailResponse(BaseModel):
    """Response model for company information"""
    company_id: str
    company_name: str
    company_slug: str
    data_storage_name: str
    admin_email: EmailStr
    
    class Config:
        from_attributes = True


# SECURITY UTILITIES 
class CryptoService:
    """Handles password encryption and decryption"""
    
    def __init__(self):
        self.crypto_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    def encrypt_password(self, raw_password: str) -> str:
        """Encrypt plain text password using bcrypt"""
        return self.crypto_context.hash(raw_password)
    
    def verify_password(self, raw_password: str, encrypted_password: str) -> bool:
        """Verify plain text password against encrypted version"""
        return self.crypto_context.verify(raw_password, encrypted_password)


class JWTService:
    """Handles JWT token creation and validation"""
    
    def __init__(self, secret: str, algorithm: str, expire_minutes: int):
        self.secret = secret
        self.algorithm = algorithm
        self.expire_minutes = expire_minutes
    
    def create_access_token(self, admin_id: str, company_id: str, email: str) -> str:
        """Create JWT access token with admin and company context"""
        expires = datetime.utcnow() + timedelta(minutes=self.expire_minutes)
        payload = {
            "sub": admin_id,
            "company_id": company_id,
            "email": email,
            "exp": expires
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)
    
    def decode_access_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate JWT token"""
        try:
            return jwt.decode(token, self.secret, algorithms=[self.algorithm])
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Token is invalid: {str(e)}")


crypto_service = CryptoService()
jwt_service = JWTService(
    settings.JWT_SECRET_KEY,
    settings.JWT_ALGORITHM,
    settings.ACCESS_TOKEN_EXPIRE_MINUTES
)


# UTILITY FUNCTIONS
def create_company_slug(company_name: str) -> str:
    """
    Convert company name to URL-safe slug.
    Example: "Tech Solutions Inc" -> "tech-solutions-inc"
    """
    slug = company_name.lower().strip()
    slug = re.sub(r'\s+', '-', slug)
    slug = re.sub(r'[^a-z0-9-]', '', slug)
    slug = re.sub(r'-+', '-', slug).strip('-')
    
    if not slug or not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', slug):
        raise ValueError("Company name cannot be converted to valid slug")
    
    return slug


def generate_storage_collection_name(slug: str) -> str:
    """
    Generate storage collection name for company data.
    Example: "tech-solutions-inc" -> "storage_tech_solutions_inc"
    """
    return f"storage_{slug.replace('-', '_')}"


# DATA ACCESS LAYER 
class AdminDataHandler:
    """Handles all admin-related database operations"""
    
    def __init__(self, database: AsyncIOMotorDatabase):
        self.db = database
        self.admins_collection = "admin_users"
    
    async def get_admin_by_email(self, email: str) -> Optional[Dict]:
        """Retrieve admin record by email"""
        return await self.db[self.admins_collection].find_one({"email": email})
    
    async def get_admin_by_id(self, admin_id: str) -> Optional[Dict]:
        """Retrieve admin record by ID"""
        try:
            return await self.db[self.admins_collection].find_one({"_id": ObjectId(admin_id)})
        except Exception:
            return None
    
    async def create_admin(self, admin_data: Dict) -> str:
        """Create new admin record and return ID"""
        result = await self.db[self.admins_collection].insert_one(admin_data)
        return str(result.inserted_id)
    
    async def remove_admin(self, admin_id: str) -> bool:
        """Delete admin record"""
        result = await self.db[self.admins_collection].delete_one({"_id": ObjectId(admin_id)})
        return result.deleted_count > 0


class CompanyDataHandler:
    """Handles all company-related database operations"""
    
    def __init__(self, database: AsyncIOMotorDatabase):
        self.db = database
        self.companies_collection = "company_accounts"
    
    async def get_company_by_slug(self, slug: str) -> Optional[Dict]:
        """Retrieve company by slug"""
        return await self.db[self.companies_collection].find_one({"slug": slug})
    
    async def get_company_by_id(self, company_id: str) -> Optional[Dict]:
        """Retrieve company by ID"""
        try:
            return await self.db[self.companies_collection].find_one({"_id": ObjectId(company_id)})
        except Exception:
            return None
    
    async def create_company(self, company_data: Dict) -> str:
        """Create new company record and return ID"""
        result = await self.db[self.companies_collection].insert_one(company_data)
        return str(result.inserted_id)
    
    async def update_company(self, company_id: str, updates: Dict) -> bool:
        """Update company record"""
        result = await self.db[self.companies_collection].update_one(
            {"_id": ObjectId(company_id)},
            {"$set": updates}
        )
        return result.modified_count > 0
    
    async def remove_company(self, company_id: str) -> bool:
        """Delete company record"""
        result = await self.db[self.companies_collection].delete_one({"_id": ObjectId(company_id)})
        return result.deleted_count > 0


class DataStorageManager:
    """Manages company-specific data storage collections"""
    
    def __init__(self, database: AsyncIOMotorDatabase):
        self.db = database
    
    async def create_storage(self, collection_name: str) -> None:
        """Create and initialize company storage collection"""
        collection = self.db[collection_name]
        await collection.insert_one({
            "system": {
                "created_at": datetime.utcnow(),
                "version": "1.0"
            }
        })
    
    async def copy_storage(self, source_name: str, destination_name: str) -> int:
        """Copy all data from source to destination storage"""
        source_collection = self.db[source_name]
        dest_collection = self.db[destination_name]
        
        documents = await source_collection.find({}).to_list(None)
        copied = 0
        
        for doc in documents:
            doc.pop("_id", None)
            await dest_collection.insert_one(doc)
            copied += 1
        
        return copied
    
    async def delete_storage(self, collection_name: str) -> None:
        """Delete company storage collection"""
        await self.db.drop_collection(collection_name)


# Initialize data handlers
admin_handler = AdminDataHandler(mongo_db.db)
company_handler = CompanyDataHandler(mongo_db.db)
storage_manager = DataStorageManager(mongo_db.db)


#  BUSINESS LOGIC LAYER 
class AuthenticationLogic:
    """Handles authentication operations"""
    
    def __init__(self, admin_handler: AdminDataHandler, company_handler: CompanyDataHandler):
        self.admin_handler = admin_handler
        self.company_handler = company_handler
    
    async def process_login(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate admin and generate JWT token"""
        admin = await self.admin_handler.get_admin_by_email(email)
        
        if not admin or not crypto_service.verify_password(password, admin["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        company = await self.company_handler.get_company_by_id(str(admin["company_id"]))
        if not company:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Company not found"
            )
        
        token = jwt_service.create_access_token(
            str(admin["_id"]),
            str(company["_id"]),
            email
        )
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "admin_id": str(admin["_id"]),
            "company_id": str(company["_id"])
        }


class CompanyManagementLogic:
    """Handles company management operations"""
    
    def __init__(self, admin_handler: AdminDataHandler, company_handler: CompanyDataHandler, 
                 storage_manager: DataStorageManager):
        self.admin_handler = admin_handler
        self.company_handler = company_handler
        self.storage_manager = storage_manager
    
    async def setup_company(self, name: str, email: str, password: str) -> Dict[str, Any]:
        """Create new company with admin account and storage"""
        
        slug = create_company_slug(name)
        
        existing = await self.company_handler.get_company_by_slug(slug)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Company '{name}' already exists"
            )
        
        # Create admin account
        admin_record = {
            "email": email,
            "password_hash": crypto_service.encrypt_password(password),
            "created_at": datetime.utcnow()
        }
        admin_id = await self.admin_handler.create_admin(admin_record)
        
        # Create company record
        storage_name = generate_storage_collection_name(slug)
        company_record = {
            "name": name,
            "slug": slug,
            "data_storage_name": storage_name,
            "admin_id": ObjectId(admin_id),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        company_id = await self.company_handler.create_company(company_record)
        
        # Link admin to company
        await mongo_db.db["admin_users"].update_one(
            {"_id": ObjectId(admin_id)},
            {"$set": {"company_id": ObjectId(company_id)}}
        )
        
        # Initialize storage
        await self.storage_manager.create_storage(storage_name)
        
        return {
            "company_id": company_id,
            "company_name": name,
            "company_slug": slug,
            "data_storage_name": storage_name,
            "admin_email": email
        }
    
    async def fetch_company(self, name: str) -> Dict[str, Any]:
        """Retrieve company details by name"""
        slug = create_company_slug(name)
        company = await self.company_handler.get_company_by_slug(slug)
        
        if not company:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Company '{name}' not found"
            )
        
        admin = await self.admin_handler.get_admin_by_id(str(company["admin_id"]))
        
        return {
            "company_id": str(company["_id"]),
            "company_name": company["name"],
            "company_slug": company["slug"],
            "data_storage_name": company["data_storage_name"],
            "admin_email": admin["email"] if admin else "unknown"
        }
    
    async def modify_company(self, current_name: str, new_name: str, email: str, 
                            password: str) -> Dict[str, Any]:
        """Update company name and migrate storage"""
        
        current_slug = create_company_slug(current_name)
        new_slug = create_company_slug(new_name)
        
        # Verify admin credentials
        admin = await self.admin_handler.get_admin_by_email(email)
        if not admin or not crypto_service.verify_password(password, admin["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin credentials"
            )
        
        # Get current company
        company = await self.company_handler.get_company_by_slug(current_slug)
        if not company:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Company '{current_name}' not found"
            )
        
        # Check if new name is available
        if new_slug != current_slug:
            existing = await self.company_handler.get_company_by_slug(new_slug)
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Company name '{new_name}' already in use"
                )
        
        # Migrate storage
        old_storage = company["data_storage_name"]
        new_storage = generate_storage_collection_name(new_slug)
        
        await self.storage_manager.create_storage(new_storage)
        migrated_count = await self.storage_manager.copy_storage(old_storage, new_storage)
        await self.storage_manager.delete_storage(old_storage)
        
        # Update company
        update_fields = {
            "name": new_name,
            "slug": new_slug,
            "data_storage_name": new_storage,
            "updated_at": datetime.utcnow()
        }
        await self.company_handler.update_company(str(company["_id"]), update_fields)
        
        return {
            "message": "Company updated successfully",
            "previous_storage": old_storage,
            "current_storage": new_storage,
            "records_migrated": migrated_count,
            "company_slug": new_slug
        }
    
    async def destroy_company(self, name: str, requester_admin_id: str) -> Dict[str, str]:
        """Permanently delete company and all associated data"""
        
        slug = create_company_slug(name)
        company = await self.company_handler.get_company_by_slug(slug)
        
        if not company:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Company '{name}' not found"
            )
        
        # Check authorization
        if str(company["admin_id"]) != requester_admin_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to delete this company"
            )
        
        # Delete storage
        await self.storage_manager.delete_storage(company["data_storage_name"])
        
        # Delete admin
        await self.admin_handler.remove_admin(str(company["admin_id"]))
        
        # Delete company
        await self.company_handler.remove_company(str(company["_id"]))
        
        return {"message": "Company and all data have been successfully deleted"}


auth_logic = AuthenticationLogic(admin_handler, company_handler)
company_logic = CompanyManagementLogic(admin_handler, company_handler, storage_manager)


#  DEPENDENCY INJECTION 
async def extract_current_admin(authorization: str = Header(None)) -> Dict[str, Any]:
    """
    Extract and validate admin from JWT token in Authorization header.
    Expected format: "Bearer <token>"
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing or invalid"
        )
    
    token = authorization.split(" ", 1)[1]
    
    try:
        payload = jwt_service.decode_access_token(token)
        return payload
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid or expired"
        )


# FASTAPI APPLICATION 
app = FastAPI(
    title="Company Management Service",
    description="Multi-tenant company management API with JWT authentication",
    version="2.0.0"
)


@app.on_event("startup")
async def startup_event():
    """Initialize database connection on startup"""
    await mongo_db.connect()


@app.on_event("shutdown")
async def shutdown_event():
    """Close database connection on shutdown"""
    await mongo_db.disconnect()


#  API ENDPOINTS 

@app.post("/company/register", response_model=CompanyDetailResponse)
async def register_company(payload: CompanyCreationInput):
    """
    Register new company with admin account.
    
    - **company_name**: Name of the company (3-100 characters)
    - **admin_email**: Email of the admin user
    - **admin_password**: Password for admin (minimum 8 characters)
    """
    return await company_logic.setup_company(
        payload.company_name,
        payload.admin_email,
        payload.admin_password
    )


@app.get("/company/info", response_model=CompanyDetailResponse)
async def get_company_info(company_name: str):
    """
    Get company information by name.
    
    - **company_name**: Name of the company to retrieve
    """
    return await company_logic.fetch_company(company_name)


@app.put("/company/modify")
async def modify_company(
    payload: CompanyUpdateInput,
    current_admin: Dict[str, Any] = Depends(extract_current_admin)
):
    """
    Modify company name and storage configuration.
    Requires valid JWT authentication.
    
    - **company_name**: New name for the company
    - **admin_email**: Admin email (for verification)
    - **admin_password**: Admin password (for verification)
    """
    return await company_logic.modify_company(
        payload.company_name,
        payload.company_name,
        payload.admin_email,
        payload.admin_password
    )


@app.delete("/company/remove")
async def remove_company(
    payload: CompanyDeletionInput,
    current_admin: Dict[str, Any] = Depends(extract_current_admin)
):
    """
    Remove company and all associated data permanently.
    Requires valid JWT authentication and authorization.
    
    - **company_name**: Name of the company to delete
    """
    return await company_logic.destroy_company(
        payload.company_name,
        current_admin["sub"]
    )


@app.post("/admin/authenticate")
async def authenticate_admin(payload: AdminLoginInput):
    """
    Authenticate admin user and issue JWT token.
    
    - **admin_email**: Admin email address
    - **admin_password**: Admin password
    
    Returns JWT access token for authenticated requests.
    """
    return await auth_logic.process_login(payload.admin_email, payload.admin_password)


@app.get("/health")
async def health_status():
    """API health check endpoint"""
    return {"status": "healthy", "service": "Company Management API v2"}
