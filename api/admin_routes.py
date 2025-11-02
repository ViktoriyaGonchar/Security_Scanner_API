"""Admin API routes."""
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import logging
from pathlib import Path

from storage.database import DatabaseManager
from admin.auth import authenticate_user, create_access_token, get_current_admin, verify_token
from datetime import timedelta

logger = logging.getLogger(__name__)

# Get base directory (project root)
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

router = APIRouter(
    tags=["Admin API"],
    responses={404: {"description": "Not found"}, 401: {"description": "Unauthorized"}},
)


class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response model."""
    access_token: str
    token_type: str = "bearer"


class RuleUpdateRequest(BaseModel):
    """Rule update request model."""
    pattern: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None


def get_db_manager(request: Request) -> DatabaseManager:
    """Get database manager from app state."""
    return request.app.state.db_manager


@router.post("/api/admin/login", response_model=LoginResponse)
async def login(
    login_request: LoginRequest,
    request: Request
):
    """Admin login endpoint.
    
    Args:
        login_request: Login credentials
        request: FastAPI request
        
    Returns:
        Access token
    """
    logger.info(f"Login attempt for user: {login_request.username}")
    logger.debug(f"Request from: {request.client.host if request.client else 'unknown'}")
    
    db_manager = request.app.state.db_manager
    logger.debug("Database manager retrieved from app.state")
    
    user = await authenticate_user(
        login_request.username,
        login_request.password,
        db_manager
    )
    
    if not user:
        await db_manager.add_system_log(
            'WARNING',
            f'Failed login attempt: {login_request.username}',
            {}
        )
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )
    
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=timedelta(minutes=30)
    )
    
    await db_manager.add_system_log(
        'INFO',
        f'Admin login: {user["username"]}',
        {}
    )
    
    return LoginResponse(access_token=access_token, token_type="bearer")


@router.get("/admin-panel", response_class=HTMLResponse, tags=["Admin"])
async def admin_panel_page(request: Request):
    """Serve admin panel interface page."""
    logger.debug(f"Admin panel page requested: {request.url}")
    logger.debug(f"TEMPLATES_DIR: {TEMPLATES_DIR}")
    
    template_path = TEMPLATES_DIR / "admin.html"
    logger.debug(f"Looking for template at: {template_path}")
    logger.debug(f"Template exists: {template_path.exists()}")
    
    if not template_path.exists():
        logger.error(f"❌ Template not found: {template_path}")
        logger.error(f"Current working directory: {Path.cwd()}")
        raise HTTPException(status_code=500, detail=f"Template file not found: {template_path}")
    
    try:
        logger.debug("Reading template file...")
        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()
        logger.info(f"✓ Template loaded successfully: {len(content)} characters")
        return HTMLResponse(content=content)
    except Exception as e:
        logger.error(f"❌ Error reading template: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error reading template: {str(e)}")


@router.get("/api/admin/scan-history")
async def get_scan_history(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    current_admin: dict = Depends(get_current_admin)
):
    """Get scan history.
    
    Args:
        request: FastAPI request
        limit: Maximum number of records
        offset: Offset for pagination
        current_admin: Current admin user
        
    Returns:
        List of scan history records
    """
    db_manager = request.app.state.db_manager
    history = await db_manager.get_scan_history(limit=limit, offset=offset)
    return {"history": history}


@router.get("/api/admin/statistics")
async def get_statistics(
    request: Request,
    current_admin: dict = Depends(get_current_admin)
):
    """Get application statistics.
    
    Args:
        request: FastAPI request
        current_admin: Current admin user
        
    Returns:
        Statistics dictionary
    """
    db_manager = request.app.state.db_manager
    stats = await db_manager.get_statistics()
    return stats


@router.get("/api/admin/rules")
async def get_rules(
    request: Request,
    current_admin: dict = Depends(get_current_admin)
):
    """Get scanning rules.
    
    Args:
        request: FastAPI request
        current_admin: Current admin user
        
    Returns:
        List of scanning rules
    """
    db_manager = request.app.state.db_manager
    rules = await db_manager.get_scanning_rules()
    return {"rules": rules}


@router.put("/api/admin/rules/{rule_id}")
async def update_rule(
    rule_id: int,
    rule_update: RuleUpdateRequest,
    request: Request,
    current_admin: dict = Depends(get_current_admin)
):
    """Update scanning rule.
    
    Args:
        rule_id: Rule ID
        rule_update: Rule update data
        request: FastAPI request
        current_admin: Current admin user
        
    Returns:
        Success status
    """
    db_manager = request.app.state.db_manager
    
    success = await db_manager.update_scanning_rule(
        rule_id=rule_id,
        pattern=rule_update.pattern,
        description=rule_update.description,
        enabled=rule_update.enabled
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    await db_manager.add_system_log(
        'INFO',
        f'Rule updated: {rule_id}',
        {'rule_id': rule_id, 'updated_by': current_admin['username']}
    )
    
    return {"success": True}


@router.get("/api/admin/logs")
async def get_logs(
    request: Request,
    level: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_admin: dict = Depends(get_current_admin)
):
    """Get system logs.
    
    Args:
        request: FastAPI request
        level: Filter by log level (optional)
        limit: Maximum number of records
        offset: Offset for pagination
        current_admin: Current admin user
        
    Returns:
        List of log entries
    """
    db_manager = request.app.state.db_manager
    logs = await db_manager.get_system_logs(level=level, limit=limit, offset=offset)
    return {"logs": logs}

