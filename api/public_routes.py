"""Public API routes."""
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
import logging
from pathlib import Path

from storage.database import DatabaseManager
from validators.input_validator import InputValidator
from scanner.vulnerability_scanner import VulnerabilityScanner

logger = logging.getLogger(__name__)

# Get base directory (project root)
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

router = APIRouter(
    tags=["Public API"],
    responses={404: {"description": "Not found"}},
)


class ScanRequest(BaseModel):
    """Scan request model."""
    input_data: str
    scan_type: str  # 'url' or 'text'


class ScanResponse(BaseModel):
    """Scan response model."""
    success: bool
    xss_detected: bool
    sqli_detected: bool
    risk_level: str
    summary: str
    xss_findings: list
    sqli_findings: list
    scan_id: Optional[int] = None


def get_db_manager(request: Request) -> DatabaseManager:
    """Get database manager from app state."""
    return request.app.state.db_manager


def get_validator() -> InputValidator:
    """Get input validator."""
    return InputValidator()


def get_scanner(request: Request) -> VulnerabilityScanner:
    """Get vulnerability scanner.
    Note: Rules are loaded dynamically in the scan endpoint.
    """
    return VulnerabilityScanner(rules=None)


@router.post("/api/scan", response_model=ScanResponse, summary="Scan input for vulnerabilities")
async def scan_input(
    scan_request: ScanRequest,
    db_manager: DatabaseManager = Depends(get_db_manager),
    validator: InputValidator = Depends(get_validator),
    scanner: VulnerabilityScanner = Depends(get_scanner)
):
    """Scan input for vulnerabilities.
    
    Args:
        scan_request: Scan request data
        db_manager: Database manager
        validator: Input validator
        scanner: Vulnerability scanner
        
    Returns:
        Scan results
    """
    logger.info(f"Scan request received: type={scan_request.scan_type}, data_length={len(scan_request.input_data)}")
    try:
        input_data = scan_request.input_data.strip()
        scan_type = scan_request.scan_type.lower()
        
        # Validate input
        if scan_type == 'url':
            is_valid, error = validator.validate_url(input_data)
            if not is_valid:
                await db_manager.add_system_log(
                    'WARNING',
                    f'Invalid URL input: {error}',
                    {'input': input_data[:100]}
                )
                raise HTTPException(status_code=400, detail=f"Invalid URL: {error}")
        elif scan_type == 'text':
            is_valid, error = validator.validate_text(input_data)
            if not is_valid:
                await db_manager.add_system_log(
                    'WARNING',
                    f'Invalid text input: {error}',
                    {'input': input_data[:100]}
                )
                raise HTTPException(status_code=400, detail=f"Invalid text: {error}")
        else:
            raise HTTPException(status_code=400, detail="scan_type must be 'url' or 'text'")
        
        # Sanitize input for storage
        sanitized_data = validator.sanitize_input(input_data, max_length=500)
        
        # Load rules from database and create scanner with them
        rules = await db_manager.get_scanning_rules()
        scanner_with_rules = VulnerabilityScanner(rules=rules)
        
        # Scan for vulnerabilities
        scan_results = scanner_with_rules.scan(input_data)
        
        # Save to database
        scan_id = await db_manager.save_scan_result(
            scan_type=scan_type,
            input_data=input_data[:500],  # Limit stored length
            sanitized_data=sanitized_data,
            result=scan_results['summary'],
            xss_detected=scan_results['xss_detected'],
            sqli_detected=scan_results['sqli_detected'],
            risk_level=scan_results['risk_level']
        )
        
        # Log scan
        await db_manager.add_system_log(
            'INFO',
            f'Scan completed: {scan_type}',
            {
                'scan_id': scan_id,
                'xss_detected': scan_results['xss_detected'],
                'sqli_detected': scan_results['sqli_detected'],
                'risk_level': scan_results['risk_level']
            }
        )
        
        return ScanResponse(
            success=True,
            xss_detected=scan_results['xss_detected'],
            sqli_detected=scan_results['sqli_detected'],
            risk_level=scan_results['risk_level'],
            summary=scan_results['summary'],
            xss_findings=scan_results['xss_findings'],
            sqli_findings=scan_results['sqli_findings'],
            scan_id=scan_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan error: {str(e)}", exc_info=True)
        await db_manager.add_system_log(
            'ERROR',
            f'Scan error: {str(e)}',
            {'input_type': scan_type if 'scan_type' in locals() else 'unknown'}
        )
        raise HTTPException(status_code=500, detail="Internal server error during scan")


@router.get("/scanner", response_class=HTMLResponse, tags=["Frontend"])
async def scanner_page(request: Request):
    """Serve scanner interface page."""
    logger.info(f"📄 Scanner page requested from {request.client.host if request.client else 'unknown'}")
    logger.debug(f"Full URL: {request.url}")
    logger.debug(f"TEMPLATES_DIR: {TEMPLATES_DIR}")
    logger.debug(f"Absolute path: {TEMPLATES_DIR.resolve()}")
    
    template_path = TEMPLATES_DIR / "index.html"
    logger.debug(f"Looking for template at: {template_path}")
    logger.debug(f"Template exists: {template_path.exists()}")
    
    if not template_path.exists():
        error_msg = f"❌ Template not found: {template_path}"
        logger.error(error_msg)
        logger.error(f"Current working directory: {Path.cwd()}")
        logger.error(f"BASE_DIR: {BASE_DIR}")
        logger.error(f"TEMPLATES_DIR absolute: {TEMPLATES_DIR.resolve()}")
        raise HTTPException(status_code=500, detail=f"Template file not found: {template_path}")
    
    try:
        logger.debug("Reading template file...")
        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()
        logger.info(f"✓ Template loaded successfully: {len(content)} characters")
        logger.info(f"✓ Returning HTML response")
        return HTMLResponse(content=content)
    except Exception as e:
        error_msg = f"❌ Error reading template: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error reading template: {str(e)}")


@router.get("/health", tags=["Health"], summary="Health check")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "Security Scanner API"}

