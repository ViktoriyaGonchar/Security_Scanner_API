"""Main application file for Security Scanner API."""
import logging
import sys
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from contextlib import asynccontextmanager

from storage.database import DatabaseManager
from api.public_routes import router as public_router
from api.admin_routes import router as admin_router

# Configure detailed logging with guaranteed console output
import sys
from logging.handlers import RotatingFileHandler

# Clear any existing handlers
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

# Create formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)

# Console handler - force output to stdout
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)
console_handler.stream = sys.stdout  # Force stdout

# File handler
file_handler = RotatingFileHandler(
    'app.log',
    encoding='utf-8',
    mode='a',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

# Root logger configuration
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)
root_logger.addHandler(console_handler)
root_logger.addHandler(file_handler)

# Application logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Print startup message directly to console
print("\n" + "=" * 60)
print("🚀 Security Scanner API - Logging Initialized")
print("=" * 60)
sys.stdout.flush()

# Global database manager
db_manager = DatabaseManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown."""
    # Startup
    startup_msg = "=" * 60 + "\nStarting Security Scanner API...\n" + "=" * 60
    print(startup_msg)
    logger.info(startup_msg)
    sys.stdout.flush()
    
    try:
        print("Initializing database manager...")
        logger.debug("Initializing database manager...")
        sys.stdout.flush()
        
        await db_manager.initialize()
        
        success_msg = "✓ Database initialized successfully"
        print(success_msg)
        logger.info(success_msg)
        sys.stdout.flush()
        
        print("Setting database manager to app.state...")
        logger.debug("Setting database manager to app.state...")
        sys.stdout.flush()
        
        app.state.db_manager = db_manager
        
        state_msg = "✓ App state configured"
        print(state_msg)
        logger.info(state_msg)
        sys.stdout.flush()
        
        completion_msg = "=" * 60 + "\nApplication startup completed successfully!\n" + "=" * 60
        print(completion_msg)
        logger.info(completion_msg)
        sys.stdout.flush()
    except Exception as e:
        error_msg = f"❌ Startup failed: {str(e)}"
        print(error_msg)
        logger.error(error_msg, exc_info=True)
        sys.stdout.flush()
        raise
    
    yield
    
    # Shutdown
    logger.info("=" * 60)
    logger.info("Shutting down Security Scanner API...")
    logger.info("=" * 60)


# Create FastAPI app with proper configuration
logger.debug("Creating FastAPI application instance...")
app = FastAPI(
    title="Security Scanner API",
    description="Web Vulnerability Scanner for XSS and SQL Injection Detection. "
                "Automated vulnerability detection using pattern matching and heuristic analysis.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)
logger.info("✓ FastAPI app created")

# Configure CORS
logger.debug("Configuring CORS middleware...")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
logger.info("✓ CORS middleware configured")

# Add request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests."""
    import time
    start_time = time.time()
    
    client_host = request.client.host if request.client else "unknown"
    method = request.method
    path = request.url.path
    query_params = str(request.query_params) if request.query_params else ""
    
    request_msg = f"🌐 {method} {path}{'?' + query_params if query_params else ''} from {client_host}"
    print(request_msg)
    logger.info(request_msg)
    sys.stdout.flush()
    
    logger.debug(f"Headers: {dict(request.headers)}")
    
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        response_msg = f"✓ {method} {path} -> {response.status_code} ({process_time:.3f}s)"
        print(response_msg)
        logger.info(response_msg)
        sys.stdout.flush()
        return response
    except Exception as e:
        process_time = time.time() - start_time
        error_msg = f"❌ {method} {path} -> ERROR after {process_time:.3f}s: {str(e)}"
        print(error_msg)
        logger.error(error_msg, exc_info=True)
        sys.stdout.flush()
        raise

# Include routers with tags for better documentation
logger.debug("Including routers...")
try:
    app.include_router(public_router, tags=["Public API"])
    logger.info("✓ Public router included")
except Exception as e:
    logger.error(f"❌ Failed to include public router: {str(e)}", exc_info=True)
    raise

try:
    app.include_router(admin_router, tags=["Admin API"], prefix="")
    logger.info("✓ Admin router included")
except Exception as e:
    logger.error(f"❌ Failed to include admin router: {str(e)}", exc_info=True)
    raise

# Exception handlers
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Handle 404 errors with JSON response."""
    logger.warning(f"404 Not Found: {request.method} {request.url.path}")
    logger.debug(f"Request headers: {dict(request.headers)}")
    return JSONResponse(
        status_code=404,
        content={"detail": f"Endpoint not found: {request.url.path}"}
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    """Handle 500 errors with JSON response."""
    logger.error("=" * 60)
    logger.error(f"❌ Internal server error on {request.method} {request.url.path}")
    logger.error(f"Error: {str(exc)}", exc_info=True)
    logger.error(f"Request URL: {request.url}")
    logger.error(f"Request method: {request.method}")
    logger.error("=" * 60)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors."""
    logger.warning(f"422 Validation error on {request.method} {request.url.path}")
    logger.debug(f"Validation errors: {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": exc.body}
    )


# Root endpoint - redirect to docs
@app.get("/", include_in_schema=False)
async def root(request: Request):
    """Redirect root to API documentation."""
    client_info = f"🏠 Root endpoint accessed from {request.client.host if request.client else 'unknown'}"
    print(client_info)
    logger.info(client_info)
    
    redirect_msg = "📍 Redirecting to /docs"
    print(redirect_msg)
    logger.info(redirect_msg)
    sys.stdout.flush()
    
    return RedirectResponse(url="/docs")


@app.get("/api", tags=["Info"])
async def api_info():
    """API information endpoint."""
    logger.debug("API info endpoint accessed")
    return {
        "name": "Security Scanner API",
        "version": "1.0.0",
        "description": "Web Vulnerability Scanner for XSS and SQL Injection Detection",
        "docs": "/docs",
        "redoc": "/redoc",
        "scanner_ui": "/scanner",
        "admin_panel": "/admin-panel"
    }


if __name__ == "__main__":
    import uvicorn
    import socket
    
    # Check if port is available
    port = 8000
    host = "0.0.0.0"
    
    def check_port(host, port):
        """Check if port is available."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((host, port))
            sock.close()
            return True
        except OSError:
            return False
    
    print(f"\n{'=' * 60}")
    print("🔍 Checking port availability...")
    print(f"{'=' * 60}\n")
    
    if not check_port(host, port):
        error_msg = f"""
{'=' * 60}
❌ ERROR: Port {port} is already in use!
{'=' * 60}

Port {port} is currently being used by another process.

Solutions:
1. Stop the process using port {port}:
   Windows: netstat -ano | findstr :8000
           taskkill /PID <PID> /F
   
2. Use a different port:
   Change port in main.py or set PORT environment variable
   
3. Find and kill the process:
   netstat -ano | findstr :8000
   (Then kill the process with the PID shown)

{'=' * 60}
"""
        print(error_msg)
        logger.error(f"Port {port} is already in use")
        sys.exit(1)
    
    print(f"✓ Port {port} is available\n")
    
    # Print startup info directly to console (guaranteed output)
    startup_info = f"""
{'=' * 60}
🚀 Security Scanner API Starting...
{'=' * 60}
📍 API URL: http://localhost:{port}
📚 Documentation: http://localhost:{port}/docs
🔍 Scanner UI: http://localhost:{port}/scanner
🔐 Admin Panel: http://localhost:{port}/admin-panel
{'=' * 60}

Waiting for requests...
"""
    print(startup_info)
    sys.stdout.flush()
    
    logger.info(f"Starting uvicorn server on {host}:{port}")
    
    try:
        # Configure uvicorn to use our logging
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="info",
            access_log=False,  # We handle our own logging
            use_colors=True
        )
    except KeyboardInterrupt:
        print("\n\n⚠️  Server stopped by user")
        logger.info("Server stopped by user")
        sys.stdout.flush()
    except OSError as e:
        if e.errno == 10048 or e.winerror == 10048:
            error_msg = f"""
{'=' * 60}
❌ ERROR: Port {port} is already in use!
{'=' * 60}

Another process is using port {port}. 

To fix this:
1. Find the process: netstat -ano | findstr :{port}
2. Kill it: taskkill /PID <PID> /F
3. Or use a different port

{'=' * 60}
"""
            print(error_msg)
            logger.error(f"Port {port} is already in use: {str(e)}")
        else:
            error_msg = f"\n❌ ERROR: {str(e)}\n"
            print(error_msg)
            logger.error(error_msg, exc_info=True)
        sys.stdout.flush()
        sys.exit(1)
    except Exception as e:
        error_msg = f"\n❌ ERROR: Failed to start server: {str(e)}\n"
        print(error_msg)
        logger.error(error_msg, exc_info=True)
        sys.stdout.flush()
        sys.exit(1)

