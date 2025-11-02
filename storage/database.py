"""Database management for Security Scanner API."""
import aiosqlite
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database operations for the Security Scanner API."""
    
    def __init__(self, db_path: str = "security_scanner.db"):
        """Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize database schema."""
        logger.info(f"Initializing database at: {self.db_path}")
        if self._initialized:
            logger.debug("Database already initialized, skipping...")
            return
        
        logger.debug(f"Connecting to database: {self.db_path}")
        async with aiosqlite.connect(self.db_path) as db:
            logger.debug("Creating database tables...")
            # Scan history table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    input_data TEXT NOT NULL,
                    sanitized_data TEXT,
                    result TEXT NOT NULL,
                    xss_detected INTEGER DEFAULT 0,
                    sqli_detected INTEGER DEFAULT 0,
                    risk_level TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Admin users table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS admin_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Scanning rules table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scanning_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_type TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    description TEXT,
                    enabled INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # System logs table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    context TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.commit()
            logger.debug("✓ Database tables created")
            
            # Insert default admin user (username: admin, password: admin123)
            # Using plain text password for simplicity (for development/demo)
            # In production, use password hashing
            logger.debug("Creating default admin user...")
            await db.execute("""
                INSERT OR REPLACE INTO admin_users (username, password_hash)
                VALUES ('admin', 'admin123')
            """)
            logger.info("✓ Default admin user created (admin/admin123)")
            
            # Insert default scanning rules
            logger.debug("Initializing default scanning rules...")
            await self._initialize_default_rules(db)
            logger.info("✓ Default scanning rules created")
            
            await db.commit()
            logger.debug("✓ Database commit successful")
        
        self._initialized = True
        logger.info(f"✓ Database fully initialized at {self.db_path}")
    
    async def _initialize_default_rules(self, db: aiosqlite.Connection) -> None:
        """Initialize default scanning rules."""
        default_rules = [
            # XSS rules
            ('xss', r'<script[^>]*>.*?</script>', 'Script tag detection', 1),
            ('xss', r'javascript:', 'JavaScript protocol', 1),
            ('xss', r'on\w+\s*=', 'Event handler attribute', 1),
            ('xss', r'<iframe[^>]*>', 'Iframe tag detection', 1),
            ('xss', r'<img[^>]*src\s*=\s*["\']?javascript:', 'Image with JavaScript source', 1),
            ('xss', r'<svg[^>]*>.*?<script', 'SVG with script', 1),
            
            # SQLi rules
            ('sqli', r'(\bUNION\b.*\bSELECT\b)', 'UNION SELECT injection', 1),
            ('sqli', r'(\bOR\b|\bAND\b)\s*[\'"]?\s*\d+\s*=\s*\d+', 'Boolean-based SQL injection', 1),
            ('sqli', r'(\bOR\b|\bAND\b)\s*[\'"]?\s*[\'"][\'"]?\s*=\s*[\'"][\'"]?', 'String-based SQL injection', 1),
            ('sqli', r';\s*(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|EXEC)', 'SQL command injection', 1),
            ('sqli', r'(\'|\"|;|--|\#|\/\*|\*\/)', 'SQL special characters', 1),
            ('sqli', r'\b(EXEC|EXECUTE|xp_|sp_)\b', 'SQL procedure/function call', 1),
        ]
        
        for rule_type, pattern, description, enabled in default_rules:
            await db.execute("""
                INSERT OR IGNORE INTO scanning_rules (rule_type, pattern, description, enabled)
                VALUES (?, ?, ?, ?)
            """, (rule_type, pattern, description, enabled))
    
    async def save_scan_result(
        self,
        scan_type: str,
        input_data: str,
        sanitized_data: str,
        result: str,
        xss_detected: bool,
        sqli_detected: bool,
        risk_level: str
    ) -> int:
        """Save scan result to database.
        
        Args:
            scan_type: Type of scan (url or text)
            input_data: Original input data
            sanitized_data: Sanitized input data
            result: Scan result details
            xss_detected: Whether XSS was detected
            sqli_detected: Whether SQLi was detected
            risk_level: Risk level (safe, low, medium, high)
            
        Returns:
            ID of inserted record
        """
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                INSERT INTO scan_history 
                (scan_type, input_data, sanitized_data, result, xss_detected, sqli_detected, risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (scan_type, input_data, sanitized_data, result, int(xss_detected), int(sqli_detected), risk_level))
            await db.commit()
            return cursor.lastrowid
    
    async def get_scan_history(
        self,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get scan history.
        
        Args:
            limit: Maximum number of records
            offset: Offset for pagination
            
        Returns:
            List of scan history records
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT * FROM scan_history
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    async def get_scan_count(self) -> int:
        """Get total number of scans."""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT COUNT(*) FROM scan_history")
            row = await cursor.fetchone()
            return row[0] if row else 0
    
    async def get_admin_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get admin user by username.
        
        Args:
            username: Admin username
            
        Returns:
            User data or None
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM admin_users WHERE username = ?",
                (username,)
            )
            row = await cursor.fetchone()
            return dict(row) if row else None
    
    async def get_scanning_rules(self) -> List[Dict[str, Any]]:
        """Get all scanning rules.
        
        Returns:
            List of scanning rules
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT * FROM scanning_rules
                ORDER BY rule_type, id
            """)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    async def update_scanning_rule(
        self,
        rule_id: int,
        pattern: Optional[str] = None,
        description: Optional[str] = None,
        enabled: Optional[bool] = None
    ) -> bool:
        """Update scanning rule.
        
        Args:
            rule_id: Rule ID
            pattern: New pattern (optional)
            description: New description (optional)
            enabled: Enable/disable flag (optional)
            
        Returns:
            True if updated, False otherwise
        """
        updates = []
        params = []
        
        if pattern is not None:
            updates.append("pattern = ?")
            params.append(pattern)
        
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(int(enabled))
        
        if not updates:
            return False
        
        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(rule_id)
        
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(f"""
                UPDATE scanning_rules
                SET {', '.join(updates)}
                WHERE id = ?
            """, params)
            await db.commit()
            return cursor.rowcount > 0
    
    async def add_system_log(
        self,
        level: str,
        message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add system log entry.
        
        Args:
            level: Log level (INFO, WARNING, ERROR)
            message: Log message
            context: Additional context data
        """
        context_json = json.dumps(context) if context else None
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO system_logs (level, message, context)
                VALUES (?, ?, ?)
            """, (level, message, context_json))
            await db.commit()
    
    async def get_system_logs(
        self,
        level: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get system logs.
        
        Args:
            level: Filter by log level (optional)
            limit: Maximum number of records
            offset: Offset for pagination
            
        Returns:
            List of log entries
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            if level:
                cursor = await db.execute("""
                    SELECT * FROM system_logs
                    WHERE level = ?
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (level, limit, offset))
            else:
                cursor = await db.execute("""
                    SELECT * FROM system_logs
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset))
            
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get application statistics.
        
        Returns:
            Dictionary with statistics
        """
        async with aiosqlite.connect(self.db_path) as db:
            stats = {}
            
            # Total scans
            cursor = await db.execute("SELECT COUNT(*) FROM scan_history")
            stats['total_scans'] = (await cursor.fetchone())[0]
            
            # XSS detected
            cursor = await db.execute("SELECT COUNT(*) FROM scan_history WHERE xss_detected = 1")
            stats['xss_detected_count'] = (await cursor.fetchone())[0]
            
            # SQLi detected
            cursor = await db.execute("SELECT COUNT(*) FROM scan_history WHERE sqli_detected = 1")
            stats['sqli_detected_count'] = (await cursor.fetchone())[0]
            
            # Risk level distribution
            cursor = await db.execute("""
                SELECT risk_level, COUNT(*) as count
                FROM scan_history
                GROUP BY risk_level
            """)
            stats['risk_distribution'] = {row[0]: row[1] for row in await cursor.fetchall()}
            
            # Scans by type
            cursor = await db.execute("""
                SELECT scan_type, COUNT(*) as count
                FROM scan_history
                GROUP BY scan_type
            """)
            stats['scans_by_type'] = {row[0]: row[1] for row in await cursor.fetchall()}
            
            # Total logs
            cursor = await db.execute("SELECT COUNT(*) FROM system_logs")
            stats['total_logs'] = (await cursor.fetchone())[0]
            
            return stats

