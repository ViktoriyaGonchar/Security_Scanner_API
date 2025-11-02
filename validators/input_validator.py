"""Input validation and sanitization module."""
import re
import html
from typing import Optional, Tuple
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class InputValidator:
    """Validates and sanitizes user input."""
    
    MAX_URL_LENGTH = 2048
    MAX_TEXT_LENGTH = 10000
    ALLOWED_SCHEMES = {'http', 'https', 'ftp', 'ftps'}
    
    def __init__(self):
        """Initialize input validator."""
        self.url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE
        )
    
    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL input.
        
        Args:
            url: URL string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url or not isinstance(url, str):
            return False, "URL cannot be empty"
        
        url = url.strip()
        
        if len(url) > self.MAX_URL_LENGTH:
            return False, f"URL length exceeds maximum of {self.MAX_URL_LENGTH} characters"
        
        try:
            parsed = urlparse(url)
            
            if not parsed.scheme:
                return False, "URL must include a scheme (http:// or https://)"
            
            if parsed.scheme.lower() not in self.ALLOWED_SCHEMES:
                return False, f"URL scheme must be one of: {', '.join(self.ALLOWED_SCHEMES)}"
            
            if not parsed.netloc:
                return False, "URL must include a valid domain or IP address"
            
            # Check for suspicious patterns
            if self._contains_suspicious_chars(url):
                logger.warning(f"Suspicious characters detected in URL: {url[:50]}...")
            
            return True, None
            
        except Exception as e:
            logger.error(f"URL validation error: {str(e)}")
            return False, "Invalid URL format"
    
    def validate_text(self, text: str) -> Tuple[bool, Optional[str]]:
        """Validate text input.
        
        Args:
            text: Text string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not text or not isinstance(text, str):
            return False, "Text cannot be empty"
        
        text = text.strip()
        
        if len(text) > self.MAX_TEXT_LENGTH:
            return False, f"Text length exceeds maximum of {self.MAX_TEXT_LENGTH} characters"
        
        return True, None
    
    def sanitize_input(self, input_data: str, max_length: Optional[int] = None) -> str:
        """Sanitize input data for safe storage and display.
        
        Args:
            input_data: Input string to sanitize
            max_length: Maximum length (optional)
            
        Returns:
            Sanitized string
        """
        if not input_data:
            return ""
        
        # HTML escape to prevent XSS in stored data
        sanitized = html.escape(input_data)
        
        # Truncate if needed
        if max_length and len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "..."
        
        return sanitized
    
    def sanitize_for_display(self, input_data: str, max_length: int = 100) -> str:
        """Sanitize input for safe display in UI.
        
        Args:
            input_data: Input string to sanitize
            max_length: Maximum display length
            
        Returns:
            Sanitized string safe for display
        """
        sanitized = self.sanitize_input(input_data, max_length)
        return sanitized
    
    def _contains_suspicious_chars(self, text: str) -> bool:
        """Check if text contains suspicious characters.
        
        Args:
            text: Text to check
            
        Returns:
            True if suspicious characters found
        """
        suspicious_patterns = [
            r'<script',
            r'javascript:',
            r'on\w+\s*=',
            r'--',
            r'/\*',
            r'\*/',
            r"';",
            r'";',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def normalize_whitespace(self, text: str) -> str:
        """Normalize whitespace in text.
        
        Args:
            text: Text to normalize
            
        Returns:
            Normalized text
        """
        if not text:
            return ""
        
        # Replace multiple spaces with single space
        text = re.sub(r' +', ' ', text)
        
        # Replace multiple newlines with single newline
        text = re.sub(r'\n+', '\n', text)
        
        return text.strip()

