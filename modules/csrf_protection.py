import hmac
import time
import secrets
from base64 import b64encode, b64decode
import json

class CSRFProtection:
    def __init__(self, secret_key: str, token_lifetime: int = 3600):
        """
        Initialize CSRF protection.
        
        Args:
            secret_key: Secret key for token generation
            token_lifetime: Token lifetime in seconds (default: 1 hour)
        """
        self.secret_key = secret_key.encode('utf-8')
        self.token_lifetime = token_lifetime

    def _generate_token_hmac(self, token: str, timestamp: int) -> str:
        """
        Generate HMAC for token validation.
        
        Args:
            token: Random token
            timestamp: Token creation timestamp
        
        Returns:
            HMAC signature
        """
        message = f"{token}:{timestamp}".encode()
        signature = hmac.new(self.secret_key, message, 'sha256').hexdigest()
        return signature

    def generate_token(self) -> str:
        """
        Generate a new CSRF token.
        
        Returns:
            Encoded CSRF token
        """
        # Generate random token
        token = secrets.token_urlsafe(32)
        timestamp = int(time.time())
        
        # Generate HMAC
        signature = self._generate_token_hmac(token, timestamp)
        
        # Create token package
        token_data = {
            'token': token,
            'timestamp': timestamp,
            'signature': signature
        }
        
        # Encode token package
        return b64encode(json.dumps(token_data).encode('utf-8')).decode('utf-8')

    def validate_token(self, encoded_token: str, strict: bool = True) -> tuple[bool, str | None]:
        """
        Validate a CSRF token.
        
        Args:
            encoded_token: Encoded token to validate
            strict: Whether to enforce strict timing validation
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Decode token package
            token_data = json.loads(b64decode(encoded_token.encode('utf-8')))
            
            # Extract components
            token = token_data['token']
            timestamp = token_data['timestamp']
            provided_signature = token_data['signature']
            
            # Check timestamp
            current_time = time.time()
            if strict and (current_time - timestamp) > self.token_lifetime:
                return False, "Token has expired"
            
            # Validate signature
            expected_signature = self._generate_token_hmac(token, timestamp)
            if not hmac.compare_digest(provided_signature, expected_signature):
                return False, "Invalid token signature"
            
            return True, None
            
        except Exception as e:
            return False, f"Token validation failed: {str(e)}"

    def get_token_age(self, encoded_token: str) -> float | None:
        """
        Get age of a token in seconds.
        
        Args:
            encoded_token: Encoded token
        
        Returns:
            Token age in seconds or None if token is invalid
        """
        try:
            token_data = json.loads(b64decode(encoded_token.encode('utf-8')))
            timestamp = token_data['timestamp']
            return time.time() - timestamp
        except Exception:
            return None

class CSRFMiddleware:
    def __init__(self, csrf_protection: CSRFProtection, exempt_paths: list | None = None):
        """
        Initialize CSRF middleware.
        
        Args:
            csrf_protection: CSRFProtection instance
            exempt_paths: List of paths exempt from CSRF protection
        """
        self.csrf = csrf_protection
        self.exempt_paths = exempt_paths or ['/api/health']

    def is_exempt(self, path: str) -> bool:
        """
        Check if path is exempt from CSRF protection.
        
        Args:
            path: Request path
        
        Returns:
            True if path is exempt
        """
        return any(path.startswith(exempt) for exempt in self.exempt_paths)

    def process_request(self, request_data: dict) -> tuple[bool, str | None]:
        """
        Process request for CSRF validation.
        
        Args:
            request_data: Dictionary containing request data
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Skip validation for exempt paths
        if self.is_exempt(request_data.get('path', '')):
            return True, None
        
        # Skip validation for safe methods
        if request_data.get('method', '').upper() in ['GET', 'HEAD', 'OPTIONS', 'TRACE']:
            return True, None
        
        # Get token from request
        token = request_data.get('csrf_token')
        if not token:
            return False, "CSRF token missing"
        
        # Validate token
        return self.csrf.validate_token(token)

    def get_response_headers(self) -> dict[str, str]:
        """
        Get headers to be added to response.
        
        Returns:
            Dictionary of response headers
        """
        return {
            'X-CSRF-Token': self.csrf.generate_token(),
            'Vary': 'Cookie'
        }

def create_csrf_protected_form(csrf_token: str) -> str:
    """
    Create HTML form with CSRF protection.
    
    Args:
        csrf_token: CSRF token to include in form
    
    Returns:
        HTML form string with CSRF protection
    """
    return f"""
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <!-- Add other form fields here -->
        </form>
    """

def verify_same_origin(request_data: dict) -> bool:
    """
    Verify request is from same origin.
    
    Args:
        request_data: Dictionary containing request data
    
    Returns:
        True if request is from same origin
    """
    origin = request_data.get('origin')
    referer = request_data.get('referer')
    host = request_data.get('host')
    
    if not origin and not referer:
        # No origin or referer header
        return False
    
    if origin:
        return origin == f"https://{host}"
    
    if referer:
        try:
            from urllib.parse import urlparse
            referer_host = urlparse(referer).netloc
            return referer_host == host
        except Exception:
            return False
    
    return False
