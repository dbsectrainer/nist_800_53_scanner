import secrets
import os
from datetime import datetime, timedelta
from argon2 import PasswordHasher
import json
import stat


class AuthenticationManager:
    def __init__(self, credentials_file="credentials.json"):
        self.credentials_file = credentials_file
        self.credentials: dict[str, dict] = self._load_credentials()
        self.ph = PasswordHasher()
        self.failed_attempts = {}
        self.MAX_ATTEMPTS = 5
        self.LOCKOUT_DURATION = timedelta(minutes=30)
        self.SESSION_DURATION = timedelta(hours=1)
        self._ensure_secure_permissions()

    def _ensure_secure_permissions(self):
        """Ensure credentials file has secure permissions (600)."""
        if os.path.exists(self.credentials_file):
            os.chmod(self.credentials_file, stat.S_IRUSR | stat.S_IWUSR)

    def _load_credentials(self) -> dict[str, dict]:
        """Load credentials from file or create if not exists."""
        if not os.path.exists(self.credentials_file):
            return {}

        with open(self.credentials_file) as f:
            creds = json.load(f)
            # Migrate any old SHA256 hashed passwords to Argon2
            self._migrate_password_hashes(creds)
            return creds

    def _migrate_password_hashes(self, creds: dict):
        """Migrate old SHA256 hashes to Argon2."""
        ph = PasswordHasher()
        for username, data in creds.items():
            if "salt" in data:  # Old format detection
                # Cannot migrate without original password
                # Mark for password reset
                data["requires_reset"] = True
                del data["salt"]
                del data["hashed_password"]
                self._save_credentials()

    def _save_credentials(self):
        """Save credentials to file with secure permissions."""
        temp_file = f"{self.credentials_file}.tmp"
        with open(temp_file, "w") as f:
            json.dump(self.credentials, f, indent=2)

        # Secure the file permissions before moving
        os.chmod(temp_file, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temp_file, self.credentials_file)

    def _check_rate_limit(self, username: str) -> bool:
        """Check if user is rate limited."""
        if username in self.failed_attempts:
            attempts = self.failed_attempts[username]
            if len(attempts) >= self.MAX_ATTEMPTS:
                oldest_attempt = min(attempts)
                if datetime.now() - oldest_attempt < self.LOCKOUT_DURATION:
                    return False
                # Reset attempts if lockout period has passed
                self.failed_attempts[username] = []
        return True

    def _record_failed_attempt(self, username: str):
        """Record a failed login attempt."""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = []
        self.failed_attempts[username].append(datetime.now())
        # Remove attempts older than lockout duration
        self.failed_attempts[username] = [
            attempt for attempt in self.failed_attempts[username] if datetime.now() - attempt < self.LOCKOUT_DURATION
        ]

    def create_user(self, username: str, password: str, role: str = "user") -> bool:
        """Create a new user with secure password storage."""
        if username in self.credentials:
            return False

        # Hash password with Argon2
        hashed_password = self.ph.hash(password)

        self.credentials[username] = {
            "hashed_password": hashed_password,
            "role": role,
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "api_key": None,
            "session": None,
            "requires_reset": False,
        }

        self._save_credentials()
        return True

    def authenticate(self, username: str, password: str) -> str | None:
        """Authenticate a user and return API key if successful."""
        if not self._check_rate_limit(username):
            return None

        if username not in self.credentials:
            self._record_failed_attempt(username)
            return None

        user = self.credentials[username]

        if user.get("requires_reset", False):
            return None

        try:
            self.ph.verify(user["hashed_password"], password)

            # Update password hash if needed
            if self.ph.check_needs_rehash(user["hashed_password"]):
                user["hashed_password"] = self.ph.hash(password)

            # Generate new session
            session = self._create_session()
            user["session"] = session
            user["last_login"] = datetime.now().isoformat()
            user["api_key"] = secrets.token_urlsafe(32)

            self._save_credentials()
            return user["api_key"]

        except Exception:
            self._record_failed_attempt(username)
            return None

    def _create_session(self) -> dict:
        """Create a new session."""
        return {
            "id": secrets.token_urlsafe(32),
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + self.SESSION_DURATION).isoformat(),
        }

    def validate_api_key(self, api_key: str) -> dict | None:
        """Validate an API key and return user details."""
        for username, user_data in self.credentials.items():
            if user_data.get("api_key") == api_key:
                # Check session expiration
                session = user_data.get("session")
                if not session:
                    return None

                expires_at = datetime.fromisoformat(session["expires_at"])
                if datetime.now() > expires_at:
                    # Session expired
                    user_data["api_key"] = None
                    user_data["session"] = None
                    self._save_credentials()
                    return None

                return {"username": username, "role": user_data["role"]}
        return None

    def rotate_credentials(self, username: str) -> str | None:
        """Rotate API key and session for a user."""
        if username not in self.credentials:
            return None

        # Generate new session and API key
        self.credentials[username]["session"] = self._create_session()
        new_api_key = secrets.token_urlsafe(32)
        self.credentials[username]["api_key"] = new_api_key
        self._save_credentials()

        return new_api_key

    def check_role_access(self, api_key: str, required_roles: list) -> bool:
        """Check if the user with the given API key has the required role."""
        user_details = self.validate_api_key(api_key)
        return bool(user_details and user_details["role"] in required_roles)

    def invalidate_session(self, username: str):
        """Invalidate a user's current session."""
        if username in self.credentials:
            self.credentials[username]["api_key"] = None
            self.credentials[username]["session"] = None
            self._save_credentials()
