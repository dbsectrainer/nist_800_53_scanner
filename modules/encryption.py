import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Union

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap


class SecureKeyStorage:
    def __init__(self, master_key_path: str):
        """
        Initialize secure key storage with a master key.

        Args:
            master_key_path: Path to master key file
        """
        self.master_key_path = master_key_path
        self.master_key = self._load_or_create_master_key()

    def _load_or_create_master_key(self) -> bytes:
        """Load existing master key or create a new one."""
        key_file = Path(self.master_key_path)

        if key_file.exists():
            # Load existing key with secure permissions check
            if oct(key_file.stat().st_mode)[-3:] != "600":
                raise ValueError("Insecure master key file permissions")
            return key_file.read_bytes()

        # Create new master key
        key = AESGCM.generate_key(bit_length=256)

        # Save with secure permissions
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.touch(mode=0o600)
        key_file.write_bytes(key)

        return key

    def wrap_key(self, key: bytes) -> bytes:
        """Wrap a key using the master key."""
        return aes_key_wrap(self.master_key, key)

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        """Unwrap a key using the master key."""
        return aes_key_unwrap(self.master_key, wrapped_key)


class SecureDataHandler:
    def __init__(self, key_storage: SecureKeyStorage, key_rotation_interval: int = 30):
        """
        Initialize encryption handler with secure key storage.

        Args:
            key_storage: SecureKeyStorage instance
            key_rotation_interval: Days between key rotations
        """
        self.key_storage = key_storage
        self.key_rotation_interval = key_rotation_interval
        self.keys_file = "encryption_keys.json"
        self.keys = self._load_or_create_keys()

    def _load_or_create_keys(self) -> Dict:
        """Load existing keys or create new ones."""
        if os.path.exists(self.keys_file):
            with open(self.keys_file, "r") as f:
                keys_data = json.load(f)

            # Unwrap keys
            return {
                "current": self.key_storage.unwrap_key(base64.b64decode(keys_data["current"]["key"])),
                "previous": self.key_storage.unwrap_key(base64.b64decode(keys_data["previous"]["key"]))
                if keys_data.get("previous")
                else None,
                "created_at": keys_data["current"]["created_at"],
            }

        # Create new key
        return {"current": Fernet.generate_key(), "previous": None, "created_at": time.time()}

    def _save_keys(self):
        """Save wrapped keys securely."""
        keys_data = {
            "current": {
                "key": base64.b64encode(self.key_storage.wrap_key(self.keys["current"])).decode(),
                "created_at": self.keys["created_at"],
            }
        }

        if self.keys["previous"]:
            keys_data["previous"] = {"key": base64.b64encode(self.key_storage.wrap_key(self.keys["previous"])).decode()}

        with open(self.keys_file, "w") as f:
            json.dump(keys_data, f)

        # Secure file permissions
        os.chmod(self.keys_file, 0o600)

    def _check_key_rotation(self):
        """Check and perform key rotation if needed."""
        current_time = time.time()
        if current_time - self.keys["created_at"] > self.key_rotation_interval * 86400:
            # Rotate keys
            self.keys["previous"] = self.keys["current"]
            self.keys["current"] = Fernet.generate_key()
            self.keys["created_at"] = current_time
            self._save_keys()

    def _get_fernet(self) -> MultiFernet:
        """Get MultiFernet instance with current and previous keys."""
        self._check_key_rotation()

        fernets = [Fernet(self.keys["current"])]
        if self.keys["previous"]:
            fernets.append(Fernet(self.keys["previous"]))

        return MultiFernet(fernets)

    def encrypt_data(self, data: Union[str, Dict, Any]) -> Dict[str, str]:
        """
        Encrypt data with integrity protection.

        Args:
            data: Data to encrypt

        Returns:
            Dict containing encrypted data and HMAC
        """
        # Convert data to JSON string if needed
        if not isinstance(data, str):
            data = json.dumps(data)

        # Get Fernet instance
        f = self._get_fernet()

        # Encrypt the data
        encrypted_data = f.encrypt(data.encode("utf-8"))

        # Calculate HMAC
        h = hmac.new(self.keys["current"], encrypted_data, hashlib.sha256)

        return {"data": base64.urlsafe_b64encode(encrypted_data).decode("utf-8"), "hmac": h.hexdigest()}

    def decrypt_data(self, encrypted_package: Dict[str, str]) -> Union[str, Dict, Any]:
        """
        Decrypt data and verify integrity.

        Args:
            encrypted_package: Dict containing encrypted data and HMAC

        Returns:
            Decrypted data
        """
        try:
            # Decode the encrypted data
            encrypted_data = base64.urlsafe_b64decode(encrypted_package["data"].encode("utf-8"))

            # Verify HMAC
            h = hmac.new(self.keys["current"], encrypted_data, hashlib.sha256)
            if not hmac.compare_digest(h.hexdigest(), encrypted_package["hmac"]):
                raise ValueError("Data integrity check failed")

            # Decrypt the data
            f = self._get_fernet()
            decrypted_bytes = f.decrypt(encrypted_data)
            decrypted_str = decrypted_bytes.decode("utf-8")

            # Try to parse as JSON
            try:
                return json.loads(decrypted_str)
            except json.JSONDecodeError:
                return decrypted_str

        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def secure_file(self, file_path: str) -> Dict[str, str]:
        """
        Encrypt a file with integrity protection.

        Args:
            file_path: Path to the file to encrypt

        Returns:
            Dict containing paths to encrypted file and HMAC file
        """
        with open(file_path, "rb") as file:
            file_data = file.read()

        # Get Fernet instance
        f = self._get_fernet()

        # Encrypt the file
        encrypted_data = f.encrypt(file_data)

        # Calculate HMAC
        h = hmac.new(self.keys["current"], encrypted_data, hashlib.sha256)

        # Save encrypted file
        encrypted_file_path = f"{file_path}.encrypted"
        hmac_file_path = f"{file_path}.hmac"

        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        with open(hmac_file_path, "w") as hmac_file:
            hmac_file.write(h.hexdigest())

        # Secure file permissions
        os.chmod(encrypted_file_path, 0o600)
        os.chmod(hmac_file_path, 0o600)

        return {"encrypted_file": encrypted_file_path, "hmac_file": hmac_file_path}

    def unsecure_file(self, encrypted_file_path: str, output_path: Optional[str] = None) -> str:
        """
        Decrypt a file and verify integrity.

        Args:
            encrypted_file_path: Path to the encrypted file
            output_path: Optional path to save decrypted file

        Returns:
            Path to the decrypted file
        """
        # Get HMAC file path
        hmac_file_path = encrypted_file_path.replace(".encrypted", ".hmac")

        # Read encrypted data and stored HMAC
        with open(encrypted_file_path, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()

        with open(hmac_file_path, "r") as hmac_file:
            stored_hmac = hmac_file.read()

        # Verify HMAC
        h = hmac.new(self.keys["current"], encrypted_data, hashlib.sha256)
        if not hmac.compare_digest(h.hexdigest(), stored_hmac):
            raise ValueError("File integrity check failed")

        # Decrypt the file
        f = self._get_fernet()
        decrypted_data = f.decrypt(encrypted_data)

        # Use provided output path or create one
        if output_path is None:
            output_path = encrypted_file_path.replace(".encrypted", "")

        # Save decrypted file
        with open(output_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        return output_path
