import os
import json
import tempfile
import pytest
from modules.encryption import SecureDataHandler

class TestSecureDataHandler:
    def setup_method(self):
        """Create a fresh encryption handler for each test"""
        self.encryption_handler = SecureDataHandler()

    def test_string_encryption(self):
        """Test encryption and decryption of simple string"""
        original_string = "Sensitive information"
        
        # Encrypt
        encrypted_data = self.encryption_handler.encrypt_data(original_string)
        
        # Decrypt
        decrypted_data = self.encryption_handler.decrypt_data(encrypted_data)
        
        assert decrypted_data == original_string, "Decrypted string should match original"

    def test_dict_encryption(self):
        """Test encryption and decryption of dictionary"""
        original_dict = {
            'username': 'testuser',
            'sensitive_data': {
                'api_key': 'secret_key_123',
                'tokens': ['token1', 'token2']
            }
        }
        
        # Encrypt
        encrypted_data = self.encryption_handler.encrypt_data(original_dict)
        
        # Decrypt
        decrypted_data = self.encryption_handler.decrypt_data(encrypted_data)
        
        assert decrypted_data == original_dict, "Decrypted dictionary should match original"

    def test_complex_data_encryption(self):
        """Test encryption of complex nested data structures"""
        original_data = {
            'users': [
                {'id': 1, 'name': 'Alice', 'roles': ['admin']},
                {'id': 2, 'name': 'Bob', 'roles': ['user']}
            ],
            'config': {
                'debug': False,
                'log_level': 'INFO'
            }
        }
        
        # Encrypt
        encrypted_data = self.encryption_handler.encrypt_data(original_data)
        
        # Decrypt
        decrypted_data = self.encryption_handler.decrypt_data(encrypted_data)
        
        assert decrypted_data == original_data, "Decrypted complex data should match original"

    def test_file_encryption(self):
        """Test file encryption and decryption"""
        # Create a temporary file with test content
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as temp_file:
            test_content = "Sensitive file contents that need protection"
            temp_file.write(test_content)
            temp_file.close()
        
        try:
            # Encrypt the file
            encrypted_file_path = self.encryption_handler.secure_file(temp_file.name)
            
            # Verify encryption created a new file
            assert os.path.exists(encrypted_file_path), "Encrypted file should be created"
            assert encrypted_file_path.endswith('.encrypted'), "Encrypted file should have .encrypted extension"
            
            # Decrypt the file
            decrypted_file_path = self.encryption_handler.unsecure_file(encrypted_file_path)
            
            # Read decrypted file contents
            with open(decrypted_file_path, 'r') as decrypted_file:
                decrypted_content = decrypted_file.read()
            
            assert decrypted_content == test_content, "Decrypted file content should match original"
        
        finally:
            # Cleanup temporary files
            for file_path in [temp_file.name, encrypted_file_path, decrypted_file_path]:
                if os.path.exists(file_path):
                    os.unlink(file_path)

    def test_encryption_error_handling(self):
        """Test error handling for invalid encryption/decryption scenarios"""
        # Test decrypting invalid data
        with pytest.raises(ValueError, match="Decryption failed"):
            self.encryption_handler.decrypt_data("invalid_encrypted_data")

    def test_large_data_encryption(self):
        """Test encryption of large data structures"""
        large_data = {
            'large_list': list(range(10000)),
            'nested_data': {
                'more_data': ['x' * 1000 for _ in range(100)]
            }
        }
        
        # Encrypt
        encrypted_data = self.encryption_handler.encrypt_data(large_data)
        
        # Decrypt
        decrypted_data = self.encryption_handler.decrypt_data(encrypted_data)
        
        assert decrypted_data == large_data, "Large data structure should be encrypted and decrypted correctly"

    def test_different_secret_keys(self):
        """Test encryption with different secret keys"""
        # Create two different encryption handlers
        handler1 = SecureDataHandler(secret_key=b'secret_key_1')
        handler2 = SecureDataHandler(secret_key=b'secret_key_2')
        
        original_data = {'sensitive': 'information'}
        
        # Encrypt with first handler
        encrypted_data = handler1.encrypt_data(original_data)
        
        # Try to decrypt with second handler (should fail)
        with pytest.raises(ValueError, match="Decryption failed"):
            handler2.decrypt_data(encrypted_data)

    def test_none_input(self):
        """Test encryption and decryption with None input"""
        with pytest.raises(TypeError):
            self.encryption_handler.encrypt_data(None)
        
        with pytest.raises(ValueError):
            self.encryption_handler.decrypt_data(None)
