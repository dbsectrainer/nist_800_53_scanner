import os
import json
import tempfile
import pytest
from modules.encryption import SecureDataHandler, SecureKeyStorage


def make_handler(directory, name='default', **kwargs):
    return SecureDataHandler(
        SecureKeyStorage(str(directory / f'{name}.master.key')),
        keys_file=str(directory / f'{name}.keys.json'),
        **kwargs
    )

class TestSecureDataHandler:
    @pytest.fixture(autouse=True)
    def _handler(self, tmp_path):
        """Create a fresh, isolated encryption handler for each test"""
        self.tmp_path = tmp_path
        self.encryption_handler = make_handler(tmp_path)

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
        source = self.tmp_path / 'secret.txt'
        test_content = "Sensitive file contents that need protection"
        source.write_text(test_content)

        paths = self.encryption_handler.secure_file(str(source))

        assert paths['encrypted_file'].endswith('.encrypted')
        assert os.path.exists(paths['hmac_file'])
        assert test_content.encode() not in open(paths['encrypted_file'], 'rb').read()

        decrypted_path = self.tmp_path / 'decrypted.txt'
        result = self.encryption_handler.unsecure_file(paths['encrypted_file'], str(decrypted_path))

        assert open(result).read() == test_content, "Decrypted file content should match original"

    def test_tampered_file_is_rejected(self):
        source = self.tmp_path / 'secret.txt'
        source.write_text("original")
        paths = self.encryption_handler.secure_file(str(source))

        with open(paths['encrypted_file'], 'ab') as f:
            f.write(b'tamper')

        with pytest.raises(ValueError, match="integrity"):
            self.encryption_handler.unsecure_file(paths['encrypted_file'])

    def test_tampered_data_is_rejected(self):
        package = self.encryption_handler.encrypt_data({'a': 1})
        package['hmac'] = '0' * 64
        with pytest.raises(ValueError, match="Decryption failed"):
            self.encryption_handler.decrypt_data(package)

    def test_keys_survive_restart(self):
        """Data encrypted before a restart must still decrypt afterwards"""
        package = self.encryption_handler.encrypt_data({'persisted': True})

        restarted = make_handler(self.tmp_path)

        assert restarted.decrypt_data(package) == {'persisted': True}

    def test_decrypts_data_from_before_key_rotation(self):
        package = self.encryption_handler.encrypt_data("written before rotation")

        # Age the current key past the rotation interval
        self.encryption_handler.keys['created_at'] -= 31 * 86400
        self.encryption_handler.encrypt_data("triggers rotation")

        assert self.encryption_handler.keys['previous'] is not None
        assert self.encryption_handler.decrypt_data(package) == "written before rotation"

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
        """Data must not be readable by a handler holding different keys"""
        handler1 = make_handler(self.tmp_path, 'one')
        handler2 = make_handler(self.tmp_path, 'two')

        encrypted_data = handler1.encrypt_data({'sensitive': 'information'})

        with pytest.raises(ValueError, match="Decryption failed"):
            handler2.decrypt_data(encrypted_data)

    def test_none_input(self):
        """Test encryption and decryption with None input"""
        with pytest.raises(TypeError):
            self.encryption_handler.encrypt_data(None)
        
        with pytest.raises(ValueError):
            self.encryption_handler.decrypt_data(None)
