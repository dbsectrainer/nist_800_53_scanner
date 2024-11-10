import pytest
import os
import time
from modules.authentication import AuthenticationManager

class TestAuthenticationManager:
    def setup_method(self):
        """Create a fresh authentication manager for each test"""
        self.auth_manager = AuthenticationManager()
        # Use a test-specific credentials file
        self.auth_manager.credentials_file = 'test_credentials.json'

    def teardown_method(self):
        """Clean up test credentials file after each test"""
        if os.path.exists(self.auth_manager.credentials_file):
            os.remove(self.auth_manager.credentials_file)

    def test_create_user(self):
        """Test user creation"""
        result = self.auth_manager.create_user('testuser', 'StrongP@ss123!')
        assert result is True, "User creation should succeed"

    def test_duplicate_user_creation(self):
        """Test preventing duplicate user creation"""
        self.auth_manager.create_user('testuser', 'StrongP@ss123!')
        result = self.auth_manager.create_user('testuser', 'AnotherP@ss456!')
        assert result is False, "Duplicate user creation should fail"

    def test_authentication(self):
        """Test user authentication"""
        username = 'testuser'
        password = 'StrongP@ss123!'
        self.auth_manager.create_user(username, password)
        
        api_key = self.auth_manager.authenticate(username, password)
        assert api_key is not None, "Authentication should return an API key"

    def test_invalid_authentication(self):
        """Test authentication with incorrect credentials"""
        username = 'testuser'
        password = 'StrongP@ss123!'
        self.auth_manager.create_user(username, password)
        
        api_key = self.auth_manager.authenticate(username, 'WrongPassword')
        assert api_key is None, "Authentication should fail with incorrect password"

    def test_api_key_validation(self):
        """Test API key validation"""
        username = 'testuser'
        password = 'StrongP@ss123!'
        self.auth_manager.create_user(username, password)
        
        api_key = self.auth_manager.authenticate(username, password)
        user_details = self.auth_manager.validate_api_key(api_key)
        
        assert user_details is not None, "API key validation should succeed"
        assert user_details['username'] == username, "Validated user should match original user"

    def test_credential_rotation(self):
        """Test API key rotation"""
        username = 'testuser'
        password = 'StrongP@ss123!'
        self.auth_manager.create_user(username, password)
        
        original_api_key = self.auth_manager.authenticate(username, password)
        new_api_key = self.auth_manager.rotate_credentials(username)
        
        assert new_api_key is not None, "API key rotation should succeed"
        assert new_api_key != original_api_key, "New API key should be different from original"

    def test_role_based_access(self):
        """Test role-based access control"""
        admin_user = 'admin'
        standard_user = 'user'
        
        self.auth_manager.create_user(admin_user, 'AdminP@ss123!', role='admin')
        self.auth_manager.create_user(standard_user, 'UserP@ss456!', role='user')
        
        admin_api_key = self.auth_manager.authenticate(admin_user, 'AdminP@ss123!')
        user_api_key = self.auth_manager.authenticate(standard_user, 'UserP@ss456!')
        
        assert self.auth_manager.check_role_access(admin_api_key, ['admin', 'user']), "Admin should have admin and user access"
        assert self.auth_manager.check_role_access(user_api_key, ['user']), "User should only have user access"
        assert not self.auth_manager.check_role_access(user_api_key, ['admin']), "User should not have admin access"
