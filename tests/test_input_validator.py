import pytest
from modules.input_validator import InputValidator

class TestInputValidator:
    def test_email_validation(self):
        """Test email validation"""
        valid_emails = [
            'user@example.com',
            'first.last@domain.co.uk',
            'user+tag@example.org'
        ]
        invalid_emails = [
            'invalid-email',
            'user@.com',
            '@domain.com',
            'user@domain'
        ]

        for email in valid_emails:
            assert InputValidator.validate_email(email), f"{email} should be valid"

        for email in invalid_emails:
            assert not InputValidator.validate_email(email), f"{email} should be invalid"

    def test_password_validation(self):
        """Test password strength validation"""
        valid_passwords = [
            'StrongP@ss123!',
            'Secure_Password_2023!',
            'C0mpl3x_P@ssw0rd'
        ]
        invalid_passwords = [
            'short',
            'onlylowercase',
            'ONLYUPPERCASE',
            '12345678',
            'NoSpecialChar'
        ]

        for password in valid_passwords:
            assert InputValidator.validate_password(password), f"{password} should be valid"

        for password in invalid_passwords:
            assert not InputValidator.validate_password(password), f"{password} should be invalid"

    def test_input_sanitization(self):
        """Test input sanitization"""
        test_cases = [
            # String sanitization
            ('<script>alert("XSS")</script>', 'scriptalertXSS/script'),
            ('Hello & World', 'Hello  World'),
            
            # Dictionary sanitization
            (
                {'username': '<evil>admin</evil>', 'password': 'test&pass'},
                {'username': 'eviladmin', 'password': 'testpass'}
            ),
            
            # List sanitization
            (
                ['<script>test</script>', 'safe&input', 123],
                ['scriptest/script', 'safeinput', 123]
            )
        ]

        for input_data, expected_output in test_cases:
            sanitized = InputValidator.sanitize_input(input_data)
            assert sanitized == expected_output, f"Sanitization failed for {input_data}"

    def test_scan_parameter_validation(self):
        """Test scan parameter validation"""
        valid_params = [
            # Complete valid parameters
            {
                'target': '192.168.1.1', 
                'scan_type': 'network', 
                'depth': 3, 
                'timeout': 300
            },
            # Minimal required parameters
            {
                'target': 'example.com', 
                'scan_type': 'web'
            }
        ]

        invalid_params = [
            # Missing required parameters
            {},
            {'target': 123},  # Invalid type for target
            {'scan_type': 'network'},  # Missing target
            
            # Invalid parameter types
            {
                'target': 123,  # Target should be string
                'scan_type': 'network',
                'depth': 'deep'  # Depth should be integer
            }
        ]

        for params in valid_params:
            assert InputValidator.validate_scan_parameters(params), f"{params} should be valid"

        for params in invalid_params:
            assert not InputValidator.validate_scan_parameters(params), f"{params} should be invalid"

    def test_max_length_sanitization(self):
        """Test input sanitization with max length"""
        long_input = 'a' * 2000
        sanitized = InputValidator.sanitize_input(long_input, max_length=1000)
        
        assert len(sanitized) == 1000, "Sanitization should truncate to max length"
        assert sanitized == 'a' * 1000, "Sanitization should preserve start of input"

    def test_nested_input_sanitization(self):
        """Test sanitization of nested complex structures"""
        nested_input = {
            'user': {
                'name': '<script>evil</script>',
                'details': ['test&input', '<dangerous>data</dangerous>']
            },
            'sensitive_data': 'secret&key'
        }

        sanitized = InputValidator.sanitize_input(nested_input)
        
        assert sanitized['user']['name'] == 'scriptevil/script'
        assert sanitized['user']['details'] == ['testinput', 'scriptdangerous/script']
        assert sanitized['sensitive_data'] == 'secretkey'
