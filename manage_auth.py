#!/usr/bin/env python3
import argparse
import getpass
import sys
from modules.authentication import AuthenticationManager
from modules.input_validator import InputValidator

class NISTScannerAuthManager:
    def __init__(self):
        self.auth_manager = AuthenticationManager()

    def create_admin_user(self, username=None, password=None):
        """
        Create an admin user with secure password validation.
        
        Args:
            username: Optional username (will prompt if not provided)
            password: Optional password (will prompt securely if not provided)
        """
        # Prompt for username if not provided
        if not username:
            username = input("Enter admin username: ")
        
        # Prompt for password if not provided
        if not password:
            while True:
                password = getpass.getpass("Enter admin password: ")
                confirm_password = getpass.getpass("Confirm admin password: ")
                
                if password != confirm_password:
                    print("Passwords do not match. Please try again.")
                    continue
                
                # Validate password strength
                if not InputValidator.validate_password(password):
                    print("""
Password does not meet complexity requirements:
- Minimum 12 characters
- Must include:
  * At least one uppercase letter
  * At least one lowercase letter
  * At least one number
  * At least one special character
                """)
                    continue
                
                break
        
        # Attempt to create admin user
        try:
            if self.auth_manager.create_user(username, password, role='admin'):
                print(f"Admin user {username} created successfully.")
                
                # Generate and display API key
                api_key = self.auth_manager.authenticate(username, password)
                print(f"\n🔑 API Key: {api_key}")
                print("\nPlease store this API key securely. It will be required for authenticated scans.")
            else:
                print(f"Failed to create admin user. The username {username} might already exist.")
        except Exception as e:
            print(f"Error creating admin user: {e}")

    def rotate_api_key(self, username=None):
        """
        Rotate API key for a given user.
        
        Args:
            username: Optional username (will prompt if not provided)
        """
        if not username:
            username = input("Enter username to rotate API key: ")
        
        try:
            new_api_key = self.auth_manager.rotate_credentials(username)
            if new_api_key:
                print(f"API key rotated for user {username}")
                print(f"🔑 New API Key: {new_api_key}")
            else:
                print(f"Failed to rotate API key for user {username}")
        except Exception as e:
            print(f"Error rotating API key: {e}")

def main():
    parser = argparse.ArgumentParser(description='NIST 800-53 Scanner Authentication Management')
    
    # Create subparsers for different actions
    subparsers = parser.add_subparsers(dest='action', help='Authentication management actions')
    
    # Create admin user subparser
    create_admin_parser = subparsers.add_parser('create-admin', help='Create a new admin user')
    create_admin_parser.add_argument('--username', help='Admin username')
    create_admin_parser.add_argument('--password', help='Admin password (not recommended to provide via CLI)')
    
    # Rotate API key subparser
    rotate_key_parser = subparsers.add_parser('rotate-key', help='Rotate API key for a user')
    rotate_key_parser.add_argument('--username', help='Username to rotate API key')
    
    args = parser.parse_args()
    
    auth_manager = NISTScannerAuthManager()
    
    if args.action == 'create-admin':
        auth_manager.create_admin_user(args.username, args.password)
    elif args.action == 'rotate-key':
        auth_manager.rotate_api_key(args.username)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
