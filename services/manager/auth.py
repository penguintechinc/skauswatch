"""
Authentication and authorization system for SkausWatch Manager Service

This module provides:
- User authentication with session management
- Multi-factor authentication (MFA) support
- Role-based access control (RBAC)
- Password policies and security
- Session management and security
"""

import datetime
import hashlib
import secrets
import logging
import json
from typing import Dict, Any, Optional, List, Tuple
import bcrypt
import pyotp
import qrcode
from io import BytesIO
import base64

from py4web import Session, request, redirect, URL, Field
from py4web.utils.auth import Auth
from pydal import DAL
from pydal.objects import Row

from .config import AuthConfig

logger = logging.getLogger(__name__)


class PasswordPolicy:
    """Password policy enforcement"""
    
    def __init__(self, config: AuthConfig):
        self.config = config
    
    def validate(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password against policy
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check minimum length
        if len(password) < self.config.password_min_length:
            errors.append(f"Password must be at least {self.config.password_min_length} characters long")
        
        # Check complexity if enabled
        if self.config.password_complexity:
            if not any(c.isupper() for c in password):
                errors.append("Password must contain at least one uppercase letter")
            
            if not any(c.islower() for c in password):
                errors.append("Password must contain at least one lowercase letter")
            
            if not any(c.isdigit() for c in password):
                errors.append("Password must contain at least one digit")
            
            if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors
    
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure password
        
        Args:
            length: Password length
            
        Returns:
            Generated secure password
        """
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password


class MFAManager:
    """Multi-factor authentication manager"""
    
    def __init__(self, config: AuthConfig):
        self.config = config
    
    def generate_secret(self) -> str:
        """Generate MFA secret
        
        Returns:
            Base32 encoded secret
        """
        return pyotp.random_base32()
    
    def generate_qr_code(self, user_email: str, secret: str) -> str:
        """Generate QR code for MFA setup
        
        Args:
            user_email: User's email address
            secret: MFA secret
            
        Returns:
            Base64 encoded QR code image
        """
        try:
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user_email,
                issuer_name=self.config.mfa_issuer
            )
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            buffer.seek(0)
            
            return base64.b64encode(buffer.getvalue()).decode()
            
        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}")
            raise
    
    def verify_token(self, secret: str, token: str) -> bool:
        """Verify MFA token
        
        Args:
            secret: User's MFA secret
            token: Token to verify
            
        Returns:
            True if token is valid
        """
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)  # Allow 30 seconds drift
        except Exception as e:
            logger.error(f"Failed to verify MFA token: {e}")
            return False
    
    def generate_backup_codes(self, count: Optional[int] = None) -> List[str]:
        """Generate backup codes for MFA
        
        Args:
            count: Number of codes to generate
            
        Returns:
            List of backup codes
        """
        if count is None:
            count = self.config.backup_codes_count
        
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()  # 8 character hex codes
            codes.append(f"{code[:4]}-{code[4:]}")
        
        return codes
    
    def hash_backup_codes(self, codes: List[str]) -> List[str]:
        """Hash backup codes for storage
        
        Args:
            codes: List of backup codes
            
        Returns:
            List of hashed backup codes
        """
        hashed_codes = []
        for code in codes:
            # Remove dashes and convert to uppercase
            clean_code = code.replace("-", "").upper()
            hashed = hashlib.sha256(clean_code.encode()).hexdigest()
            hashed_codes.append(hashed)
        
        return hashed_codes
    
    def verify_backup_code(self, stored_codes: List[str], provided_code: str) -> bool:
        """Verify backup code
        
        Args:
            stored_codes: List of hashed stored backup codes
            provided_code: Code provided by user
            
        Returns:
            True if code is valid
        """
        try:
            clean_code = provided_code.replace("-", "").upper()
            code_hash = hashlib.sha256(clean_code.encode()).hexdigest()
            return code_hash in stored_codes
        except Exception as e:
            logger.error(f"Failed to verify backup code: {e}")
            return False


class SessionManager:
    """Session management with security features"""
    
    def __init__(self, db: DAL, session: Session, config: AuthConfig):
        self.db = db
        self.session = session
        self.config = config
    
    def create_session(self, user: Row, remember_me: bool = False) -> str:
        """Create new user session
        
        Args:
            user: User record
            remember_me: Whether to create persistent session
            
        Returns:
            Session ID
        """
        try:
            # Generate secure session ID
            session_id = secrets.token_urlsafe(32)
            
            # Calculate expiration
            if remember_me:
                expires_at = datetime.datetime.utcnow() + datetime.timedelta(
                    seconds=self.config.remember_me_timeout
                )
            else:
                expires_at = datetime.datetime.utcnow() + datetime.timedelta(
                    seconds=user.session_timeout or self.config.session_timeout
                )
            
            # Store session in database
            self.db.auth_session.insert(
                session_id=session_id,
                user_id=user.id,
                ip_address=request.environ.get('REMOTE_ADDR'),
                user_agent=request.environ.get('HTTP_USER_AGENT', '')[:1000],
                expires_at=expires_at,
                is_active=True
            )
            
            # Store in py4web session
            self.session['user_id'] = user.id
            self.session['session_id'] = session_id
            self.session['expires_at'] = expires_at.isoformat()
            
            # Update user last login
            self.db(self.db.auth_user.id == user.id).update(
                last_login=datetime.datetime.utcnow(),
                failed_login_attempts=0,
                account_locked_until=None
            )
            
            self.db.commit()
            
            logger.info(f"Session created for user {user.username}", 
                       extra={"user_id": user.id, "session_id": session_id})
            
            return session_id
            
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise
    
    def validate_session(self, session_id: str) -> Optional[Row]:
        """Validate session and return user
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            User record if session is valid, None otherwise
        """
        try:
            # Get session from database
            session_record = self.db(
                (self.db.auth_session.session_id == session_id) &
                (self.db.auth_session.is_active == True) &
                (self.db.auth_session.expires_at > datetime.datetime.utcnow())
            ).select(
                self.db.auth_session.ALL,
                self.db.auth_user.ALL,
                left=self.db.auth_user.on(self.db.auth_user.id == self.db.auth_session.user_id)
            ).first()
            
            if not session_record or not session_record.auth_user.is_active:
                return None
            
            # Update last accessed time
            self.db(self.db.auth_session.session_id == session_id).update(
                last_accessed=datetime.datetime.utcnow()
            )
            self.db.commit()
            
            return session_record.auth_user
            
        except Exception as e:
            logger.error(f"Failed to validate session: {e}")
            return None
    
    def destroy_session(self, session_id: str) -> None:
        """Destroy user session
        
        Args:
            session_id: Session ID to destroy
        """
        try:
            # Mark session as inactive
            self.db(self.db.auth_session.session_id == session_id).update(
                is_active=False
            )
            self.db.commit()
            
            # Clear py4web session
            self.session.clear()
            
            logger.info(f"Session destroyed", extra={"session_id": session_id})
            
        except Exception as e:
            logger.error(f"Failed to destroy session: {e}")
    
    def cleanup_expired_sessions(self) -> None:
        """Clean up expired sessions"""
        try:
            count = self.db(
                self.db.auth_session.expires_at < datetime.datetime.utcnow()
            ).delete()
            
            self.db.commit()
            
            if count > 0:
                logger.info(f"Cleaned up {count} expired sessions")
                
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")


class RBACManager:
    """Role-based access control manager"""
    
    def __init__(self, db: DAL):
        self.db = db
    
    def user_has_permission(self, user_id: int, resource: str, action: str) -> bool:
        """Check if user has permission for resource and action
        
        Args:
            user_id: User ID
            resource: Resource name
            action: Action name
            
        Returns:
            True if user has permission
        """
        try:
            # Check if user is superuser
            user = self.db(self.db.auth_user.id == user_id).select().first()
            if user and user.is_superuser:
                return True
            
            # Check through roles and permissions
            permission_query = self.db(
                (self.db.auth_user_role.user_id == user_id) &
                (self.db.auth_user_role.role_id == self.db.auth_role.id) &
                (self.db.auth_role_permission.role_id == self.db.auth_role.id) &
                (self.db.auth_role_permission.permission_id == self.db.auth_permission.id) &
                (self.db.auth_permission.resource == resource) &
                (self.db.auth_permission.action == action) &
                (
                    (self.db.auth_user_role.expires_at == None) |
                    (self.db.auth_user_role.expires_at > datetime.datetime.utcnow())
                )
            ).select()
            
            return len(permission_query) > 0
            
        except Exception as e:
            logger.error(f"Failed to check permission: {e}")
            return False
    
    def get_user_roles(self, user_id: int) -> List[Row]:
        """Get user roles
        
        Args:
            user_id: User ID
            
        Returns:
            List of role records
        """
        try:
            roles = self.db(
                (self.db.auth_user_role.user_id == user_id) &
                (self.db.auth_user_role.role_id == self.db.auth_role.id) &
                (
                    (self.db.auth_user_role.expires_at == None) |
                    (self.db.auth_user_role.expires_at > datetime.datetime.utcnow())
                )
            ).select(self.db.auth_role.ALL)
            
            return [role for role in roles]
            
        except Exception as e:
            logger.error(f"Failed to get user roles: {e}")
            return []
    
    def get_user_permissions(self, user_id: int) -> List[Row]:
        """Get user permissions
        
        Args:
            user_id: User ID
            
        Returns:
            List of permission records
        """
        try:
            permissions = self.db(
                (self.db.auth_user_role.user_id == user_id) &
                (self.db.auth_user_role.role_id == self.db.auth_role.id) &
                (self.db.auth_role_permission.role_id == self.db.auth_role.id) &
                (self.db.auth_role_permission.permission_id == self.db.auth_permission.id) &
                (
                    (self.db.auth_user_role.expires_at == None) |
                    (self.db.auth_user_role.expires_at > datetime.datetime.utcnow())
                )
            ).select(self.db.auth_permission.ALL)
            
            return [perm for perm in permissions]
            
        except Exception as e:
            logger.error(f"Failed to get user permissions: {e}")
            return []


class SkausWatchAuth(Auth):
    """Enhanced authentication system for SkausWatch"""
    
    def __init__(self, db: DAL, config: AuthConfig, session: Session):
        """Initialize authentication system
        
        Args:
            db: Database connection
            config: Authentication configuration
            session: Session manager
        """
        super().__init__(session, db)
        
        self.config = config
        self.password_policy = PasswordPolicy(config)
        self.mfa_manager = MFAManager(config)
        self.session_manager = SessionManager(db, session, config)
        self.rbac_manager = RBACManager(db)
        
        # Override default auth tables
        self.param.table_user_name = "auth_user"
        self.param.login_url = URL("auth/login")
        self.param.logout_url = URL("auth/logout")
        self.param.profile_url = URL("auth/profile")
        self.param.register_url = URL("auth/register")
        
    def login(self, username: str, password: str, remember_me: bool = False,
              mfa_token: Optional[str] = None) -> Tuple[bool, str, Optional[Row]]:
        """Enhanced login with MFA support
        
        Args:
            username: Username or email
            password: Password
            remember_me: Remember me option
            mfa_token: MFA token (if MFA is enabled)
            
        Returns:
            Tuple of (success, message, user_record)
        """
        try:
            # Find user by username or email
            user = self.db(
                (self.db.auth_user.username == username) |
                (self.db.auth_user.email == username)
            ).select().first()
            
            if not user:
                self._log_security_event("authentication_failure", 
                                        f"Login attempt with unknown username: {username}")
                return False, "Invalid credentials", None
            
            # Check if account is locked
            if (user.account_locked_until and 
                user.account_locked_until > datetime.datetime.utcnow()):
                self._log_security_event("authentication_failure",
                                       f"Login attempt on locked account: {username}",
                                       user_id=user.id)
                return False, "Account is temporarily locked", None
            
            # Check if account is active
            if not user.is_active:
                self._log_security_event("authentication_failure",
                                       f"Login attempt on inactive account: {username}",
                                       user_id=user.id)
                return False, "Account is disabled", None
            
            # Verify password
            if not self.verify_password(password, str(user.password)):
                # Increment failed attempts
                failed_attempts = (user.failed_login_attempts or 0) + 1
                update_data = {"failed_login_attempts": failed_attempts}
                
                # Lock account if too many failures
                if failed_attempts >= self.config.max_login_attempts:
                    update_data["account_locked_until"] = (
                        datetime.datetime.utcnow() + 
                        datetime.timedelta(seconds=self.config.lockout_duration)
                    )
                
                self.db(self.db.auth_user.id == user.id).update(**update_data)
                self.db.commit()
                
                self._log_security_event("authentication_failure",
                                       f"Invalid password for user: {username}",
                                       user_id=user.id)
                
                return False, "Invalid credentials", None
            
            # Check MFA if enabled
            if user.mfa_enabled:
                if not mfa_token:
                    return False, "MFA token required", user
                
                # Try TOTP token first
                if user.mfa_secret and self.mfa_manager.verify_token(user.mfa_secret, mfa_token):
                    pass  # TOTP verified
                elif user.backup_codes:
                    # Try backup codes
                    backup_codes = json.loads(user.backup_codes) if isinstance(user.backup_codes, str) else user.backup_codes
                    if self.mfa_manager.verify_backup_code(backup_codes, mfa_token):
                        # Remove used backup code
                        clean_code = mfa_token.replace("-", "").upper()
                        code_hash = hashlib.sha256(clean_code.encode()).hexdigest()
                        backup_codes.remove(code_hash)
                        self.db(self.db.auth_user.id == user.id).update(
                            backup_codes=json.dumps(backup_codes)
                        )
                        self.db.commit()
                    else:
                        self._log_security_event("authentication_failure",
                                               f"Invalid MFA token for user: {username}",
                                               user_id=user.id)
                        return False, "Invalid MFA token", None
                else:
                    self._log_security_event("authentication_failure",
                                           f"Invalid MFA token for user: {username}",
                                           user_id=user.id)
                    return False, "Invalid MFA token", None
            
            # Create session
            session_id = self.session_manager.create_session(user, remember_me)
            
            # Log successful login
            self._log_audit_event("authentication", "user_login", "auth_user", 
                                str(user.id), user.id, success=True)
            
            return True, "Login successful", user
            
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return False, "Login failed due to system error", None
    
    def logout(self, session_id: Optional[str] = None) -> None:
        """Enhanced logout
        
        Args:
            session_id: Session ID to logout (optional)
        """
        try:
            if not session_id and hasattr(self.session, 'session_id'):
                session_id = self.session.get('session_id')
            
            if session_id:
                user_id = self.session.get('user_id')
                self.session_manager.destroy_session(session_id)
                
                # Log logout
                self._log_audit_event("authentication", "user_logout", "auth_user",
                                    str(user_id), user_id, success=True)
                
        except Exception as e:
            logger.error(f"Logout failed: {e}")
    
    def register_user(self, username: str, email: str, password: str, 
                     first_name: str, last_name: str, **kwargs) -> Tuple[bool, str, Optional[int]]:
        """Register new user with validation
        
        Args:
            username: Username
            email: Email address
            password: Password
            first_name: First name
            last_name: Last name
            **kwargs: Additional user fields
            
        Returns:
            Tuple of (success, message, user_id)
        """
        try:
            # Validate password
            password_valid, password_errors = self.password_policy.validate(password)
            if not password_valid:
                return False, "; ".join(password_errors), None
            
            # Check if username or email already exists
            existing = self.db(
                (self.db.auth_user.username == username) |
                (self.db.auth_user.email == email)
            ).select().first()
            
            if existing:
                return False, "Username or email already exists", None
            
            # Hash password
            password_hash = str(Field("password", "password", requires=[])(password)[0])
            
            # Create user
            user_id = self.db.auth_user.insert(
                username=username,
                email=email,
                password=password_hash,
                first_name=first_name,
                last_name=last_name,
                **kwargs
            )
            
            # Assign default role
            default_role = self.db(self.db.auth_role.name == "user").select().first()
            if default_role:
                self.db.auth_user_role.insert(
                    user_id=user_id,
                    role_id=default_role.id,
                    granted_by=user_id  # Self-granted for registration
                )
            
            self.db.commit()
            
            # Log user registration
            self._log_audit_event("user_management", "user_registration", "auth_user",
                                str(user_id), user_id, success=True)
            
            return True, "User registered successfully", user_id
            
        except Exception as e:
            logger.error(f"User registration failed: {e}")
            return False, "Registration failed due to system error", None
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user password
        
        Args:
            user_id: User ID
            old_password: Current password
            new_password: New password
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Get user
            user = self.db(self.db.auth_user.id == user_id).select().first()
            if not user:
                return False, "User not found"
            
            # Verify old password
            if not self.verify_password(old_password, str(user.password)):
                self._log_security_event("authentication_failure",
                                       f"Invalid old password for password change",
                                       user_id=user_id)
                return False, "Current password is incorrect"
            
            # Validate new password
            password_valid, password_errors = self.password_policy.validate(new_password)
            if not password_valid:
                return False, "; ".join(password_errors)
            
            # Hash new password
            password_hash = str(Field("password", "password", requires=[])(new_password)[0])
            
            # Update password
            self.db(self.db.auth_user.id == user_id).update(
                password=password_hash,
                password_changed_at=datetime.datetime.utcnow()
            )
            self.db.commit()
            
            # Log password change
            self._log_audit_event("user_management", "password_change", "auth_user",
                                str(user_id), user_id, success=True)
            
            return True, "Password changed successfully"
            
        except Exception as e:
            logger.error(f"Password change failed: {e}")
            return False, "Password change failed due to system error"
    
    def setup_mfa(self, user_id: int) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Setup MFA for user
        
        Args:
            user_id: User ID
            
        Returns:
            Tuple of (success, message, mfa_data)
        """
        try:
            # Get user
            user = self.db(self.db.auth_user.id == user_id).select().first()
            if not user:
                return False, "User not found", None
            
            # Generate secret and backup codes
            secret = self.mfa_manager.generate_secret()
            backup_codes = self.mfa_manager.generate_backup_codes()
            hashed_backup_codes = self.mfa_manager.hash_backup_codes(backup_codes)
            
            # Generate QR code
            qr_code = self.mfa_manager.generate_qr_code(user.email, secret)
            
            # Store secret and backup codes (temporarily - will be confirmed later)
            self.db(self.db.auth_user.id == user_id).update(
                mfa_secret=secret,
                backup_codes=json.dumps(hashed_backup_codes),
                mfa_enabled=False  # Will be enabled after verification
            )
            self.db.commit()
            
            mfa_data = {
                "secret": secret,
                "qr_code": qr_code,
                "backup_codes": backup_codes
            }
            
            return True, "MFA setup initiated", mfa_data
            
        except Exception as e:
            logger.error(f"MFA setup failed: {e}")
            return False, "MFA setup failed due to system error", None
    
    def verify_mfa_setup(self, user_id: int, token: str) -> Tuple[bool, str]:
        """Verify and enable MFA setup
        
        Args:
            user_id: User ID
            token: MFA token to verify
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Get user
            user = self.db(self.db.auth_user.id == user_id).select().first()
            if not user or not user.mfa_secret:
                return False, "MFA setup not found"
            
            # Verify token
            if not self.mfa_manager.verify_token(user.mfa_secret, token):
                return False, "Invalid MFA token"
            
            # Enable MFA
            self.db(self.db.auth_user.id == user_id).update(
                mfa_enabled=True
            )
            self.db.commit()
            
            # Log MFA enable
            self._log_audit_event("user_management", "mfa_enabled", "auth_user",
                                str(user_id), user_id, success=True)
            
            return True, "MFA enabled successfully"
            
        except Exception as e:
            logger.error(f"MFA verification failed: {e}")
            return False, "MFA verification failed due to system error"
    
    def disable_mfa(self, user_id: int) -> Tuple[bool, str]:
        """Disable MFA for user
        
        Args:
            user_id: User ID
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Update user
            self.db(self.db.auth_user.id == user_id).update(
                mfa_enabled=False,
                mfa_secret=None,
                backup_codes=None
            )
            self.db.commit()
            
            # Log MFA disable
            self._log_audit_event("user_management", "mfa_disabled", "auth_user",
                                str(user_id), user_id, success=True)
            
            return True, "MFA disabled successfully"
            
        except Exception as e:
            logger.error(f"MFA disable failed: {e}")
            return False, "MFA disable failed due to system error"
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash
        
        Args:
            password: Plain text password
            password_hash: Hashed password
            
        Returns:
            True if password matches
        """
        try:
            # Handle different hash formats (bcrypt, pbkdf2, etc.)
            if password_hash.startswith('pbkdf2:'):
                # py4web/web2py format
                from pydal.validators import CRYPT
                return CRYPT()(password)[0] == password_hash
            elif password_hash.startswith('$2b$') or password_hash.startswith('$2a$'):
                # bcrypt format
                return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
            else:
                # Fallback to py4web validation
                from pydal.validators import CRYPT
                return CRYPT()(password)[0] == password_hash
                
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False
    
    def _log_audit_event(self, event_type: str, action: str, resource_type: str,
                        resource_id: str, user_id: Optional[int] = None, 
                        success: bool = True, **kwargs) -> None:
        """Log audit event
        
        Args:
            event_type: Type of event
            action: Action performed
            resource_type: Type of resource
            resource_id: ID of resource
            user_id: User ID (optional)
            success: Whether action was successful
            **kwargs: Additional details
        """
        try:
            details = {k: v for k, v in kwargs.items()}
            
            self.db.audit_log.insert(
                event_type=event_type,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                user_id=user_id,
                session_id=self.session.get('session_id'),
                ip_address=request.environ.get('REMOTE_ADDR'),
                user_agent=request.environ.get('HTTP_USER_AGENT', '')[:1000],
                success=success,
                details=json.dumps(details)
            )
            self.db.commit()
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
    
    def _log_security_event(self, category: str, description: str, 
                           user_id: Optional[int] = None, severity: str = "medium",
                           **kwargs) -> None:
        """Log security event
        
        Args:
            category: Event category
            description: Event description
            user_id: User ID (optional)
            severity: Event severity
            **kwargs: Additional details
        """
        try:
            details = {k: v for k, v in kwargs.items()}
            
            self.db.security_event.insert(
                event_category=category,
                severity=severity,
                user_id=user_id,
                session_id=self.session.get('session_id'),
                ip_address=request.environ.get('REMOTE_ADDR'),
                user_agent=request.environ.get('HTTP_USER_AGENT', '')[:1000],
                description=description,
                details=json.dumps(details)
            )
            self.db.commit()
            
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    @property
    def user(self) -> Optional[Row]:
        """Get current authenticated user"""
        user_id = self.session.get('user_id')
        if user_id:
            return self.db(self.db.auth_user.id == user_id).select().first()
        return None