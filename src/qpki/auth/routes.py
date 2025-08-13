"""
Authentication Routes for qPKI

Flask Blueprint for authentication-related routes including login, logout,
user management, and password operations.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, g, current_app, jsonify, send_file
from werkzeug.security import generate_password_hash
import secrets
from datetime import datetime, timezone
import base64
from io import BytesIO

from .auth_manager import AuthenticationManager, login_required, admin_required
from .models import UserRole, UserStatus

# Create authentication blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    # Redirect if already logged in and session is valid
    if session.get('user_id'):
        auth_manager = current_app.auth_manager
        valid, user = auth_manager.validate_session()
        if valid and user:
            return redirect(url_for('index'))
        else:
            # Clear invalid session data
            session.clear()
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = 'remember_me' in request.form
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('auth/login.html')
        
        # Authenticate user
        auth_manager = current_app.auth_manager
        success, user, message = auth_manager.authenticate_user(
            username, password, request.remote_addr
        )
        
        if success and user:
            # Check if user has MFA enabled
            user_obj = auth_manager.get_user(user_id=user['id'])
            if user_obj and user_obj.two_factor_enabled:
                # Store user data temporarily for MFA verification
                session['mfa_user_id'] = user['id']
                session['mfa_username'] = user['username']
                session['mfa_remember_me'] = remember_me
                session['mfa_next_page'] = request.form.get('next') or request.args.get('next')
                
                flash('Please enter your authentication code from your authenticator app.', 'info')
                return redirect(url_for('auth.mfa_verify'))
            
            # No MFA required, proceed with normal login
            session_token = auth_manager.create_session(
                user, 
                request.remote_addr, 
                request.user_agent.string
            )
            
            if session_token:
                # Store additional session info
                session.permanent = remember_me
                
                # Check if password change is required
                if user.get('force_password_change') or user.get('is_password_expired'):
                    flash('Password change required. Please update your password.', 'warning')
                    return redirect(url_for('auth.change_password'))
                
                # Log successful login
                current_app.logger.info(f"User {user['username']} logged in from {request.remote_addr}")
                
                flash(f'Welcome back, {user["full_name"]}!', 'success')
                
                # Redirect to next page or dashboard
                next_page = request.form.get('next') or request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('index'))
            else:
                flash('Session creation failed. Please try again.', 'error')
        else:
            flash(message, 'error')
            current_app.logger.warning(f"Failed login attempt for {username} from {request.remote_addr}")
    
    return render_template('auth/login.html')


@auth_bp.route('/logout')
def logout():
    """User logout."""
    if session.get('user_id'):
        auth_manager = current_app.auth_manager
        auth_manager.logout_user()
        
        current_app.logger.info(f"User {session.get('username', 'unknown')} logged out")
        flash('You have been logged out successfully.', 'info')
    
    # Clear any cached authentication data
    response = redirect(url_for('auth.login'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required()
def change_password():
    """Change user password."""
    user = g.current_user
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate input - current password not required for forced changes
        if user.get('force_password_change'):
            # For forced password changes, only new password and confirm are required
            if not new_password or not confirm_password:
                flash('New password and confirmation are required.', 'error')
                return render_template('auth/change_password.html', user=user)
        else:
            # For regular password changes, all fields are required
            if not current_password or not new_password or not confirm_password:
                flash('All fields are required.', 'error')
                return render_template('auth/change_password.html', user=user)
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('auth/change_password.html', user=user)
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('auth/change_password.html', user=user)
        
        # Verify current password (unless forced change) by re-authenticating
        if not user.get('force_password_change'):
            auth_manager = current_app.auth_manager
            auth_success, auth_user, auth_message = auth_manager.authenticate_user(
                user['username'], current_password
            )
            if not auth_success:
                flash('Current password is incorrect.', 'error')
                return render_template('auth/change_password.html', user=user)
        
        # Update password
        auth_manager = current_app.auth_manager
        success, updated_user, message = auth_manager.update_user(
            user['id'], 
            {'password': new_password},
            user['username']
        )
        
        if success:
            flash('Password updated successfully.', 'success')
            current_app.logger.info(f"Password changed for user {user['username']}")
            return redirect(url_for('index'))
        else:
            flash(message, 'error')
    
    return render_template('auth/change_password.html', user=user)


@auth_bp.route('/profile')
@login_required()
def profile():
    """User profile page."""
    user = g.current_user
    return render_template('auth/profile.html', user=user)


@auth_bp.route('/update-profile', methods=['POST'])
@login_required()
def update_profile():
    """Update user profile information."""
    user = g.current_user
    
    # Get form data
    updates = {
        'full_name': request.form.get('full_name', '').strip(),
        'email': request.form.get('email', '').strip(),
        'department': request.form.get('department', '').strip(),
        'phone': request.form.get('phone', '').strip()
    }
    
    # Remove empty fields
    updates = {k: v for k, v in updates.items() if v}
    
    if not updates.get('full_name') or not updates.get('email'):
        flash('Full name and email are required.', 'error')
        return redirect(url_for('auth.profile'))
    
    # Update user
    auth_manager = current_app.auth_manager
    success, updated_user, message = auth_manager.update_user(
        user['id'], 
        updates,
        user['username']
    )
    
    if success:
        flash('Profile updated successfully.', 'success')
        current_app.logger.info(f"Profile updated for user {user['username']}")
    else:
        flash(message, 'error')
    
    return redirect(url_for('auth.profile'))


# Admin-only user management routes

@auth_bp.route('/users')
@login_required('admin')
def list_users():
    """List all users (admin only)."""
    auth_manager = current_app.auth_manager
    users = auth_manager.list_users(limit=100)
    
    # Get user statistics
    total_users = len(users)
    active_users = len([u for u in users if u.is_active])
    admin_users = len([u for u in users if u.role == UserRole.ADMIN.value])
    
    stats = {
        'total': total_users,
        'active': active_users,
        'admins': admin_users,
        'inactive': total_users - active_users
    }
    
    return render_template('auth/list_users.html', users=users, stats=stats)


@auth_bp.route('/users/create', methods=['GET', 'POST'])
@login_required('admin')
def create_user():
    """Create new user (admin only)."""
    if request.method == 'POST':
        # Get form data
        user_data = {
            'username': request.form.get('username', '').strip(),
            'email': request.form.get('email', '').strip(),
            'full_name': request.form.get('full_name', '').strip(),
            'department': request.form.get('department', '').strip(),
            'phone': request.form.get('phone', '').strip(),
            'role': request.form.get('role', UserRole.VIEWER.value),
            'password': request.form.get('password', ''),
            'force_password_change': 'force_password_change' in request.form
        }
        
        # Validate required fields
        if not all([user_data['username'], user_data['email'], user_data['full_name'], user_data['password']]):
            flash('Username, email, full name, and password are required.', 'error')
            return render_template('auth/create_user.html', roles=UserRole, user_data=user_data)
        
        if len(user_data['password']) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('auth/create_user.html', roles=UserRole, user_data=user_data)
        
        # Create user
        auth_manager = current_app.auth_manager
        success, user_data_result, message = auth_manager.create_user(
            user_data,
            g.current_user['username']
        )
        
        if success:
            flash(f'User "{user_data_result["username"]}" created successfully.', 'success')
            current_app.logger.info(f"User {user_data_result['username']} created by {g.current_user['username']}")
            return redirect(url_for('auth.list_users'))
        else:
            flash(message, 'error')
    
    return render_template('auth/create_user.html', roles=UserRole, user_data={})


@auth_bp.route('/users/<int:user_id>')
@login_required('admin')
def view_user(user_id):
    """View user details (admin only)."""
    auth_manager = current_app.auth_manager
    user = auth_manager.get_user(user_id=user_id)
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth.list_users'))
    
    return render_template('auth/view_user.html', user=user)


@auth_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required('admin')
def edit_user(user_id):
    """Edit user (admin only)."""
    auth_manager = current_app.auth_manager
    user = auth_manager.get_user(user_id=user_id)
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth.list_users'))
    
    if request.method == 'POST':
        # Get form data
        updates = {
            'full_name': request.form.get('full_name', '').strip(),
            'email': request.form.get('email', '').strip(),
            'department': request.form.get('department', '').strip(),
            'phone': request.form.get('phone', '').strip(),
            'role': request.form.get('role'),
            'status': request.form.get('status'),
            'is_active': 'is_active' in request.form
        }
        
        # Handle password update
        new_password = request.form.get('new_password', '').strip()
        if new_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long.', 'error')
                return render_template('auth/edit_user.html', user=user, roles=UserRole, statuses=UserStatus)
            updates['password'] = new_password
        
        # Remove empty fields except booleans
        updates = {k: v for k, v in updates.items() if v is not None and (isinstance(v, bool) or v != '')}
        
        # Update user
        success, updated_user, message = auth_manager.update_user(
            user_id,
            updates,
            g.current_user['username']
        )
        
        if success:
            flash('User updated successfully.', 'success')
            current_app.logger.info(f"User {user.username} updated by {g.current_user['username']}")
            return redirect(url_for('auth.view_user', user_id=user_id))
        else:
            flash(message, 'error')
    
    return render_template('auth/edit_user.html', user=user, roles=UserRole, statuses=UserStatus)


@auth_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required('admin')
def delete_user(user_id):
    """Delete user (admin only)."""
    # Prevent self-deletion
    if user_id == g.current_user['id']:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('auth.list_users'))
    
    auth_manager = current_app.auth_manager
    user = auth_manager.get_user(user_id=user_id)
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth.list_users'))
    
    # Confirm deletion
    if request.form.get('confirm') != 'DELETE':
        flash('Deletion not confirmed. Type "DELETE" to confirm.', 'error')
        return redirect(url_for('auth.view_user', user_id=user_id))
    
    success, message = auth_manager.delete_user(user_id)
    
    if success:
        flash(f'User "{user.username}" deleted successfully.', 'success')
        current_app.logger.info(f"User {user.username} deleted by {g.current_user['username']}")
    else:
        flash(message, 'error')
    
    return redirect(url_for('auth.list_users'))


@auth_bp.route('/users/<int:user_id>/reset-password', methods=['POST'])
@login_required('admin')
def reset_user_password(user_id):
    """Reset user password (admin only)."""
    auth_manager = current_app.auth_manager
    user = auth_manager.get_user(user_id=user_id)
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth.list_users'))
    
    # Generate temporary password
    temp_password = secrets.token_urlsafe(12)
    
    # Update user with new password and force change
    success, updated_user, message = auth_manager.update_user(
        user_id,
        {
            'password': temp_password,
            'force_password_change': True
        },
        g.current_user['username']
    )
    
    if success:
        flash(f'Password reset for user "{user.username}". Temporary password: {temp_password}', 'success')
        current_app.logger.info(f"Password reset for user {user.username} by {g.current_user['username']}")
    else:
        flash(message, 'error')
    
    return redirect(url_for('auth.view_user', user_id=user_id))


@auth_bp.route('/sessions')
@login_required('admin')
def list_sessions():
    """List active sessions (admin only)."""
    from .models import UserSession, User
    from sqlalchemy.orm import sessionmaker
    
    Session = sessionmaker(bind=current_app.db_manager.engine)
    db_session = Session()
    
    try:
        # Get active sessions with user info
        sessions = db_session.query(UserSession).filter_by(is_active=True).all()
        
        # Enrich with user information
        session_data = []
        for sess in sessions:
            user = db_session.query(User).filter_by(id=sess.user_id).first()
            session_info = sess.to_dict()
            session_info['user'] = {
                'username': user.username if user else 'Unknown',
                'full_name': user.full_name if user else 'Unknown'
            }
            session_data.append(session_info)
        
        return render_template('auth/list_sessions.html', sessions=session_data)
        
    finally:
        db_session.close()


@auth_bp.route('/sessions/<int:session_id>/invalidate', methods=['POST'])
@login_required('admin')
def invalidate_session(session_id):
    """Invalidate a user session (admin only)."""
    from .models import UserSession
    from sqlalchemy.orm import sessionmaker
    
    Session = sessionmaker(bind=current_app.db_manager.engine)
    db_session = Session()
    
    try:
        user_session = db_session.query(UserSession).filter_by(id=session_id).first()
        
        if not user_session:
            flash('Session not found.', 'error')
        else:
            # Prevent invalidating own session
            current_session_token = session.get('session_token')
            if user_session.session_token == current_session_token:
                flash('You cannot invalidate your own session.', 'error')
            else:
                user_session.invalidate('admin_forced')
                db_session.commit()
                flash('Session invalidated successfully.', 'success')
                current_app.logger.info(f"Session {session_id} invalidated by {g.current_user['username']}")
        
        return redirect(url_for('auth.list_sessions'))
        
    except Exception as e:
        flash(f'Error invalidating session: {str(e)}', 'error')
        return redirect(url_for('auth.list_sessions'))
    finally:
        db_session.close()


# API endpoints for session validation
@auth_bp.route('/api/validate-session')
@login_required()
def api_validate_session():
    """API endpoint to validate current session."""
    user = g.current_user
    return jsonify({
        'valid': True,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'full_name': user['full_name'],
            'role': user['role']
        },
        'session': {
            'expires_at': session.get('_permanent', False)
        }
    })


# Context processor to make user available in templates
@auth_bp.app_context_processor
def inject_user():
    """Make current user and auth functions available in all templates."""
    from .auth_manager import has_permission
    
    if 'user_id' in session:
        auth_manager = current_app.auth_manager
        valid, user = auth_manager.validate_session()
        if valid and user:
            return dict(current_user=user, has_permission=has_permission)
    return dict(current_user=None, has_permission=has_permission)


# MFA (Multi-Factor Authentication) Routes

@auth_bp.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    """MFA verification during login."""
    # Check if user is in MFA verification state
    mfa_user_id = session.get('mfa_user_id')
    if not mfa_user_id:
        flash('No active MFA verification session.', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        verification_code = request.form.get('verification_code', '').strip()
        
        if not verification_code:
            flash('Please enter the verification code.', 'error')
            return render_template('auth/mfa_verify.html')
        
        # Verify MFA code
        auth_manager = current_app.auth_manager
        success, message = auth_manager.verify_mfa_code(mfa_user_id, verification_code)
        
        if success:
            # MFA verification successful, create session
            user_obj = auth_manager.get_user(user_id=mfa_user_id)
            if not user_obj:
                # Clear MFA session data
                for key in ['mfa_user_id', 'mfa_username', 'mfa_remember_me', 'mfa_next_page']:
                    session.pop(key, None)
                flash('User not found.', 'error')
                return redirect(url_for('auth.login'))
            
            # Convert user object to dictionary
            user_data = {
                'id': user_obj.id,
                'username': user_obj.username,
                'role': user_obj.role,
                'full_name': user_obj.full_name,
                'email': user_obj.email,
                'force_password_change': user_obj.force_password_change,
                'is_password_expired': user_obj.is_password_expired()
            }
            
            # Create session
            session_token = auth_manager.create_session(
                user_data,
                request.remote_addr,
                request.user_agent.string
            )
            
            if session_token:
                # Set remember me preference
                session.permanent = session.get('mfa_remember_me', False)
                
                # Clear MFA session data
                next_page = session.pop('mfa_next_page', None)
                for key in ['mfa_user_id', 'mfa_username', 'mfa_remember_me']:
                    session.pop(key, None)
                
                # Check if password change is required
                if user_data.get('force_password_change') or user_data.get('is_password_expired'):
                    flash('Password change required. Please update your password.', 'warning')
                    return redirect(url_for('auth.change_password'))
                
                # Log successful login
                current_app.logger.info(f"User {user_data['username']} logged in with MFA from {request.remote_addr}")
                
                flash(f'Welcome back, {user_data["full_name"]}!', 'success')
                
                # Redirect to next page or dashboard
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('index'))
            else:
                flash('Session creation failed. Please try again.', 'error')
                return redirect(url_for('auth.login'))
        else:
            flash(message, 'error')
            current_app.logger.warning(f"Failed MFA attempt for user ID {mfa_user_id} from {request.remote_addr}")
    
    return render_template('auth/mfa_verify.html', 
                         username=session.get('mfa_username', 'Unknown'))


@auth_bp.route('/mfa/setup', methods=['GET', 'POST'])
@login_required()
def setup_mfa():
    """Setup MFA for current user."""
    user = g.current_user
    auth_manager = current_app.auth_manager
    
    # Check if MFA is already enabled
    user_obj = auth_manager.get_user(user_id=user['id'])
    if user_obj and user_obj.two_factor_enabled:
        flash('MFA is already enabled for your account.', 'info')
        return redirect(url_for('auth.profile'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'start_setup':
            # Start MFA setup process
            success, secret_key, provisioning_uri, session_token = auth_manager.setup_mfa_for_user(user['id'])
            
            if success:
                # Store setup session token temporarily
                session['mfa_setup_token'] = session_token
                
                return render_template('auth/mfa_setup.html', 
                                     user=user,
                                     secret_key=secret_key,
                                     provisioning_uri=provisioning_uri,
                                     show_qr=True)
            else:
                flash(session_token, 'error')  # session_token contains error message
        
        elif action == 'verify_setup':
            # Verify MFA setup
            verification_code = request.form.get('verification_code', '').strip()
            setup_token = session.get('mfa_setup_token')
            
            if not verification_code:
                flash('Please enter the verification code.', 'error')
                return redirect(url_for('auth.setup_mfa'))
            
            if not setup_token:
                flash('Setup session expired. Please start over.', 'error')
                return redirect(url_for('auth.setup_mfa'))
            
            success, message = auth_manager.verify_mfa_setup(setup_token, verification_code)
            
            if success:
                # Clear setup session
                session.pop('mfa_setup_token', None)
                
                # Generate backup codes for display
                success_codes, backup_codes, codes_message = auth_manager.regenerate_backup_codes(user['id'])
                
                flash('MFA has been successfully enabled for your account!', 'success')
                current_app.logger.info(f"MFA enabled for user {user['username']}")
                
                from datetime import datetime
                current_date = datetime.now().strftime('%B %d, %Y at %I:%M:%S %p')
                
                return render_template('auth/mfa_backup_codes.html', 
                                     user=user,
                                     backup_codes=backup_codes if success_codes else [],
                                     current_date=current_date)
            else:
                flash(message, 'error')
    
    return render_template('auth/mfa_setup.html', user=user, show_qr=False)


@auth_bp.route('/mfa/qrcode')
@login_required()
def mfa_qrcode():
    """Generate QR code for MFA setup."""
    setup_token = session.get('mfa_setup_token')
    if not setup_token:
        flash('No active MFA setup session.', 'error')
        return redirect(url_for('auth.setup_mfa'))
    
    # Get setup session to retrieve provisioning URI
    from .mfa import mfa_setup_sessions
    setup_session = mfa_setup_sessions.get_setup_session(setup_token)
    
    if not setup_session:
        flash('Setup session expired.', 'error')
        return redirect(url_for('auth.setup_mfa'))
    
    auth_manager = current_app.auth_manager
    user_obj = auth_manager.get_user(user_id=g.current_user['id'])
    
    if not user_obj:
        flash('User not found.', 'error')
        return redirect(url_for('auth.profile'))
    
    # Generate provisioning URI and QR code
    provisioning_uri = auth_manager.mfa_manager.get_provisioning_uri(
        user_obj.email, 
        setup_session['secret_key']
    )
    
    qr_code_buffer = auth_manager.mfa_manager.generate_qr_code(provisioning_uri)
    
    return send_file(qr_code_buffer, mimetype='image/png')


@auth_bp.route('/mfa/disable', methods=['POST'])
@login_required()
def disable_mfa():
    """Disable MFA for current user."""
    user = g.current_user
    auth_manager = current_app.auth_manager
    
    # Verify current password
    current_password = request.form.get('current_password', '')
    if not current_password:
        flash('Current password is required to disable MFA.', 'error')
        return redirect(url_for('auth.profile'))
    
    # Authenticate user
    auth_success, auth_user, auth_message = auth_manager.authenticate_user(
        user['username'], current_password
    )
    
    if not auth_success:
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('auth.profile'))
    
    # Disable MFA
    success, message = auth_manager.disable_mfa_for_user(user['id'])
    
    if success:
        flash('MFA has been disabled for your account.', 'success')
        current_app.logger.info(f"MFA disabled for user {user['username']}")
    else:
        flash(message, 'error')
    
    return redirect(url_for('auth.profile'))


@auth_bp.route('/mfa/backup-codes')
@login_required()
def view_backup_codes():
    """View backup codes information."""
    user = g.current_user
    auth_manager = current_app.auth_manager
    
    success, count, message = auth_manager.get_backup_codes_info(user['id'])
    
    if not success:
        flash(message, 'error')
        return redirect(url_for('auth.profile'))
    
    return render_template('auth/mfa_backup_codes_info.html', user=user, backup_codes_count=count)


@auth_bp.route('/mfa/regenerate-backup-codes', methods=['POST'])
@login_required()
def regenerate_backup_codes():
    """Regenerate backup codes for current user."""
    user = g.current_user
    auth_manager = current_app.auth_manager
    
    # Verify current password
    current_password = request.form.get('current_password', '')
    if not current_password:
        flash('Current password is required to regenerate backup codes.', 'error')
        return redirect(url_for('auth.view_backup_codes'))
    
    # Authenticate user
    auth_success, auth_user, auth_message = auth_manager.authenticate_user(
        user['username'], current_password
    )
    
    if not auth_success:
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('auth.view_backup_codes'))
    
    # Regenerate backup codes
    success, backup_codes, message = auth_manager.regenerate_backup_codes(user['id'])
    
    if success:
        flash('New backup codes generated successfully. Please save them securely.', 'success')
        current_app.logger.info(f"Backup codes regenerated for user {user['username']}")
        
        from datetime import datetime
        current_date = datetime.now().strftime('%B %d, %Y at %I:%M:%S %p')
        
        return render_template('auth/mfa_backup_codes.html', 
                             user=user,
                             backup_codes=backup_codes,
                             current_date=current_date)
    else:
        flash(message, 'error')
        return redirect(url_for('auth.view_backup_codes'))


# Admin MFA management routes

@auth_bp.route('/users/<int:user_id>/mfa/disable', methods=['POST'])
@login_required('admin')
def admin_disable_mfa(user_id):
    """Disable MFA for a user (admin only)."""
    auth_manager = current_app.auth_manager
    user = auth_manager.get_user(user_id=user_id)
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth.list_users'))
    
    success, message = auth_manager.disable_mfa_for_user(user_id, admin_action=True)
    
    if success:
        flash(f'MFA disabled for user "{user.username}".', 'success')
        current_app.logger.info(f"MFA disabled for user {user.username} by admin {g.current_user['username']}")
    else:
        flash(message, 'error')
    
    return redirect(url_for('auth.view_user', user_id=user_id))
