"""
Authentication Routes for qPKI

Flask Blueprint for authentication-related routes including login, logout,
user management, and password operations.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, g, current_app, jsonify
from werkzeug.security import generate_password_hash
import secrets
from datetime import datetime, timezone

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
            # user is already a dictionary from authenticate_user
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
        success, user, message = auth_manager.create_user(
            user_data,
            g.current_user['username']
        )
        
        if success:
            flash(f'User "{user.username}" created successfully.', 'success')
            current_app.logger.info(f"User {user.username} created by {g.current_user['username']}")
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
