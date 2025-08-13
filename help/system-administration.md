# System Administration Guide

This guide covers administrative features and system management capabilities in qPKI, including the log viewer, system monitoring, and administrative tools.

## 📋 Table of Contents

- [Admin Access](#admin-access)
- [System Log Viewer](#system-log-viewer)
- [User Management](#user-management)
- [System Monitoring](#system-monitoring)
- [Maintenance Tasks](#maintenance-tasks)
- [Security Management](#security-management)

---

## 🔐 Admin Access

### Admin User Requirements

Administrative features are only available to users with the `admin` role:

- **Default Admin**: `admin` / generated password (shown on first startup)
- **Access Level**: Full system access including logs, user management, and system settings
- **Navigation**: Admin features are accessible via the "Administration" dropdown in the navigation bar

### Admin Permissions

Admin users can:
- View and manage system logs
- Create, modify, and delete user accounts
- View active user sessions
- Access system configuration files
- Clear log files and perform maintenance
- Monitor system performance and health

---

## 📊 System Log Viewer

The log viewer is a powerful tool for monitoring system activity, troubleshooting issues, and auditing system usage.

### Accessing the Log Viewer

1. **Login** as an admin user
2. **Navigate** to Administration → System Logs
3. **URL**: `http://localhost:9090/admin/logs`

### Available Log Files

qPKI maintains several log files:

| Log File | Purpose | Contents |
|----------|---------|----------|
| `qpki_YYYYMMDD.log` | Main application log | Web app activities, CA/certificate operations, authentication |
| `email_notifications.log` | Email system log | Notification sends, SMTP errors, email configuration |
| `expiration_check.log` | Certificate monitoring | Expiration checks, certificate status updates |

### Log Viewer Features

#### 🎛️ **Filtering and Search**

**Log File Selection**:
- Dropdown to select which log file to view
- Shows file size for each log file
- Automatically loads the most recent log file

**Log Level Filter**:
- `ALL` - Show all log levels
- `DEBUG` - Debug information
- `INFO` - General information
- `WARNING` - Warning messages
- `ERROR` - Error messages
- `CRITICAL` - Critical errors

**Lines to Display**:
- Choose from 50, 100, 250, 500, or 1000 lines
- Shows the most recent entries first
- Efficient loading even for large files

**Search Functionality**:
- Real-time search across log messages, logger names, and function names
- Case-insensitive search
- Highlights search terms in results
- Use Ctrl+F to focus search box

#### 📋 **Log Entry Display**

Each log entry shows:
- **Timestamp**: Precise date and time
- **Level**: Color-coded log level badge
- **Logger**: Component that generated the log
- **Function:Line**: Source function and line number
- **Message**: Complete log message

#### 🎨 **Visual Indicators**

- **Error/Critical**: Red highlighting
- **Warning**: Yellow highlighting  
- **Debug**: Muted gray text
- **Info**: Normal text
- Search terms highlighted in yellow

#### 🛠️ **Log Management**

**Download Logs**:
- Click "Download" to save the complete log file
- Useful for offline analysis or sharing with support

**Clear Logs**:
- "Clear Log" button truncates the selected log file
- Confirmation dialog prevents accidental deletion
- Logged action for audit trail

**Refresh**:
- Manual refresh button to update log entries
- Keyboard shortcut: Ctrl+R or F5

### Log File Information

The log viewer also displays:
- **File Size**: Current size in KB/MB
- **Last Modified**: When the log was last updated
- **Quick Actions**: Direct view/download buttons for each log file

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+F` | Focus search box |
| `Ctrl+R` / `F5` | Refresh page |
| `Escape` | Clear search (when search box is focused) |
| `Enter` | Submit search/filter |

### Common Log Analysis Tasks

#### **Monitoring User Activity**
```
Filter: INFO level
Search: "Activity:"
```
Shows all user actions like certificate creation, CA operations, etc.

#### **Finding Errors**
```
Filter: ERROR level
Search: (empty)
```
Displays all error messages for troubleshooting.

#### **Certificate Operations**
```
Search: "certificate_created" or "ca_created"
```
Tracks certificate and CA creation activities.

#### **Authentication Issues**
```
Search: "login" or "authentication"
```
Monitors login attempts and authentication problems.

#### **Email Notification Problems**
```
Log File: email_notifications.log
Filter: ERROR or WARNING
```
Debugs email sending issues.

---

## 👥 User Management

### Creating Users

1. **Navigate** to Administration → Add User
2. **Fill Form**:
   - Username (unique)
   - Full name
   - Email address
   - Password
   - Role (user/admin)
3. **Submit** to create the user

### Managing Existing Users

1. **Navigate** to Administration → User Management
2. **View Users**: See all user accounts with details
3. **Edit Users**: Modify user information and roles
4. **Delete Users**: Remove user accounts (with confirmation)
5. **Password Reset**: Force password changes for users

### Active Sessions

1. **Navigate** to Administration → Active Sessions
2. **Monitor Sessions**: See who's currently logged in
3. **Session Details**: IP address, login time, last activity
4. **Terminate Sessions**: Force logout if needed

---

## 📈 System Monitoring

### Dashboard Metrics

The main dashboard provides:
- **Certificate Count**: Total certificates in system
- **CA Count**: Number of Certificate Authorities
- **Recent Activity**: Latest system operations
- **System Status**: Overall health indicators

### Resource Monitoring

#### **Disk Space Usage**
- Certificate storage directory size
- Log file sizes and rotation
- Database file size

#### **Performance Indicators**
- Certificate creation times
- Database query performance
- File system performance

### Health Checks

#### **Certificate Health**
- Expiring certificates (30, 60, 90 days)
- Revoked certificates count
- Certificate chain validation

#### **System Health**
- Database connectivity
- SMTP server connectivity (if configured)
- File system permissions
- Log file write permissions

---

## 🧹 Maintenance Tasks

### Regular Maintenance

#### **Weekly Tasks**
- Review system logs for errors
- Check disk space usage
- Verify backup processes
- Update certificate expiration reports

#### **Monthly Tasks**
- Rotate or archive old log files
- Review user accounts and permissions
- Update documentation
- Performance optimization review

### Log File Management

#### **Log Rotation**
qPKI automatically rotates log files when they exceed 50MB:
- Keeps 10 backup files by default
- Files are compressed automatically
- Old files are automatically deleted

#### **Manual Log Management**
```bash
# View log file sizes
ls -lh logs/

# Manually archive old logs
tar -czf logs_archive_$(date +%Y%m%d).tar.gz logs/*.log.1 logs/*.log.2

# Clear all log files (emergency only)
# Use the web interface instead for better audit trail
```

### Database Maintenance

#### **SQLite Database (Default)**
- Automatic maintenance built-in
- VACUUM operation runs periodically
- Backup files created automatically

#### **PostgreSQL/MySQL (If Configured)**
- Follow database-specific maintenance procedures
- Regular backup and optimization
- Index maintenance

---

## 🔒 Security Management

### Security Monitoring

#### **Failed Login Attempts**
Monitor logs for:
```
Search: "authentication" + "failed" + "invalid"
```

#### **Suspicious Activities**
Watch for:
- Multiple failed login attempts
- Unusual certificate creation patterns
- Access from unexpected IP addresses
- Administrative action outside normal hours

### Access Control

#### **IP Address Restrictions**
- Monitor access logs for unusual IP addresses
- Consider firewall rules for admin access
- VPN requirements for remote administration

#### **Session Management**
- Regular session timeout enforcement
- Force logout on suspicious activity
- Monitor concurrent sessions per user

### Audit Trail

All administrative actions are logged:
- User account modifications
- Log file operations
- System configuration changes
- Certificate operations
- Authentication events

### Security Best Practices

1. **Regular Password Updates**: Force password changes every 90 days
2. **Two-Factor Authentication**: Consider implementing 2FA (future enhancement)
3. **Access Logging**: Enable detailed access logging
4. **Regular Security Reviews**: Monthly review of user accounts and permissions
5. **Backup Security**: Secure backup files with appropriate permissions

---

## 🚨 Emergency Procedures

### System Recovery

#### **Database Recovery**
1. Stop qPKI application
2. Restore from latest backup
3. Verify data integrity
4. Restart application

#### **Certificate Emergency**
1. Use log viewer to identify issue
2. Check certificate expiration status
3. Regenerate if necessary
4. Update notification settings

#### **Log Analysis for Emergencies**
1. **Access** log viewer immediately
2. **Filter** by ERROR/CRITICAL levels
3. **Search** for specific error patterns
4. **Download** logs for detailed analysis
5. **Document** findings for post-incident review

### Support Information

When contacting support, provide:
- Relevant log excerpts (use log viewer to export)
- System configuration details
- Steps to reproduce the issue
- Screenshots of error messages
- User and session information

---

## 📚 Additional Resources

- [Troubleshooting Guide](./troubleshooting.md) - Detailed problem-solving
- [Configuration Reference](./config-reference.md) - System configuration options
- [Security Guide](./security.md) - Security best practices
- [Backup and Recovery](./backup-recovery.md) - Data protection procedures

---

**Next Steps**: 
- Set up regular log monitoring procedures
- Configure automated alerts for critical errors
- Establish maintenance schedules
- Review security policies regularly
