# 📊 Log Viewer Feature - Implementation Summary

## 🎯 Overview

Added a comprehensive system log viewer to the qPKI web interface, providing administrators with powerful log monitoring, analysis, and management capabilities.

## ✨ Features Implemented

### 🔐 Admin-Only Access
- **Route Protection**: Only admin users can access log viewer
- **Navigation Integration**: Added to Administration dropdown menu
- **URL**: `/admin/logs`

### 📋 Multi-Log File Support
- **Main Application Log**: `qpki_YYYYMMDD.log` - Web activities, operations, authentication
- **Email Notifications**: `email_notifications.log` - SMTP operations, notification status
- **Certificate Monitoring**: `expiration_check.log` - Certificate expiration checks

### 🎛️ Advanced Filtering & Search
- **Log Level Filter**: ALL, DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Line Count**: 50, 100, 250, 500, 1000 lines
- **Real-time Search**: Case-insensitive search across messages, loggers, functions
- **Search Highlighting**: Yellow highlighting of search terms in results

### 📊 Rich Log Display
- **Structured Table**: Timestamp, Level, Logger, Function:Line, Message
- **Color Coding**: 
  - 🔴 ERROR/CRITICAL: Red highlighting
  - 🟡 WARNING: Yellow highlighting
  - 🔵 INFO: Blue badges
  - ⚫ DEBUG: Gray/muted
- **Responsive Design**: Bootstrap-based responsive table
- **Tooltips**: Full text display for truncated content

### 🛠️ Log Management
- **Download Logs**: Full file download for offline analysis
- **Clear Logs**: Truncate log files with confirmation dialog
- **Refresh**: Manual and keyboard shortcuts (Ctrl+R, F5)
- **Real-time Updates**: Easy refresh for monitoring

### ⌨️ Keyboard Shortcuts
- `Ctrl+F`: Focus search box
- `Ctrl+R` / `F5`: Refresh page
- `Escape`: Clear search
- `Enter`: Submit filters

### 📱 User Experience
- **File Size Display**: Shows log file sizes in the selection dropdown
- **Last Modified**: Displays when logs were last updated
- **Entry Count**: Shows number of filtered entries
- **Empty State**: Helpful messages when no entries match filters

## 🏗️ Technical Implementation

### Backend (Flask Routes)
```python
@app.route('/admin/logs')
@admin_required
def view_logs():
    # Main log viewer with filtering and pagination

@app.route('/admin/logs/download/<filename>')
@admin_required  
def download_log(filename):
    # Secure log file download with path validation

@app.route('/admin/logs/clear/<filename>', methods=['POST'])
@admin_required
def clear_log(filename):
    # Log file clearing with audit logging
```

### Helper Functions
```python
def _read_log_file(log_dir, filename, level_filter, search_term, lines):
    # Efficient log file reading with filtering

def _parse_log_line(line, line_num):
    # Parse qPKI log format into structured data
```

### Frontend Template
- **File**: `templates/admin/view_logs.html`
- **Responsive Bootstrap UI**
- **JavaScript enhancements for search highlighting**
- **Modal dialogs for destructive actions**

### Security Features
- **Path Validation**: Prevents directory traversal attacks
- **Admin Authorization**: Role-based access control
- **Audit Logging**: All log management actions are logged
- **Confirmation Dialogs**: Prevents accidental log clearing

## 📚 Documentation

### Created Documentation
- **System Administration Guide**: `help/system-administration.md`
  - Complete log viewer usage instructions
  - Common log analysis tasks
  - Keyboard shortcuts and tips
  - Maintenance procedures

### Updated Documentation
- **Navigation Menu**: Added "System Logs" to Administration dropdown
- **Help System**: Integrated into comprehensive help documentation

## 🎯 Use Cases

### 🔍 Troubleshooting
- Filter by ERROR level to find system problems
- Search for specific error messages or functions
- Download logs for detailed offline analysis

### 👀 Security Monitoring  
- Search for "authentication" to monitor login attempts
- Track user activities with "Activity:" search
- Monitor certificate operations

### 📊 System Monitoring
- View recent INFO messages for normal operations
- Check email notification status in dedicated log
- Monitor certificate expiration checks

### 🛠️ Maintenance
- Clear old log files to save disk space
- Monitor log file sizes and growth
- Regular system health checks

## 🔧 Configuration

### Log Files Location
```
logs/
├── qpki_20250813.log       # Main application log
├── email_notifications.log # Email system log  
├── expiration_check.log    # Certificate monitoring
└── *.log.1, *.log.2       # Rotated backup logs
```

### Log Format
```
YYYY-MM-DD HH:MM:SS | LEVEL    | logger.name          | function_name       :line | Message content
```

## 🚀 Future Enhancements

### Planned Features
- **Auto-refresh**: Automatic page refresh for real-time monitoring
- **Export Filters**: Save and load common filter combinations
- **Log Aggregation**: Combine multiple log files in single view
- **Alert Integration**: Email alerts for critical errors
- **Chart Visualization**: Graphical log level trends

### Performance Optimizations
- **Lazy Loading**: Load logs on-demand for very large files
- **Compressed Archives**: Handle .gz rotated logs
- **Search Indexing**: Full-text search for large log files

## 🎉 Summary

The log viewer feature significantly enhances the administrative capabilities of qPKI by providing:

✅ **Complete Visibility** into system operations and issues  
✅ **Powerful Filtering** and search capabilities for efficient analysis  
✅ **Professional UI** with responsive design and intuitive controls  
✅ **Security-First** approach with admin-only access and audit logging  
✅ **Comprehensive Documentation** for administrators  
✅ **Future-Ready** architecture for additional monitoring features  

This feature transforms qPKI from a certificate management tool into a fully observable system with professional logging and monitoring capabilities.

## 🔗 Quick Access

- **URL**: `http://localhost:9090/admin/logs` (admin login required)
- **Navigation**: Administration → System Logs
- **Documentation**: [System Administration Guide](./help/system-administration.md#system-log-viewer)
- **Troubleshooting**: [Troubleshooting Guide](./help/troubleshooting.md#debug-tools-and-commands)
