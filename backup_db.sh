#!/bin/bash
# Database backup script for Linux/Ubuntu
echo "Creating database backup..."
if [ -f "instance/ssl_tracker.db" ]; then
    timestamp=$(date +"%Y%m%d_%H%M%S")
    cp "instance/ssl_tracker.db" "instance/ssl_tracker_backup_${timestamp}.db"
    echo "Database backed up successfully to: ssl_tracker_backup_${timestamp}.db"
else
    echo "No database found to backup."
fi
