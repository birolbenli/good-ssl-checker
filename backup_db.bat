@echo off
REM Database backup script
echo Creating database backup...
if exist "instance\ssl_tracker.db" (
    copy "instance\ssl_tracker.db" "instance\ssl_tracker_backup_%date:~10,4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%.db"
    echo Database backed up successfully!
) else (
    echo No database found to backup.
)
pause
