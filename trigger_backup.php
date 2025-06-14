<?php
session_start();
require_once 'db.php'; // For audit logging
require_once 'functions.php'; // For recordAuditLog

// 1. Authentication Check - CRITICAL
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit();
}
$admin_id_current = $_SESSION['user_id']; // For audit

// 2. Configuration
$batch_file_path = "C:\\backup_config\\mysqlbackup.bat";

$message = '';
$message_type = 'info';
$log_details_backup = "Admin ID: {$admin_id_current} initiated database backup.";

if (!file_exists($batch_file_path)) {
    $message = "Error: Backup script not found at {$batch_file_path}.";
    $message_type = 'danger';
    $log_details_backup .= " Failed: Script not found.";
    error_log("Admin Backup Trigger: Batch file not found at {$batch_file_path}");
} elseif (!is_executable($batch_file_path) && strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
    $message = "Error: Backup script is not executable by the web server.";
    $message_type = 'danger';
    $log_details_backup .= " Failed: Script not executable.";
    error_log("Admin Backup Trigger: Batch file {$batch_file_path} is not executable.");
} else {
    $backup_dir = dirname($batch_file_path);
    $current_dir_php = getcwd();
    if (is_dir($backup_dir)) { // Check if backup_dir is valid before chdir
      chdir($backup_dir);
    }

    $command = $batch_file_path;
    shell_exec($command); // Consider capturing output or error codes if .bat provides them
    
    if (is_dir($backup_dir)) {
      chdir($current_dir_php); // Change back
    }

    $message = "Database backup process has been initiated via '{$batch_file_path}'. Check server logs/backup location for status.";
    $message_type = 'success';
    $log_details_backup .= " Executed: {$batch_file_path}.";
    error_log("Admin Backup Trigger: Attempted to execute {$batch_file_path} by Admin ID: {$admin_id_current}");
}

// --- Record Audit Log for Backup Attempt ---
if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
    recordAuditLog($conn, $admin_id_current, "ADMIN_DB_BACKUP_TRIGGERED", "system_maintenance", "batch_script", null, $log_details_backup);
} else {
    error_log("Backup Trigger: DB connection not available for audit logging. Details: " . $log_details_backup);
}
// --- End Audit Log ---

$_SESSION['admin_dashboard_message'] = $message;
$_SESSION['admin_dashboard_message_type'] = $message_type;

// Close DB Connection if open
if (isset($conn) && $conn instanceof mysqli && $conn->ping()) {
    $conn->close();
}

header("Location: admin_dashboard.php?view=stats");
exit();
?>