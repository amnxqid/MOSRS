<?php
session_start();

// --- 1. Authentication & Authorization Check ---
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'authority' || empty($_SESSION['authority_type'])) {
    $_SESSION['login_message'] = "Access Denied. Please log in as an authority user.";
    $_SESSION['login_message_type'] = "danger";
    header("Location: login.php");
    exit();
}
$authority_user_id = $_SESSION['user_id']; // Authority's user ID for audit log

// Include necessary files
include_once 'db.php';
include_once 'email.php';
include_once 'functions.php'; // For addToInbox AND recordAuditLog

// --- 2. Check Request Method ---
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: authority_dashboard.php"); // Default redirect
    exit();
}

// --- CSRF Verification ---
verifyCsrfToken();

// --- 3. Validate Input ---
$return_url = $_POST['return_url'] ?? 'authority_dashboard.php'; // Define early for all redirects
if (!isset($_POST['report_id']) || !is_numeric($_POST['report_id']) || empty($_POST['status_id']) || !is_numeric($_POST['status_id'])) {
    $_SESSION['update_status_message'] = "Invalid input data provided for status update.";
    $_SESSION['update_status_type'] = "danger";
    header("Location: " . $return_url);
    exit();
}

$report_id = (int)$_POST['report_id'];
$new_status_id = (int)$_POST['status_id'];
$authority_type = $_SESSION['authority_type'];

// --- Database Connection Check ---
if (!$conn || $conn->connect_error) {
    error_log("update_report_status.php - DB Connection Error: " . ($conn ? $conn->connect_error : "No connection object"));
    $_SESSION['update_status_message'] = "Database connection error. Cannot update status.";
    $_SESSION['update_status_type'] = "danger";
    header("Location: " . $return_url);
    exit();
}

// --- 4. Verify Authority Permission & Fetch Report/Old Status Info ---
$reporter_id = null;
$report_title = null;
$reporter_email = null;
$old_status_id = null; // For audit log
$old_status_name = 'N/A'; // For audit log

$sql_verify_fetch = "SELECT r.report_id, r.user_id AS reporter_id, r.report_title, r.status_id AS current_status_id,
                           u.email AS reporter_email, rs_old.status_name AS current_status_name
                    FROM reports r
                    JOIN users u ON r.user_id = u.user_id
                    LEFT JOIN report_status rs_old ON r.status_id = rs_old.status_id
                    WHERE r.report_id = ? AND r.authority_type = ?";
$stmt_verify = $conn->prepare($sql_verify_fetch);

if (!$stmt_verify) {
    error_log("update_report_status.php - Prepare failed (verify_fetch): " . $conn->error);
    $_SESSION['update_status_message'] = "Database error during report verification.";
    $_SESSION['update_status_type'] = "danger";
    if ($conn) $conn->close();
    header("Location: " . $return_url);
    exit();
}

$stmt_verify->bind_param("is", $report_id, $authority_type);
$stmt_verify->execute();
$result_verify = $stmt_verify->get_result();

if ($result_verify->num_rows === 0) {
    $_SESSION['update_status_message'] = "Error: Report (ID: {$report_id}) not found or you do not have permission to modify it.";
    $_SESSION['update_status_type'] = "danger";
    $stmt_verify->close();
    if ($conn) $conn->close();
    header("Location: " . $return_url);
    exit();
}

$report_info = $result_verify->fetch_assoc();
$reporter_id = $report_info['reporter_id'];
$report_title = $report_info['report_title'];
$reporter_email = $report_info['reporter_email'];
$old_status_id = $report_info['current_status_id'];
$old_status_name = $report_info['current_status_name'] ?? 'N/A';
$stmt_verify->close();

// --- 5. Get New Status Name ---
$new_status_name = 'Unknown Status';
$stmt_status_name = $conn->prepare("SELECT status_name FROM report_status WHERE status_id = ?");
if($stmt_status_name) {
    $stmt_status_name->bind_param("i", $new_status_id);
    $stmt_status_name->execute();
    $result_status_name = $stmt_status_name->get_result();
    if ($row_status_name = $result_status_name->fetch_assoc()) {
        $new_status_name = $row_status_name['status_name'];
    } else {
         $_SESSION['update_status_message'] = "Error: The selected status ID ({$new_status_id}) does not exist.";
         $_SESSION['update_status_type'] = "danger";
         $stmt_status_name->close();
         if ($conn) $conn->close();
         header("Location: " . $return_url);
         exit();
    }
    $stmt_status_name->close();
}

// --- 6. Execute the Status Update ---
$stmt_update = $conn->prepare("UPDATE reports SET status_id = ?, updated_at = NOW() WHERE report_id = ? AND authority_type = ?");

if ($stmt_update) {
    $stmt_update->bind_param("iis", $new_status_id, $report_id, $authority_type);

    if ($stmt_update->execute()) {
        if ($stmt_update->affected_rows > 0) {
            $log_old_value_status = "Report ID: {$report_id}, Old Status: '{$old_status_name}' (ID: {$old_status_id})";
            $log_new_value_status = "Report ID: {$report_id}, New Status: '{$new_status_name}' (ID: {$new_status_id})";
            recordAuditLog($conn, $authority_user_id, "AUTHORITY_REPORT_STATUS_UPDATED", "reports", "status_id", $log_old_value_status, $log_new_value_status);

            // --- FULL NOTIFICATION LOGIC ---
            $notification_success_flag = true;

            if ($reporter_id && $reporter_email && $report_title) {
                $authority_display_name_notify = $_SESSION['name'] ?? $authority_type;
                $email_subject_notify = "Update on your MOSRS Report: " . htmlspecialchars($report_title);
                $email_body_notify = "Dear Reporter,\n\nThe status of your report titled '" . htmlspecialchars($report_title) . "' (ID: {$report_id}) has been updated to '" . htmlspecialchars($new_status_name) . "' by " . htmlspecialchars($authority_display_name_notify) . ".\n\nPlease log in to the system for more details.\n\nSincerely,\nThe MOSRS Team";
                $inbox_message_notify = "Status of your report '" . htmlspecialchars($report_title) . "' updated to '" . htmlspecialchars($new_status_name) . "'.";

                if (function_exists('addToInbox')) {
                    if (!addToInbox($conn, $reporter_id, $inbox_message_notify, $report_id)) {
                        error_log("update_report_status.php Error: Failed to add status update to inbox for user ID {$reporter_id}, report ID {$report_id}");
                        $notification_success_flag = false;
                    }
                } else { 
                    error_log("update_report_status.php Error: addToInbox function not found."); 
                    $notification_success_flag = false; 
                }

                if (function_exists('sendReportUpdateEmail')) {
                    $email_result_notify = sendReportUpdateEmail($reporter_email, $email_subject_notify, $email_body_notify);
                    if ($email_result_notify !== 'Message has been sent') {
                        error_log("update_report_status.php Email Error for report ID {$report_id} to {$reporter_email}. Result: " . $email_result_notify);
                        $notification_success_flag = false;
                    }
                } else { 
                    error_log("update_report_status.php Error: sendReportUpdateEmail function not found."); 
                    $notification_success_flag = false; 
                }

                if ($notification_success_flag) {
                   $_SESSION['update_status_message'] = "Report (ID: {$report_id}) status successfully updated to '{$new_status_name}'. Reporter notified.";
                   $_SESSION['update_status_type'] = "success";
                } else {
                   $_SESSION['update_status_message'] = "Report (ID: {$report_id}) status updated to '{$new_status_name}'. (Warning: Notification delivery failed.)";
                   $_SESSION['update_status_type'] = "warning";
                }
            } else {
                error_log("update_report_status.php Warning: Could not fetch reporter details for report ID {$report_id} to send notifications.");
                $_SESSION['update_status_message'] = "Report (ID: {$report_id}) status successfully updated to '{$new_status_name}'. (Warning: Could not send notification - reporter info missing).";
                $_SESSION['update_status_type'] = "warning";
            }
            // --- END FULL NOTIFICATION LOGIC ---

        } else {
            $_SESSION['update_status_message'] = "Report (ID: {$report_id}) status is already '{$new_status_name}' or no change was applicable.";
            $_SESSION['update_status_type'] = "info";
            recordAuditLog($conn, $authority_user_id, "AUTHORITY_REPORT_STATUS_NO_CHANGE", "reports", "status_id", "Report ID: {$report_id}, Attempted status '{$new_status_name}' (ID: {$new_status_id}), no change made.", null);
        }
    } else {
        error_log("update_report_status.php - Execute failed (update): " . $stmt_update->error);
        $_SESSION['update_status_message'] = "Error updating status for report ID: {$report_id}.";
        $_SESSION['update_status_type'] = "danger";
        recordAuditLog($conn, $authority_user_id, "AUTHORITY_REPORT_STATUS_UPDATE_FAILED", "reports", "status_id", "Report ID: {$report_id}, Attempted status '{$new_status_name}' (ID: {$new_status_id})", "Error: " . $stmt_update->error);
    }
    $stmt_update->close();
} else {
    error_log("update_report_status.php - Prepare failed (update): " . $conn->error);
    $_SESSION['update_status_message'] = "Database error during status update preparation.";
    $_SESSION['update_status_type'] = "danger";
}

if ($conn) {
    $conn->close();
}

header("Location: " . $return_url);
exit();
?>  