<?php
session_start();

// --- 1. Authentication & Authorization Check ---
// Ensure user is logged in, is an authority, and has an authority_type
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'authority' || empty($_SESSION['authority_type'])) {
    $_SESSION['message'] = "Access Denied. Please log in as an authority user.";
    $_SESSION['message_type'] = "danger";
    header("Location: login.php");
    exit();
}

include 'db.php'; // Database connection

// --- 2. Check if it's a POST request ---
// This script should only process POST requests for updates
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    // If accessed directly via GET, redirect to the dashboard
    header("Location: authority_dashboard.php?view=manage_reports");
    exit();
}

// --- 3. Validate Input ---
// Check if required POST data is set and numeric
if (!isset($_POST['report_id']) || !is_numeric($_POST['report_id']) || !isset($_POST['status_id']) || !is_numeric($_POST['status_id'])) {
    // Use a specific session key for status update messages
    $_SESSION['update_status_message'] = "Invalid input data provided for status update.";
    $_SESSION['update_status_type'] = "danger";
    // Redirect back using return_url if provided, otherwise default
    $return_url = $_POST['return_url'] ?? 'authority_dashboard.php?view=manage_reports';
    header("Location: " . $return_url);
    exit();
}

// Sanitize and assign variables
$report_id = (int)$_POST['report_id'];
$new_status_id = (int)$_POST['status_id'];
$authority_type = $_SESSION['authority_type'];
$user_id = $_SESSION['user_id']; // Authority's user ID for logging/notifications

// --- 4. Verify Authority Permission ---
// Check if the report exists and is assigned to this authority
$sql_verify = "SELECT report_id, user_id AS reporter_id, report_title FROM reports WHERE report_id = ? AND authority_type = ?";
$stmt_verify = $conn->prepare($sql_verify);

// Handle prepare error
if (!$stmt_verify) {
    error_log("manage_report.php - Prepare failed (verify): " . $conn->error);
    $_SESSION['update_status_message'] = "Database error during report verification.";
    $_SESSION['update_status_type'] = "danger";
    $return_url = $_POST['return_url'] ?? 'authority_dashboard.php?view=manage_reports';
    header("Location: " . $return_url);
    exit();
}

// Execute verification query
$stmt_verify->bind_param("is", $report_id, $authority_type);
$stmt_verify->execute();
$result_verify = $stmt_verify->get_result();

// Check if report found and permission granted
if ($result_verify->num_rows === 0) {
    $_SESSION['update_status_message'] = "Error: Report (ID: {$report_id}) not found or you do not have permission to modify it.";
    $_SESSION['update_status_type'] = "danger";
    $stmt_verify->close();
    $return_url = $_POST['return_url'] ?? 'authority_dashboard.php?view=manage_reports';
    header("Location: " . $return_url);
    exit();
}

// Get report details for notifications
$report_info = $result_verify->fetch_assoc();
$reporter_id = $report_info['reporter_id'];
$report_title = $report_info['report_title'];
$stmt_verify->close();


// --- 5. Get New Status Name (for user feedback) ---
$status_name = 'Unknown Status'; // Default
$stmt_status_name = $conn->prepare("SELECT status_name FROM report_status WHERE status_id = ?");
if($stmt_status_name) {
    $stmt_status_name->bind_param("i", $new_status_id);
    $stmt_status_name->execute();
    $result_status_name = $stmt_status_name->get_result();
    if ($row_status_name = $result_status_name->fetch_assoc()) {
        $status_name = $row_status_name['status_name'];
    }
    $stmt_status_name->close();
} else {
     error_log("manage_report.php - Prepare failed (get status name): " . $conn->error);
     // Non-critical error, proceed but use default status name
}

// --- 6. Execute the Update ---
// Assuming you have an 'updated_at' column to track changes
$stmt_update = $conn->prepare("UPDATE reports SET status_id = ?, updated_at = NOW() WHERE report_id = ? AND authority_type = ?");

if ($stmt_update) {
    $stmt_update->bind_param("iis", $new_status_id, $report_id, $authority_type);

    if ($stmt_update->execute()) {
        // Check if any row was actually updated
        if ($stmt_update->affected_rows > 0) {
             $_SESSION['update_status_message'] = "Report (ID: {$report_id}) status successfully updated to '{$status_name}'.";
             $_SESSION['update_status_type'] = "success";

              // --- Optional: Send Notification to Reporter ---
             include_once 'email.php'; // Use include_once to prevent redeclaration errors
             include_once 'functions.php';

             // Get reporter's email
             $stmt_reporter = $conn->prepare("SELECT email FROM users WHERE user_id = ?");
             if ($stmt_reporter) {
                 $stmt_reporter->bind_param("i", $reporter_id);
                 $stmt_reporter->execute();
                 $result_reporter = $stmt_reporter->get_result();
                 if($reporter_details = $result_reporter->fetch_assoc()) {
                     $reporter_email = $reporter_details['email'];

                     // Prepare messages
                     $authority_display_name = $_SESSION['name'] ?? $authority_type; // Use authority's name if available
                     $email_subject = "Update on your MOSRS Report: " . htmlspecialchars($report_title);
                     $email_body = "Dear Reporter,\n\nThe status of your report titled '" . htmlspecialchars($report_title) . "' (ID: {$report_id}) has been updated to '" . htmlspecialchars($status_name) . "' by " . htmlspecialchars($authority_display_name) . ".\n\nPlease log in to the system for more details.\n\nSincerely,\nThe MOSRS Team";
                     $inbox_message = "Status of your report '" . htmlspecialchars($report_title) . "' updated to '" . htmlspecialchars($status_name) . "'.";

                     // Add to reporter's inbox
                     addToInbox($conn, $reporter_id, $inbox_message, $report_id);

                     // Send email notification
                      $email_result = sendReportUpdateEmail($reporter_email, $email_subject, $email_body); // Assuming sendReportUpdateEmail takes subject now
                       if ($email_result !== 'Message has been sent') {
                           error_log("manage_report.php - Email sending error for report ID {$report_id}: " . $email_result);
                           // Append warning to success message
                           $_SESSION['update_status_message'] .= " (Warning: Email notification to reporter failed)";
                           $_SESSION['update_status_type'] = "warning";
                       }

                 } else {
                      error_log("manage_report.php - Could not find reporter email for user ID: {$reporter_id}");
                 }
                 $stmt_reporter->close();
             } else {
                 error_log("manage_report.php - Prepare failed (get reporter email): " . $conn->error);
             }
             // --- End Notification ---

        } else {
            // Query successful, but 0 rows affected (status might be unchanged)
            $_SESSION['update_status_message'] = "Report (ID: {$report_id}) status is already '{$status_name}'. No change made.";
            $_SESSION['update_status_type'] = "info";
        }

    } else {
        // Update query execution failed
        error_log("manage_report.php - Execute failed (update): " . $stmt_update->error);
        $_SESSION['update_status_message'] = "Error updating status for report ID: {$report_id}. Please try again.";
        $_SESSION['update_status_type'] = "danger";
    }
    $stmt_update->close();
} else {
    // Update statement preparation failed
     error_log("manage_report.php - Prepare failed (update): " . $conn->error);
    $_SESSION['update_status_message'] = "Database error during status update preparation.";
    $_SESSION['update_status_type'] = "danger";
}

// Close DB connection
if ($conn) {
    $conn->close();
}

// --- 7. Redirect Back ---
// Redirect to the URL provided by the form, or default to the manage reports view
$return_url = $_POST['return_url'] ?? 'authority_dashboard.php?view=manage_reports';
header("Location: " . $return_url);
exit();

?>