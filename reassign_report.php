<?php
session_start();

// 1. Authentication Check
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'admin') {
    $_SESSION['message'] = "Access Denied. Please log in as an administrator.";
    $_SESSION['message_type'] = "danger";
    header("Location: login.php");
    exit();
}
$admin_id_current = $_SESSION['user_id']; // Admin performing the action

// Include essential files early
include_once 'db.php';        // Ensure db.php is included with include_once for consistency
include_once 'functions.php'; // For addToInbox AND recordAuditLog
include_once 'email.php';     // For sendReportUpdateEmail

// 2. Get and Validate Report ID
$report_id = isset($_GET['report_id']) ? filter_input(INPUT_GET, 'report_id', FILTER_VALIDATE_INT) : 0;

if ($report_id <= 0) {
    $_SESSION['message'] = "Invalid Report ID specified.";
    $_SESSION['message_type'] = "warning";
    header("Location: admin_dashboard.php?view=view_reports");
    exit();
}

// 3. Fetch Report Details & Reporter Info
$report = null;
$current_authority_log = null; // For storing the authority before change (for audit log)
$reporter_id = null;
$reporter_email = null;
$report_title = null;
$fetch_error = '';

if (!$conn || $conn->connect_error) { // Check connection before proceeding
    $fetch_error = "Database connection error. Cannot fetch report details.";
    error_log("Reassign Fetch Error (Initial DB Check): " . ($conn ? $conn->connect_error : "No connection object"));
    $_SESSION['message'] = $fetch_error;
    $_SESSION['message_type'] = "danger";
    header("Location: admin_dashboard.php?view=view_reports");
    exit();
}

$report_sql = "SELECT r.report_title, r.authority_type, r.user_id AS reporter_id, u.email AS reporter_email
               FROM reports r
               JOIN users u ON r.user_id = u.user_id
               WHERE r.report_id = ?";
$report_stmt = $conn->prepare($report_sql);

if ($report_stmt) {
    $report_stmt->bind_param("i", $report_id);
    $report_stmt->execute();
    $report_result = $report_stmt->get_result();

    if ($report_result->num_rows > 0) {
        $report = $report_result->fetch_assoc();
        $current_authority_log = $report['authority_type']; // Store for audit log and display
        $reporter_id = $report['reporter_id'];
        $reporter_email = $report['reporter_email'];
        $report_title = $report['report_title'];
        error_log("Fetched report details for ID $report_id: Title='{$report_title}', CurrentAuth='{$current_authority_log}', ReporterID={$reporter_id}, ReporterEmail={$reporter_email}");
    } else {
        $fetch_error = "Report with ID {$report_id} not found.";
        error_log($fetch_error);
    }
    $report_stmt->close();
} else {
    $fetch_error = "Database error preparing to fetch report details: " . $conn->error;
    error_log("Reassign Fetch Error (Prepare): " . $conn->error);
}

if ($report === null && !empty($fetch_error)) {
     $_SESSION['message'] = $fetch_error;
     $_SESSION['message_type'] = "danger";
     if ($conn) $conn->close(); // Close connection before exit
     header("Location: admin_dashboard.php?view=view_reports");
     exit();
}


// 4. Handle Form Submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    error_log("--- Processing Reassign POST Request for Report ID: {$report_id} by Admin ID: {$admin_id_current} ---");

    if (!$conn || $conn->connect_error) { // Re-check connection for POST
        $_SESSION['message'] = "Database connection error during reassignment.";
        $_SESSION['message_type'] = "danger";
        error_log("Reassign POST Error: DB connection lost before processing.");
        header("Location: reassign_report.php?report_id=" . $report_id);
        exit();
    }

    if (!isset($_POST['report_id']) || (int)$_POST['report_id'] !== $report_id) {
        $_SESSION['message'] = "Form submission error: Report ID mismatch.";
        $_SESSION['message_type'] = "danger";
        error_log("Reassign POST Error: Report ID mismatch in POST data.");
        if ($conn) $conn->close();
        header("Location: reassign_report.php?report_id=" . $report_id);
        exit();
    }

    $new_authority_type_input = $_POST['authority_type'] ?? null;
    $new_authority_type_db = ($new_authority_type_input === 'NULL_VALUE') ? null : $new_authority_type_input;
    error_log("New authority type selected for DB: " . ($new_authority_type_db ?? 'NULL (Unassign)'));

    // Use $current_authority_log which was fetched before POST for accurate "old value"
    $old_authority_for_audit = $current_authority_log ?? 'Previously Unknown/Unassigned';

    $update_sql = "UPDATE reports SET authority_type = ? WHERE report_id = ?";
    $update_stmt = $conn->prepare($update_sql);

    if ($update_stmt) {
        $update_stmt->bind_param("si", $new_authority_type_db, $report_id);

        if ($update_stmt->execute()) {
            error_log("Report ID {$report_id} DB update successful. Rows affected: " . $update_stmt->affected_rows);
            $assigned_to_text = $new_authority_type_db ?? 'Not Assigned';

            // --- Record Audit Log for Reassignment ---
            $log_action_reassign = "ADMIN_REPORT_REASSIGNED";
            $log_table_reassign = "reports";
            $log_column_reassign = "authority_type"; // Primary column changed
            $log_old_value_reassign = "Report ID: {$report_id}, Old Authority: {$old_authority_for_audit}";
            $log_new_value_reassign = "Report ID: {$report_id}, New Authority: {$assigned_to_text}";
            recordAuditLog($conn, $admin_id_current, $log_action_reassign, $log_table_reassign, $log_column_reassign, $log_old_value_reassign, $log_new_value_reassign);
            // --- End Audit Log ---


            error_log("Checking reporter info for notification: RepID={$reporter_id}, RepEmail={$reporter_email}, RepTitle={$report_title}");
            if ($reporter_id && $reporter_email && $report_title) {
                $notification_success = true;

                $email_subject = "Update on your MOSRS Report: " . htmlspecialchars($report_title);
                $email_body = "Dear Reporter,\n\nYour report titled '" . htmlspecialchars($report_title) . "' (ID: {$report_id}) has been reassigned by the Administrator.\n\nIt is now assigned to: " . htmlspecialchars($assigned_to_text) . ".\n\nPlease log in to the system if you need further details.\n\nSincerely,\nThe MOSRS Team";
                $inbox_message = "Your report '" . htmlspecialchars($report_title) . "' (ID: {$report_id}) has been reassigned to: " . htmlspecialchars($assigned_to_text) . ".";

                if (function_exists('addToInbox')) {
                    if (!addToInbox($conn, $reporter_id, $inbox_message, $report_id)) {
                        error_log("Reassign Error: addToInbox FAILED for user ID {$reporter_id}, report ID {$report_id}");
                        $notification_success = false;
                    }
                } else { error_log("Reassign Error: addToInbox function not found."); $notification_success = false; }

                if (function_exists('sendReportUpdateEmail')) {
                    $email_result = sendReportUpdateEmail($reporter_email, $email_subject, $email_body);
                    if ($email_result !== 'Message has been sent') {
                        error_log("Reassign Error: Email sending FAILED. Result: " . var_export($email_result, true));
                        $notification_success = false;
                    }
                } else { error_log("Reassign Error: sendReportUpdateEmail function not found."); $notification_success = false; }

                if ($notification_success) {
                    $_SESSION['message'] = "Report (ID: {$report_id}) successfully reassigned to: " . htmlspecialchars($assigned_to_text) . ". Reporter notified.";
                    $_SESSION['message_type'] = "success";
                } else {
                    $_SESSION['message'] = "Report (ID: {$report_id}) reassigned to: " . htmlspecialchars($assigned_to_text) . " (Warning: Notification delivery failed. Check server logs.)";
                    $_SESSION['message_type'] = "warning";
                }
            } else {
                error_log("Reassign Warning: Notification skipped - missing reporter details for report ID {$report_id}.");
                $_SESSION['message'] = "Report (ID: {$report_id}) successfully reassigned to: " . htmlspecialchars($assigned_to_text) . " (Warning: Could not send notification - reporter info missing).";
                $_SESSION['message_type'] = "warning";
            }
            error_log("--- Reassign POST Request Processed. Redirecting... ---");
            if ($conn) $conn->close();
            header("Location: admin_dashboard.php?view=view_reports");
            exit();
        } else {
            $_SESSION['message'] = "Error updating report assignment: " . $update_stmt->error;
            $_SESSION['message_type'] = "danger";
            error_log("Reassign Error (Execute Update): " . $update_stmt->error);
        }
        $update_stmt->close();
    } else {
        $_SESSION['message'] = "Database error preparing update: " . $conn->error;
        $_SESSION['message_type'] = "danger";
        error_log("Reassign Error (Prepare Update): " . $conn->error);
    }
    error_log("--- Reassign POST Request FAILED. Redirecting back to form... ---");
    if ($conn) $conn->close();
    header("Location: reassign_report.php?report_id=" . $report_id);
    exit();
}

// Close DB connection if script reaches here (i.e., displaying the form for GET request)
if ($conn) {
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reassign Report - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
     <style>
        body { display: flex; flex-direction: column; min-height: 100vh; background-color: #f8f9fa; }
        .main-container { flex: 1; }
        .header-logo { height: 50px; position: absolute; left: 15px; top: 50%; transform: translateY(-50%); }
        .footer { background-color: #343a40; color: white; padding: 1rem 0; text-align: center; }
    </style>
</head>
<body>
    <header class="bg-primary text-white text-center p-3 position-relative">
        <a href="index.php"><img src="kementerian.jpg" alt="Logo" class="header-logo d-none d-md-block" onerror="this.onerror=null; this.style.display='none';"></a>
        <h2 class="mb-0">Reassign Report</h2>
    </header>

    <div class="container main-container my-4">
         <div class="row justify-content-center">
            <div class="col-md-8 col-lg-6">
                <div class="card shadow-sm">
                     <div class="card-body">
                        <?php if ($report): ?>
                             <h3 class="card-title mb-3">Reassign Report</h3>
                             <p><strong>Report Title:</strong> <?php echo htmlspecialchars($report_title ?? 'N/A'); ?></p>
                             <p class="mb-4"><strong>Current Assignment:</strong> <span class="badge bg-info"><?php echo htmlspecialchars($current_authority_log ?? 'Not Assigned'); ?></span></p>
                             <?php
                             // Display session messages if redirected back to this page on POST error
                             if (isset($_SESSION['message'])) {
                                 $message_type_display = $_SESSION['message_type'] ?? 'danger';
                                 echo "<div class='alert alert-{$message_type_display} alert-dismissible fade show' role='alert'>"
                                    . htmlspecialchars($_SESSION['message'])
                                    . "<button type='button' class='btn-close' data-bs-dismiss='alert' aria-label='Close'></button>"
                                    . "</div>";
                                 unset($_SESSION['message']); unset($_SESSION['message_type']);
                             }
                             ?>
                            <form method="post" action="reassign_report.php?report_id=<?php echo $report_id; ?>">
                                <input type="hidden" name="report_id" value="<?php echo $report_id; ?>">
                                <div class="mb-3">
                                    <label for="authority_type" class="form-label">Assign to New Authority:</label>
                                    <select name="authority_type" id="authority_type" class="form-select" required>
                                        <option value="" disabled <?php echo (!isset($current_authority_log) || $current_authority_log === '') ? 'selected' : ''; ?>>-- Select New Assignment --</option>
                                        <option value="PDRM" <?php echo ($current_authority_log === 'PDRM') ? 'selected' : ''; ?>>PDRM (Police)</option>
                                        <option value="BNM" <?php echo ($current_authority_log === 'BNM') ? 'selected' : ''; ?>>BNM (Bank Negara Malaysia)</option>
                                        <option value="MCMC" <?php echo ($current_authority_log === 'MCMC') ? 'selected' : ''; ?>>MCMC (Communications & Multimedia Commission)</option>
                                        <option value="NULL_VALUE" <?php echo (is_null($current_authority_log) || $current_authority_log === 'Not Sure') ? 'selected' : ''; ?>>-- Not Assigned / Not Sure --</option>
                                    </select>
                                    <div class="form-text">Select '-- Not Assigned / Not Sure --' to unassign the report or mark as 'Not Sure'.</div>
                                </div>
                                <div class="d-flex justify-content-between">
                                     <a href="admin_dashboard.php?view=view_reports" class="btn btn-secondary">Cancel / Back to Reports</a>
                                     <button type="submit" class="btn btn-primary">Update Assignment</button>
                                </div>
                            </form>
                        <?php else: ?>
                             <div class="alert alert-danger"><?php echo htmlspecialchars($fetch_error ?: "Report could not be loaded."); ?></div>
                             <div class="text-center"><a href="admin_dashboard.php?view=view_reports" class="btn btn-secondary">Back to Reports</a></div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="footer mt-auto">
        <div class="container"><span>© MOSRS <?php echo date("Y"); ?></span></div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>