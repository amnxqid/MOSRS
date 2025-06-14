<?php
session_start();
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit();
}
$admin_id_current = $_SESSION['user_id'];

include_once 'db.php';
include_once 'functions.php';

$csrf_token = generateCsrfToken();
$error_message = '';
$success_message = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    verifyCsrfToken();
    
    if (!$conn || $conn->connect_error) {
        $error_message = "Database connection error.";
    } else {
        if (isset($_POST['report_id']) && isset($_POST['user_id']) && !empty($_POST['report_id']) && !empty($_POST['user_id'])) {
            $report_id_assign = filter_input(INPUT_POST, 'report_id', FILTER_VALIDATE_INT);
            $user_id_authority = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);

            if (!$report_id_assign || !$user_id_authority) {
                $error_message = "Invalid report ID or authority user ID.";
            } else {
                $sql_user_auth = "SELECT authority_type FROM users WHERE user_id = ? AND user_type = 'authority'";
                $stmt_user_auth = $conn->prepare($sql_user_auth);

                if ($stmt_user_auth) {
                    $stmt_user_auth->bind_param("i", $user_id_authority);
                    $stmt_user_auth->execute();
                    $result_user_auth = $stmt_user_auth->get_result();

                    if ($result_user_auth->num_rows > 0) {
                        $row_user_auth = $result_user_auth->fetch_assoc();
                        $authority_type_assign = $row_user_auth["authority_type"];

                        if (!empty($authority_type_assign)) {
                            $old_authority_log = 'N/A';
                            $stmt_old_report_auth = $conn->prepare("SELECT authority_type FROM reports WHERE report_id = ?");
                            if ($stmt_old_report_auth) {
                                $stmt_old_report_auth->bind_param("i", $report_id_assign);
                                $stmt_old_report_auth->execute();
                                $res_old_report_auth = $stmt_old_report_auth->get_result();
                                if ($row_old_report_auth = $res_old_report_auth->fetch_assoc()) {
                                    $old_authority_log = $row_old_report_auth['authority_type'] ?? 'Unassigned';
                                }
                                $stmt_old_report_auth->close();
                            }
                            
                            $status_id_assigned = 2;

                            $stmt_update_report = $conn->prepare("UPDATE reports SET authority_type = ?, status_id = ? WHERE report_id = ?");
                            if ($stmt_update_report) {
                                $stmt_update_report->bind_param("sii", $authority_type_assign, $status_id_assigned, $report_id_assign);
                                if ($stmt_update_report->execute()) {
                                    $success_message = "Report (ID: " . htmlspecialchars($report_id_assign) . ") assigned successfully to " . htmlspecialchars($authority_type_assign) . " and status updated!";
                                    $log_action_assign = "ADMIN_REPORT_ASSIGNED";
                                    $log_table_assign = "reports";
                                    $log_column_assign = "authority_type, status_id";
                                    $log_old_val_assign = "Report ID: {$report_id_assign}, Old Authority: {$old_authority_log}";
                                    $log_new_val_assign = "Report ID: {$report_id_assign}, New Authority: {$authority_type_assign}, Status ID set to {$status_id_assigned}";
                                    recordAuditLog($conn, $admin_id_current, $log_action_assign, $log_table_assign, $log_column_assign, $log_old_val_assign, $log_new_val_assign);
                                } else { $error_message = "Error updating report assignment: " . $stmt_update_report->error; }
                                $stmt_update_report->close();
                            } else { $error_message = "Error preparing report update statement: " . $conn->error; }
                        } else { $error_message = "Error: The selected user does not have a valid Authority Type."; }
                    } else { $error_message = "Error: Selected Authority User ID ({$user_id_authority}) not found or is not an authority type user."; }
                    $stmt_user_auth->close();
                } else { $error_message = "Error preparing user lookup statement: " . $conn->error; }
            }
        } else { $error_message = "Error: Please select both a report and an authority."; }
    }
}

$unassigned_reports_sql = "SELECT r.report_id, r.report_title, rs.status_name FROM reports r LEFT JOIN report_status rs ON r.status_id = rs.status_id WHERE r.authority_type IS NULL OR r.authority_type = '' OR r.authority_type = 'Not Sure' ORDER BY r.report_id DESC";
$unassigned_reports_result = $conn->query($unassigned_reports_sql);
$authorities_sql = "SELECT user_id, name, authority_type FROM users WHERE user_type = 'authority' AND authority_type IS NOT NULL AND authority_type != '' ORDER BY name ASC";
$authorities_result = $conn->query($authorities_sql);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Assign Report - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { display: flex; flex-direction: column; min-height: 100vh; background-color: #f8f9fa; }
        .main-container { flex: 1; }
        .footer { background-color: #343a40; color: white; padding: 1rem 0; text-align: center; }
    </style>
</head>
<body>
    <header class="bg-primary text-white text-center p-3"><h2>Assign Report</h2></header>
    <div class="container main-container my-4">
        <div class="row justify-content-center">
            <div class="col-md-8 col-lg-6">
                <div class="card shadow-sm">
                    <div class="card-body">
                        <h3 class="card-title text-center mb-4">Assign a Report to an Authority</h3>
                        <?php if (!empty($error_message)): ?><div class="alert alert-danger"><?php echo htmlspecialchars($error_message); ?></div><?php endif; ?>
                        <?php if (!empty($success_message)): ?><div class="alert alert-success"><?php echo htmlspecialchars($success_message); ?></div><?php endif; ?>
                        <?php if ($unassigned_reports_result && $unassigned_reports_result->num_rows > 0 && $authorities_result && $authorities_result->num_rows > 0): ?>
                            <form method="post" action="assign_report.php">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                                <div class="mb-3">
                                    <label for="report_id" class="form-label">Select Report:</label>
                                    <select name="report_id" id="report_id" class="form-select" required>
                                        <option value="" disabled selected>-- Select a Report --</option>
                                        <?php while ($row_unassigned = $unassigned_reports_result->fetch_assoc()) { $status_display = !empty($row_unassigned['status_name']) ? " (Status: " . htmlspecialchars($row_unassigned['status_name']) . ")" : ""; echo "<option value='" . $row_unassigned['report_id'] . "'>" . htmlspecialchars($row_unassigned['report_title']) . " (ID: " . $row_unassigned['report_id'] . $status_display . ")</option>"; } ?>
                                    </select>
                                </div>
                                <div class="mb-3">
                                    <label for="user_id" class="form-label">Assign to Authority:</label>
                                    <select name="user_id" id="user_id" class="form-select" required>
                                        <option value="" disabled selected>-- Select an Authority --</option>
                                        <?php while ($row_auth = $authorities_result->fetch_assoc()) { echo "<option value='" . $row_auth['user_id'] . "'>" . htmlspecialchars($row_auth['name']) . " (" . htmlspecialchars($row_auth['authority_type']) . ")</option>"; } ?>
                                    </select>
                                </div>
                                <div class="d-grid gap-2"><button type="submit" name="assign_report_action" class="btn btn-primary">Assign Report</button></div>
                            </form>
                        <?php else: ?>
                             <div class="alert alert-warning">
                                <?php if (!$unassigned_reports_result || $unassigned_reports_result->num_rows == 0) { echo "There are currently no unassigned reports available."; } elseif (!$authorities_result || $authorities_result->num_rows == 0) { echo "No Authority users found."; } ?>
                            </div>
                        <?php endif; ?>
                        <div class="text-center mt-4"><a href="admin_dashboard.php?view=view_reports" class="btn btn-secondary">Back to Dashboard</a></div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <footer class="footer mt-auto"><div class="container"><span>© MOSRS <?php echo date("Y"); ?></span></div></footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
<?php if ($conn) { $conn->close(); } ?>