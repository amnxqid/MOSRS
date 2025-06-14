<?php
session_start();

// 1. Authentication Check
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit();
}

// 2. Include Core Files
include_once 'db.php';
include_once 'email.php';
include_once 'functions.php';

// 3. Configuration & Initialization
$evidence_base_url = "http://localhost/fyp/";
$add_user_errors = [];
$add_user_error_string = '';
$add_user_success = '';
$comment_success = '';
$comment_error = '';
$admin_name = $_SESSION['name'] ?? 'Admin';
$admin_id_current = $_SESSION['user_id'];

$admin_dashboard_message = '';
$admin_dashboard_message_type = 'info';
if (isset($_SESSION['admin_dashboard_message'])) {
    $admin_dashboard_message = $_SESSION['admin_dashboard_message'];
    $admin_dashboard_message_type = $_SESSION['admin_dashboard_message_type'] ?? 'info';
    unset($_SESSION['admin_dashboard_message']);
    unset($_SESSION['admin_dashboard_message_type']);
}

// Determine current view
$view = isset($_GET['view']) ? $_GET['view'] : 'stats';

// CSRF Token Generation for all forms on this page
$csrf_token = generateCsrfToken();

// Date Range Handling
$default_end_date = date('Y-m-d');
$default_start_date = date('Y-m-d', strtotime('-29 days'));
$start_date = isset($_GET['start_date']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['start_date']) ? $_GET['start_date'] : $default_start_date;
$end_date = isset($_GET['end_date']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['end_date']) ? $_GET['end_date'] : $default_end_date;
$end_date_for_query = $end_date . ' 23:59:59';

// --- 4. Handle POST Requests ---
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    verifyCsrfToken();

    if (isset($_POST['add_user'])) {
        if (!$conn || $conn->connect_error) {
            $add_user_error_string = "Database connection error during user addition.";
        } else {
            $name = trim($_POST['name']);
            $email = trim($_POST['email']);
            $password = $_POST['password'];
            $user_type = $_POST['new_user_type'];
            $authority_type_form = ($user_type == "authority" && isset($_POST['authority_type'])) ? $_POST['authority_type'] : NULL;
            $phone_number = trim($_POST['phone_number']);

            if (empty($name)) { $add_user_errors[] = "Name is required."; }
            if (empty($email)) { $add_user_errors[] = "Email is required."; }
            elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) { $add_user_errors[] = "Invalid email format."; }
            else {
                $checkEmail = $conn->prepare("SELECT email FROM users WHERE email = ?");
                if ($checkEmail) {
                    $checkEmail->bind_param("s", $email); $checkEmail->execute(); $checkEmail->store_result();
                    if ($checkEmail->num_rows > 0) { $add_user_errors[] = "Email already registered."; }
                    $checkEmail->close();
                } else { $add_user_errors[] = "DB error checking email."; }
            }
            if (empty($password)) { $add_user_errors[] = "Password is required."; }
            elseif (strlen($password) < 8) { $add_user_errors[] = "Password must be at least 8 characters long."; }
            elseif (!preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password) || !preg_match('/[0-9]/', $password)) { $add_user_errors[] = "Password must contain at least one uppercase letter, one lowercase letter, and one number."; }
            if (empty($phone_number)) { $add_user_errors[] = "Phone number is required."; }
            elseif (!preg_match('/^[0-9+\s-]+$/', $phone_number)) { $add_user_errors[] = "Invalid phone number format."; }
            if ($user_type == 'authority' && empty($authority_type_form)) { $add_user_errors[] = "Authority Type is required for Authority users."; }

            if (!empty($add_user_errors)) {
                $add_user_error_string = implode("<br>", $add_user_errors);
            } else {
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $stmt_add_user = $conn->prepare("INSERT INTO users (name, email, password, user_type, authority_type, phone_number) VALUES (?, ?, ?, ?, ?, ?)");
                if ($stmt_add_user) {
                    $stmt_add_user->bind_param("ssssss", $name, $email, $hashed_password, $user_type, $authority_type_form, $phone_number);
                    if ($stmt_add_user->execute()) {
                        $newly_added_user_id = $stmt_add_user->insert_id;
                        $add_user_success = "User added successfully! (ID: {$newly_added_user_id})";
                        $log_new_val = "Admin ID: {$admin_id_current} added User: {$name} ({$email}), Type: {$user_type}" . ($authority_type_form ? ", Authority: {$authority_type_form}" : "");
                        recordAuditLog($conn, $admin_id_current, "ADMIN_USER_CREATED", "users", "user_id: {$newly_added_user_id}", null, $log_new_val);
                    } else { $add_user_error_string = "Error adding user: " . $stmt_add_user->error; }
                    $stmt_add_user->close();
                } else { $add_user_error_string = "DB error preparing add user statement: ".$conn->error; }
            }
        }
    }

    if (isset($_POST['add_comment'])) {
        if (!$conn || $conn->connect_error) {
             $comment_error = "Database connection error during comment submission.";
        } else {
            $report_id_comment = filter_input(INPUT_POST, 'report_id', FILTER_VALIDATE_INT);
            $comment_text = trim($_POST['comment_text']);

            if ($report_id_comment && !empty($comment_text)) {
                $stmt_add_comment = $conn->prepare("INSERT INTO report_comments (report_id, user_id, comment_text) VALUES (?, ?, ?)");
                if($stmt_add_comment) {
                    $stmt_add_comment->bind_param("iis", $report_id_comment, $admin_id_current, $comment_text);
                    if ($stmt_add_comment->execute()) {
                        $new_comment_id = $stmt_add_comment->insert_id;
                        $comment_success = "Comment added successfully!";
                        recordAuditLog($conn, $admin_id_current, "ADMIN_COMMENT_ADDED", "report_comments", "comment_id: {$new_comment_id}", null, "Admin ID: {$admin_id_current} added comment to Report ID: {$report_id_comment}.");
                         $report_sql_notify = "SELECT r.report_title, u.email, r.user_id FROM reports r JOIN users u ON r.user_id = u.user_id WHERE r.report_id = ?";
                         $report_stmt_notify = $conn->prepare($report_sql_notify);
                         if($report_stmt_notify){
                             $report_stmt_notify->bind_param("i", $report_id_comment); $report_stmt_notify->execute(); $report_result_notify = $report_stmt_notify->get_result();
                             if ($report_result_notify->num_rows > 0) {
                                 $row_notify = $report_result_notify->fetch_assoc();
                                 $update_message = "Dear Reporter,\n\nA new comment has been added by an administrator to your report titled '" . htmlspecialchars($row_notify['report_title']) . "'.\n\nPlease log in.\n\nSincerely,\nThe MOSRS Team";
                                 $inbox_message = "An administrator added a comment to your report: '".htmlspecialchars($row_notify['report_title'])."'.";
                                 if ($admin_id_current != $row_notify['user_id']) {
                                     addToInbox($conn, $row_notify['user_id'], $inbox_message, $report_id_comment);
                                     if(function_exists('sendReportUpdateEmail')) {
                                         sendReportUpdateEmail($row_notify['email'], "Update on your MOSRS Report: ". $row_notify['report_title'], $update_message);
                                     }
                                 }
                             }
                             $report_stmt_notify->close();
                         }
                    } else { $comment_error = "Error adding comment: " . $stmt_add_comment->error; }
                    $stmt_add_comment->close();
                } else { $comment_error = "DB Error preparing comment insert: ".$conn->error; }
            } elseif(empty($comment_text)) { $comment_error = "Comment cannot be empty!";
            } elseif (!$report_id_comment) { $comment_error = "Invalid report specified for comment."; }
        }
    }
}

// --- 5. Fetch Data for Stats View ---
$total_reports_stat = 0; $total_users = 0; $status_counts = []; $assigned_reports_stat = 0;
if (isset($conn) && $conn && !$conn->connect_error) {
    $stmt_total_reports = $conn->prepare("SELECT COUNT(*) AS total FROM reports WHERE created_at BETWEEN ? AND ?");
    $stmt_total_reports->bind_param("ss", $start_date, $end_date_for_query);
    $stmt_total_reports->execute();
    $total_reports_stat = $stmt_total_reports->get_result()->fetch_assoc()['total'] ?? 0;
    $stmt_total_reports->close();

    $total_users = $conn->query("SELECT COUNT(*) AS total FROM users")->fetch_assoc()['total'] ?? 0;
    
    $statuses_result = $conn->query("SELECT status_name FROM report_status");
    if ($statuses_result) {
        $stmt_status_count = $conn->prepare("SELECT COUNT(*) AS total FROM reports r JOIN report_status rs ON r.status_id = rs.status_id WHERE rs.status_name = ? AND r.created_at BETWEEN ? AND ?");
        while ($status_row = $statuses_result->fetch_assoc()) {
            $status_name_loop = $status_row['status_name'];
            $stmt_status_count->bind_param("sss", $status_name_loop, $start_date, $end_date_for_query);
            $stmt_status_count->execute();
            $status_counts[$status_name_loop] = $stmt_status_count->get_result()->fetch_assoc()['total'] ?? 0;
        }
        $stmt_status_count->close();
    }
    
    $stmt_assigned_reports = $conn->prepare("SELECT COUNT(*) AS total FROM reports WHERE authority_type IS NOT NULL AND authority_type != '' AND authority_type != 'Not Sure' AND created_at BETWEEN ? AND ?");
    $stmt_assigned_reports->bind_param("ss", $start_date, $end_date_for_query);
    $stmt_assigned_reports->execute();
    $assigned_reports_stat = $stmt_assigned_reports->get_result()->fetch_assoc()['total'] ?? 0;
    $stmt_assigned_reports->close();
} else {
    $db_connection_error = "Warning: Database connection failed.";
}

// --- 6. Function Definitions Needed Locally ---
function getReportComments($conn, $report_id_func) {
    if (!$conn || $conn->connect_error) { return []; }
    $sql_comments = "SELECT rc.*, u.name FROM report_comments rc JOIN users u ON rc.user_id = u.user_id WHERE rc.report_id = ? ORDER BY rc.created_at ASC";
    $stmt_comments = $conn->prepare($sql_comments); $comments_arr = [];
    if ($stmt_comments) { $stmt_comments->bind_param("i", $report_id_func);
        if ($stmt_comments->execute()) { $result_comments = $stmt_comments->get_result(); if ($result_comments) { while ($row_comment = $result_comments->fetch_assoc()) { $comments_arr[] = $row_comment; } } }
        $stmt_comments->close();
    } return $comments_arr;
}
function getStatusBadgeClass(?string $status_name_func): string {
    $status_name_lower_func = strtolower($status_name_func ?? '');
    switch ($status_name_lower_func) { case 'pending': return 'bg-warning text-dark'; case 'in progress': return 'bg-primary'; case 'resolved': return 'bg-success'; case 'rejected': return 'bg-danger'; case 'requires info': return 'bg-info text-dark'; default: return 'bg-secondary'; }
}

// --- Pagination Configuration ---
$entries_per_page = 15;
$current_page_num = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
if ($current_page_num < 1) { $current_page_num = 1; }
$offset_val = ($current_page_num - 1) * $entries_per_page;
$total_entries_for_view = 0;
$total_pages_for_view = 0;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css">
    <link rel="stylesheet" href="admin_dashboard_styles.css">
    <style>
        .audit-timeline{position:relative;padding:1rem 0;list-style:none}.audit-timeline::before{content:'';position:absolute;top:0;left:40px;height:100%;width:4px;background:#e9ecef;border-radius:2px}.timeline-item{margin-bottom:2rem;position:relative;padding-left:70px}.timeline-icon{position:absolute;left:20px;top:0;width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;z-index:10;box-shadow:0 0 0 4px #f8f9fa}.timeline-icon.action-login{background-color:#198754}.timeline-icon.action-logout{background-color:#6c757d}.timeline-icon.action-create{background-color:#0d6efd}.timeline-icon.action-update{background-color:#ffc107}.timeline-icon.action-delete{background-color:#dc3545}.timeline-icon.action-failure{background-color:#fd7e14}.timeline-icon.action-system{background-color:#6f42c1}.timeline-content{background:#fff;padding:1rem 1.5rem;border-radius:.5rem;border:1px solid #dee2e6;box-shadow:0 3px 8px rgba(0,0,0,.05)}.timeline-header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;border-bottom:1px solid #e9ecef;padding-bottom:.75rem;margin-bottom:.75rem}.timeline-action{font-weight:600;font-size:1.1rem;color:#343a40}.timeline-timestamp{font-size:.85rem;color:#6c757d}.timeline-user{font-weight:500}.timeline-details dl{margin-bottom:0;font-size:.9rem}.timeline-details dt{font-weight:600;color:#6c757d;width:120px;float:left;clear:left}.timeline-details dd{margin-left:130px;word-break:break-word}.timeline-changes{margin-top:1rem;padding-top:1rem;border-top:1px dashed #ced4da}.change-box{padding:.75rem;border-radius:.25rem;font-family:'Courier New',Courier,monospace;font-size:.85rem;white-space:pre-wrap;word-break:break-all;max-height:150px;overflow-y:auto}.change-box.old-value{background-color:#ffebe9;border:1px solid #f5c6cb}.change-box.new-value{background-color:#d1e7dd;border:1px solid #badbcc}
    </style>
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/daterangepicker/daterangepicker.css" />
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary sticky-top shadow-sm">
        <div class="container-fluid">
            <a class="navbar-brand" href="admin_dashboard.php"><img src="kementerian.jpg" alt="Logo" class="header-logo-img" onerror="this.onerror=null; this.style.display='none';">MOSRS Admin</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNavAdmin"><span class="navbar-toggler-icon"></span></button>
            <div class="collapse navbar-collapse" id="navbarNavAdmin">
                <ul class="navbar-nav ms-auto align-items-center">
                    <li class="nav-item dropdown"><a class="nav-link dropdown-toggle profile-dropdown-toggler" href="#" id="adminProfileDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false"><span class="profile-avatar-sm"><?php echo strtoupper(substr($admin_name, 0, 1)); ?></span> <?php echo htmlspecialchars($admin_name); ?> <i class="fas fa-chevron-down fa-xs ms-1"></i></a>
                        <ul class="dropdown-menu dropdown-menu-end profile-dropdown-menu" aria-labelledby="adminProfileDropdown">
                            <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user-circle"></i> View Profile</a></li>
                            <li><a class="dropdown-item" href="edit_profile.php"><i class="fas fa-user-edit"></i> Edit Profile</a></li>
                            <li><a class="dropdown-item" href="change_password.php"><i class="fas fa-key"></i> Change Password</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item text-danger" href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container main-container mt-3">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h2 class="page-title mb-0">Admin Dashboard</h2>
            <div>
                 <a class="btn btn-info btn-sm me-2" href="create_report_admin.php"><i class="fas fa-plus-circle me-1"></i>Create Report</a>
                 <a class="btn btn-success btn-sm" href="assign_report.php"><i class="fas fa-tasks me-1"></i> Assign Job</a>
            </div>
        </div>
        <div class="admin-action-card-grid mb-4">
            <a href="admin_dashboard.php?view=stats" class="admin-action-card <?php echo ($view == 'stats' ? 'active' : ''); ?>"><div class="action-icon"><i class="fas fa-chart-line"></i></div><h5>Dashboard Stats</h5><p class="action-description">View system overview and statistics.</p></a>
            <a href="admin_dashboard.php?view=manage_users" class="admin-action-card <?php echo ($view == 'manage_users' ? 'active' : ''); ?>"><div class="action-icon"><i class="fas fa-users-cog"></i></div><h5>Manage Users</h5><p class="action-description">Add, search, or manage system users.</p></a>
            <a href="admin_dashboard.php?view=view_reports" class="admin-action-card <?php echo ($view == 'view_reports' ? 'active' : ''); ?>"><div class="action-icon"><i class="fas fa-file-alt"></i></div><h5>View All Reports</h5><p class="action-description">Browse and manage all submitted reports.</p></a>
            <a href="admin_dashboard.php?view=audit_log" class="admin-action-card <?php echo ($view == 'audit_log' ? 'active' : ''); ?>"><div class="action-icon"><i class="fas fa-history"></i></div><h5>Audit Log</h5><p class="action-description">Review system activity and changes.</p></a>
            <a href="download_report_summary_pdf.php" class="admin-action-card" target="_blank"><div class="action-icon"><i class="fas fa-file-pdf"></i></div><h5>Download Summary</h5><p class="action-description">Get a PDF summary of system statistics.</p></a>
            <a href="trigger_backup.php" class="admin-action-card" onclick="return confirm('Are you sure you want to run the database backup script?');"><div class="action-icon"><i class="fas fa-database"></i></div><h5>Backup Database</h5><p class="action-description">Initiate a manual database backup.</p></a>
            <a href="admin_dashboard.php?view=system_settings" class="admin-action-card <?php echo ($view == 'system_settings' ? 'active' : ''); ?>"><div class="action-icon"><i class="fas fa-cogs"></i></div><h5>System Settings</h5><p class="action-description">Configure system parameters (TBD).</p></a>
        </div>
        <?php if (!empty($admin_dashboard_message)): ?><div class="alert alert-<?php echo htmlspecialchars($admin_dashboard_message_type); ?> alert-dismissible fade show" role="alert"><?php echo htmlspecialchars($admin_dashboard_message); ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>
        <?php if (isset($db_connection_error)): ?><div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($db_connection_error); ?></div><?php endif; ?>
        <?php if (!empty($comment_success)): ?><div class="alert alert-success alert-dismissible fade show" role="alert"><?php echo htmlspecialchars($comment_success); ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>
        <?php if (!empty($comment_error)): ?><div class="alert alert-danger alert-dismissible fade show" role="alert"><?php echo htmlspecialchars($comment_error); ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>
        <?php
        if (!isset($conn) || !$conn || $conn->connect_error) {
            if (!isset($db_connection_error)) { echo "<div class='alert alert-danger'>Database connection error.</div>"; }
        } else {
            switch ($view) {
                case 'stats':
                    ?>
                    <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap">
                        <h4 class="page-title mb-2 mb-md-0">System Overview & Statistics</h4>
                        <div id="reportrange" style="background: #fff; cursor: pointer; padding: 5px 10px; border: 1px solid #ccc; border-radius: 0.25rem;">
                            <i class="fa fa-calendar"></i> <span></span> <i class="fa fa-caret-down"></i>
                        </div>
                    </div>
                    <div class="row g-4 justify-content-center">
                        <div class="col-md-6 col-xl-4 mb-4"><div class="card stat-card bg-c-blue h-100"><div class="card-body"><i class="fas fa-file-alt stat-icon"></i><h5 class="card-title">Total Reports (in range)</h5><p class="stat-number"><?php echo $total_reports_stat; ?></p></div></div></div>
                        <div class="col-md-6 col-xl-4 mb-4"><div class="card stat-card bg-c-green h-100"><div class="card-body"><i class="fas fa-users stat-icon"></i><h5 class="card-title">Total Users (all time)</h5><p class="stat-number"><?php echo $total_users; ?></p></div></div></div>
                        <div class="col-md-6 col-xl-4 mb-4"><div class="card stat-card bg-c-yellow h-100"><div class="card-body"><i class="fas fa-tasks stat-icon"></i><h5 class="card-title">Assigned Reports (in range)</h5><p class="stat-number"><?php echo $assigned_reports_stat; ?></p></div></div></div>
                        <?php
                        $status_visuals = ['Pending' => ['icon' => 'fas fa-hourglass-half','bg_class' => 'bg-c-orange'],'In Progress' => ['icon' => 'fas fa-cogs','bg_class' => 'bg-c-teal'],'Resolved' => ['icon' => 'fas fa-check-circle','bg_class' => 'bg-c-green'],'Rejected' => ['icon' => 'fas fa-times-circle','bg_class' => 'bg-c-red']];
                        foreach ($status_counts as $status_key => $count_val):
                            $visual = $status_visuals[$status_key] ?? ['icon' => 'fas fa-question-circle', 'bg_class' => 'bg-c-gray'];
                        ?>
                            <div class="col-md-6 col-xl-4 mb-4"><div class="card stat-card <?php echo $visual['bg_class']; ?> h-100"><div class="card-body"><i class="<?php echo $visual['icon']; ?> stat-icon"></i><h5 class="card-title"><?php echo htmlspecialchars($status_key); ?> (in range)</h5><p class="stat-number"><?php echo $count_val; ?></p></div></div></div>
                        <?php endforeach; ?>
                    </div>
                    <?php
                    break;
                case 'manage_users':
                    $search_term = isset($_GET['search']) ? trim($_GET['search']) : '';
                    $filter_role = isset($_GET['filter_role']) ? $_GET['filter_role'] : '';
                    $sort_columns = ['user_id', 'name', 'email', 'user_type'];
                    $sort_by = isset($_GET['sort']) && in_array($_GET['sort'], $sort_columns) ? $_GET['sort'] : 'user_id';
                    $sort_order = isset($_GET['order']) && strtolower($_GET['order']) === 'desc' ? 'DESC' : 'ASC';
                    ?>
                    <h4 class="mb-3 page-title">Manage Users</h4>
                    <div class="card shadow-sm mb-4"><div class="card-header"><button class="btn btn-success" type="button" data-bs-toggle="collapse" data-bs-target="#addUserCollapse" aria-expanded="<?php echo !empty($add_user_error_string) ? 'true' : 'false'; ?>"><i class="fas fa-user-plus"></i> Add New User</button></div>
                        <div class="collapse <?php echo !empty($add_user_error_string) ? 'show' : ''; ?>" id="addUserCollapse"><div class="card-body"><h5>Add New User</h5><?php if (!empty($add_user_error_string)): ?> <div class="alert alert-danger"><?php echo $add_user_error_string; ?></div><?php endif; ?><?php if (!empty($add_user_success)): ?> <div class="alert alert-success"><?php echo htmlspecialchars($add_user_success); ?></div><?php endif; ?><form method="post" action="admin_dashboard.php?view=manage_users"><input type="hidden" name="add_user" value="1"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>"><div class="mb-3"><label for="name_form" class="form-label">Name:</label><input type="text" id="name_form" name="name" class="form-control" required></div><div class="mb-3"><label for="email_form" class="form-label">Email:</label><input type="email" id="email_form" name="email" class="form-control" required></div><div class="mb-3"><label for="password_form" class="form-label">Password:</label><input type="password" id="password_form" name="password" class="form-control" required></div><div class="mb-3"><label for="phone_number_form" class="form-label">Phone:</label><input type="tel" id="phone_number_form" name="phone_number" class="form-control" required></div><div class="mb-3"><label for="new_user_type_form" class="form-label">Type:</label><select id="new_user_type_form" name="new_user_type" class="form-select" required onchange="document.getElementById('authorityTypeGroup').style.display = (this.value === 'authority' ? 'block' : 'none');"><option value="public">Public</option><option value="admin">Admin</option><option value="authority">Authority</option></select></div><div class="mb-3" id="authorityTypeGroup" style="display: none;"><label for="authority_type_select_form" class="form-label">Authority Type:</label><select id="authority_type_select_form" name="authority_type" class="form-select"><option value="">-- Select --</option><option value="PDRM">PDRM</option><option value="BNM">BNM</option><option value="MCMC">MCMC</option></select></div><button type="submit" class="btn btn-primary">Add</button></form></div></div>
                    </div>
                    <div class="card shadow-sm"><div class="card-header"><h5>Existing Users</h5></div>
                        <div class="card-body border-bottom"><form method="GET" action="admin_dashboard.php"><input type="hidden" name="view" value="manage_users"><div class="row g-2 align-items-end"><div class="col-md-5"><label for="search" class="form-label">Search</label><input class="form-control form-control-sm" type="search" id="search" name="search" placeholder="Name, Email, ID" value="<?php echo htmlspecialchars($search_term); ?>"></div><div class="col-md-4"><label for="filter_role" class="form-label">Role</label><select name="filter_role" id="filter_role" class="form-select form-select-sm"><option value="">All</option><option value="public" <?php if($filter_role == 'public') echo 'selected'; ?>>Public</option><option value="admin" <?php if($filter_role == 'admin') echo 'selected'; ?>>Admin</option><option value="authority" <?php if($filter_role == 'authority') echo 'selected'; ?>>Authority</option></select></div><div class="col-md-3 d-flex gap-2"><button class="btn btn-primary btn-sm w-100" type="submit"><i class="fas fa-filter"></i> Apply</button><a href="admin_dashboard.php?view=manage_users" class="btn btn-outline-secondary btn-sm w-100">Clear</a></div></div></form></div>
                        <div class="card-body"><div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>
                            <?php function sort_link($title, $column, $current_sort, $current_order) {$order = ($current_sort == $column && $current_order == 'ASC') ? 'desc' : 'asc';$icon = '';if ($current_sort == $column) {$icon = $current_order == 'ASC' ? ' <i class="fas fa-sort-up"></i>' : ' <i class="fas fa-sort-down"></i>';}$query_params = http_build_query(array_merge($_GET, ['sort' => $column, 'order' => $order]));return "<a href='?{$query_params}' class='text-dark text-decoration-none'>{$title}{$icon}</a>";} ?>
                            <th><?php echo sort_link('ID', 'user_id', $sort_by, $sort_order); ?></th><th><?php echo sort_link('Name', 'name', $sort_by, $sort_order); ?></th><th><?php echo sort_link('Email', 'email', $sort_by, $sort_order); ?></th><th><?php echo sort_link('Role', 'user_type', $sort_by, $sort_order); ?></th><th>Authority</th><th>Actions</th></tr></thead><tbody>
                            <?php
                                $sql_users_list = "SELECT user_id, name, email, user_type, authority_type FROM users";
                                $params = [];$types = '';$where_clauses = [];
                                if (!empty($search_term)) {$where_clauses[] = "(name LIKE ? OR email LIKE ? OR user_id = ?)";$like_search_term = "%" . $search_term . "%";$params[] = $like_search_term;$params[] = $like_search_term;$params[] = $search_term;$types .= "ssi";}
                                if (!empty($filter_role)) {$where_clauses[] = "user_type = ?";$params[] = $filter_role;$types .= "s";}
                                if (!empty($where_clauses)) {$sql_users_list .= " WHERE " . implode(" AND ", $where_clauses);}
                                $sql_users_list .= " ORDER BY {$sort_by} {$sort_order}";
                                $stmt_users_list = $conn->prepare($sql_users_list);
                                if ($stmt_users_list) {
                                    if (!empty($params)) {$stmt_users_list->bind_param($types, ...$params);}
                                    $stmt_users_list->execute();$result_users_list = $stmt_users_list->get_result();
                                    if ($result_users_list && $result_users_list->num_rows > 0) {
                                        while ($row = $result_users_list->fetch_assoc()) {
                                            echo "<tr><td>{$row['user_id']}</td><td>".htmlspecialchars($row['name'])."</td><td>".htmlspecialchars($row['email'])."</td><td>".ucfirst($row['user_type'])."</td><td>".($row['authority_type'] ?? 'N/A')."</td><td>";
                                            echo "<a href='view_user_profile.php?user_id={$row['user_id']}' class='btn btn-info btn-sm'><i class='fas fa-eye'></i></a>";
                                            if ($row['user_id'] != $_SESSION['user_id']) {echo " <form method='post' action='delete_user.php' class='d-inline' onsubmit='return confirm(\"Delete this user?\")'><input type='hidden' name='user_id' value='{$row['user_id']}'><input type='hidden' name='csrf_token' value='".htmlspecialchars($csrf_token)."'><button type='submit' class='btn btn-danger btn-sm'><i class='fas fa-trash'></i></button></form>";}
                                            echo "</td></tr>";
                                        }
                                    } else { echo "<tr><td colspan='6' class='text-center'>No users found.</td></tr>"; }
                                    $stmt_users_list->close();
                                }
                            ?>
                            </tbody></table></div></div>
                    </div>
                    <?php
                    break;
                case 'view_reports':
                    $count_sql_reports = "SELECT COUNT(*) as total FROM reports";
                    $count_result_reports = $conn->query($count_sql_reports);
                    if ($count_result_reports) {$total_entries_for_view = $count_result_reports->fetch_assoc()['total'];$total_pages_for_view = ceil($total_entries_for_view / $entries_per_page);
                    } else {echo "<div class='alert alert-danger'>Error fetching report count.</div>";$total_pages_for_view = 0;}
                    ?>
                     <h4 class="mb-3 page-title">View All Reports <small class="text-muted fs-6">(Page <?php echo $current_page_num; ?> of <?php echo $total_pages_for_view > 0 ? $total_pages_for_view : 1; ?>)</small></h4>
                     <div class="card shadow-sm">
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped table-hover table-bordered align-middle">
                                     <thead class="table-dark"><tr><?php $col_count_reports = 0; $report_fields_display = [];$sql_cols_reports = "SHOW COLUMNS FROM reports";$result_cols_reports = $conn->query($sql_cols_reports);if ($result_cols_reports) {while($field_row_reports = $result_cols_reports->fetch_assoc()){$field_name_reports = $field_row_reports['Field'];$report_fields_display[] = $field_name_reports;if ($field_name_reports === 'evidence' || $field_name_reports === 'status_id') continue;echo "<th>" . htmlspecialchars(ucwords(str_replace('_', ' ', $field_name_reports))) . "</th>"; $col_count_reports++;}echo "<th>Status</th><th>Reassign</th><th>Comments</th>"; $col_count_reports+=3;} else { $col_count_reports = 8; echo "<th colspan='{$col_count_reports}'>Error loading report structure</th>"; }?></tr></thead>
                                    <tbody>
                                    <?php
                                        $sql_reports_list = "SELECT r.*, rs.status_name FROM reports r LEFT JOIN report_status rs ON r.status_id = rs.status_id ORDER BY r.report_id DESC LIMIT ? OFFSET ?";
                                        $stmt_reports_list = $conn->prepare($sql_reports_list);
                                        if ($stmt_reports_list) {
                                            $stmt_reports_list->bind_param("ii", $entries_per_page, $offset_val);$stmt_reports_list->execute(); $result_reports_list = $stmt_reports_list->get_result();
                                            if ($result_reports_list && $result_reports_list->num_rows > 0) {
                                                while ($row_report_list = $result_reports_list->fetch_assoc()) {
                                                    echo "<tr>";foreach($report_fields_display as $field_name_reports_loop){if ($field_name_reports_loop === 'evidence' || $field_name_reports_loop === 'status_id') continue;echo "<td>" . htmlspecialchars($row_report_list[$field_name_reports_loop] ?? 'N/A') . "</td>";}
                                                    echo "<td><span class='badge " . getStatusBadgeClass($row_report_list['status_name'] ?? null) . "'>" . htmlspecialchars($row_report_list['status_name'] ?? 'N/A') . "</span></td>";
                                                    echo "<td><a href='reassign_report.php?report_id=" . htmlspecialchars($row_report_list['report_id']) . "' class='btn btn-warning btn-sm'><i class='fas fa-random'></i></a></td>";
                                                    echo "<td><button class='btn btn-primary btn-sm' type='button' data-bs-toggle='collapse' data-bs-target='#commentsCollapse-{$row_report_list['report_id']}'><i class='fas fa-comments'></i></button>";
                                                    echo "<div class='collapse' id='commentsCollapse-{$row_report_list['report_id']}'>";echo "<div class='comment-section mt-2'>";$comments_display = getReportComments($conn, $row_report_list['report_id']);if (!empty($comments_display)) { foreach ($comments_display as $comment) { echo "<div class='comment'><strong>".htmlspecialchars($comment['name']).":</strong> ".nl2br(htmlspecialchars($comment['comment_text']))."</div>"; } }else { echo "<p class='text-muted small'>No comments yet.</p>"; }echo "</div>";
                                                    echo "<form method='post' action='admin_dashboard.php?view=view_reports&page={$current_page_num}' class='mt-2'><input type='hidden' name='report_id' value='" . htmlspecialchars($row_report_list['report_id']) . "'><input type='hidden' name='csrf_token' value='" . htmlspecialchars($csrf_token) . "'><textarea name='comment_text' class='form-control form-control-sm' rows='2' required></textarea><button type='submit' class='btn btn-success btn-sm mt-1' name='add_comment'>Post</button></form>";
                                                    echo "</div></td></tr>";
                                                }
                                            } else { echo "<tr><td colspan='" . $col_count_reports . "' class='text-center'>No reports found.</td></tr>";}
                                            $stmt_reports_list->close();
                                        } else { echo "<tr><td colspan='" . $col_count_reports . "' class='text-center text-danger'>Error preparing report list.</td></tr>"; }
                                    ?>
                                    </tbody>
                                </table>
                            </div>
                            <?php if ($total_pages_for_view > 1): ?>
                            <nav><ul class="pagination justify-content-center mt-4">
                                <li class="page-item <?php echo ($current_page_num <= 1 ? 'disabled' : ''); ?>"><a class="page-link" href="?view=view_reports&page=<?php echo $current_page_num - 1; ?>">«</a></li>
                                <?php for ($i=1; $i<=$total_pages_for_view; $i++):?><li class="page-item <?php echo ($i == $current_page_num ? 'active' : ''); ?>"><a class="page-link" href="?view=view_reports&page=<?php echo $i; ?>"><?php echo $i; ?></a></li><?php endfor; ?>
                                <li class="page-item <?php echo ($current_page_num >= $total_pages_for_view ? 'disabled' : ''); ?>"><a class="page-link" href="?view=view_reports&page=<?php echo $current_page_num + 1; ?>">»</a></li>
                            </ul></nav>
                            <?php endif; ?>
                        </div>
                     </div>
                    <?php
                    break;
                case 'audit_log':
                    $count_sql_audit = "SELECT COUNT(*) as total FROM audit_log";
                    $count_result_audit = $conn->query($count_sql_audit);
                    if ($count_result_audit) {$total_entries_for_view = $count_result_audit->fetch_assoc()['total'];$total_pages_for_view = ceil($total_entries_for_view / $entries_per_page);
                    } else {echo "<div class='alert alert-danger'>Error fetching audit log count.</div>";$total_pages_for_view = 0;}
                    ?>
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h4 class="page-title mb-0">System Activity Log</h4>
                        <small class="text-muted">Page <?php echo $current_page_num; ?> of <?php echo $total_pages_for_view > 0 ? $total_pages_for_view : 1; ?></small>
                    </div>
                    <div class="audit-timeline">
                    <?php
                        $sql_audit_list = "SELECT al.*, u.name as user_name_audit, u.email as user_email_audit FROM audit_log al LEFT JOIN users u ON al.user_id = u.user_id ORDER BY al.log_id DESC LIMIT ? OFFSET ?";
                        $stmt_audit_list = $conn->prepare($sql_audit_list);
                        if ($stmt_audit_list) {
                            $stmt_audit_list->bind_param("ii", $entries_per_page, $offset_val);
                            $stmt_audit_list->execute();
                            $result_audit_list = $stmt_audit_list->get_result();
                            if ($result_audit_list && $result_audit_list->num_rows > 0) {
                                while ($log = $result_audit_list->fetch_assoc()) {
                                    $icon_class = 'fas fa-info-circle'; $icon_bg = 'action-system';
                                    if (str_contains(strtoupper($log['action']), 'LOGIN')) { $icon_class = 'fas fa-sign-in-alt'; $icon_bg = 'action-login'; }
                                    if (str_contains(strtoupper($log['action']), 'LOGOUT')) { $icon_class = 'fas fa-sign-out-alt'; $icon_bg = 'action-logout'; }
                                    if (str_contains(strtoupper($log['action']), 'CREATED')) { $icon_class = 'fas fa-plus-circle'; $icon_bg = 'action-create'; }
                                    if (str_contains(strtoupper($log['action']), 'UPDATED') || str_contains(strtoupper($log['action']), 'REASSIGNED')) { $icon_class = 'fas fa-pencil-alt'; $icon_bg = 'action-update'; }
                                    if (str_contains(strtoupper($log['action']), 'DELETED')) { $icon_class = 'fas fa-trash-alt'; $icon_bg = 'action-delete'; }
                                    if (str_contains(strtoupper($log['action']), 'FAILED') || str_contains(strtoupper($log['action']), 'ATTEMPT')) { $icon_class = 'fas fa-exclamation-triangle'; $icon_bg = 'action-failure'; }
                                    ?>
                                    <div class="timeline-item">
                                        <div class="timeline-icon <?php echo $icon_bg; ?>"><i class="<?php echo $icon_class; ?>"></i></div>
                                        <div class="timeline-content">
                                            <div class="timeline-header">
                                                <span class="timeline-action"><?php echo htmlspecialchars(ucwords(str_replace('_', ' ', strtolower($log['action'])))); ?></span>
                                                <span class="timeline-timestamp"><i class="far fa-clock"></i> <?php echo date("d M Y, H:i:s", strtotime($log['timestamp'])); ?></span>
                                            </div>
                                            <div class="timeline-details">
                                                <dl>
                                                    <dt>User:</dt><dd class="timeline-user"><?php echo $log['user_name_audit'] ? htmlspecialchars($log['user_name_audit']) : ($log['user_email_audit'] ? htmlspecialchars($log['user_email_audit']) : '<em class="text-muted">System/Unknown</em>'); ?> (ID: <?php echo $log['user_id'] ?? 'N/A'; ?>)</dd>
                                                    <dt>Target Table:</dt><dd><?php echo htmlspecialchars($log['table_name'] ?? 'N/A'); ?></dd>
                                                    <dt>Target/Column:</dt><dd><?php echo htmlspecialchars($log['column_name'] ?? 'N/A'); ?></dd>
                                                </dl>
                                            </div>
                                            <?php if (!empty($log['old_value']) || !empty($log['new_value'])): ?>
                                            <div class="timeline-changes">
                                                <div class="row g-2">
                                                    <?php if (!empty($log['old_value']) && $log['old_value'] !== 'N/A'): ?><div class="col-md-6"><strong>Old Value / Context:</strong><div class="change-box old-value"><?php echo htmlspecialchars($log['old_value']); ?></div></div><?php endif; ?>
                                                    <?php if (!empty($log['new_value']) && $log['new_value'] !== 'N/A'): ?><div class="col-md-6"><strong>New Value / Details:</strong><div class="change-box new-value"><?php echo htmlspecialchars($log['new_value']); ?></div></div><?php endif; ?>
                                                </div>
                                            </div>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                    <?php
                                }
                            } else { echo "<div class='text-center p-5 bg-light rounded'><p class='lead'>No audit log entries found.</p></div>"; }
                            $stmt_audit_list->close();
                        } else { echo "<div class='alert alert-danger'>Error preparing audit log list: " . htmlspecialchars($conn->error) . "</div>"; }
                    ?>
                    </div>
                    <?php if ($total_pages_for_view > 1): ?>
                        <nav><ul class="pagination justify-content-center mt-4">
                            <li class="page-item <?php echo ($current_page_num <= 1 ? 'disabled' : ''); ?>"><a class="page-link" href="?view=audit_log&page=<?php echo $current_page_num - 1; ?>">« Previous</a></li>
                            <li class="page-item <?php echo ($current_page_num >= $total_pages_for_view ? 'disabled' : ''); ?>"><a class="page-link" href="?view=audit_log&page=<?php echo $current_page_num + 1; ?>">Next »</a></li>
                        </ul></nav>
                    <?php endif; ?>
                    <?php
                    break;
                case 'system_settings':
                    ?>
                    <h4 class="mb-3 page-title">System Settings</h4>
                    <div class="alert alert-info general-content-card" role="alert"><i class="fas fa-info-circle me-2"></i>This feature is under development. Settings will be available here soon.</div>
                    <?php
                    break;
                default:
                    echo "<div class='alert alert-warning'>Invalid view specified ('".htmlspecialchars($view)."'). Displaying statistics.</div>";
                    ?>
                    <h4 class="text-center mb-4 page-title">System Overview & Statistics</h4>
                    <div class="row g-4 justify-content-center">
                        <div class="col-md-6 col-xl-4 mb-4"><div class="card stat-card bg-c-blue h-100"><div class="card-body"><i class="fas fa-file-alt stat-icon"></i><h5 class="card-title">Total Reports</h5><p class="stat-number"><?php echo $total_reports_stat; ?></p></div></div></div>
                        <div class="col-md-6 col-xl-4 mb-4"><div class="card stat-card bg-c-green h-100"><div class="card-body"><i class="fas fa-users stat-icon"></i><h5 class="card-title">Total Users</h5><p class="stat-number"><?php echo $total_users; ?></p></div></div></div>
                        <div class="col-md-6 col-xl-4 mb-4"><div class="card stat-card bg-c-yellow h-100"><div class="card-body"><i class="fas fa-tasks stat-icon"></i><h5 class="card-title">Assigned Reports</h5><p class="stat-number"><?php echo $assigned_reports_stat; ?></p></div></div></div>
                    </div>
                    <?php
                    break;
            }
        }
        ?>
    </div>
    <footer class="footer"><div class="container"><span>© MALAYSIA ONLINE SCAM REPORTING SYSTEM (MOSRS) <?php echo date("Y"); ?></span></div></footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/jquery/latest/jquery.min.js"></script>
    <script src="https://cdn.jsdelivr.net/momentjs/latest/moment.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/daterangepicker/daterangepicker.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const userTypeSelectForm = document.getElementById('new_user_type_form');
            const authorityGroupForm = document.getElementById('authorityTypeGroup');
            if (userTypeSelectForm && authorityGroupForm) {
                 authorityGroupForm.style.display = (userTypeSelectForm.value === 'authority' ? 'block' : 'none');
                 userTypeSelectForm.onchange = function() { authorityGroupForm.style.display = (this.value === 'authority' ? 'block' : 'none'); };
            }
        });
        $(function() {
            var start = moment('<?php echo htmlspecialchars($start_date); ?>');
            var end = moment('<?php echo htmlspecialchars($end_date); ?>');
            function cb(start, end) { $('#reportrange span').html(start.format('MMMM D, YYYY') + ' - ' + end.format('MMMM D, YYYY')); }
            $('#reportrange').daterangepicker({ startDate: start, endDate: end, ranges: { 'Today': [moment(), moment()], 'Yesterday': [moment().subtract(1, 'days'), moment().subtract(1, 'days')], 'Last 7 Days': [moment().subtract(6, 'days'), moment()], 'Last 30 Days': [moment().subtract(29, 'days'), moment()], 'This Month': [moment().startOf('month'), moment().endOf('month')], 'Last Month': [moment().subtract(1, 'month').startOf('month'), moment().subtract(1, 'month').endOf('month')] } }, cb);
            cb(start, end);
            $('#reportrange').on('apply.daterangepicker', function(ev, picker) {
                var startDate = picker.startDate.format('YYYY-MM-DD');
                var endDate = picker.endDate.format('YYYY-MM-DD');
                var urlParams = new URLSearchParams(window.location.search);
                urlParams.set('view', 'stats');
                urlParams.set('start_date', startDate);
                urlParams.set('end_date', endDate);
                window.location.search = urlParams.toString();
            });
        });
    </script>
<?php
if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
    $conn->close();
}
?>
</body>
</html>