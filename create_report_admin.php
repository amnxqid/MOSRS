<?php
session_start();
include_once 'db.php';
include_once 'functions.php';

// --- 1. Authentication Check ---
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'admin') {
    $_SESSION['login_message'] = "Please log in as an administrator.";
    $_SESSION['login_message_type'] = "danger";
    header("Location: login.php");
    exit();
}
$admin_id_current = $_SESSION['user_id'];

// CSRF Token
$csrf_token = generateCsrfToken();

// --- 2. Initialize variables ---
$errors = [];
$pending_status_id = null;
$file_path_uploaded = NULL;
$original_filename_uploaded = NULL;
$critical_error = '';

$message = $_SESSION['admin_message'] ?? null;
$message_type = $_SESSION['admin_message_type'] ?? 'danger';
unset($_SESSION['admin_message'], $_SESSION['admin_message_type']);

$postdata = $_SESSION['admin_postdata'] ?? [];
unset($_SESSION['admin_postdata']);

// --- 4. Get Pending Status ID ---
if ($conn && !$conn->connect_error) {
    $status_sql = "SELECT status_id FROM report_status WHERE status_name = 'Pending'";
    $status_result = $conn->query($status_sql);
    if ($status_result && $status_result->num_rows > 0) {
        $pending_status_id = $status_result->fetch_assoc()['status_id'];
    } else {
        $critical_error = "System configuration error: 'Pending' status is missing.";
        if ($message === null) { $message = $critical_error; $message_type = 'danger'; }
    }
} else {
    $critical_error = "Database connection error.";
    if ($message === null) { $message = $critical_error; $message_type = 'danger'; }
}

// --- 5. Handle the form submission ---
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    verifyCsrfToken();

    if (!$conn || $conn->connect_error) {
        $_SESSION['admin_message'] = "Database connection error.";
        $_SESSION['admin_message_type'] = 'danger';
        $_SESSION['admin_postdata'] = $_POST;
        header("Location: create_report_admin.php");
        exit();
    }

    if (empty($_POST['user_id']) || !is_numeric($_POST['user_id'])) { $errors[] = "A user must be selected."; }
    if (empty(trim($_POST['report_title']))) { $errors[] = "Report Title is required."; }
    if (empty(trim($_POST['report_details']))) { $errors[] = "Report Details are required."; }
    if (empty($_POST['category'])) { $errors[] = "Category is required."; }
    if (isset($_POST['category']) && $_POST['category'] === "Other" && empty(trim($_POST['other_category']))) { $errors[] = "Please specify the 'Other' category."; }
    if (!isset($_POST['authority_type']) || $_POST['authority_type'] === '') { $errors[] = "Authority Type is required."; }
    if ($pending_status_id === null) { $errors[] = $critical_error ?: "System error: 'Pending' status not found."; }

    if (empty($errors)) {
        $user_id_for_report = (int)$_POST['user_id'];
        $report_title_create = trim($_POST['report_title']);
        $report_details_create = trim($_POST['report_details']);
        $category_form = $_POST['category'];
        $other_category_form = trim($_POST['other_category'] ?? '');
        $final_category_create = ($category_form === "Other") ? $other_category_form : $category_form;
        $authority_type_create = $_POST['authority_type'];

        if (isset($_FILES["evidence"]) && $_FILES["evidence"]["error"] == UPLOAD_ERR_OK) {
            $target_dir_upload = "uploads/";
            if (!is_dir($target_dir_upload)) { if (!mkdir($target_dir_upload, 0755, true)) { $errors[] = "Server error: Failed to create upload directory."; }}
            if (empty($errors) && !is_writable($target_dir_upload)) { $errors[] = "Server error: Upload directory is not writable.";}
            if (empty($errors)) {
                 $original_filename_uploaded = basename($_FILES["evidence"]["name"]);
                 $file_ext_upload = strtolower(pathinfo($original_filename_uploaded, PATHINFO_EXTENSION));
                 $allowed_types = ["jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "txt", "heic", "webp"];
                 if (!in_array($file_ext_upload, $allowed_types)) { $errors[] = "Invalid file type: " . $file_ext_upload; }
                if (empty($errors)) {
                     $safe_original_filename_upload = preg_replace("/[^A-Za-z0-9._-]/", "_", $original_filename_uploaded);
                     $unique_filename_upload = uniqid('report_initial_', true) . '.' . $file_ext_upload;
                     $target_file_path_upload = $target_dir_upload . $unique_filename_upload;
                    if (move_uploaded_file($_FILES["evidence"]["tmp_name"], $target_file_path_upload)) {
                        $file_path_uploaded = $target_file_path_upload;
                    } else { $errors[] = "Server error: Failed to move uploaded file."; }
                }
            }
        }
        
        if (empty($errors)) {
            $stmt_insert_report = $conn->prepare("INSERT INTO reports (user_id, report_title, report_details, category, authority_type, evidence, created_at, status_id) VALUES (?, ?, ?, ?, ?, ?, NOW(), ?)");
             if($stmt_insert_report) {
                $stmt_insert_report->bind_param("isssssi", $user_id_for_report, $report_title_create, $report_details_create, $final_category_create, $authority_type_create, $file_path_uploaded, $pending_status_id);
                if ($stmt_insert_report->execute()) {
                    $new_report_id_admin_created = $stmt_insert_report->insert_id;
                    if ($file_path_uploaded && $original_filename_uploaded) {
                        $stmt_evidence_insert = $conn->prepare("INSERT INTO evidence (report_id, user_id, file_path, original_filename, uploaded_at) VALUES (?, ?, ?, ?, NOW())");
                        if ($stmt_evidence_insert) {
                            $stmt_evidence_insert->bind_param("iiss", $new_report_id_admin_created, $admin_id_current, $file_path_uploaded, $original_filename_uploaded);
                            if (!$stmt_evidence_insert->execute()) { error_log("Admin Create Report: Failed to insert into evidence table for report {$new_report_id_admin_created}: " . $stmt_evidence_insert->error); }
                            $stmt_evidence_insert->close();
                        }
                    }
                    $log_new_val_create_admin = "Admin ID: {$admin_id_current} created Report ID: {$new_report_id_admin_created} for User ID: {$user_id_for_report}, Title: '{$report_title_create}'";
                    recordAuditLog($conn, $admin_id_current, "ADMIN_REPORT_CREATED", "reports", "report_id: {$new_report_id_admin_created}", null, $log_new_val_create_admin);
                    $_SESSION['admin_dashboard_message'] = "Report (ID: {$new_report_id_admin_created}) created successfully!";
                    $_SESSION['admin_dashboard_message_type'] = 'success';
                    if ($conn) { $conn->close(); }
                    header("Location: admin_dashboard.php?view=view_reports");
                    exit();
                } else { $errors[] = "Database error: Failed to create report."; if ($file_path_uploaded && file_exists($file_path_uploaded)) { unlink($file_path_uploaded); }}
                $stmt_insert_report->close();
            } else { $errors[] = "Database error: Failed to prepare report creation."; if ($file_path_uploaded && file_exists($file_path_uploaded)) { unlink($file_path_uploaded); }}
        }
    }

    if (!empty($errors)) {
        $_SESSION['admin_message'] = implode("<br>", $errors);
        $_SESSION['admin_message_type'] = 'danger';
        $_SESSION['admin_postdata'] = $_POST;
        if ($conn) { $conn->close(); }
        header("Location: create_report_admin.php");
        exit();
    }
}

// --- 6. Fetch users list ---
$users_list = [];
if ($conn && !$conn->connect_error) {
    $users_sql = "SELECT user_id, name, email FROM users WHERE user_type = 'public' ORDER BY name";
    $users_result = $conn->query($users_sql);
    if ($users_result) {
        while ($user_row = $users_result->fetch_assoc()) { $users_list[] = $user_row; }
    } else {
         if($message === null) { $message = "Error loading user list."; $message_type = 'warning'; }
    }
}

// --- 7. Close DB connection ---
if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) { $conn->close(); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Report for User - Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css">
    <link rel="stylesheet" href="admin_create_report.css"> <!-- New Stylesheet -->
</head>
<body>
    <div class="container main-container my-4">
        <div class="page-header">
            <h2><i class="fas fa-plus-circle me-2"></i>Create a New Report</h2>
            <p class="text-muted">Manually file a new report on behalf of a system user.</p>
        </div>
        
        <?php if ($message !== null): ?>
            <div class="alert alert-<?php echo htmlspecialchars($message_type); ?> alert-dismissible fade show" role="alert">
                <?php echo $message; ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>

        <form method="POST" action="create_report_admin.php" enctype="multipart/form-data" id="createReportForm" novalidate>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
            <input type="hidden" name="user_id" id="user_id_hidden" value="<?php echo htmlspecialchars($postdata['user_id'] ?? ''); ?>" required>
            
            <div class="row g-4">
                <!-- Left Column: User Selection -->
                <div class="col-lg-5">
                    <div class="card form-section-card">
                        <div class="card-header">1. Select User</div>
                        <div class="card-body">
                            <div class="user-search-container">
                                <label for="userSearch" class="form-label">Search by Name or Email</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-search"></i></span>
                                    <input type="text" id="userSearch" class="form-control" autocomplete="off" placeholder="Start typing...">
                                    <button class="btn btn-outline-secondary" type="button" data-bs-toggle="modal" data-bs-target="#allUsersModal" title="View All Users">List All</button>
                                </div>
                                <div id="userSearchResults"></div>
                            </div>
                            <div id="selected-user-card" style="display: none;">
                                <h6 class="mb-1 user-name"></h6>
                                <p class="mb-0 user-email"></p>
                            </div>
                            <div class="invalid-feedback" id="user-selection-error" style="display:none;">A user must be selected.</div>
                        </div>
                    </div>
                </div>

                <!-- Right Column: Report Details -->
                <div class="col-lg-7">
                    <div class="card form-section-card">
                        <div class="card-header">2. Report Information</div>
                        <div class="card-body">
                            <div class="mb-3">
                                <label for="report_title" class="form-label">Report Title <span class="text-danger">*</span></label>
                                <input type="text" name="report_title" id="report_title" class="form-control" value="<?php echo htmlspecialchars($postdata['report_title'] ?? ''); ?>" required>
                            </div>
                            <div class="mb-3">
                                <label for="report_details" class="form-label">Report Details <span class="text-danger">*</span></label>
                                <textarea name="report_details" id="report_details" class="form-control" rows="6" required><?php echo htmlspecialchars($postdata['report_details'] ?? ''); ?></textarea>
                            </div>
                            <div class="row gx-3">
                                <div class="col-md-6 mb-3">
                                    <label for="category" class="form-label">Category <span class="text-danger">*</span></label>
                                    <select name="category" id="category" class="form-select" required onchange="showOtherCategoryInput(this.value)">
                                        <option value="" disabled <?php echo empty($postdata['category']) ? 'selected' : ''; ?>>-- Select --</option>
                                        <?php $categories = ["Scam Call", "Online Fraud", "Fake Investment", "Phishing Email", "E-commerce Scam", "Love Scam", "Job Scam", "Lottery Scam", "Rental Scam", "Identity Theft", "Loan Scam", "Other"]; $selected_category = $postdata['category'] ?? ''; foreach ($categories as $cat) { $selected = ($cat === $selected_category) ? 'selected' : ''; echo "<option value=\"" . htmlspecialchars($cat) . "\" $selected>" . htmlspecialchars($cat) . "</option>"; } ?>
                                    </select>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label for="authority_type" class="form-label">Assign to <span class="text-danger">*</span></label>
                                    <select name="authority_type" id="authority_type" class="form-select" required>
                                        <option value="" disabled <?php echo empty($postdata['authority_type']) ? 'selected' : ''; ?>>-- Select --</option>
                                        <?php $authorities = ["PDRM", "BNM", "MCMC", "Not Sure"]; $selected_authority = $postdata['authority_type'] ?? ''; foreach ($authorities as $auth) { $selected = ($auth === $selected_authority) ? 'selected' : ''; $label = ($auth === 'Not Sure') ? "Not Sure" : $auth; echo "<option value=\"" . htmlspecialchars($auth) . "\" $selected>" . htmlspecialchars($label) . "</option>"; } ?>
                                    </select>
                                </div>
                            </div>
                            <div class="mb-3" id="other-category-group" style="<?php echo ($postdata['category'] ?? '') === 'Other' ? 'display: block;' : 'display: none;'; ?>">
                                <label for="other_category" class="form-label">Specify Other Category <span class="text-danger" style="display:none;">*</span></label>
                                <input type="text" name="other_category" id="other_category" class="form-control" value="<?php echo htmlspecialchars($postdata['other_category'] ?? ''); ?>">
                            </div>
                            <div class="mb-3">
                                <label for="evidence" class="form-label">Upload Evidence (Optional)</label>
                                <input type="file" name="evidence" id="evidence" class="form-control">
                                <div class="form-text">Max 10MB.</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="d-flex justify-content-between mt-4">
                <a href="admin_dashboard.php" class="btn btn-secondary"><i class="fas fa-times me-2"></i>Cancel</a>
                <button type="submit" name="create_report_action" class="btn btn-primary btn-lg" <?php if($critical_error) echo 'disabled'; ?>><i class="fas fa-save me-2"></i>Create Report</button>
            </div>
        </form>
    </div>

    <!-- All Users Modal -->
    <div class="modal fade" id="allUsersModal" tabindex="-1" aria-labelledby="allUsersModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title" id="allUsersModalLabel">All Public Users</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                <div class="modal-body">
                    <?php if (!empty($users_list)): ?>
                        <table class="table table-striped table-hover table-sm"><thead><tr><th>Name</th><th>Email</th><th>Action</th></tr></thead><tbody>
                        <?php foreach ($users_list as $modal_user): ?><tr><td><?php echo htmlspecialchars($modal_user['name']); ?></td><td><?php echo htmlspecialchars($modal_user['email']); ?></td><td><button type="button" class="btn btn-primary select-user-btn" data-user-id="<?php echo $modal_user['user_id']; ?>" data-user-name="<?php echo htmlspecialchars($modal_user['name']); ?>" data-user-email="<?php echo htmlspecialchars($modal_user['email']); ?>" data-bs-dismiss="modal">Select</button></td></tr><?php endforeach; ?>
                        </tbody></table>
                    <?php else: ?><p class="text-muted">No public users found.</p><?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const userSearchInput = document.getElementById('userSearch');
        const userSearchResults = document.getElementById('userSearchResults');
        const hiddenUserIdInput = document.getElementById('user_id_hidden');
        const selectedUserCard = document.getElementById('selected-user-card');
        const selectedUserName = selectedUserCard.querySelector('.user-name');
        const selectedUserEmail = selectedUserCard.querySelector('.user-email');
        const userSelectionError = document.getElementById('user-selection-error');
        const allUsers = <?php echo json_encode($users_list); ?> || [];
        let debounceTimer;

        userSearchInput.addEventListener('input', () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => filterAndDisplayUsers(userSearchInput.value), 250);
        });

        function filterAndDisplayUsers(searchTerm) {
            const filter = searchTerm.trim().toUpperCase();
            userSearchResults.innerHTML = '';
            userSearchResults.style.display = 'none';

            if (filter === '') return;
            const matches = allUsers.filter(user => (user.name.toUpperCase().includes(filter) || user.email.toUpperCase().includes(filter))).slice(0, 10);

            if (matches.length > 0) {
                matches.forEach(user => {
                    const suggestionDiv = document.createElement('div');
                    suggestionDiv.classList.add('suggestion-item');
                    suggestionDiv.textContent = `${user.name} (${user.email})`;
                    suggestionDiv.addEventListener('click', () => selectUser(user.user_id, user.name, user.email));
                    userSearchResults.appendChild(suggestionDiv);
                });
                userSearchResults.style.display = 'block';
            }
        }

        function selectUser(userId, userName, userEmail) {
            hiddenUserIdInput.value = userId;
            selectedUserName.textContent = userName;
            selectedUserEmail.textContent = userEmail;
            selectedUserCard.style.display = 'block';
            userSearchInput.value = '';
            userSearchResults.style.display = 'none';
            userSelectionError.style.display = 'none';
        }

        document.addEventListener('click', function(event) {
            if (!userSearchInput.contains(event.target) && !userSearchResults.contains(event.target)) {
                userSearchResults.style.display = 'none';
            }
            if (event.target.classList.contains('select-user-btn')) {
                selectUser(event.target.dataset.userId, event.target.dataset.userName, event.target.dataset.userEmail);
            }
        });
        
        document.getElementById('createReportForm').addEventListener('submit', function(event) {
            if (!hiddenUserIdInput.value) {
                event.preventDefault();
                userSelectionError.style.display = 'block';
                userSearchInput.focus();
            }
        });

        function showOtherCategoryInput(value) {
            const otherGroup = document.getElementById("other-category-group");
            const otherInput = document.getElementById("other_category");
            const otherLabelAsterisk = otherGroup.querySelector('.text-danger');
            if (value === "Other") {
                otherGroup.style.display = "block";
                otherInput.required = true;
                otherLabelAsterisk.style.display = '';
            } else {
                otherGroup.style.display = "none";
                otherInput.required = false;
                otherInput.value = '';
                otherLabelAsterisk.style.display = 'none';
            }
        }
    </script>
</body>
</html>