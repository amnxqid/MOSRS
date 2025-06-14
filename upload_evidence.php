<?php
session_start();
require_once "db.php";
require_once "functions.php";

// 1. Authentication Check
if (!isset($_SESSION['user_id'])) {
    $_SESSION['redirect_url'] = $_SERVER['REQUEST_URI'];
    $_SESSION['login_message'] = "Please log in to upload evidence.";
    $_SESSION['login_message_type'] = "warning";
    header("Location: login.php");
    exit();
}
if (isset($_SESSION['redirect_url']) && strpos($_SESSION['redirect_url'], 'upload_evidence.php') !== false) {
    unset($_SESSION['redirect_url']);
}

$csrf_token = generateCsrfToken();
$user_id_upload = $_SESSION['user_id'];
$user_dashboard_link = ($_SESSION['user_type'] ?? 'public') === 'admin' ? 'admin_dashboard.php' : 'user_dashboard.php';

$errors = [];
$success_message = '';
$target_dir = "uploads/";

// --- Handle POST Request ---
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    verifyCsrfToken(); // CSRF Check

    if (!$conn || $conn->connect_error) {
        $_SESSION['upload_message'] = "Database connection error. Cannot upload evidence.";
        $_SESSION['upload_message_type'] = 'danger';
        header("Location: upload_evidence.php" . (isset($_POST['report_id']) ? "?report_id=".(int)$_POST['report_id'] : ""));
        exit();
    }

    $report_id_upload = isset($_POST['report_id']) ? filter_input(INPUT_POST, 'report_id', FILTER_VALIDATE_INT) : 0;

    if ($report_id_upload <= 0) { $errors[] = "Please select a valid report from the list."; }
    if (!isset($_FILES["evidence"]) || $_FILES["evidence"]["error"] == UPLOAD_ERR_NO_FILE) { $errors[] = "Please select a file to upload."; }
    elseif ($_FILES["evidence"]["error"] != UPLOAD_ERR_OK) {
        $upload_errors_map_upload = [ UPLOAD_ERR_INI_SIZE => 'File exceeds server upload limit.', UPLOAD_ERR_FORM_SIZE => 'File exceeds form upload limit.', UPLOAD_ERR_PARTIAL => 'File was only partially uploaded.', UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder.', UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.', UPLOAD_ERR_EXTENSION => 'A PHP extension stopped the file upload.' ];
        $error_code_upload = $_FILES["evidence"]["error"]; $errors[] = $upload_errors_map_upload[$error_code_upload] ?? 'An unknown file upload error occurred.';
        error_log("Upload Evidence Error Code {$error_code_upload} for user {$user_id_upload}, report {$report_id_upload}");
    }

    if (empty($errors)) {
        // Verify user ownership of the report (admins can upload to any)
        if ($_SESSION['user_type'] !== 'admin') {
            $sql_verify_upload = "SELECT report_id FROM reports WHERE report_id = ? AND user_id = ?";
            $stmt_verify_upload = $conn->prepare($sql_verify_upload);
            if ($stmt_verify_upload) {
                $stmt_verify_upload->bind_param("ii", $report_id_upload, $user_id_upload);
                $stmt_verify_upload->execute(); $stmt_verify_upload->store_result();
                if ($stmt_verify_upload->num_rows === 0) {
                     $errors[] = "Invalid selection or you do not have permission for Report ID: {$report_id_upload}.";
                }
                $stmt_verify_upload->close();
            } else { $errors[] = "Database error during report verification."; error_log("Upload Evidence - Prepare failed (verify): " . $conn->error); }
        }
    }

    if (empty($errors)) {
        $original_filename_up = basename($_FILES["evidence"]["name"]);
        $file_tmp_path_up = $_FILES["evidence"]["tmp_name"];
        $file_size_up = $_FILES["evidence"]["size"];
        $file_info_up = pathinfo($original_filename_up);
        $file_ext_up = strtolower($file_info_up['extension'] ?? '');
        $allowed_types_up = ["jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "txt", "heic", "webp"];
        $max_file_size_up = 10 * 1024 * 1024;
        if (!in_array($file_ext_up, $allowed_types_up)) { $errors[] = "Invalid file type ('." . htmlspecialchars($file_ext_up) . "')."; }
        if ($file_size_up > $max_file_size_up) { $errors[] = "File is too large (Max 10MB)."; }
    }

    if (empty($errors)) {
        if (!is_dir($target_dir)) { if (!mkdir($target_dir, 0755, true)) { $errors[] = "Failed to create upload directory."; error_log("Upload Evidence Error: Failed to create directory {$target_dir}"); }}
        if (empty($errors) && !is_writable($target_dir)) { $errors[] = "Upload directory is not writable."; error_log("Upload Evidence Error: Upload directory {$target_dir} is not writable.");}
        if (empty($errors)) {
            $safe_original_filename_up = preg_replace("/[^A-Za-z0-9._-]/", "_", $original_filename_up);
            $safe_original_filename_up = substr($safe_original_filename_up, 0, 240);
            $unique_filename_up = uniqid('evidence_' . $report_id_upload . '_', true) . '.' . $file_ext_up;
            $target_file_path_up = $target_dir . $unique_filename_up;

            if (move_uploaded_file($file_tmp_path_up, $target_file_path_up)) {
                $stmt_insert_ev = $conn->prepare("INSERT INTO evidence (report_id, user_id, file_path, original_filename, uploaded_at) VALUES (?, ?, ?, ?, NOW())");
                if ($stmt_insert_ev) {
                    $stmt_insert_ev->bind_param("iiss", $report_id_upload, $user_id_upload, $target_file_path_up, $safe_original_filename_up);
                    if ($stmt_insert_ev->execute()) {
                        $new_evidence_id = $stmt_insert_ev->insert_id;
                        $success_message = "Evidence '" . htmlspecialchars($original_filename_up) . "' uploaded successfully for Report ID: " . $report_id_upload;
                        $log_action_evidence = ($_SESSION['user_type'] === 'admin') ? "ADMIN_EVIDENCE_UPLOADED" : "USER_EVIDENCE_UPLOADED";
                        $log_new_value_evidence = "User ID: {$user_id_upload} uploaded evidence '{$safe_original_filename_up}' for Report ID: {$report_id_upload}.";
                        recordAuditLog($conn, $user_id_upload, $log_action_evidence, "evidence", "evidence_id: {$new_evidence_id}", null, $log_new_value_evidence);
                    } else { $errors[] = "Database error saving evidence record."; if (file_exists($target_file_path_up)) { unlink($target_file_path_up); } }
                    $stmt_insert_ev->close();
                } else { $errors[] = "Database error preparing evidence record."; if (file_exists($target_file_path_up)) { unlink($target_file_path_up); } }
            } else { $errors[] = "Server error: Failed to move uploaded file."; }
        }
    }

    if (!empty($errors)) { $_SESSION['upload_message'] = implode("<br>", $errors); $_SESSION['upload_message_type'] = 'danger'; }
    elseif (!empty($success_message)) { $_SESSION['upload_message'] = $success_message; $_SESSION['upload_message_type'] = 'success'; }
    if ($conn) { $conn->close(); }
    header("Location: upload_evidence.php" . ($report_id_upload > 0 ? "?report_id=" . $report_id_upload : ""));
    exit();
}

$report_id_from_get = isset($_GET['report_id']) ? filter_input(INPUT_GET, 'report_id', FILTER_VALIDATE_INT) : 0;
$user_reports = []; $fetch_user_reports_error = '';
if (!isset($conn) || !$conn || $conn->connect_error) { include 'db.php'; }

if ($conn && !$conn->connect_error) {
    // If admin, show all reports. If user, show only their reports.
    $sql_user_reports = "SELECT report_id, report_title FROM reports";
    if ($_SESSION['user_type'] !== 'admin') {
        $sql_user_reports .= " WHERE user_id = ?";
    }
    $sql_user_reports .= " ORDER BY created_at DESC";
    
    $stmt_user_reports = $conn->prepare($sql_user_reports);
    if ($stmt_user_reports) {
        if ($_SESSION['user_type'] !== 'admin') {
            $stmt_user_reports->bind_param("i", $user_id_upload);
        }
        if ($stmt_user_reports->execute()) {
            $result_user_reports = $stmt_user_reports->get_result();
            while ($row_rep = $result_user_reports->fetch_assoc()) { $user_reports[] = $row_rep; }
            if (empty($user_reports)) { $fetch_user_reports_error = "No reports found to upload evidence to."; }
        } else { $fetch_user_reports_error = "Error fetching reports list."; }
        $stmt_user_reports->close();
    } else { $fetch_user_reports_error = "Database error preparing to fetch reports."; }
} else { $fetch_user_reports_error = "Database connection failed."; }

$display_message = $_SESSION['upload_message'] ?? null;
$message_type_display = $_SESSION['upload_message_type'] ?? 'info';
unset($_SESSION['upload_message'], $_SESSION['upload_message_type']);
if (isset($conn) && $conn) { $conn->close(); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Evidence - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css">
    <link rel="stylesheet" href="upload_styles.css"> <!-- Our new styles -->
</head>
<body>
    <div class="container main-container d-flex align-items-center py-4">
        <div class="row justify-content-center w-100">
            <div class="col-md-8 col-lg-6">
                <div class="card upload-card">
                    <div class="upload-card-header">
                        <div class="icon-wrapper"><i class="fas fa-paperclip"></i></div>
                        <h2 class="mb-0">Upload Evidence</h2>
                        <p class="mb-0 opacity-75">Attach supporting files to your report</p>
                    </div>
                    <div class="card-body p-4 p-md-5">
                        <?php if (isset($display_message)) : ?><div class="alert alert-<?php echo htmlspecialchars($message_type_display); ?> alert-dismissible fade show"><?php echo $display_message; ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>
                        
                        <?php if (!empty($fetch_user_reports_error)): ?>
                            <div class="alert alert-warning text-center"><?php echo htmlspecialchars($fetch_user_reports_error); ?></div>
                            <div class="text-center mt-3"><a href="<?php echo $user_dashboard_link; ?>" class="btn btn-secondary"><i class="fas fa-arrow-left"></i> Back to Dashboard</a></div>
                        <?php else: ?>
                            <form action="upload_evidence.php" method="post" enctype="multipart/form-data">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                                
                                <div class="mb-4">
                                    <label for="report_id" class="form-label fs-5">1. Select the Associated Report</label>
                                    <select name="report_id" id="report_id" class="form-select form-select-lg" required>
                                        <option value="" disabled <?php echo ($report_id_from_get <= 0 && empty($_POST['report_id'])) ? 'selected' : ''; ?>>-- Please Select a Report --</option>
                                        <?php foreach ($user_reports as $user_report):
                                            $is_selected = ($report_id_from_get == $user_report['report_id']) || (isset($_POST['report_id']) && $_POST['report_id'] == $user_report['report_id']);
                                            $title_snippet = htmlspecialchars(substr($user_report['report_title'], 0, 70) . (strlen($user_report['report_title']) > 70 ? '...' : ''));
                                        ?>
                                            <option value="<?php echo $user_report['report_id']; ?>" <?php echo $is_selected ? 'selected' : ''; ?>><?php echo $title_snippet . " (ID: " . $user_report['report_id'] . ")"; ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>

                                <div class="mb-3">
                                    <label for="evidence" class="form-label fs-5">2. Choose or Drag a File</label>
                                    <div class="file-upload-wrapper" id="file-upload-area">
                                        <input type="file" name="evidence" id="evidence" required>
                                        <div class="file-upload-content">
                                            <i class="fas fa-cloud-upload-alt file-upload-icon"></i>
                                            <p class="file-upload-text">Drag & drop file here, or <span>browse</span>.</p>
                                            <p id="file-upload-filename" class="fw-bold"></p>
                                        </div>
                                    </div>
                                    <div class="form-text mt-2">Max 10MB. Allowed: JPG, PNG, PDF, DOCX, TXT.</div>
                                </div>
                                
                                <div class="d-flex justify-content-between align-items-center mt-4">
                                    <a href="<?php echo $user_dashboard_link; ?>" class="btn btn-outline-secondary">Cancel</a>
                                    <button type="submit" class="btn btn-primary btn-lg"><i class="fas fa-upload me-2"></i>Upload File</button>
                                </div>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function () {
            const fileUploadArea = document.getElementById('file-upload-area');
            const fileInput = document.getElementById('evidence');
            const fileNameDisplay = document.getElementById('file-upload-filename');

            if (fileUploadArea) {
                fileUploadArea.addEventListener('dragover', (e) => {
                    e.preventDefault();
                    fileUploadArea.classList.add('dragover');
                });
                fileUploadArea.addEventListener('dragleave', () => {
                    fileUploadArea.classList.remove('dragover');
                });
                fileUploadArea.addEventListener('drop', (e) => {
                    e.preventDefault();
                    fileUploadArea.classList.remove('dragover');
                    if (e.dataTransfer.files.length) {
                        fileInput.files = e.dataTransfer.files;
                        fileNameDisplay.textContent = fileInput.files[0].name;
                    }
                });
                fileInput.addEventListener('change', () => {
                    if (fileInput.files.length) {
                        fileNameDisplay.textContent = fileInput.files[0].name;
                    } else {
                        fileNameDisplay.textContent = '';
                    }
                });
            }
        });
    </script>
</body>
</html>