<?php
session_start();
require_once "db.php";
require_once "functions.php";

if (!isset($_SESSION['user_id'])) {
    $_SESSION['redirect_url'] = 'report.php';
    $_SESSION['login_message'] = "Please log in to submit a report.";
    $_SESSION['login_message_type'] = "warning";
    header("Location: login.php");
    exit();
}
if (isset($_SESSION['redirect_url']) && $_SESSION['redirect_url'] == 'report.php') {
    unset($_SESSION['redirect_url']);
}

$csrf_token = generateCsrfToken();
$user_id_report = $_SESSION['user_id'];
$user_dashboard_link = ($_SESSION['user_type'] ?? 'public') === 'admin' ? 'admin_dashboard.php' : 'user_dashboard.php';

$errors = [];
$pending_status_id = null;
$uploaded_file_path = NULL;
$uploaded_original_filename = NULL;

if (!$conn || $conn->connect_error) {
    $_SESSION['report_errors'] = ["Database connection error."];
    header("Location: report.php");
    exit();
}

$status_sql = "SELECT status_id FROM report_status WHERE status_name = 'Pending'";
$status_result = $conn->query($status_sql);
if ($status_result && $status_result->num_rows > 0) {
    $status_row = $status_result->fetch_assoc();
    $pending_status_id = $status_row['status_id'];
} else {
    $error_message_critical = "System configuration error: 'Pending' status is missing.";
    error_log($error_message_critical);
    $_SESSION['report_errors'] = [$error_message_critical];
    if ($conn) { $conn->close(); }
    header("Location: report.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    verifyCsrfToken();
    if (!$conn || $conn->connect_error) {
        $_SESSION['report_errors'] = ["Database connection error."];
        $_SESSION['report_postdata'] = $_POST;
        header("Location: report.php");
        exit();
    }

    $report_title = trim($_POST['title']);
    $report_details = trim($_POST['report_details']);
    $category = $_POST['category'] ?? '';
    $other_category = trim($_POST['other_category'] ?? '');
    $authority_type = $_POST['authority_type'] ?? '';

    if (empty($report_title)) { $errors[] = "Report Title is required."; }
    if (empty($report_details)) { $errors[] = "Report Details are required."; }
    if (empty($category)) { $errors[] = "Please select a Category."; }
    if ($category === "Other" && empty($other_category)) { $errors[] = "Please specify the category if 'Other' is selected."; }
    if ($authority_type === '') { $errors[] = "Please select the relevant Authority Type or 'Not Sure'."; }

    $final_category = ($category === "Other") ? $other_category : $category;

    if (isset($_FILES["evidence"]) && $_FILES["evidence"]["error"] == UPLOAD_ERR_OK) {
        $target_dir = "uploads/";
        if (!is_dir($target_dir)) { if (!mkdir($target_dir, 0755, true)) { $errors[] = "Server error: Failed to create upload directory."; error_log("Report.php Error: Failed to create directory {$target_dir}"); }}
        if (empty($errors)) {
            $original_filename = basename($_FILES["evidence"]["name"]);
            $file_ext = strtolower(pathinfo($original_filename, PATHINFO_EXTENSION));
            $allowed_types = ["jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "txt", "heic", "webp"];
            if (in_array($file_ext, $allowed_types)) {
                $safe_original_filename = preg_replace("/[^A-Za-z0-9._-]/", "_", $original_filename);
                $unique_filename = uniqid('report_initial_', true) . '.' . $file_ext;
                $target_file = $target_dir . $unique_filename;
                if (move_uploaded_file($_FILES["evidence"]["tmp_name"], $target_file)) {
                    $uploaded_file_path = $target_file;
                    $uploaded_original_filename = $safe_original_filename;
                } else { $errors[] = "Server error moving uploaded file."; }
            } else { $errors[] = "Invalid file type."; }
        }
    }

    if (empty($errors)) {
        $new_report_id = null;
        $stmt_report = $conn->prepare("INSERT INTO reports (user_id, report_title, report_details, category, authority_type, evidence, created_at, status_id) VALUES (?, ?, ?, ?, ?, ?, NOW(), ?)");
        if ($stmt_report) {
            $stmt_report->bind_param("isssssi", $user_id_report, $report_title, $report_details, $final_category, $authority_type, $uploaded_file_path, $pending_status_id);
            if ($stmt_report->execute()) {
                $new_report_id = $conn->insert_id;
                if ($new_report_id && $uploaded_file_path && $uploaded_original_filename) {
                    $stmt_evidence = $conn->prepare("INSERT INTO evidence (report_id, user_id, file_path, original_filename, uploaded_at) VALUES (?, ?, ?, ?, NOW())");
                    if ($stmt_evidence) {
                        $stmt_evidence->bind_param("iiss", $new_report_id, $user_id_report, $uploaded_file_path, $uploaded_original_filename);
                        if (!$stmt_evidence->execute()) { $errors[] = "Report submitted, but failed to save evidence record."; }
                        $stmt_evidence->close();
                    }
                }
                if (empty($errors)) {
                    $log_new_value_submit = "User ID: {$user_id_report} submitted Report ID: {$new_report_id}, Title: '{$report_title}'";
                    recordAuditLog($conn, $user_id_report, "USER_REPORT_SUBMITTED", "reports", "report_id: {$new_report_id}", null, $log_new_value_submit);
                }
            } else { $errors[] = "Failed to submit report (DB Error)."; }
            $stmt_report->close();
        } else { $errors[] = "Failed to submit report (DB Prepare Error)."; }
    }

    if (empty($errors)) {
        $_SESSION['dashboard_message'] = "Report submitted successfully! Your Report ID is {$new_report_id}. Thank you.";
        $_SESSION['dashboard_message_type'] = "success";
        if ($conn) { $conn->close(); }
        header("Location: user_dashboard.php");
        exit();
    } else {
        $_SESSION['report_errors'] = $errors;
        $_SESSION['report_postdata'] = $_POST;
        if ($conn) { $conn->close(); }
        header("Location: report.php");
        exit();
    }
}

$display_errors = $_SESSION['report_errors'] ?? [];
$postdata = $_SESSION['report_postdata'] ?? [];
unset($_SESSION['report_errors'], $_SESSION['report_postdata']);
if (isset($conn) && $conn) { $conn->close(); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Submit a New Report - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css">
    <link rel="stylesheet" href="report_form_styles.css"> <!-- Our new styles -->
</head>
<body>
<header class="bg-primary text-white text-center p-3 shadow-sm position-relative">
    <a href="<?php echo $user_dashboard_link; ?>" class="header-logo">
        <img src="kementerian.jpg" alt="Logo" class="d-none d-md-block" style="height: 40px;" onerror="this.onerror=null; this.style.display='none';">
    </a>
    <h2 class="mb-0">Submit a New Report</h2>
</header>
<div class="container main-container my-4">
    <div class="row justify-content-center">
         <div class="col-md-10 col-lg-8">
             <div class="card shadow-lg border-0">
                <div class="card-body p-4 p-md-5">

                    <!-- Progress Bar -->
                    <div class="progress-container">
                        <div class="progress-bar-steps">
                            <div class="progress-bar-line" id="progress-line"></div>
                            <div class="step active" id="step1"><i class="fas fa-bullhorn"></i><span class="step-label">Incident</span></div>
                            <div class="step" id="step2"><i class="fas fa-align-left"></i><span class="step-label">Details</span></div>
                            <div class="step" id="step3"><i class="fas fa-paperclip"></i><span class="step-label">Evidence</span></div>
                        </div>
                    </div>
                    
                    <?php if (!empty($display_errors)) : ?>
                        <div class="alert alert-danger" id="error-alert"><strong>Please correct the issues and try again:</strong><br><ul><?php foreach ($display_errors as $err) : ?><li><?php echo htmlspecialchars($err); ?></li><?php endforeach; ?></ul></div>
                    <?php endif; ?>

                    <form action="report.php" method="POST" enctype="multipart/form-data" id="reportForm">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">

                        <!-- Step 1: The Incident -->
                        <div class="form-step active" id="form-step-1">
                            <h4 class="mb-4 text-center">Step 1: The Incident</h4>
                            <div class="mb-3">
                                <label for="title" class="form-label fs-5">Report Title <span class="text-danger">*</span></label>
                                <input type="text" name="title" id="title" class="form-control form-control-lg" value="<?php echo htmlspecialchars($postdata['title'] ?? ''); ?>" required placeholder="e.g., Fake LHDN Phone Call Scam">
                            </div>
                            <div class="mb-3">
                                <label for="category" class="form-label fs-5">Scam Category <span class="text-danger">*</span></label>
                                <select name="category" id="category" class="form-select form-select-lg" required onchange="document.getElementById('other-category-group').style.display = this.value === 'Other' ? 'block' : 'none';">
                                    <option value="" disabled <?php echo empty($postdata['category']) ? 'selected' : ''; ?>>-- Please Select a Category --</option>
                                    <?php $categories = ["Scam Call", "Online Fraud", "Fake Investment", "Phishing Email", "E-commerce Scam", "Love Scam", "Job Scam", "Lottery Scam", "Rental Scam", "Identity Theft", "Loan Scam", "Other"];
                                    foreach ($categories as $cat) {
                                        $selected = (isset($postdata['category']) && $postdata['category'] == $cat) ? 'selected' : '';
                                        echo "<option value=\"" . htmlspecialchars($cat) . "\" $selected>" . htmlspecialchars($cat) . "</option>";
                                    } ?>
                                </select>
                            </div>
                            <div class="mb-3" id="other-category-group" style="<?php echo (isset($postdata['category']) && $postdata['category'] === 'Other') ? 'display: block;' : 'display: none;'; ?>">
                                <label for="other_category" class="form-label">If Other, Please Specify <span class="text-danger">*</span></label>
                                <input type="text" name="other_category" id="other_category" class="form-control" value="<?php echo htmlspecialchars($postdata['other_category'] ?? ''); ?>">
                            </div>
                        </div>

                        <!-- Step 2: Details -->
                        <div class="form-step" id="form-step-2">
                            <h4 class="mb-4 text-center">Step 2: Report Details</h4>
                            <div class="mb-3">
                                <label for="report_details" class="form-label fs-5">Describe what happened <span class="text-danger">*</span></label>
                                <textarea name="report_details" id="report_details" class="form-control" rows="8" required placeholder="Please provide as much detail as possible, including dates, names, websites, phone numbers, and the sequence of events."><?php echo htmlspecialchars($postdata['report_details'] ?? ''); ?></textarea>
                            </div>
                        </div>

                        <!-- Step 3: Evidence -->
                        <div class="form-step" id="form-step-3">
                            <h4 class="mb-4 text-center">Step 3: Evidence & Assignment</h4>
                            <div class="mb-4">
                                <label class="form-label fs-5">Upload Evidence (Optional)</label>
                                <div class="file-upload-wrapper" id="file-upload-area">
                                    <input type="file" name="evidence" id="evidence">
                                    <div class="file-upload-content">
                                        <i class="fas fa-cloud-upload-alt file-upload-icon"></i>
                                        <p class="file-upload-text">Drag & drop your file here, or <span>browse</span> to upload.</p>
                                        <p id="file-upload-filename"></p>
                                    </div>
                                </div>
                                <div class="form-text">Max 10MB. Allowed: JPG, PNG, PDF, DOCX, TXT.</div>
                            </div>
                            <div class="mb-3">
                                <label for="authority_type" class="form-label fs-5">Relevant Authority <span class="text-danger">*</span></label>
                                <select name="authority_type" id="authority_type" class="form-select form-select-lg" required>
                                    <option value="" disabled <?php echo empty($postdata['authority_type']) ? 'selected' : ''; ?>>-- Select an Authority or "Not Sure" --</option>
                                    <?php $authorities = ["PDRM" => "PDRM (Police - General Crime)", "BNM" => "BNM (Bank Negara - Financial/Banking)", "MCMC" => "MCMC (Communications - Phone/SMS/Website)", "Not Sure" => "I'm Not Sure"];
                                    foreach ($authorities as $value => $label) {
                                        $selected = (isset($postdata['authority_type']) && $postdata['authority_type'] == $value) ? 'selected' : '';
                                        echo "<option value=\"" . htmlspecialchars($value) . "\" $selected>" . htmlspecialchars($label) . "</option>";
                                    } ?>
                                </select>
                            </div>
                        </div>

                        <!-- Navigation Buttons -->
                        <div class="form-navigation-btns">
                            <button type="button" class="btn btn-secondary" id="btn-prev" style="display: none;">Previous</button>
                            <button type="button" class="btn btn-primary" id="btn-next">Next</button>
                            <button type="submit" class="btn btn-success" id="btn-submit" style="display: none;">Submit Report</button>
                        </div>
                    </form>
                </div>
             </div>
         </div>
    </div>
</div>
<footer class="footer mt-auto"><div class="container"><span>© MOSRS <?php echo date("Y"); ?></span></div></footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function () {
    const steps = document.querySelectorAll('.step');
    const formSteps = document.querySelectorAll('.form-step');
    const progressLine = document.getElementById('progress-line');
    const btnNext = document.getElementById('btn-next');
    const btnPrev = document.getElementById('btn-prev');
    const btnSubmit = document.getElementById('btn-submit');
    let currentStep = 0;

    btnNext.addEventListener('click', () => {
        if (validateStep(currentStep)) {
            if (currentStep < formSteps.length - 1) {
                currentStep++;
                updateFormSteps();
            }
        }
    });

    btnPrev.addEventListener('click', () => {
        if (currentStep > 0) {
            currentStep--;
            updateFormSteps();
        }
    });

    function updateFormSteps() {
        formSteps.forEach((step, index) => {
            step.classList.toggle('active', index === currentStep);
        });
        updateProgressBar();
        updateNavButtons();
    }

    function updateProgressBar() {
        steps.forEach((step, index) => {
            if (index < currentStep + 1) {
                step.classList.add('active');
            } else {
                step.classList.remove('active');
            }
        });
        const progressWidth = (currentStep / (steps.length - 1)) * 100;
        progressLine.style.width = progressWidth + '%';
    }

    function updateNavButtons() {
        btnPrev.style.display = currentStep > 0 ? 'inline-block' : 'none';
        btnNext.style.display = currentStep < formSteps.length - 1 ? 'inline-block' : 'none';
        btnSubmit.style.display = currentStep === formSteps.length - 1 ? 'inline-block' : 'none';
    }

    function validateStep(stepIndex) {
        const currentFormStep = formSteps[stepIndex];
        const inputs = currentFormStep.querySelectorAll('input[required], select[required], textarea[required]');
        let isValid = true;
        inputs.forEach(input => {
            if (!input.value.trim()) {
                input.classList.add('is-invalid');
                isValid = false;
            } else {
                input.classList.remove('is-invalid');
            }
            // Special check for 'Other' category
            if (input.id === 'other_category' && document.getElementById('category').value === 'Other' && !input.value.trim()) {
                input.classList.add('is-invalid');
                isValid = false;
            }
        });
        if (!isValid) {
            alert('Please fill out all required fields in this step.');
        }
        return isValid;
    }
    
    // File Upload Area Logic
    const fileUploadArea = document.getElementById('file-upload-area');
    const fileInput = document.getElementById('evidence');
    const fileNameDisplay = document.getElementById('file-upload-filename');

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
});
</script>
</body>
</html>