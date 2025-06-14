<?php
session_start();
require_once 'db.php';
require_once 'functions.php';
require_once 'email.php';

if (!isset($_SESSION['user_id'])) {
    $_SESSION['login_message'] = "Please log in to change your password.";
    $_SESSION['login_message_type'] = "warning";
    header("Location: login.php");
    exit();
}

$csrf_token = generateCsrfToken();

$user_id = $_SESSION['user_id'];
$user_name = $_SESSION['name'] ?? 'User';
$user_email_for_notification = '';

if (isset($conn) && $conn && !$conn->connect_error) {
    $stmt_email = $conn->prepare("SELECT email FROM users WHERE user_id = ?");
    if ($stmt_email) {
        $stmt_email->bind_param("i", $user_id);
        $stmt_email->execute();
        $result_email = $stmt_email->get_result();
        if ($user_email_data = $result_email->fetch_assoc()) {
            $user_email_for_notification = $user_email_data['email'];
        }
        $stmt_email->close();
    }
}

$errors = [];
$success_message = '';
$message_type = 'danger';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    verifyCsrfToken();

    if (!$conn || $conn->connect_error) {
        $errors[] = "Database connection error. Please try again later.";
        error_log("Change Password Error: DB connection failed for User ID: {$user_id}");
    } else {
        $current_password = $_POST['current_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        if (empty($current_password)) { $errors[] = "Current Password is required."; }
        if (empty($new_password)) { $errors[] = "New Password is required."; }
        elseif (strlen($new_password) < 8) { $errors[] = "New Password must be at least 8 characters long."; }
        elseif (!preg_match('/[A-Z]/', $new_password) || !preg_match('/[a-z]/', $new_password) || !preg_match('/[0-9]/', $new_password)) {
            $errors[] = "New Password requires at least one uppercase letter, one lowercase letter, and one number.";
        }
        if (empty($confirm_password)) { $errors[] = "Confirm New Password is required."; }
        elseif ($new_password !== $confirm_password) { $errors[] = "New Password and Confirm New Password do not match."; }
        if ($new_password === $current_password && !empty($new_password)) { $errors[] = "New password cannot be the same as the current password.";}

        if (empty($errors)) {
            $stmt_check = $conn->prepare("SELECT password FROM users WHERE user_id = ?");
            if ($stmt_check) {
                $stmt_check->bind_param("i", $user_id);
                $stmt_check->execute();
                $result_check = $stmt_check->get_result();
                $user_data = $result_check->fetch_assoc();
                $stmt_check->close();

                if ($user_data && password_verify($current_password, $user_data['password'])) {
                    $hashed_new_password = password_hash($new_password, PASSWORD_DEFAULT);
                    $stmt_update = $conn->prepare("UPDATE users SET password = ? WHERE user_id = ?");
                    if ($stmt_update) {
                        $stmt_update->bind_param("si", $hashed_new_password, $user_id);
                        if ($stmt_update->execute()) {
                            $success_message = "Password changed successfully!";
                            $message_type = "success";
                            recordAuditLog($conn, $user_id, "USER_PASSWORD_CHANGED_SUCCESS", "users", "password", "User changed their password", null);

                            if (!empty($user_email_for_notification) && function_exists('sendNotificationEmail')) {
                                $email_subject_notify = "MOSRS Account Security Alert: Password Changed";
                                $email_body_notify = "Dear " . htmlspecialchars($user_name) . ",\n\nThis email confirms that the password for your MOSRS account was recently changed.\n\nIf you did NOT make this change, please contact support immediately.\n\nSincerely,\nThe MOSRS Team";
                                $email_send_result = sendNotificationEmail($user_email_for_notification, $email_subject_notify, $email_body_notify, false);
                                if ($email_send_result === 'Message has been sent') {
                                    $success_message .= " A confirmation email has been sent.";
                                }
                            }
                        } else {
                            $errors[] = "Error updating password. Please try again.";
                            recordAuditLog($conn, $user_id, "USER_PASSWORD_CHANGE_FAILED_DB", "users", "password", "DB error during update", "Error: " . $stmt_update->error);
                        }
                        $stmt_update->close();
                    } else { $errors[] = "Database error preparing password update. Please try again."; }
                } else {
                    $errors[] = "Incorrect Current Password.";
                    recordAuditLog($conn, $user_id, "USER_PASSWORD_CHANGE_FAILED_WRONG_CURRENT", "users", "password", "Attempted password change with incorrect current password", null);
                }
            } else { $errors[] = "Database error verifying current password. Please try again."; }
        }
    }
}

$dashboard_link = match ($_SESSION['user_type'] ?? 'public') {
    'admin' => 'admin_dashboard.php',
    'authority' => 'authority_dashboard.php',
    default => 'user_dashboard.php',
};

if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Password - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css">
    <link rel="stylesheet" href="password_styles.css"> <!-- Link to the new separated CSS -->
    <style>
        body { display: flex; flex-direction: column; min-height: 100vh; background-color: #f8f9fa; }
        .main-container { flex: 1; }
        .header-logo { height: 50px; position: absolute; left: 15px; top: 50%; transform: translateY(-50%); }
        .footer { background-color: #343a40; color: white; padding: 1rem 0; text-align: center; margin-top: auto; }
        .password-help { font-size: 0.875em; color: #6c757d; }
    </style>
</head>
<body>
    <header class="bg-primary text-white text-center p-3 position-relative">
        <a href="<?php echo $dashboard_link; ?>"><img src="kementerian.jpg" alt="Logo" class="header-logo d-none d-md-block" onerror="this.onerror=null; this.style.display='none';"></a>
        <h2 class="mb-0">Change Your Password</h2>
    </header>

    <div class="container main-container my-4">
        <div class="row justify-content-center">
            <div class="col-md-7 col-lg-6">
                <div class="card shadow-sm border-0">
                    <div class="card-body p-4 p-md-5">
                        <h3 class="card-title text-center mb-4">Update Password</h3>
                        <?php if (!empty($errors)): ?>
                            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                <strong>Please correct the following errors:</strong><br>
                                <ul><?php foreach ($errors as $err): ?><li><?php echo htmlspecialchars($err); ?></li><?php endforeach; ?></ul>
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                            </div>
                        <?php endif; ?>
                        <?php if (!empty($success_message)): ?>
                            <div class="alert alert-<?php echo $message_type; ?> alert-dismissible fade show" role="alert">
                                <?php echo htmlspecialchars($success_message); ?>
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                            </div>
                        <?php endif; ?>
                        <form method="POST" action="change_password.php" id="changePasswordForm">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                            <div class="mb-3"><label for="current_password" class="form-label">Current Password:</label><input type="password" name="current_password" id="current_password" class="form-control" required></div>
                            
                            <div class="mb-3">
                                <label for="new_password" class="form-label">New Password:</label>
                                <input type="password" name="new_password" id="new_password" class="form-control" required aria-describedby="newPasswordHelp">
                                <div class="password-strength-meter">
                                    <div class="strength-bar" id="strength-bar"></div>
                                </div>
                                <div id="newPasswordHelp" class="form-text password-help">Min 8 chars, include uppercase, lowercase, and number.</div>
                            </div>

                            <div class="mb-3"><label for="confirm_password" class="form-label">Confirm New Password:</label><input type="password" name="confirm_password" id="confirm_password" class="form-control" required></div>
                            <hr class="my-4">
                            <div class="d-grid gap-2 d-md-flex justify-content-md-between"><a href="<?php echo $dashboard_link; ?>" class="btn btn-secondary col-12 col-md-auto"><i class="fas fa-arrow-left me-2"></i>Back to Dashboard</a><button type="submit" class="btn btn-primary col-12 col-md-auto"><i class="fas fa-save me-2"></i>Change Password</button></div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <footer class="footer"><span>© MALAYSIA ONLINE SCAM REPORTING SYSTEM (MOSRS) <?php echo date("Y"); ?></span></footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const passwordInput = document.getElementById('new_password');
            const strengthBar = document.getElementById('strength-bar');

            if (passwordInput && strengthBar) {
                passwordInput.addEventListener('input', function() {
                    const password = passwordInput.value;
                    let score = 0;

                    if (password.length >= 8) score++;
                    if (password.match(/[a-z]/)) score++;
                    if (password.match(/[A-Z]/)) score++;
                    if (password.match(/[0-9]/)) score++;
                    if (password.match(/[^A-Za-z0-9]/)) score++;

                    let width = (score / 5) * 100;
                    let color = '#dc3545';

                    if (score >= 4) {
                        color = '#198754';
                    } else if (score >= 2) {
                        color = '#ffc107';
                    }
                    
                    if (password.length === 0) {
                        width = 0;
                    }

                    strengthBar.style.width = width + '%';
                    strengthBar.style.backgroundColor = color;
                });
            }
        });
    </script>
</body>
</html>