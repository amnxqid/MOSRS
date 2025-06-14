<?php
session_start();
require_once 'db.php';
require_once 'email.php';
require_once 'functions.php';

$error = '';
$message = '';
$message_type = 'info';

if (isset($_SESSION['login_message'])) {
    $message = $_SESSION['login_message'];
    $message_type = $_SESSION['login_message_type'] ?? 'success';
    unset($_SESSION['login_message'], $_SESSION['login_message_type']);
}

if (isset($_SESSION['user_id'])) {
    $redirect_page = 'user_dashboard.php';
    if ($_SESSION['user_type'] == 'admin') $redirect_page = 'admin_dashboard.php';
    elseif ($_SESSION['user_type'] == 'authority') $redirect_page = 'authority_dashboard.php';
    header("Location: " . $redirect_page);
    exit();
}

$csrf_token = generateCsrfToken();
$action = $_GET['action'] ?? 'login';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    verifyCsrfToken();

    if (isset($_POST['login_action'])) {
        $email = trim($_POST['email']);
        $password = $_POST['password'];
        if (!empty($email) && !empty($password)) {
            if ($conn) {
                $stmt = $conn->prepare("SELECT user_id, name, email, password, user_type, authority_type FROM users WHERE email = ?");
                if ($stmt) {
                    $stmt->bind_param("s", $email);
                    $stmt->execute();
                    $user = $stmt->get_result()->fetch_assoc();
                    $stmt->close();
                    if ($user && password_verify($password, $user['password'])) {
                        session_regenerate_id(true);
                        $_SESSION['user_id'] = $user['user_id'];
                        $_SESSION['name'] = $user['name'];
                        $_SESSION['user_type'] = $user['user_type'];
                        $_SESSION['authority_type'] = $user['authority_type'] ?? null;
                        $_SESSION['email'] = $user['email'];
                        recordAuditLog($conn, $user['user_id'], "LOGIN_SUCCESS", "users", "session", null, "User logged in.");
                        $redirect_page = 'user_dashboard.php';
                        if ($user['user_type'] == 'admin') $redirect_page = 'admin_dashboard.php';
                        elseif ($user['user_type'] == 'authority') $redirect_page = 'authority_dashboard.php';
                        if ($conn) { $conn->close(); }
                        header("Location: " . $redirect_page);
                        exit();
                    } else {
                        $error = "Invalid email or password.";
                        $login_user_id = $user['user_id'] ?? null;
                        recordAuditLog($conn, $login_user_id, "LOGIN_FAILURE", "users", "password_attempt", "Attempt for: " . $email, null);
                    }
                } else { $error = "Database error. Please try again."; }
            } else { $error = "Database connection failed."; }
        } else { $error = "Please enter both email and password."; }
        $action = 'login';
    } elseif (isset($_POST['forgot_action'])) {
        $email = trim($_POST['forgot_email']);
        $action = 'forgot';
        if (!empty($email) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
            if ($conn) {
                $stmt_check = $conn->prepare("SELECT user_id FROM users WHERE email = ?");
                if ($stmt_check) {
                    $stmt_check->bind_param("s", $email);
                    $stmt_check->execute();
                    $user_data = $stmt_check->get_result()->fetch_assoc();
                    $stmt_check->close();
                    if ($user_data) {
                        try {
                            $token = bin2hex(random_bytes(32));
                            $expires_at = date('Y-m-d H:i:s', strtotime('+1 hour'));
                            $conn->prepare("DELETE FROM password_resets WHERE email = ?")->execute([$email]);
                            $stmt_insert = $conn->prepare("INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)");
                            if($stmt_insert){
                                $stmt_insert->bind_param("sss", $email, $token, $expires_at);
                                if ($stmt_insert->execute()) {
                                    $reset_link = "http://localhost/fyp/reset_password.php?token=" . $token;
                                    $email_subject = "MOSRS Password Reset Request";
                                    $email_body = "You requested a password reset. Click the link below to reset your password (valid for 1 hour):\n" . $reset_link;
                                    $email_result = sendNotificationEmail($email, $email_subject, $email_body);
                                    if ($email_result === 'Message has been sent') {
                                        $message = "If an account with that email exists, a reset link has been sent.";
                                        $message_type = "success";
                                        recordAuditLog($conn, $user_data['user_id'], "PASSWORD_RESET_REQUESTED", "users", "email", "Email: " . $email, "Token generated");
                                    } else { $message = "Could not send password reset email."; $message_type = "danger"; }
                                }
                                $stmt_insert->close();
                            }
                        } catch (Exception $e) { $message = "An error occurred."; $message_type = "danger"; }
                    } else {
                        $message = "If an account with that email exists, a reset link has been sent.";
                        $message_type = "info";
                        recordAuditLog($conn, null, "PASSWORD_RESET_ATTEMPT_UNKNOWN_EMAIL", "users", "email", "Attempted for: " . $email, null);
                    }
                }
            }
        } else { $message = "Please enter a valid email address."; $message_type = "warning"; }
    }
}

if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
    if ($action !== 'login' || !empty($error)) { $conn->close(); }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo ($action === 'forgot' ? 'Forgot Password' : 'Login'); ?> - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="login_styles.css">
</head>
<body class="login-page">
    <div class="login-container">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-xl-10 col-lg-12">
                    <div class="card login-card">
                        <div class="row g-0">
                            <div class="col-lg-6">
                                <div class="login-form-side">
                                    <div class="text-center mb-4">
                                        <a href="index.php"><img src="kementerian.jpg" alt="Logo" style="height: 60px;"></a>
                                    </div>

                                    <?php if (!empty($message)): ?>
                                        <div class="alert alert-<?php echo $message_type; ?> alert-dismissible fade show" role="alert"><?php echo htmlspecialchars($message); ?><button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>
                                    <?php endif; ?>

                                    <?php if ($action === 'forgot'): ?>
                                        <h3 class="mb-2">Forgot Password?</h3>
                                        <p class="text-muted mb-4">No worries, we'll send you reset instructions.</p>
                                        <form method="POST" action="login.php?action=forgot">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                                            <input type="hidden" name="forgot_action" value="1">
                                            <div class="form-floating mb-3">
                                                <input type="email" name="forgot_email" id="forgot_email" class="form-control" placeholder="name@example.com" required autofocus>
                                                <label for="forgot_email">Email address</label>
                                            </div>
                                            <div class="d-grid mb-3"><button type="submit" class="btn btn-primary btn-lg">Send Reset Link</button></div>
                                            <div class="text-center"><a href="login.php" class="text-decoration-none">← Back to Login</a></div>
                                        </form>
                                    <?php else: ?>
                                        <h3 class="mb-2">Welcome Back!</h3>
                                        <p class="text-muted mb-4">Please enter your details to sign in.</p>
                                        <?php if (!empty($error)): ?>
                                            <div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($error); ?></div>
                                        <?php endif; ?>
                                        <form method="POST" action="login.php">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                                            <input type="hidden" name="login_action" value="1">
                                            <div class="form-floating mb-3">
                                                <input type="email" name="email" id="email" class="form-control" placeholder="name@example.com" required value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" autofocus>
                                                <label for="email">Email address</label>
                                            </div>
                                            <div class="form-floating mb-4">
                                                <input type="password" name="password" id="password" class="form-control" placeholder="Password" required>
                                                <label for="password">Password</label>
                                            </div>
                                            <div class="d-grid mb-3"><button type="submit" class="btn btn-primary btn-lg fw-bold">Sign In</button></div>
                                            <div class="d-flex justify-content-between">
                                                <a href="login.php?action=forgot" class="text-decoration-none small">Forgot Password?</a>
                                                <a href="register.php" class="text-decoration-none small">Create an Account</a>
                                            </div>
                                        </form>
                                    <?php endif; ?>
                                    
                                    <!-- Back Button Added Here -->
                                    <hr class="my-4">
                                    <div class="text-center">
                                        <a href="index.php" class="btn btn-outline-secondary btn-sm">
                                            <i class="fas fa-home me-1"></i> Back to Home Page
                                        </a>
                                    </div>
                                    <!-- End Back Button -->

                                </div>
                            </div>
                            <div class="col-lg-6 d-none d-lg-flex login-branding-side">
                                <div>
                                    <img src="kementerian.jpg" alt="MOSRS Brand" class="brand-logo">
                                    <h2 class="mt-3">Malaysia Online Scam Reporting System</h2>
                                    <p class="mt-2">Your central platform for reporting and combating online fraud together.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>