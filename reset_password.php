<?php
session_start();
require_once 'db.php';

$token = $_GET['token'] ?? null;
$error = '';
$success = '';
$showForm = false; // Flag to control form display
$user_email = null; // Store email associated with valid token

if ($token === null || strlen($token) !== 64) { // Basic validation (64 chars for bin2hex(32))
    $error = "Invalid password reset link.";
} else {
    // Validate token against the database
    $sql = "SELECT email, expires_at FROM password_resets WHERE token = ? LIMIT 1";
    $stmt = $conn->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("s", $token);
        $stmt->execute();
        $result = $stmt->get_result();
        $reset_request = $result->fetch_assoc();
        $stmt->close();

        if ($reset_request) {
            $expires_at = strtotime($reset_request['expires_at']);
            $now = time();
            if ($now < $expires_at) {
                // Token is valid and not expired
                $showForm = true;
                $user_email = $reset_request['email']; // Store email for update
            } else {
                $error = "Password reset link has expired. Please request a new one.";
                 // Optionally delete expired token here
                 $conn->query("DELETE FROM password_resets WHERE token = '" . $conn->real_escape_string($token) . "'");
            }
        } else {
            $error = "Invalid password reset link.";
        }
    } else {
        $error = "Database error validating token. Please try again later.";
        error_log("Reset Password Error (Prepare Select): " . $conn->error);
    }
}

// Handle form submission for new password
if ($_SERVER["REQUEST_METHOD"] == "POST" && $showForm) { // Only process if token was initially valid
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];
    $submitted_token = $_POST['token'] ?? ''; // Get token from hidden field

     // Re-verify token from form submission
    if ($submitted_token !== $token) {
         $error = "Invalid request. Please use the link provided in the email.";
         $showForm = false; // Don't show form again if token mismatch
    }
    // Validate new password
    elseif (empty($new_password) || empty($confirm_password)) {
        $error = "Please enter and confirm your new password.";
    } elseif ($new_password !== $confirm_password) {
        $error = "Passwords do not match.";
    } elseif (strlen($new_password) < 8) {
        $error = "Password must be at least 8 characters long.";
    } elseif (!preg_match('/[A-Z]/', $new_password) || !preg_match('/[a-z]/', $new_password) || !preg_match('/[0-9]/', $new_password)) {
        $error = "Password requires uppercase, lowercase, and a number.";
    } else {
        // --- Validation passed, update password ---
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

        // Begin transaction for safety
        $conn->begin_transaction();

        try {
            // Update user's password in users table
            $stmt_update = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");
            if(!$stmt_update) throw new Exception("Prepare update failed: " . $conn->error);
            $stmt_update->bind_param("ss", $hashed_password, $user_email);
            if(!$stmt_update->execute()) throw new Exception("Execute update failed: " . $stmt_update->error);
            $stmt_update->close();

            // Delete the token from password_resets table
            $stmt_delete = $conn->prepare("DELETE FROM password_resets WHERE email = ? AND token = ?");
             if(!$stmt_delete) throw new Exception("Prepare delete failed: " . $conn->error);
            $stmt_delete->bind_param("ss", $user_email, $token);
            if(!$stmt_delete->execute()) throw new Exception("Execute delete failed: " . $stmt_delete->error);
            $stmt_delete->close();

            // Commit transaction
            $conn->commit();

            // Success: Set message for login page and redirect
            $_SESSION['login_message'] = "Your password has been reset successfully! Please log in.";
            $_SESSION['login_message_type'] = "success";
            header("Location: login.php");
            exit();

        } catch (Exception $e) {
            $conn->rollback(); // Rollback changes on error
            $error = "An error occurred while updating your password. Please try again.";
            error_log("Reset Password Exception: " . $e->getMessage());
            $showForm = true; // Keep showing the form so user can retry (but token might be invalid now)
        }
    }
     // If validation failed, $error is set and the form will be redisplayed below
}

// Close connection if still open
if($conn) { $conn->close(); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - MOSRS</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* Keep existing styles for body, header, footer */
         body { display: flex; flex-direction: column; min-height: 100vh; background-color: #f8f9fa; }
         .main-container { flex: 1; display: flex; align-items: center; }
         .header-logo { height: 50px; position: absolute; left: 15px; top: 50%; transform: translateY(-50%); }
         .footer { background-color: #343a40; color: white; padding: 1rem 0; text-align: center; }
         .password-help { font-size: 0.875em; color: #6c757d; }
    </style>
</head>
<body>
    <header class="bg-primary text-white text-center p-3 position-relative">
         <a href="index.php"><img src="kementerian.jpg" alt="Logo" class="header-logo d-none d-md-block" onerror="this.onerror=null; this.style.display='none';"></a>
        <h2 class="mb-0">Reset Your Password</h2>
    </header>

    <div class="container main-container">
        <div class="row justify-content-center w-100">
            <div class="col-md-6 col-lg-5 col-xl-4">
                <div class="card shadow-sm border-0">
                    <div class="card-body p-4">

                        <?php // Display Errors
                        if (!empty($error)): ?>
                            <div class="alert alert-danger" role="alert">
                                <?php echo htmlspecialchars($error); ?>
                            </div>
                        <?php endif; ?>

                        <?php // Show form only if token is valid
                        if ($showForm): ?>
                            <h3 class="card-title text-center mb-4">Enter New Password</h3>
                            <form method="POST" action="reset_password.php?token=<?php echo htmlspecialchars($token); ?>"> <!-- Submit back to this page with token -->
                                <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">
                                <div class="mb-3">
                                    <label for="new_password" class="form-label">New Password</label>
                                    <input type="password" name="new_password" id="new_password" class="form-control" required autofocus aria-describedby="passwordHelp">
                                     <div id="passwordHelp" class="form-text password-help">
                                         Min 8 chars, requires uppercase, lowercase, and number.
                                     </div>
                                </div>
                                <div class="mb-3">
                                    <label for="confirm_password" class="form-label">Confirm New Password</label>
                                    <input type="password" name="confirm_password" id="confirm_password" class="form-control" required>
                                </div>
                                 <div class="d-grid mb-3">
                                    <button type="submit" class="btn btn-primary">Reset Password</button>
                                </div>
                            </form>
                        <?php else: ?>
                            <!-- Message if token is invalid/expired -->
                             <p class="text-center">If the link was valid and not expired, you would see a form here.</p>
                             <div class="text-center mt-3">
                                 <a href="login.php?action=forgot" class="btn btn-warning btn-sm">Request New Reset Link</a>
                                 <a href="login.php" class="btn btn-secondary btn-sm">Back to Login</a>
                             </div>
                        <?php endif; // End $showForm check ?>

                    </div>
                </div>
            </div>
        </div>
    </div> <!-- /container -->

     <footer class="footer mt-auto">
        <div class="container"><span>© MOSRS <?php echo date("Y"); ?></span></div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>