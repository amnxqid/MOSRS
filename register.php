<?php
session_start();
include_once 'db.php';
include_once 'email.php';
include_once 'functions.php';

if (isset($_SESSION['user_id'])) {
    if ($_SESSION['user_type'] == 'admin') { header("Location: admin_dashboard.php"); }
    elseif ($_SESSION['user_type'] == 'authority') { header("Location: authority_dashboard.php"); }
    else { header("Location: user_dashboard.php"); }
    exit();
}

$csrf_token = generateCsrfToken();

$errors = [];
$error_message_display = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    verifyCsrfToken();
    
    if (!$conn || $conn->connect_error) {
         $_SESSION['register_errors'] = ["Database connection error during registration. Please try again later."];
         $_SESSION['register_postdata'] = $_POST; unset($_SESSION['register_postdata']['password']);
         header("Location: register.php");
         exit();
    }

    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $phone_number = trim($_POST['phone_number']);
    $region = trim($_POST['region']);

    if (empty($name)) { $errors[] = "Name is required."; }
    if (empty($email)) { $errors[] = "Email is required."; }
    elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) { $errors[] = "Invalid email format."; }
    else {
        $checkEmail = $conn->prepare("SELECT email FROM users WHERE email = ?");
        if ($checkEmail) {
            $checkEmail->bind_param("s", $email); $checkEmail->execute(); $checkEmail->store_result();
            if ($checkEmail->num_rows > 0) { $errors[] = "Email address is already registered. Please <a href='login.php' class='alert-link'>login</a> or use a different email."; }
            $checkEmail->close();
        } else { $errors[] = "Database error checking email uniqueness."; error_log("Register Error (Prepare - Check Email): " . $conn->error); }
    }
    if (empty($password)) { $errors[] = "Password is required."; }
    elseif (strlen($password) < 8) { $errors[] = "Password must be at least 8 characters long."; }
    elseif (!preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password) || !preg_match('/[0-9]/', $password)) { $errors[] = "Password requires at least one uppercase letter, one lowercase letter, and one number."; }
    if (empty($phone_number)) { $errors[] = "Phone number is required."; }
    elseif (!preg_match('/^[0-9+\s-]+$/', $phone_number)) { $errors[] = "Invalid phone number format (only numbers, +, -, space allowed)."; }
    if (empty($region)) { $errors[] = "Please select your region."; }

    if (!empty($errors)) {
        $_SESSION['register_errors'] = $errors;
        $_SESSION['register_postdata'] = $_POST; unset($_SESSION['register_postdata']['password']);
        if ($conn) { $conn->close(); }
        header("Location: register.php");
        exit();
    } else {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $user_type = 'public'; $authority_type = NULL;

        $stmt_insert_user = $conn->prepare("INSERT INTO users (name, email, password, user_type, authority_type, phone_number, region) VALUES (?, ?, ?, ?, ?, ?, ?)");
        if ($stmt_insert_user) {
            $stmt_insert_user->bind_param("sssssss", $name, $email, $hashed_password, $user_type, $authority_type, $phone_number, $region);
            if ($stmt_insert_user->execute()) {
                $new_user_id_registered = $conn->insert_id;
                $log_action_register = "USER_REGISTERED";
                $log_table_register = "users";
                $log_column_register = "user_id: {$new_user_id_registered}";
                $log_new_value_register = "User: {$name} ({$email}) registered. Type: {$user_type}, Region: {$region}.";
                if ($conn && !$conn->connect_error) { recordAuditLog($conn, $new_user_id_registered, $log_action_register, $log_table_register, $log_column_register, null, $log_new_value_register); }
                
                $email_subject = "Welcome to MOSRS - Registration Successful!";
                $email_body = "Dear " . htmlspecialchars($name) . ",\n\nThank you for registering with the Malaysia Online Scam Reporting System (MOSRS).\n\nYour account has been created successfully.\nYou can now log in using your email address (" . htmlspecialchars($email) . ") and the password you created.\n\nLogin here: http://localhost/fyp/login.php\n\nSincerely,\nThe MOSRS Team";
                if (function_exists('sendNotificationEmail')) { sendNotificationEmail($email, $email_subject, $email_body, false); }
                
                $_SESSION['login_message'] = "Registration successful! Please log in with your credentials.";
                $_SESSION['login_message_type'] = "success";
                $stmt_insert_user->close();
                if ($conn) { $conn->close(); }
                header("Location: login.php");
                exit();
            } else { $error_message_display = "Registration failed due to a database error (Execute). Please try again later."; error_log("Register Error (Execute Insert): " . $stmt_insert_user->error); }
            $stmt_insert_user->close();
        } else { $error_message_display = "Registration failed due to a database error (Prepare). Please try again later."; error_log("Register Error (Prepare Insert): " . $conn->error); }

         if (!empty($error_message_display)) {
              $_SESSION['register_errors'] = [$error_message_display];
              $_SESSION['register_postdata'] = $_POST; unset($_SESSION['register_postdata']['password']);
              if ($conn) { $conn->close(); }
              header("Location: register.php");
              exit();
         }
    }
}

$malaysian_regions = [ "", "Johor", "Kedah", "Kelantan", "Melaka", "Negeri Sembilan", "Pahang", "Penang", "Perak", "Perlis", "Sabah", "Sarawak", "Selangor", "Terengganu", "Kuala Lumpur", "Labuan", "Putrajaya" ];
$display_errors = $_SESSION['register_errors'] ?? [];
$postdata_display = $_SESSION['register_postdata'] ?? [];
unset($_SESSION['register_errors'], $_SESSION['register_postdata']);

if (isset($conn) && $conn && !$conn->connect_error) { $conn->close(); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create an Account - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="login_styles.css"> <!-- Reusing login styles -->
    <link rel="stylesheet" href="password_styles.css"> 
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
                                    <h3 class="mb-2">Create Your Account</h3>
                                    <p class="text-muted mb-4">Join our community to fight online scams.</p>

                                    <?php if (!empty($display_errors)) : ?>
                                        <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                            <strong>Please correct the following errors:</strong><br>
                                            <ul class="mb-0"><?php foreach ($display_errors as $err_item) : ?><li><?php echo $err_item; ?></li><?php endforeach; ?></ul>
                                            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                                        </div>
                                    <?php endif; ?>

                                    <form method="POST" action="register.php">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                                        <div class="form-floating mb-3">
                                            <input type="text" name="name" id="name" class="form-control" placeholder="Full Name" value="<?php echo htmlspecialchars($postdata_display['name'] ?? ''); ?>" required>
                                            <label for="name">Full Name</label>
                                        </div>
                                        <div class="form-floating mb-3">
                                            <input type="email" name="email" id="email" class="form-control" placeholder="Email Address" value="<?php echo htmlspecialchars($postdata_display['email'] ?? ''); ?>" required>
                                            <label for="email">Email Address</label>
                                        </div>
                                        <div class="form-floating mb-3">
                                            <input type="password" name="password" id="password" class="form-control" placeholder="Password" required>
                                            <label for="password">Password</label>
                                        </div>
                                        <div class="password-strength-meter mb-3">
                                            <div class="strength-bar" id="strength-bar"></div>
                                        </div>
                                        <div class="row g-2">
                                            <div class="col-md-6 mb-3">
                                                <div class="form-floating">
                                                    <input type="tel" name="phone_number" id="phone_number" class="form-control" placeholder="Phone Number" value="<?php echo htmlspecialchars($postdata_display['phone_number'] ?? ''); ?>" required>
                                                    <label for="phone_number">Phone Number</label>
                                                </div>
                                            </div>
                                            <div class="col-md-6 mb-3">
                                                <div class="form-floating">
                                                    <select name="region" id="region" class="form-select" required>
                                                        <?php $selected_region_form = $postdata_display['region'] ?? ''; foreach ($malaysian_regions as $region_option_form) { $selected_attr_form = ($region_option_form === $selected_region_form) ? 'selected' : ''; if (empty($region_option_form)) { echo "<option value=\"\" $selected_attr_form disabled>-- Select Region --</option>"; } else { echo "<option value=\"" . htmlspecialchars($region_option_form) . "\" $selected_attr_form>" . htmlspecialchars($region_option_form) . "</option>"; } } ?>
                                                    </select>
                                                    <label for="region">Region/State</label>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="d-grid mb-3"><button type="submit" class="btn btn-primary btn-lg fw-bold">Register</button></div>
                                        <div class="text-center">
                                            <small>Already have an account? <a href="login.php" class="text-decoration-none">Sign In</a></small>
                                        </div>
                                    </form>

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
                                    <h2 class="mt-3">Join the Fight Against Scams</h2>
                                    <p class="mt-2">By creating an account, you help build a safer online community for all Malaysians.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const passwordInput = document.getElementById('password');
            const strengthBar = document.getElementById('strength-bar');

            if (passwordInput && strengthBar) {
                passwordInput.addEventListener('input', function() {
                    const password = passwordInput.value;
                    let score = 0;
                    if (password.length >= 8) score++;
                    if (/[a-z]/.test(password)) score++;
                    if (/[A-Z]/.test(password)) score++;
                    if (/[0-9]/.test(password)) score++;
                    if (/[^A-Za-z0-9]/.test(password)) score++;
                    
                    let width = (score / 5) * 100;
                    let color = '#dc3545';
                    if (score >= 4) { color = '#198754'; } 
                    else if (score >= 2) { color = '#ffc107'; }
                    if (password.length === 0) { width = 0; }
                    strengthBar.style.width = width + '%';
                    strengthBar.style.backgroundColor = color;
                });
            }
        });
    </script>
</body>
</html>