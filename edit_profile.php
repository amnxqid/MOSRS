<?php
session_start();
include_once 'db.php';
include_once 'functions.php';

if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_type'])) {
    session_unset(); session_destroy(); session_start();
    $_SESSION['login_message'] = "Session expired or invalid. Please log in.";
    $_SESSION['login_message_type'] = "warning";
    header("Location: login.php");
    exit();
}

$csrf_token = generateCsrfToken();
$user_id_to_edit = $_SESSION['user_id'];
$editor_user_id = $_SESSION['user_id'];
$user_name = $_SESSION['name'] ?? 'User';

$current_user_data = null;
$errors = [];
$fetch_error = '';
$malaysian_regions = [ "", "Johor", "Kedah", "Kelantan", "Melaka", "Negeri Sembilan", "Pahang", "Penang", "Perak", "Perlis", "Sabah", "Sarawak", "Selangor", "Terengganu", "Kuala Lumpur", "Labuan", "Putrajaya" ];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    verifyCsrfToken();
    if (!$conn || $conn->connect_error) {
        $_SESSION['profile_message'] = "Database connection error. Could not save changes.";
        $_SESSION['profile_message_type'] = "danger";
        header("Location: profile.php");
        exit();
    }

    $name_post = trim($_POST['name']);
    $phone_number_post = trim($_POST['phone_number']);
    $region_post = trim($_POST['region']);

    if (empty($name_post)) { $errors[] = "Name is required."; }
    if (empty($phone_number_post)) { $errors[] = "Phone number is required."; }
    elseif (!preg_match('/^[0-9+\s-]+$/', $phone_number_post)) { $errors[] = "Invalid phone number format."; }
    if (empty($region_post)) { $errors[] = "Please select your region."; }
    elseif (!in_array($region_post, $malaysian_regions)) { $errors[] = "Invalid region selected."; }

    if (empty($errors)) {
        $old_name_log = $old_phone_log = $old_region_log = 'N/A';
        $stmt_old_data = $conn->prepare("SELECT name, phone_number, region FROM users WHERE user_id = ?");
        if ($stmt_old_data) {
            $stmt_old_data->bind_param("i", $user_id_to_edit);
            $stmt_old_data->execute();
            $result_old_data = $stmt_old_data->get_result();
            if ($old_data_row = $result_old_data->fetch_assoc()) {
                $old_name_log = $old_data_row['name'];
                $old_phone_log = $old_data_row['phone_number'];
                $old_region_log = $old_data_row['region'];
            }
            $stmt_old_data->close();
        }

        $update_sql = "UPDATE users SET name = ?, phone_number = ?, region = ? WHERE user_id = ?";
        $stmt_update = $conn->prepare($update_sql);
        if ($stmt_update) {
            $stmt_update->bind_param("sssi", $name_post, $phone_number_post, $region_post, $user_id_to_edit);
            if ($stmt_update->execute()) {
                $log_action = "USER_PROFILE_UPDATED";
                $changes_log = [];
                if ($old_name_log !== $name_post) $changes_log[] = "Name: '{$old_name_log}' to '{$name_post}'";
                if ($old_phone_log !== $phone_number_post) $changes_log[] = "Phone: '{$old_phone_log}' to '{$phone_number_post}'";
                if ($old_region_log !== $region_post) $changes_log[] = "Region: '{$old_region_log}' to '{$region_post}'";
                $log_details = "User ID: {$user_id_to_edit} profile updated. Changes: " . (!empty($changes_log) ? implode("; ", $changes_log) : "No data changes detected.");
                $log_old_values_summary = "Old Name: {$old_name_log}, Old Phone: {$old_phone_log}, Old Region: {$old_region_log}";
                recordAuditLog($conn, $editor_user_id, $log_action, "users", "user_id: {$user_id_to_edit}", $log_old_values_summary, $log_details);

                if ($_SESSION['name'] !== $name_post) { $_SESSION['name'] = $name_post; }
                $_SESSION['profile_message'] = "Profile updated successfully!";
                $_SESSION['profile_message_type'] = "success";
                $stmt_update->close();
                if ($conn) $conn->close();
                header("Location: profile.php");
                exit();
            } else { $errors[] = "Error updating profile: " . $stmt_update->error; }
            $stmt_update->close();
        } else { $errors[] = "Database error preparing update: " . $conn->error; }
    }
}

if (!isset($conn) || !$conn || $conn->connect_error) { include 'db.php'; }

if (isset($conn) && $conn && !$conn->connect_error) {
    $sql_fetch = "SELECT name, email, phone_number, region FROM users WHERE user_id = ?";
    $stmt_fetch = $conn->prepare($sql_fetch);
    if ($stmt_fetch) {
        $stmt_fetch->bind_param("i", $user_id_to_edit);
        if ($stmt_fetch->execute()) {
            $result_fetch = $stmt_fetch->get_result();
            if ($result_fetch && $result_fetch->num_rows > 0) {
                $current_user_data = $result_fetch->fetch_assoc();
            } else { $fetch_error = "Could not find profile data for User ID: {$user_id_to_edit}."; }
        } else { $fetch_error = "Error retrieving profile data: " . $stmt_fetch->error; }
        $stmt_fetch->close();
    } else { $fetch_error = "Database error preparing profile fetch: " . $conn->error; }
    if ($conn) $conn->close();
} elseif (empty($fetch_error)) {
    $fetch_error = "Database connection not established. Cannot load profile data.";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Profile - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css">
    <link rel="stylesheet" href="profile_styles.css"> <!-- Re-use styles from profile page -->
</head>
<body>
    <div class="container main-container my-4 my-md-5">
        <div class="row justify-content-center">
            <div class="col-md-9 col-lg-8 col-xl-7">

                <?php if (!empty($fetch_error)): ?>
                    <div class="alert alert-danger text-center"><?php echo htmlspecialchars($fetch_error); ?></div>
                <?php elseif ($current_user_data): ?>

                    <div class="profile-header">
                        <div class="profile-avatar">
                            <?php echo strtoupper(substr($user_name, 0, 1)); ?>
                        </div>
                        <h2>Edit Your Profile</h2>
                        <p class="text-role">Keep your information up to date</p>
                    </div>

                    <div class="card profile-card edit-profile-card">
                        <div class="card-body p-4 p-md-5">
                            <?php if (!empty($errors)) : ?>
                                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                    <strong>Please correct the following errors:</strong><br>
                                    <ul><?php foreach ($errors as $err) : ?><li><?php echo htmlspecialchars($err); ?></li><?php endforeach; ?></ul>
                                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                                </div>
                            <?php endif; ?>

                            <form method="POST" action="edit_profile.php">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                                
                                <div class="mb-4">
                                    <label for="email" class="form-label">Email Address</label>
                                    <input type="email" id="email" class="form-control" value="<?php echo htmlspecialchars($current_user_data['email'] ?? ''); ?>" disabled readonly>
                                    <div class="form-text">Your email address cannot be changed.</div>
                                </div>

                                <div class="mb-4">
                                    <label for="name" class="form-label">Full Name</label>
                                    <input type="text" name="name" id="name" class="form-control" value="<?php echo htmlspecialchars(isset($_POST['name']) ? $_POST['name'] : ($current_user_data['name'] ?? '')); ?>" required>
                                </div>

                                <div class="mb-4">
                                    <label for="phone_number" class="form-label">Phone Number</label>
                                    <input type="tel" name="phone_number" id="phone_number" class="form-control" placeholder="e.g., +6012-3456789" value="<?php echo htmlspecialchars(isset($_POST['phone_number']) ? $_POST['phone_number'] : ($current_user_data['phone_number'] ?? '')); ?>" required>
                                </div>

                                <div class="mb-4">
                                    <label for="region" class="form-label">Region/State</label>
                                    <select name="region" id="region" class="form-select" required>
                                        <?php
                                        $selected_region_form = isset($_POST['region']) ? $_POST['region'] : ($current_user_data['region'] ?? '');
                                        foreach ($malaysian_regions as $region_option) {
                                            $selected_attr = ($region_option === $selected_region_form) ? 'selected' : '';
                                            if (empty($region_option)) { echo "<option value=\"\" $selected_attr disabled>-- Select Your Region --</option>"; }
                                            else { echo "<option value=\"" . htmlspecialchars($region_option) . "\" $selected_attr>" . htmlspecialchars($region_option) . "</option>"; }
                                        }
                                        ?>
                                    </select>
                                </div>

                                <div class="d-flex justify-content-between align-items-center mt-5">
                                    <a href="profile.php" class="btn btn-secondary">Cancel</a>
                                    <button type="submit" class="btn btn-primary btn-lg"><i class="fas fa-save me-2"></i>Save Changes</button>
                                </div>
                            </form>
                        </div>
                    </div>

                 <?php else: ?>
                     <div class="alert alert-warning text-center">Could not load profile data for editing. Please try again or contact support.</div>
                 <?php endif; ?>
            </div>
        </div>
    </div>

    <footer class="footer mt-auto"><div class="container"><span>© MOSRS <?php echo date("Y"); ?></span></div></footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>