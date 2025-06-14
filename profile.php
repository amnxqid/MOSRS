<?php
session_start();
include_once 'db.php';

// --- 1. Authentication Check ---
if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_type'])) {
    session_unset(); session_destroy(); session_start();
    $_SESSION['login_message'] = "Session expired or invalid. Please log in.";
    $_SESSION['login_message_type'] = "warning";
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$user_data = null;
$fetch_error = '';

// --- Retrieve potential feedback message from edit_profile.php ---
$profile_message = $_SESSION['profile_message'] ?? null;
$profile_message_type = $_SESSION['profile_message_type'] ?? 'info';
unset($_SESSION['profile_message'], $_SESSION['profile_message_type']);

// --- 2. Fetch User Data ---
if ($conn && !$conn->connect_error) {
    $sql = "SELECT name, email, phone_number, region, user_type, authority_type FROM users WHERE user_id = ?";
    $stmt = $conn->prepare($sql);
    if ($stmt) {
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $result = $stmt->get_result();
            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();
            } else { $fetch_error = "Could not find your user profile data."; }
        } else { $fetch_error = "Error retrieving profile data: " . $stmt->error; }
        $stmt->close();
    } else { $fetch_error = "Database error preparing profile data: " . $conn->error; }
    $conn->close();
} else { $fetch_error = "Database connection failed."; }

// --- Determine Dashboard Link ---
$dashboard_link = match ($_SESSION['user_type'] ?? 'public') {
    'admin' => 'admin_dashboard.php',
    'authority' => 'authority_dashboard.php',
    default => 'user_dashboard.php',
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Profile - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css">
    <link rel="stylesheet" href="profile_styles.css"> <!-- Link to our new styles -->
</head>
<body>
    <div class="container main-container my-4 my-md-5">
        <div class="row justify-content-center">
            <div class="col-md-9 col-lg-8 col-xl-7">

                <?php if ($profile_message): ?>
                    <div class="alert alert-<?php echo htmlspecialchars($profile_message_type); ?> alert-dismissible fade show" role="alert">
                        <?php echo htmlspecialchars($profile_message); ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>
                
                <?php if (!empty($fetch_error)): ?>
                    <div class="alert alert-danger text-center"><?php echo htmlspecialchars($fetch_error); ?></div>
                <?php elseif ($user_data): ?>

                    <div class="profile-header">
                        <div class="profile-avatar">
                            <?php echo strtoupper(substr($user_data['name'], 0, 1)); ?>
                        </div>
                        <h2><?php echo htmlspecialchars($user_data['name']); ?></h2>
                        <p class="text-role"><?php echo htmlspecialchars(ucfirst($user_data['user_type'])); ?><?php if ($user_data['user_type'] === 'authority' && !empty($user_data['authority_type'])) { echo " (" . htmlspecialchars($user_data['authority_type']) . ")"; } ?></p>
                    </div>

                    <div class="card profile-card">
                        <div class="card-body p-0">
                            <div class="detail-item">
                                <i class="fas fa-id-card icon"></i>
                                <div class="content">
                                    <span class="label">User ID</span>
                                    <span class="value"><?php echo $user_id; ?></span>
                                </div>
                            </div>
                            <div class="detail-item">
                                <i class="fas fa-envelope icon"></i>
                                <div class="content">
                                    <span class="label">Email Address</span>
                                    <span class="value"><?php echo htmlspecialchars($user_data['email']); ?></span>
                                </div>
                            </div>
                            <?php if (!empty($user_data['phone_number'])): ?>
                                <div class="detail-item">
                                    <i class="fas fa-phone icon"></i>
                                    <div class="content">
                                        <span class="label">Phone Number</span>
                                        <span class="value"><?php echo htmlspecialchars($user_data['phone_number']); ?></span>
                                    </div>
                                </div>
                            <?php endif; ?>
                            <?php if (!empty($user_data['region'])): ?>
                                <div class="detail-item">
                                    <i class="fas fa-map-marker-alt icon"></i>
                                    <div class="content">
                                        <span class="label">Region / State</span>
                                        <span class="value"><?php echo htmlspecialchars($user_data['region']); ?></span>
                                    </div>
                                </div>
                            <?php endif; ?>
                        </div>
                         <div class="profile-actions">
                            <a href="<?php echo $dashboard_link; ?>" class="btn btn-secondary"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
                            <a href="edit_profile.php" class="btn btn-primary"><i class="fas fa-edit"></i> Edit Profile</a>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="alert alert-warning text-center">Could not load profile data.</div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <footer class="footer mt-auto"><div class="container"><span>© MOSRS <?php echo date("Y"); ?></span></div></footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>