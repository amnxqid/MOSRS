<?php
session_start();

// Authentication Check: Only admins can view user profiles
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'admin') {
    header("Location: login.php");
    exit();
}

include_once 'db.php';

$user_id_to_view = isset($_GET['user_id']) ? (int)$_GET['user_id'] : 0;
$user_data = null;
$error_message = '';

if ($user_id_to_view > 0) {
    if (isset($conn) && !$conn->connect_error) {
        // Fetch all user details. We exclude password for security.
        $stmt = $conn->prepare("SELECT user_id, name, email, phone_number, user_type, authority_type, region FROM users WHERE user_id = ?");
        if ($stmt) {
            $stmt->bind_param("i", $user_id_to_view);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows === 1) {
                $user_data = $result->fetch_assoc();
            } else {
                $error_message = "User with ID {$user_id_to_view} not found.";
            }
            $stmt->close();
        } else {
            $error_message = "Database query preparation failed.";
            error_log("View user profile prepare error: " . $conn->error);
        }
    } else {
        $error_message = "Database connection failed.";
    }
} else {
    $error_message = "No user ID was specified.";
}

$admin_name = $_SESSION['name'] ?? 'Admin';

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View User Profile - MOSRS Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css">
    <link rel="stylesheet" href="admin_dashboard_styles.css"> 
    <style>
        .profile-details-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 1rem;
        }
        @media (min-width: 768px) {
            .profile-details-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        .detail-item {
            background-color: #f8f9fa;
            padding: 0.75rem 1rem;
            border-radius: 0.375rem;
            border: 1px solid #dee2e6;
        }
        .detail-item dt {
            font-weight: 600;
            color: #6c757d;
            font-size: 0.9rem;
            margin-bottom: 0.25rem;
        }
        .detail-item dd {
            margin-bottom: 0;
            font-size: 1.1rem;
            color: #212529;
        }
    </style>
</head>
<body>

    <nav class="navbar navbar-expand-lg navbar-dark bg-primary sticky-top shadow-sm">
        <div class="container-fluid">
            <a class="navbar-brand" href="admin_dashboard.php"><img src="kementerian.jpg" alt="Logo" class="header-logo-img" onerror="this.onerror=null; this.style.display='none';">MOSRS Admin</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNavAdmin"><span class="navbar-toggler-icon"></span></button>
            <div class="collapse navbar-collapse" id="navbarNavAdmin">
                <ul class="navbar-nav ms-auto align-items-center">
                    <li class="nav-item">
                         <a class="nav-link" href="admin_dashboard.php?view=manage_users">
                           <i class="fas fa-arrow-left me-1"></i> Back to Manage Users
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container main-container mt-4">
        <h2 class="page-title mb-4">User Profile Details</h2>

        <?php if (!empty($error_message)): ?>
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i><?php echo htmlspecialchars($error_message); ?>
            </div>
        <?php elseif ($user_data): ?>
            <div class="card shadow-sm">
                <div class="card-header bg-light d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">
                        <i class="fas fa-user-circle me-2 text-primary"></i>
                        Profile for: <?php echo htmlspecialchars($user_data['name']); ?>
                    </h5>
                    <span class="badge bg-info text-dark fs-6"><?php echo htmlspecialchars(ucfirst($user_data['user_type'])); ?></span>
                </div>
                <div class="card-body">
                    <div class="profile-details-grid">
                        <dl class="detail-item">
                            <dt>User ID</dt>
                            <dd><?php echo htmlspecialchars($user_data['user_id']); ?></dd>
                        </dl>
                        <dl class="detail-item">
                            <dt>Full Name</dt>
                            <dd><?php echo htmlspecialchars($user_data['name']); ?></dd>
                        </dl>
                        <dl class="detail-item">
                            <dt>Email Address</dt>
                            <dd><?php echo htmlspecialchars($user_data['email']); ?></dd>
                        </dl>
                        <dl class="detail-item">
                            <dt>Phone Number</dt>
                            <dd><?php echo htmlspecialchars($user_data['phone_number'] ?? 'Not Provided'); ?></dd>
                        </dl>
                        <dl class="detail-item">
                            <dt>Role / User Type</dt>
                            <dd><?php echo htmlspecialchars(ucfirst($user_data['user_type'])); ?></dd>
                        </dl>
                        <dl class="detail-item">
                            <dt>Authority Type</dt>
                            <dd><?php echo htmlspecialchars($user_data['authority_type'] ?? 'N/A'); ?></dd>
                        </dl>
                         <dl class="detail-item">
                            <dt>Region</dt>
                            <dd><?php echo htmlspecialchars($user_data['region'] ?? 'Not Set'); ?></dd>
                    </div>
                </div>
                <div class="card-footer text-center">
                    <a href="admin_dashboard.php?view=manage_users" class="btn btn-secondary">
                        <i class="fas fa-chevron-left me-2"></i>Return to User List
                    </a>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <footer class="footer">
        <div class="container">
            <span>© MALAYSIA ONLINE SCAM REPORTING SYSTEM (MOSRS) <?php echo date("Y"); ?></span>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
<?php
if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
    $conn->close();
}
?>