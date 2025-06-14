<?php
session_start();
require_once 'db.php';       // For database connection
require_once 'functions.php'; // For recordAuditLog

$user_id_logout = null;
$user_info_for_log = 'N/A'; // Default if session details are missing

if (isset($_SESSION['user_id'])) {
    $user_id_logout = $_SESSION['user_id'];
    // Try to get email or name for a more descriptive log, default to User ID if not available
    if (isset($_SESSION['email'])) {
        $user_info_for_log = $_SESSION['email'];
    } elseif (isset($_SESSION['name'])) {
        $user_info_for_log = $_SESSION['name'];
    } else {
        $user_info_for_log = "User ID: " . $user_id_logout;
    }


    // --- Record Logout in Audit Log ---
    if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
        $audit_old_value = "User " . $user_info_for_log . " logged out."; // Removed IP
        recordAuditLog($conn, $user_id_logout, "LOGOUT", "users", "session", $audit_old_value, null);
    } else {
        error_log("Logout Audit: Database connection not available or failed for user ID: " . $user_id_logout);
    }
    // --- End Audit Log Record ---
} else {
    // User was not logged in, but accessed logout.php (e.g., stale session)
    // Optionally log this as an anonymous/system event if desired
    if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
         // recordAuditLog($conn, null, "LOGOUT_ATTEMPT_NO_SESSION", "system_access", "session", "Attempted logout without active session.", null);
    } else {
        // error_log("Logout Audit: DB connection unavailable for no-session logout attempt.");
    }
}


// Standard session destruction procedure
$_SESSION = array();

if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

session_destroy();

// Close the database connection if it was opened by this script and is still open
if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
    $conn->close();
}

// Redirect to login page
header("Location: login.php?message=logged_out");
exit();
?>