<?php
session_start();
require_once 'db.php';
require_once 'functions.php';

if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'admin') {
    $_SESSION['login_message'] = "Access Denied. Please log in as an administrator.";
    $_SESSION['login_message_type'] = "danger";
    header("Location: login.php");
    exit();
}

$admin_id_performing_delete = $_SESSION['user_id'];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    verifyCsrfToken();

    if (isset($_POST['user_id'])) {
        $user_id_to_delete = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);

        if (!$user_id_to_delete || $user_id_to_delete <= 0) {
            $_SESSION['admin_dashboard_message'] = "Invalid User ID specified for deletion.";
            $_SESSION['admin_dashboard_message_type'] = "danger";
        } elseif ($user_id_to_delete == $admin_id_performing_delete) {
            $_SESSION['admin_dashboard_message'] = "Error: Administrators cannot delete their own account.";
            $_SESSION['admin_dashboard_message_type'] = "warning";
            if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
                recordAuditLog($conn, $admin_id_performing_delete, "ADMIN_SELF_DELETE_ATTEMPT_DENIED", "users", "user_id: {$user_id_to_delete}", "Attempted to delete self", null);
            }
        } else {
            if (!$conn || $conn->connect_error) {
                $_SESSION['admin_dashboard_message'] = "Database connection error. Cannot delete user.";
                $_SESSION['admin_dashboard_message_type'] = "danger";
                error_log("Delete User Error: DB connection failed. Admin ID: {$admin_id_performing_delete}, Target User ID: {$user_id_to_delete}");
            } else {
                $user_email_deleted = "N/A"; $user_name_deleted = "N/A"; $user_type_deleted = "N/A";
                $stmt_fetch_user = $conn->prepare("SELECT name, email, user_type FROM users WHERE user_id = ?");
                if ($stmt_fetch_user) {
                    $stmt_fetch_user->bind_param("i", $user_id_to_delete);
                    $stmt_fetch_user->execute();
                    $result_fetch_user = $stmt_fetch_user->get_result();
                    if ($user_data = $result_fetch_user->fetch_assoc()) {
                        $user_name_deleted = $user_data['name'];
                        $user_email_deleted = $user_data['email'];
                        $user_type_deleted = $user_data['user_type'];
                    }
                    $stmt_fetch_user->close();
                }
                
                $stmt_delete_user = $conn->prepare("DELETE FROM users WHERE user_id = ?");
                if ($stmt_delete_user) {
                    $stmt_delete_user->bind_param("i", $user_id_to_delete);
                    if ($stmt_delete_user->execute()) {
                        if ($stmt_delete_user->affected_rows > 0) {
                            $_SESSION['admin_dashboard_message'] = "User (ID: {$user_id_to_delete}) deleted successfully!";
                            $_SESSION['admin_dashboard_message_type'] = "success";
                            $log_old_value_delete = "User Deleted: ID={$user_id_to_delete}, Name='{$user_name_deleted}', Email='{$user_email_deleted}', Type='{$user_type_deleted}'";
                            recordAuditLog($conn, $admin_id_performing_delete, "ADMIN_USER_DELETED", "users", "user_id: {$user_id_to_delete}", $log_old_value_delete, null);
                        } else {
                            $_SESSION['admin_dashboard_message'] = "User (ID: {$user_id_to_delete}) not found or already deleted.";
                            $_SESSION['admin_dashboard_message_type'] = "info";
                            recordAuditLog($conn, $admin_id_performing_delete, "ADMIN_USER_DELETE_NOT_FOUND", "users", "user_id: {$user_id_to_delete}", "Attempted to delete non-existent user", null);
                        }
                    } else {
                        $_SESSION['admin_dashboard_message'] = "Error deleting user. It might be linked to other records.";
                        $_SESSION['admin_dashboard_message_type'] = "danger";
                        recordAuditLog($conn, $admin_id_performing_delete, "ADMIN_USER_DELETE_FAILED", "users", "user_id: {$user_id_to_delete}", "DB Error: " . $stmt_delete_user->error, null);
                    }
                    $stmt_delete_user->close();
                } else {
                     $_SESSION['admin_dashboard_message'] = "Database error preparing delete statement.";
                     $_SESSION['admin_dashboard_message_type'] = "danger";
                }
            }
        }
    }
} else {
    $_SESSION['admin_dashboard_message'] = "Invalid request to delete user.";
    $_SESSION['admin_dashboard_message_type'] = "danger";
}

if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
    $conn->close();
}
header("Location: admin_dashboard.php?view=manage_users");
exit();
?>