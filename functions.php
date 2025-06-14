<?php
// functions.php

function addToInbox($conn, $user_id, $message_text, $report_id = null) {
    if (!$conn || $conn->connect_error) {
        error_log("addToInbox: Database connection error.");
        return false;
    }
    $stmt = $conn->prepare("INSERT INTO user_inbox (user_id, message_text, report_id) VALUES (?, ?, ?)");
    if (!$stmt) {
        error_log("addToInbox: Failed to prepare statement - " . $conn->error);
        return false;
    }
    $stmt->bind_param("isi", $user_id, $message_text, $report_id);
    if ($stmt->execute()) {
        $stmt->close();
        return true;
    } else {
        error_log("Error adding to inbox: " . $stmt->error);
        $stmt->close();
        return false;
    }
}

/**
 * Records an action in the audit log.
 *
 * @param mysqli $conn The database connection object.
 * @param int|null $user_id The ID of the user performing the action.
 * @param string $action The type of action.
 * @param string $table_name The name of the table conceptually affected.
 * @param string $column_name The name of the column conceptually affected.
 * @param string|null $old_value The old value or context (optional).
 * @param string|null $new_value The new value or event details (optional).
 * @return bool True on success, false on failure.
 */
function recordAuditLog(mysqli $conn, $user_id, string $action, string $table_name = 'system_events', string $column_name = 'details', $old_value = null, $new_value = null): bool {
    if (!$conn || $conn->connect_error) {
        error_log("recordAuditLog: Database connection is not valid or not connected.");
        return false;
    }

    $sql = "INSERT INTO audit_log (user_id, action, table_name, column_name, old_value, new_value)
            VALUES (?, ?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);

    if (!$stmt) {
        error_log("recordAuditLog: Failed to prepare statement - " . $conn->error);
        return false;
    }

    if ($user_id === null) {
        $stmt->bind_param("ssssss", $user_id, $action, $table_name, $column_name, $old_value, $new_value);
    } else {
        $typed_user_id = (int)$user_id;
        $stmt->bind_param("isssss", $typed_user_id, $action, $table_name, $column_name, $old_value, $new_value);
    }

    if ($stmt->execute()) {
        $stmt->close();
        return true;
    } else {
        error_log("recordAuditLog: Failed to execute statement - " . $stmt->error);
        $stmt->close();
        return false;
    }
}


/**
 * Generates and stores a CSRF token in the session.
 * @return string The generated token.
 */
function generateCsrfToken(): string {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verifies the submitted CSRF token from a POST request.
 * Kills the script with an error if verification fails.
 */
function verifyCsrfToken(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        // Clear the token to prevent reuse
        unset($_SESSION['csrf_token']);
        // Log the failed attempt if possible
        error_log("CSRF token validation failed for user_id: " . ($_SESSION['user_id'] ?? 'guest'));
        // End the request
        die('CSRF validation failed. Please try submitting the form again.');
    }
    // Once used, the token should be cleared to prevent replay attacks
    unset($_SESSION['csrf_token']);
}
?>