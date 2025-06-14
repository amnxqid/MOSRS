<?php
session_start();
include_once 'db.php';
include_once 'functions.php'; // Only if needed for other global functions, not currently used here

// --- 1. Authentication Check ---
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'public') {
    $_SESSION['login_message'] = "Please log in to access your inbox.";
    $_SESSION['login_message_type'] = "warning";
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$user_name_display = $_SESSION['name'] ?? 'User';
$error_message = '';

// --- Pagination Configuration ---
$messages_per_page = 10; // Number of messages per page
$current_page_inbox = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
if ($current_page_inbox < 1) { $current_page_inbox = 1; }
$offset_inbox = ($current_page_inbox - 1) * $messages_per_page;
$total_messages = 0;
$total_pages_inbox = 0;

// --- Database Connection Check ---
if (!$conn || $conn->connect_error) {
    $error_message = "Database connection error. Cannot load your inbox.";
    error_log("Inbox.php - DB Connection Error: " . ($conn ? $conn->connect_error : "No connection object"));
} else {
    // --- Function to mark a message as read ---
    if (isset($_GET['mark_read']) && is_numeric($_GET['mark_read'])) {
        $inbox_id_to_mark = (int)$_GET['mark_read'];
        $stmt_mark = $conn->prepare("UPDATE user_inbox SET is_read = 1 WHERE inbox_id = ? AND user_id = ?");
        if ($stmt_mark) {
            $stmt_mark->bind_param("ii", $inbox_id_to_mark, $user_id);
            if (!$stmt_mark->execute()) {
                $_SESSION['inbox_flash_message'] = "Failed to update message status.";
                $_SESSION['inbox_flash_message_type'] = "danger";
                error_log("Inbox.php: Failed to mark message {$inbox_id_to_mark} as read. Error: " . $stmt_mark->error);
            }
            $stmt_mark->close();
        } else {
            $_SESSION['inbox_flash_message'] = "An error occurred while processing your request.";
            $_SESSION['inbox_flash_message_type'] = "danger";
            error_log("Inbox.php: Failed to prepare statement for marking message {$inbox_id_to_mark} as read. Error: " . $conn->error);
        }
        header("Location: inbox.php?page=" . $current_page_inbox); // Redirect to current page
        exit();
    }

    // --- Fetch total messages for pagination ---
    $sql_total_count = "SELECT COUNT(*) as total FROM user_inbox WHERE user_id = ?";
    $stmt_total_count = $conn->prepare($sql_total_count);
    if($stmt_total_count){
        $stmt_total_count->bind_param("i", $user_id);
        $stmt_total_count->execute();
        $result_total_count = $stmt_total_count->get_result();
        if($row_total = $result_total_count->fetch_assoc()){
            $total_messages = (int)$row_total['total'];
            $total_pages_inbox = ceil($total_messages / $messages_per_page);
        } else { $error_message = "Could not retrieve total message count."; }
        $stmt_total_count->close();
    } else { $error_message = "Database error fetching total message count."; error_log("Inbox.php: Error preparing total count - ".$conn->error); }


    // --- Fetch inbox messages for the current page ---
    $messages = [];
    $sql_fetch_messages = "SELECT inbox_id, message_text, created_at, is_read, report_id
                           FROM user_inbox
                           WHERE user_id = ?
                           ORDER BY created_at DESC
                           LIMIT ? OFFSET ?";
    $stmt_fetch = $conn->prepare($sql_fetch_messages);

    if ($stmt_fetch) {
        $stmt_fetch->bind_param("iii", $user_id, $messages_per_page, $offset_inbox);
        if ($stmt_fetch->execute()) {
            $result_fetch = $stmt_fetch->get_result();
            while ($row_message = $result_fetch->fetch_assoc()) {
                $messages[] = $row_message;
            }
        } else {
            $error_message = "Error fetching inbox messages: " . $stmt_fetch->error;
            error_log("Inbox.php: Error executing fetch messages - " . $stmt_fetch->error);
        }
        $stmt_fetch->close();
    } else {
        $error_message = "Database error preparing inbox messages list: " . $conn->error;
        error_log("Inbox.php: Error preparing fetch messages - " . $conn->error);
    }
} // End of DB operations conditional on connection

// Retrieve flash messages from session
$display_flash_message = $_SESSION['inbox_flash_message'] ?? null;
$flash_message_type = $_SESSION['inbox_flash_message_type'] ?? 'info';
unset($_SESSION['inbox_flash_message']);
unset($_SESSION['inbox_flash_message_type']);

if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) {
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Inbox - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css">
    <link rel="stylesheet" href="inbox_styles.css"> 
</head>
<body>

    <header class="bg-primary text-white text-center p-3 position-relative">
         <a href="user_dashboard.php">
            <img src="kementerian.jpg" alt="Logo" class="header-logo d-none d-md-block" onerror="this.onerror=null; this.style.display='none';">
         </a>
        <h2 class="mb-0">My Inbox</h2>
    </header>

    <div class="container main-container my-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h3 class="page-title-inbox">Notifications & Messages</h3>
            <a href="user_dashboard.php" class="btn btn-outline-primary"><i class="fas fa-arrow-left me-1"></i>Back to Dashboard</a>
        </div>

        <?php if (isset($display_flash_message)): ?>
            <div class="alert alert-<?php echo htmlspecialchars($flash_message_type); ?> alert-dismissible fade show" role="alert">
                <?php echo htmlspecialchars($display_flash_message); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>
        <?php if (!empty($error_message) && empty($messages)): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error_message); ?></div>
        <?php endif; ?>

        <?php if (empty($messages) && empty($error_message)): ?>
            <div class="empty-inbox-message">
                <i class="fas fa-envelope-open-text"></i>
                <p>Your inbox is currently empty. No new notifications.</p>
            </div>
        <?php else: ?>
            <div class="list-group">
                <?php foreach ($messages as $message_item): ?>
                    <div class="inbox-message-item list-group-item-action <?php echo !$message_item['is_read'] ? 'unread' : ''; ?>">
                        <div class="message-header">
                            <span class="message-date">
                                <i class="fas <?php echo !$message_item['is_read'] ? 'fa-envelope' : 'fa-envelope-open'; ?> message-status-icon me-2"></i>
                                <?php echo date("D, d M Y, h:i A", strtotime($message_item['created_at'])); ?>
                            </span>
                            <div>
                                <?php if (!$message_item['is_read']): ?>
                                    <a href="inbox.php?mark_read=<?php echo (int)$message_item['inbox_id']; ?>&page=<?php echo $current_page_inbox; ?>" class="btn btn-sm btn-outline-success py-1 px-2" title="Mark as Read">
                                        <i class="fas fa-check-circle me-1"></i> Mark Read
                                    </a>
                                <?php else: ?>
                                    <span class="text-success small"><i class="fas fa-check-double"></i> Read</span>
                                <?php endif; ?>
                            </div>
                        </div>
                        <div class="message-body">
                            <p class="message-text <?php echo !$message_item['is_read'] ? 'fw-medium' : 'text-muted'; ?>">
                                <?php echo nl2br(htmlspecialchars($message_item['message_text'])); ?>
                            </p>
                            <div class="message-actions">
                                <?php if (!empty($message_item['report_id'])): ?>
                                    <a href="view_report.php#reportCard<?php echo (int)$message_item['report_id']; ?>" class="btn btn-primary">
                                        <i class="fas fa-eye me-1"></i> View Related Report (ID: <?php echo (int)$message_item['report_id']; ?>)
                                    </a>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <?php // Pagination Links - CORRECTED BLOCK
            if ($total_pages_inbox > 1): ?>
            <nav aria-label="Inbox pagination" class="mt-4">
                <ul class="pagination justify-content-center">
                    <li class="page-item <?php echo ($current_page_inbox <= 1 ? 'disabled' : ''); ?>">
                        <a class="page-link" href="inbox.php?page=<?php echo $current_page_inbox - 1; ?>">Previous</a>
                    </li>
                    <?php
                        $max_pg_links = 5;
                        $start_page_inbox = max(1, $current_page_inbox - floor($max_pg_links / 2));
                        $end_page_inbox = min($total_pages_inbox, $start_page_inbox + $max_pg_links - 1);

                        if ($end_page_inbox - $start_page_inbox + 1 < $max_pg_links && $start_page_inbox > 1) {
                           $start_page_inbox = max(1, $end_page_inbox - $max_pg_links + 1);
                        }

                        if ($start_page_inbox > 1) {
                            echo '<li class="page-item"><a class="page-link" href="inbox.php?page=1">1</a></li>';
                            if ($start_page_inbox > 2) {
                                echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                            }
                        }

                        for ($i_pg = $start_page_inbox; $i_pg <= $end_page_inbox; $i_pg++): ?>
                        <li class="page-item <?php echo ($i_pg == $current_page_inbox ? 'active' : ''); ?>">
                            <a class="page-link" href="inbox.php?page=<?php echo $i_pg; ?>"><?php echo $i_pg; ?></a>
                        </li>
                    <?php endfor;

                        if ($end_page_inbox < $total_pages_inbox) {
                            if ($end_page_inbox < $total_pages_inbox - 1) {
                                echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                            }
                            echo '<li class="page-item"><a class="page-link" href="inbox.php?page='.$total_pages_inbox.'">'.$total_pages_inbox.'</a></li>';
                        }
                    ?>
                    <li class="page-item <?php echo ($current_page_inbox >= $total_pages_inbox ? 'disabled' : ''); ?>">
                        <a class="page-link" href="inbox.php?page=<?php echo $current_page_inbox + 1; ?>">Next</a>
                    </li>
                </ul>
            </nav>
            <?php endif; ?>

        <?php endif; ?>
    </div>

    <footer class="footer">
        <div class="container"><span>© MOSRS <?php echo date("Y"); ?></span></div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>