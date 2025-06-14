<?php
session_start();
include_once 'db.php';

// --- 1. Authentication Check ---
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'public') {
    $_SESSION['login_message'] = "Please log in to view your reports.";
    $_SESSION['login_message_type'] = "warning";
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$user_name_display = $_SESSION['name'] ?? 'User';
$fetch_error = '';
$reports = [];
$evidence_base_url = "http://localhost/fyp/";

// --- 2. Function to fetch comments ---
function getReportCommentsForUserView($conn_func, $report_id_func) {
    $comments_arr = [];
    if (!$conn_func || $conn_func->connect_error) {
        error_log("getReportCommentsForUserView DB Error: Connection failed for report ID {$report_id_func}");
        return $comments_arr;
    }
    $sql_comm = "SELECT rc.comment_text, rc.created_at, u.name AS author_name, u.user_type AS author_type
                 FROM report_comments rc
                 JOIN users u ON rc.user_id = u.user_id
                 WHERE rc.report_id = ?
                 ORDER BY rc.created_at ASC";
    $stmt_comm = $conn_func->prepare($sql_comm);
    if ($stmt_comm) {
        $stmt_comm->bind_param("i", $report_id_func);
        if ($stmt_comm->execute()) {
            $result_comm = $stmt_comm->get_result();
            while ($row_comm = $result_comm->fetch_assoc()) {
                if ($row_comm['author_type'] === 'admin') {
                    $row_comm['author_name_display'] = 'Administrator';
                } elseif ($row_comm['author_type'] === 'authority') {
                    $row_comm['author_name_display'] = 'Authority Representative';
                } else {
                    $row_comm['author_name_display'] = $row_comm['author_name'];
                }
                $comments_arr[] = $row_comm;
            }
        } else { error_log("Error executing getReportCommentsForUserView query for report ID {$report_id_func}: " . $stmt_comm->error); }
        $stmt_comm->close();
    } else { error_log("Error preparing getReportCommentsForUserView query for report ID {$report_id_func}: " . $conn_func->error); }
    return $comments_arr;
}

// --- Function to get report history ---
function getReportHistory($conn_func, $report_id_func) {
    $history = [];
    if (!$conn_func || $conn_func->connect_error) {
        error_log("getReportHistory DB Error: Connection failed for report ID {$report_id_func}");
        return $history;
    }
    $like_report_id = "%Report ID: " . $report_id_func . "%";
    
    $sql_hist = "SELECT `timestamp`, `action`, `old_value`, `new_value`
                 FROM `audit_log`
                 WHERE (`old_value` LIKE ? OR `new_value` LIKE ?)
                   AND `action` IN ('USER_REPORT_SUBMITTED', 'AUTHORITY_REPORT_STATUS_UPDATED', 'ADMIN_REPORT_REASSIGNED', 'ADMIN_COMMENT_ADDED', 'AUTHORITY_COMMENT_ADDED')
                 ORDER BY `timestamp` ASC";

    $stmt_hist = $conn_func->prepare($sql_hist);
    if ($stmt_hist) {
        $stmt_hist->bind_param("ss", $like_report_id, $like_report_id);
        if ($stmt_hist->execute()) {
            $result_hist = $stmt_hist->get_result();
            while ($row_hist = $result_hist->fetch_assoc()) {
                $description = 'An update occurred.';
                switch ($row_hist['action']) {
                    case 'USER_REPORT_SUBMITTED':
                        $description = 'You submitted the report.';
                        break;
                    case 'AUTHORITY_REPORT_STATUS_UPDATED':
                        if (preg_match("/New Status: '([^']+)'/", $row_hist['new_value'], $matches)) {
                            $description = "The status was updated to <strong>" . htmlspecialchars($matches[1]) . "</strong>.";
                        }
                        break;
                    case 'ADMIN_REPORT_REASSIGNED':
                        if (preg_match("/New Authority: (.*)$/", $row_hist['new_value'], $matches)) {
                            $description = "The report was assigned to <strong>" . htmlspecialchars(trim($matches[1])) . "</strong>.";
                        }
                        break;
                    case 'ADMIN_COMMENT_ADDED':
                        $description = 'An Administrator posted a new comment.';
                        break;
                    case 'AUTHORITY_COMMENT_ADDED':
                        $description = 'An Authority Representative posted a new comment.';
                        break;
                }
                $history[] = ['timestamp' => $row_hist['timestamp'],'description' => $description];
            }
        } else { error_log("Error executing getReportHistory query for report ID {$report_id_func}: " . $stmt_hist->error); }
        $stmt_hist->close();
    } else { error_log("Error preparing getReportHistory query for report ID {$report_id_func}: " . $conn_func->error); }
    return $history;
}

// --- 3. Fetch Reports for the Logged-in User ---
if (!$conn || $conn->connect_error) {
    $fetch_error = "Database connection error. Cannot load your reports.";
    error_log("View Report Error (Initial DB Check): " . ($conn ? $conn->connect_error : "No connection object"));
} else {
    $sql_reports_user = "SELECT r.report_id, r.report_title, r.category, r.report_details, r.created_at, r.authority_type, rs.status_name
                         FROM reports r
                         LEFT JOIN report_status rs ON r.status_id = rs.status_id
                         WHERE r.user_id = ?
                         ORDER BY r.created_at DESC";
    $stmt_reports_user = $conn->prepare($sql_reports_user);

    if ($stmt_reports_user) {
        $stmt_reports_user->bind_param("i", $user_id);
        if ($stmt_reports_user->execute()) {
            $result_reports_user = $stmt_reports_user->get_result();
            while ($row_report = $result_reports_user->fetch_assoc()) {
                $row_report['comments'] = getReportCommentsForUserView($conn, $row_report['report_id']);
                $row_report['history'] = getReportHistory($conn, $row_report['report_id']);
                
                $row_report['evidence_files'] = [];
                $sql_evidence = "SELECT file_path, original_filename FROM evidence WHERE report_id = ?";
                $stmt_evidence = $conn->prepare($sql_evidence);
                if ($stmt_evidence) {
                    $stmt_evidence->bind_param("i", $row_report['report_id']);
                    if ($stmt_evidence->execute()) {
                        $result_evidence = $stmt_evidence->get_result();
                        while($evidence_file = $result_evidence->fetch_assoc()){
                            $row_report['evidence_files'][] = $evidence_file;
                        }
                    } else { error_log("View Report: Error fetching evidence for report ID {$row_report['report_id']}: " . $stmt_evidence->error); }
                    $stmt_evidence->close();
                } else { error_log("View Report: Error preparing evidence fetch for report ID {$row_report['report_id']}: " . $conn->error); }

                $reports[] = $row_report;
            }
        } else {
            $fetch_error = "Error retrieving your reports: " . $stmt_reports_user->error;
            error_log("View Report Error (Execute Fetch): UserID {$user_id} - " . $stmt_reports_user->error);
        }
        $stmt_reports_user->close();
    } else {
        $fetch_error = "Database error preparing your reports list: " . $conn->error;
        error_log("View Report Error (Prepare Fetch): UserID {$user_id} - " . $conn->error);
    }
    if ($conn) { $conn->close(); }
}

function getStatusBadgeClassForUserView($status_name_param) {
    $status_name_lower = strtolower($status_name_param ?? '');
    switch ($status_name_lower) {
        case 'pending': return 'bg-warning text-dark';
        case 'in progress': case 'assigned': return 'bg-primary';
        case 'resolved': return 'bg-success';
        case 'closed': return 'bg-secondary';
        case 'rejected': return 'bg-danger';
        case 'requires info': return 'bg-info text-dark';
        default: return 'bg-dark';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View My Reports - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css">
    <link rel="stylesheet" href="view_report_styles.css">
</head>
<body>
    <header class="bg-primary text-white text-center p-3 position-relative">
        <a href="user_dashboard.php"><img src="kementerian.jpg" alt="Logo" class="header-logo d-none d-md-block" onerror="this.onerror=null; this.style.display='none';"></a>
        <h2 class="mb-0">My Submitted Reports</h2>
    </header>
    <div class="container main-container mt-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h3 class="page-title-vr">Hello, <?php echo htmlspecialchars($user_name_display); ?>! Here are your reports:</h3>
            <a href="user_dashboard.php" class="btn btn-outline-primary"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
        </div>
        <?php if (!empty($fetch_error)): ?>
            <div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($fetch_error); ?></div>
        <?php endif; ?>
        <?php if (empty($reports) && empty($fetch_error)): ?>
            <div class="empty-reports-message">
                <i class="fas fa-folder-open"></i>
                <p>You haven't submitted any reports yet.</p>
                <a href="report.php" class="btn btn-primary"><i class="fas fa-plus-circle"></i> Submit a New Report</a>
            </div>
        <?php else: ?>
            <?php foreach ($reports as $report): ?>
                <div class="card report-card" id="reportCard<?php echo $report['report_id']; ?>">
                    <div class="report-card-header">
                        <h5 class="report-title"><?php echo htmlspecialchars($report['report_title']); ?></h5>
                        <span class="report-id-chip">ID: <?php echo $report['report_id']; ?></span>
                    </div>
                    <div class="report-card-body">
                        <div class="report-meta-grid">
                            <div class="report-meta-item"><i class="fas fa-calendar-alt"></i><strong>Submitted:</strong> <?php echo date("d M Y, h:i A", strtotime($report['created_at'])); ?></div>
                            <div class="report-meta-item"><i class="fas fa-tags"></i><strong>Category:</strong> <?php echo htmlspecialchars($report['category'] ?? 'N/A'); ?></div>
                            <div class="report-meta-item"><i class="fas fa-building"></i><strong>Assigned To:</strong> <?php echo htmlspecialchars($report['authority_type'] ?: 'Pending Assignment'); ?></div>
                            <div class="report-meta-item"><i class="fas fa-info-circle"></i><strong>Status:</strong><span class="badge report-status-badge <?php echo getStatusBadgeClassForUserView($report['status_name']); ?> ms-2"><?php echo htmlspecialchars($report['status_name'] ?? 'Not Set'); ?></span></div>
                        </div>
                        <a class="section-toggle-link" data-bs-toggle="collapse" href="#detailsCollapse<?php echo $report['report_id']; ?>" role="button" aria-expanded="false" aria-controls="detailsCollapse<?php echo $report['report_id']; ?>">View Report Details <i class="fas fa-chevron-down"></i></a>
                        <div class="collapse collapsible-section-content" id="detailsCollapse<?php echo $report['report_id']; ?>">
                            <h6>Full Report Details:</h6>
                            <p style="white-space: pre-wrap;"><?php echo htmlspecialchars($report['report_details']); ?></p>
                        </div>
                        <?php if (!empty($report['evidence_files'])): ?>
                        <a class="section-toggle-link" data-bs-toggle="collapse" href="#evidenceCollapse<?php echo $report['report_id']; ?>" role="button" aria-expanded="false" aria-controls="evidenceCollapse<?php echo $report['report_id']; ?>">View Attached Evidence (<?php echo count($report['evidence_files']); ?>) <i class="fas fa-chevron-down"></i></a>
                        <div class="collapse collapsible-section-content" id="evidenceCollapse<?php echo $report['report_id']; ?>">
                             <h6>Evidence Files:</h6>
                             <ul class="list-unstyled">
                                <?php foreach($report['evidence_files'] as $file): ?>
                                    <li><i class="fas fa-paperclip me-2 text-muted"></i><a href="<?php echo htmlspecialchars(rtrim($evidence_base_url, '/') . '/' . ltrim($file['file_path'], '/')); ?>" target="_blank"><?php echo htmlspecialchars($file['original_filename'] ?: basename($file['file_path'])); ?></a></li>
                                <?php endforeach; ?>
                             </ul>
                        </div>
                        <?php endif; ?>
                        <a class="section-toggle-link" data-bs-toggle="collapse" href="#commentsCollapse<?php echo $report['report_id']; ?>" role="button" aria-expanded="false" aria-controls="commentsCollapse<?php echo $report['report_id']; ?>">View Comments (<?php echo count($report['comments']); ?>) <i class="fas fa-chevron-down"></i></a>
                        <div class="collapse collapsible-section-content" id="commentsCollapse<?php echo $report['report_id']; ?>">
                            <h6>Communication Log:</h6>
                            <?php if (!empty($report['comments'])): ?>
                                <div class="comment-section">
                                    <?php foreach ($report['comments'] as $comment): ?>
                                        <div class="comment"><div class="author"><?php echo htmlspecialchars($comment['author_name_display']); ?></div><div class="date"><?php echo date("d M Y, h:i A", strtotime($comment['created_at'])); ?></div><div><?php echo nl2br(htmlspecialchars($comment['comment_text'])); ?></div></div>
                                    <?php endforeach; ?>
                                </div>
                            <?php else: ?>
                                <p class="text-muted fst-italic small">No comments have been posted yet.</p>
                            <?php endif; ?>
                        </div>
                        <?php if (!empty($report['history'])): ?>
                        <a class="section-toggle-link" data-bs-toggle="collapse" href="#historyCollapse<?php echo $report['report_id']; ?>" role="button" aria-expanded="false" aria-controls="historyCollapse<?php echo $report['report_id']; ?>">View Report History <i class="fas fa-chevron-down"></i></a>
                        <div class="collapse collapsible-section-content" id="historyCollapse<?php echo $report['report_id']; ?>">
                            <h6>Report Timeline:</h6>
                            <ul class="report-history-timeline">
                                <?php foreach($report['history'] as $history_item): ?>
                                    <li class="timeline-item">
                                        <span class="timeline-dot"></span>
                                        <span class="timeline-date"><?php echo date("d M Y, h:i A", strtotime($history_item['timestamp'])); ?></span>
                                        <div class="timeline-description"><?php echo $history_item['description']; ?></div>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                        <?php endif; ?>
                        <div class="report-actions-bar text-end">
                             <a href="upload_evidence.php?report_id=<?php echo $report['report_id']; ?>" class="btn btn-outline-primary btn-sm"><i class="fas fa-paperclip"></i> Upload More Evidence</a>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
    <footer class="footer"><div class="container"><span>© MOSRS <?php echo date("Y"); ?></span></div></footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener("DOMContentLoaded", function() {
            if(window.location.hash) {
                var element = document.querySelector(window.location.hash);
                if(element) {
                    element.scrollIntoView({ behavior: 'smooth' });
                    element.classList.add('border-primary', 'shadow-lg');
                    setTimeout(() => {
                        element.classList.remove('border-primary', 'shadow-lg');
                    }, 3000);
                }
            }
            var collapseToggles = document.querySelectorAll('.section-toggle-link');
            collapseToggles.forEach(function(toggle) {
                var collapseElement = document.querySelector(toggle.getAttribute('href'));
                var icon = toggle.querySelector('.fas');
                collapseElement.addEventListener('show.bs.collapse', function () {icon.style.transform = 'rotate(180deg)';});
                collapseElement.addEventListener('hide.bs.collapse', function () {icon.style.transform = 'rotate(0deg)';});
            });
        });
    </script>
</body>
</html>