<?php
session_start();

// --- 1. Authentication & Authorization ---
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'authority') {
    header("Location: login.php");
    exit();
}
if (!isset($_SESSION['authority_type']) || empty($_SESSION['authority_type'])) {
    error_log("Authority user {$_SESSION['user_id']} accessed dashboard without authority_type set.");
    session_unset(); session_destroy();
    header("Location: login.php?error=session_issue");
    exit();
}

// --- 2. Include necessary files ---
include_once 'db.php';
include_once 'email.php';
include_once 'functions.php';

$csrf_token = generateCsrfToken();

// --- 3. Configuration & User Info ---
$evidence_base_url = "http://localhost/fyp/";
$user_id = $_SESSION['user_id'];
$user_name = $_SESSION['name'] ?? 'Authority User';
$authority_type = $_SESSION['authority_type'];
$authority_name_map = [ 'PDRM' => 'PDRM', 'BNM' => 'Bank Negara Malaysia (BNM)', 'MCMC' => 'MCMC' ];
$authority_display_name = $authority_name_map[$authority_type] ?? htmlspecialchars($authority_type);

// --- 4. Filtering & Sorting ---
$filter_status = isset($_GET['status']) && is_numeric($_GET['status']) ? (int)$_GET['status'] : 0;
$sort_options = ['r.created_at', 'r.report_id', 'r.report_title', 'u.name', 'rs.status_name'];
$sort_by = isset($_GET['sort']) && in_array($_GET['sort'], $sort_options) ? $_GET['sort'] : 'r.created_at';
$sort_order = isset($_GET['order']) && strtolower($_GET['order']) === 'asc' ? 'ASC' : 'DESC';

// --- 5. Pagination ---
$reports_per_page = 10;
$current_page = isset($_GET['page']) && is_numeric($_GET['page']) ? (int)$_GET['page'] : 1;
if ($current_page < 1) { $current_page = 1; }
$offset = ($current_page - 1) * $reports_per_page;
$total_reports_for_pagination = 0;
$total_pages = 0;

// --- 6. Handle Comment Submission (for modal form) ---
$comment_success = ''; $comment_error = '';
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['add_comment_modal'])) {
    verifyCsrfToken();
    if (!$conn || $conn->connect_error) { $comment_error = "Database connection error."; }
    else {
        $report_id_comment = filter_input(INPUT_POST, 'report_id', FILTER_VALIDATE_INT);
        $comment_text = trim($_POST['comment_text']);
        if ($report_id_comment && !empty($comment_text)) {
            $stmt_insert = $conn->prepare("INSERT INTO report_comments (report_id, user_id, comment_text) VALUES (?, ?, ?)");
            if ($stmt_insert) {
                $stmt_insert->bind_param("iis", $report_id_comment, $user_id, $comment_text);
                if ($stmt_insert->execute()) {
                    $comment_success = "Comment added to Report ID: " . htmlspecialchars($report_id_comment) . "!";
                    // Full notification logic can be re-added here if desired
                } else { $comment_error = "Error adding comment: " . $stmt_insert->error; }
                $stmt_insert->close();
            }
        } else { $comment_error = "Comment cannot be empty!"; }
    }
}

// --- 7. Status Update Feedback ---
$status_update_message = $_SESSION['update_status_message'] ?? null;
$status_update_type = $_SESSION['update_status_type'] ?? 'success';
unset($_SESSION['update_status_message'], $_SESSION['update_status_type']);

// --- 8. Fetch Reports Data (EFFICIENT METHOD) ---
$reports_data = []; $fetch_error = '';
if (!$conn || $conn->connect_error) {
    $fetch_error = "Database connection error. Cannot fetch reports.";
} else {
    $params = [$authority_type];
    $types = 's';
    $where_clauses = ["r.authority_type = ?"];
    if ($filter_status > 0) {
        $where_clauses[] = "r.status_id = ?";
        $params[] = $filter_status;
        $types .= 'i';
    }
    $where_sql = implode(" AND ", $where_clauses);

    $count_sql = "SELECT COUNT(*) as total FROM reports r WHERE " . $where_sql;
    $stmt_count = $conn->prepare($count_sql);
    if ($stmt_count) {
        $stmt_count->bind_param($types, ...$params);
        $stmt_count->execute();
        $total_reports_for_pagination = $stmt_count->get_result()->fetch_assoc()['total'];
        $total_pages = ceil($total_reports_for_pagination / $reports_per_page);
        $stmt_count->close();
    }
    
    $sql_main = "SELECT r.report_id, r.report_title, r.category, r.report_details, r.status_id, rs.status_name, r.created_at, u.name AS reporter_name, u.email AS reporter_email, u.phone_number AS reporter_phone 
                 FROM reports r 
                 JOIN users u ON r.user_id = u.user_id 
                 LEFT JOIN report_status rs ON r.status_id = rs.status_id 
                 WHERE " . $where_sql . " ORDER BY $sort_by $sort_order LIMIT ? OFFSET ?";
    
    $main_params = $params;
    $main_params[] = $reports_per_page;
    $main_params[] = $offset;
    $main_types = $types . 'ii';
    
    $stmt_main = $conn->prepare($sql_main);
    if($stmt_main) {
        $stmt_main->bind_param($main_types, ...$main_params);
        if ($stmt_main->execute()) {
            $result_main = $stmt_main->get_result();
            $report_ids = [];
            while ($row = $result_main->fetch_assoc()) {
                $reports_data[$row['report_id']] = $row;
                $reports_data[$row['report_id']]['comments'] = [];
                $reports_data[$row['report_id']]['evidence'] = [];
                $report_ids[] = $row['report_id'];
            }
            
            if (!empty($report_ids)) {
                $id_placeholders = implode(',', array_fill(0, count($report_ids), '?'));
                $comment_sql = "SELECT rc.report_id, rc.comment_text, rc.created_at, u.name AS author_name FROM report_comments rc JOIN users u ON rc.user_id = u.user_id WHERE rc.report_id IN ($id_placeholders) ORDER BY rc.created_at ASC";
                $stmt_comments = $conn->prepare($comment_sql);
                $stmt_comments->bind_param(str_repeat('i', count($report_ids)), ...$report_ids);
                $stmt_comments->execute();
                $result_comments = $stmt_comments->get_result();
                while ($comment = $result_comments->fetch_assoc()) {
                    $reports_data[$comment['report_id']]['comments'][] = $comment;
                }
                $stmt_comments->close();
                
                $evidence_sql = "SELECT report_id, file_path, original_filename FROM evidence WHERE report_id IN ($id_placeholders) ORDER BY uploaded_at ASC";
                $stmt_evidence = $conn->prepare($evidence_sql);
                $stmt_evidence->bind_param(str_repeat('i', count($report_ids)), ...$report_ids);
                $stmt_evidence->execute();
                $result_evidence = $stmt_evidence->get_result();
                while ($evidence = $result_evidence->fetch_assoc()) {
                    $reports_data[$evidence['report_id']]['evidence'][] = $evidence;
                }
                $stmt_evidence->close();
            }
        } else { $fetch_error = "Error fetching reports: " . $stmt_main->error; }
        $stmt_main->close();
    } else { $fetch_error = "DB error preparing report list: " . $conn->error; }
}

$statuses = [];
if ($conn && !$conn->connect_error) {
    $status_sql = "SELECT status_id, status_name FROM report_status ORDER BY status_id";
    $status_result = $conn->query($status_sql);
    if ($status_result) { while($status_row = $status_result->fetch_assoc()) { $statuses[] = $status_row; } }
}

if(isset($conn) && $conn instanceof mysqli && !$conn->connect_error) { $conn->close(); }

function getStatusBadgeClass($status_name) {
    $status_name_lower = strtolower($status_name ?? '');
    switch ($status_name_lower) {
        case 'pending': return 'bg-warning text-dark'; case 'in progress': return 'bg-primary';
        case 'resolved': return 'bg-success'; case 'closed': return 'bg-secondary';
        case 'rejected': return 'bg-danger'; case 'requires info': return 'bg-info text-dark';
        default: return 'bg-dark';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authority Dashboard - <?php echo $authority_display_name; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css">
    <style>
        body { background-color: #f4f7f6; }
        .page-title { color: #2c3e50; font-weight: 700; }
        .filter-bar { background-color: #fff; padding: 1rem 1.5rem; border-radius: 0.5rem; margin-bottom: 1.5rem; box-shadow: 0 2px 6px rgba(0,0,0,0.05); border: 1px solid #e9ecef; }
        .modal-header.modal-header-auth { background: linear-gradient(135deg, #007bff, #0056b3); color: white; }
        .modal-header.modal-header-auth .btn-close { filter: invert(1) grayscale(100%) brightness(200%); }
        .report-card-auth { background-color: #fff; border: 1px solid #e9ecef; border-left-width: 6px; border-radius: 0.5rem; margin-bottom: 1.5rem; }
        .report-card-auth.status-pending { border-left-color: #ffc107; }
        .report-card-auth.status-in-progress, .report-card-auth.status-assigned { border-left-color: #0d6efd; }
        .report-card-auth.status-resolved { border-left-color: #198754; }
        .report-card-auth.status-closed { border-left-color: #6c757d; }
        .report-card-auth.status-rejected { border-left-color: #dc3545; }
        .report-card-auth.status-requires-info { border-left-color: #0dcaf0; }
        .report-card-auth.status-default { border-left-color: #343a40; }
        .report-card-header-auth { padding: 1rem 1.25rem; background-color: #f8f9fa; border-bottom: 1px solid #e9ecef; display: flex; justify-content: space-between; align-items: center; }
        .report-title-auth { font-size: 1.2rem; font-weight: 600; color: #343a40; }
        .report-body-auth { padding: 1.25rem; }
        .report-grid { display: grid; grid-template-columns: 1fr; gap: 1.5rem; }
        @media (min-width: 992px) { .report-grid { grid-template-columns: repeat(2, 1fr); } }
        .detail-box { background-color: #f8f9fa; padding: 1rem; border-radius: 0.375rem; border: 1px solid #e9ecef; height: 100%; }
        .detail-box h6 { font-weight: 600; margin-bottom: 0.75rem; border-bottom: 1px solid #dee2e6; padding-bottom: 0.5rem; display: flex; align-items: center; }
        .detail-box h6 i.fas { margin-right: 0.75rem; color: var(--bs-primary); }
        .detail-box p, .detail-box .evidence-links { font-size: 0.9rem; max-height: 200px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word; }
        .evidence-links a:hover { background-color: #e9ecef; }
        .reporter-info-auth { list-style: none; padding-left: 0; font-size: 0.9rem; }
        .reporter-info-auth li { padding: 0.35rem 0; }
        .reporter-info-auth i { width: 20px; text-align: center; margin-right: 0.75rem; color: #6c757d; }
        .comment-section-auth { max-height: 250px; overflow-y: auto; padding: 0.75rem; background-color: #f1f3f5; border-radius: 0.375rem; border-top: 2px solid var(--bs-primary); }
        .comment-auth { background-color: #fff; border-radius: 0.25rem; padding: 0.75rem; margin-bottom: 0.75rem; font-size: 0.9rem; border-left: 3px solid #ced4da; }
        .comment-auth .author { font-weight: 600; color: #0d6efd; }
        .comment-auth .date { font-size: 0.8em; color: #6c757d; }
    </style>
</head>
<body>

    <nav class="navbar navbar-expand-lg navbar-dark bg-primary sticky-top shadow-sm">
        <div class="container-fluid">
            <a class="navbar-brand" href="authority_dashboard.php"><img src="kementerian.jpg" alt="Logo" class="header-logo-img" onerror="this.onerror=null; this.style.display='none';">MOSRS Authority</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"><span class="navbar-toggler-icon"></span></button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto align-items-center">
                    <li class="nav-item"><span class="navbar-text me-3">Welcome, <?php echo htmlspecialchars($user_name); ?>!</span></li>
                    <li class="nav-item"><a class="nav-link" href="profile.php" title="View Profile"><i class="fas fa-user-circle fa-lg"></i></a></li>
                    <li class="nav-item"><a class="btn btn-sm btn-danger ms-2" href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid main-container mt-4 px-lg-4">
        <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap">
            <h3 class="page-title mb-2 mb-md-0">Assigned Reports</h3>
            <?php if ($total_pages > 0): ?><span class="text-muted">Page <?php echo $current_page; ?> of <?php echo $total_pages; ?> (<?php echo $total_reports_for_pagination; ?> reports found)</span><?php endif; ?>
        </div>

        <?php if (isset($status_update_message)): ?><div class="alert alert-<?php echo htmlspecialchars($status_update_type); ?> alert-dismissible fade show" role="alert"><?php echo htmlspecialchars($status_update_message); ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>
        <?php if (!empty($comment_success)): ?><div class="alert alert-success alert-dismissible fade show" role="alert"><?php echo htmlspecialchars($comment_success); ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>
        <?php if (!empty($comment_error)): ?><div class="alert alert-danger alert-dismissible fade show" role="alert"><?php echo htmlspecialchars($comment_error); ?><button type="button" class="btn-close" data-bs-dismiss="alert"></button></div><?php endif; ?>
        <?php if (!empty($fetch_error)): ?><div class="alert alert-danger" role="alert"><?php echo htmlspecialchars(trim($fetch_error)); ?></div><?php endif; ?>

        <div class="card shadow-sm">
            <div class="card-body">
                <div class="filter-bar mb-3">
                    <form method="GET" action="authority_dashboard.php">
                        <div class="row g-2 align-items-end">
                            <div class="col-md-5"><label for="status" class="form-label">Filter by Status</label><select name="status" id="status" class="form-select"><option value="0">All Statuses</option><?php foreach ($statuses as $status): ?><option value="<?php echo $status['status_id']; ?>" <?php if ($filter_status == $status['status_id']) echo 'selected'; ?>><?php echo htmlspecialchars($status['status_name']); ?></option><?php endforeach; ?></select></div>
                            <div class="col-md-5"><label for="sort" class="form-label">Sort By</label><select name="sort" id="sort" class="form-select"><option value="r.created_at" <?php if ($sort_by == 'r.created_at') echo 'selected'; ?>>Date Submitted</option><option value="r.report_id" <?php if ($sort_by == 'r.report_id') echo 'selected'; ?>>Report ID</option></select></div>
                            <div class="col-md-2 d-grid"><button type="submit" class="btn btn-primary"><i class="fas fa-filter me-1"></i>Apply</button></div>
                        </div>
                    </form>
                </div>

                <div class="table-responsive">
                    <table class="table table-hover table-bordered align-middle">
                        <thead class="table-light"><tr><th>ID</th><th>Title</th><th>Category</th><th>Reporter</th><th>Submitted</th><th>Status</th><th class="text-center">Actions</th></tr></thead>
                        <tbody>
                            <?php if (!empty($reports_data)): ?>
                                <?php foreach ($reports_data as $report): ?>
                                    <tr>
                                        <td><?php echo $report['report_id']; ?></td>
                                        <td><?php echo htmlspecialchars($report['report_title']); ?></td>
                                        <td><?php echo htmlspecialchars($report['category'] ?? 'N/A'); ?></td>
                                        <td><?php echo htmlspecialchars($report['reporter_name']); ?></td>
                                        <td><?php echo date("d M Y", strtotime($report['created_at'])); ?></td>
                                        <td><span class="badge <?php echo getStatusBadgeClass($report['status_name']); ?>"><?php echo htmlspecialchars($report['status_name'] ?? 'N/A'); ?></span></td>
                                        <td class="text-center">
                                            <button type="button" class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#reportDetailModal" data-report-data='<?php echo htmlspecialchars(json_encode($report), ENT_QUOTES, 'UTF-8'); ?>'>
                                                <i class="fas fa-eye"></i> View
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr><td colspan="7" class="text-center text-muted p-4">No reports found matching your criteria.</td></tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <?php if ($total_pages > 1): ?>
            <nav class="mt-4"><ul class="pagination justify-content-center">
                <li class="page-item <?php echo ($current_page <= 1 ? 'disabled' : ''); ?>"><a class="page-link" href="?page=<?php echo $current_page - 1; ?>&status=<?php echo $filter_status; ?>&sort=<?php echo $sort_by; ?>">«</a></li>
                <?php for ($i = 1; $i <= $total_pages; $i++): ?><li class="page-item <?php echo ($i == $current_page ? 'active' : ''); ?>"><a class="page-link" href="?page=<?php echo $i; ?>&status=<?php echo $filter_status; ?>&sort=<?php echo $sort_by; ?>"><?php echo $i; ?></a></li><?php endfor; ?>
                <li class="page-item <?php echo ($current_page >= $total_pages ? 'disabled' : ''); ?>"><a class="page-link" href="?page=<?php echo $current_page + 1; ?>&status=<?php echo $filter_status; ?>&sort=<?php echo $sort_by; ?>">»</a></li>
            </ul></nav>
        <?php endif; ?>
    </div>

    <!-- Report Detail Modal -->
    <div class="modal fade" id="reportDetailModal" tabindex="-1" aria-labelledby="reportDetailModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-xl modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header modal-header-auth"><h5 class="modal-title" id="reportDetailModalLabel">Report Details</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
                <div class="modal-body" id="reportDetailModalBody"></div>
                <div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button></div>
            </div>
        </div>
    </div>

    <footer class="footer mt-auto"><div class="container"><span>© MALAYSIA ONLINE SCAM REPORTING SYSTEM (MOSRS) <?php echo date("Y"); ?></span></div></footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const reportDetailModal = document.getElementById('reportDetailModal');
        reportDetailModal.addEventListener('show.bs.modal', function(event) {
            const button = event.relatedTarget;
            const reportData = JSON.parse(button.getAttribute('data-report-data'));
            const modalBody = document.getElementById('reportDetailModalBody');
            const modalTitle = document.getElementById('reportDetailModalLabel');
            modalTitle.textContent = `Details for Report ID: ${reportData.report_id}`;
            let evidenceHtml = '<span class="text-muted fst-italic">No evidence provided.</span>';
            if (reportData.evidence && reportData.evidence.length > 0) {
                evidenceHtml = reportData.evidence.map(file => `<a href="<?php echo $evidence_base_url; ?>${file.file_path}" target="_blank"><i class="fas fa-link me-2"></i>${file.original_filename || file.file_path.split('/').pop()}</a>`).join('');
            }
            let commentsHtml = `<p class='text-muted text-center small p-3'>No comments yet.</p>`;
            if (reportData.comments && reportData.comments.length > 0) {
                commentsHtml = reportData.comments.map(comment => `<div class='comment-auth'><div class='d-flex justify-content-between'><span class='author'>${comment.author_name}</span><span class='date'>${new Date(comment.created_at).toLocaleString()}</span></div><div>${nl2br(comment.comment_text)}</div></div>`).join('');
            }
            const statusBadgeClass = getStatusBadgeClassJs(reportData.status_name);
            const statusCardClass = `status-${(reportData.status_name || 'default').toLowerCase().replace(/\s+/g, '-')}`;
            modalBody.innerHTML = `
                <div class="card report-card-auth ${statusCardClass}">
                    <div class="report-card-header-auth"><h5 class="report-title-auth">${reportData.report_title}</h5><span class="badge ${statusBadgeClass}">${reportData.status_name || 'N/A'}</span></div>
                    <div class="card-body report-body-auth"><div class="report-grid">
                        <div>
                            <div class="detail-box mb-3"><h6><i class="fas fa-user-tie"></i>Reporter Information</h6><ul class="reporter-info-auth"><li><i class="fas fa-user"></i> ${reportData.reporter_name}</li><li><i class="fas fa-envelope"></i> ${reportData.reporter_email || ''}</li><li><i class="fas fa-phone"></i> ${reportData.reporter_phone || ''}</li></ul></div>
                            <div class="detail-box"><h6><i class="fas fa-file-alt"></i>Report Details</h6><p>${nl2br(reportData.report_details)}</p></div>
                        </div>
                        <div>
                            <div class="detail-box mb-3"><h6><i class="fas fa-paperclip"></i>Evidence</h6><div class="evidence-links">${evidenceHtml}</div></div>
                            <div class="detail-box"><h6><i class="fas fa-cogs"></i>Actions & Comments</h6>
                                <form method='post' action='update_report_status.php' class='d-flex gap-2 mb-3'>
                                    <input type='hidden' name='csrf_token' value='<?php echo htmlspecialchars($csrf_token); ?>'><input type='hidden' name='report_id' value='${reportData.report_id}'><input type='hidden' name='return_url' value='${window.location.href}'>
                                    <select name='status_id' class='form-select form-select-sm' required><option value='' disabled>Change Status...</option>
                                        <?php foreach ($statuses as $s): ?>
                                        <option value='<?php echo $s['status_id']; ?>' \${reportData.status_id == <?php echo $s['status_id']; ?> ? 'selected' : ''}><?php echo htmlspecialchars($s['status_name']); ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                    <button type='submit' class='btn btn-sm btn-primary flex-shrink-0'>Update</button>
                                </form>
                                <div class="comment-section-auth">${commentsHtml}</div>
                                <form method='post' action='${window.location.href}' class="mt-2">
                                    <input type='hidden' name='csrf_token' value='<?php echo htmlspecialchars($csrf_token); ?>'><input type='hidden' name='report_id' value='${reportData.report_id}'>
                                    <textarea name='comment_text' class='form-control form-control-sm' rows='2' placeholder='Add a new comment...' required></textarea>
                                    <button type='submit' class='btn btn-outline-success btn-sm mt-2 w-100' name='add_comment_modal'>Post Comment</button>
                                </form>
                            </div>
                        </div>
                    </div></div>
                </div>`;
        });
        function nl2br(str) { return String(str || '').replace(/(\\r\\n|\\n|\\r)/g, '<br>'); }
        function getStatusBadgeClassJs(statusName) {
            const lower = (statusName || '').toLowerCase();
            switch (lower) {
                case 'pending': return 'bg-warning text-dark';
                case 'in progress': case 'assigned': return 'bg-primary';
                case 'resolved': return 'bg-success';
                case 'closed': return 'bg-secondary';
                case 'rejected': return 'bg-danger';
                case 'requires info': return 'bg-info text-dark';
                default: return 'bg-dark';
            }
        }
    });
    </script>
</body>
</html>