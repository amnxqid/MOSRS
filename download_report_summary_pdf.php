<?php
session_start();

// 1. Authentication Check
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'admin') {
    header("HTTP/1.1 403 Forbidden");
    exit("Access Denied. You must be an admin to download this report.");
}

// 2. Include Core Files & FPDF Library
include_once 'db.php'; // Database connection
require('fpdf/fpdf.php'); // Include FPDF library

// 3. Configuration
$filename_pdf = "mosrs_report_summary_" . date('Y-m-d_H-i-s') . ".pdf";

// 4. Check Database Connection
if (!$conn || $conn->connect_error) {
    error_log("Download PDF Summary: DB connection error - " . ($conn ? $conn->connect_error : "Connection object not found"));
    // Output a simple error PDF or HTML error page
    header("Content-Type: text/plain");
    exit("Could not connect to the database to generate the report. Please try again later. Error: " . ($conn ? $conn->connect_error : "Connection object not found"));
}

// 5. Fetch Data (Same as CSV version)
$summary_data = [];
$fetch_errors = [];

try {
    // Total Reports
    $total_reports_sql = "SELECT COUNT(*) AS total FROM reports";
    $result = $conn->query($total_reports_sql);
    $summary_data['total_reports'] = $result ? $result->fetch_assoc()['total'] : 0;
    if (!$result) $fetch_errors[] = "Error fetching total reports: " . $conn->error;

    // Total Users
    $total_users_sql = "SELECT COUNT(*) AS total FROM users";
    $result = $conn->query($total_users_sql);
    $summary_data['total_users'] = $result ? $result->fetch_assoc()['total'] : 0;
    if (!$result) $fetch_errors[] = "Error fetching total users: " . $conn->error;

    // Assigned Reports
    $assigned_reports_sql = "SELECT COUNT(*) AS total FROM reports WHERE authority_type IS NOT NULL AND authority_type != '' AND authority_type != 'Not Sure'";
    $result = $conn->query($assigned_reports_sql);
    $summary_data['assigned_reports_to_authority'] = $result ? $result->fetch_assoc()['total'] : 0;
    if (!$result) $fetch_errors[] = "Error fetching assigned reports count: " . $conn->error;

    // Report Status Counts
    $summary_data['status_counts'] = [];
    $statuses_sql = "SELECT status_name FROM report_status";
    $statuses_result = $conn->query($statuses_sql);
    if ($statuses_result) {
        while ($status_row = $statuses_result->fetch_assoc()) {
            $status_name = $status_row['status_name'];
            $status_sql = "SELECT COUNT(*) AS total FROM reports r JOIN report_status rs ON r.status_id = rs.status_id WHERE rs.status_name = ?";
            $stmt_status = $conn->prepare($status_sql);
            if ($stmt_status) {
                $stmt_status->bind_param("s", $status_name);
                $stmt_status->execute();
                $status_result_q = $stmt_status->get_result();
                $summary_data['status_counts'][$status_name] = $status_result_q ? $status_result_q->fetch_assoc()['total'] : 0;
                if (!$status_result_q) $fetch_errors[] = "Error fetching count for status '$status_name': " . $stmt_status->error;
                $stmt_status->close();
            } else {
                $fetch_errors[] = "Error preparing statement for status count '$status_name': " . $conn->error;
                $summary_data['status_counts'][$status_name] = 0;
            }
        }
    } else {
        $fetch_errors[] = "Error fetching status names: " . $conn->error;
    }

    // Reports by Category (Top 5)
    $summary_data['reports_by_category'] = [];
    $sql_reports_by_category = "SELECT category, COUNT(*) AS count FROM reports GROUP BY category ORDER BY count DESC LIMIT 5";
    $result = $conn->query($sql_reports_by_category);
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            if (!empty($row['category'])) {
                $summary_data['reports_by_category'][] = ['name' => $row['category'], 'count' => (int)$row['count']];
            }
        }
    } else {
        $fetch_errors[] = "Error fetching reports by category: " . $conn->error;
    }

    // Reports by Authority Type
    $summary_data['reports_by_authority_type'] = [];
    $sql_reports_by_authority = "SELECT authority_type, COUNT(*) AS count FROM reports GROUP BY authority_type HAVING authority_type IS NOT NULL AND authority_type != '' AND authority_type != 'Not Sure' ORDER BY count DESC";
    $result = $conn->query($sql_reports_by_authority);
    if ($result) {
        while ($row = $result->fetch_assoc()) {
             $summary_data['reports_by_authority_type'][] = ['name' => $row['authority_type'], 'count' => (int)$row['count']];
        }
    } else {
        $fetch_errors[] = "Error fetching reports by authority type: " . $conn->error;
    }

    // Reports by Region (Top 5, if column exists)
    $summary_data['reports_by_region'] = [];
    $region_column_exists = false;
    $check_region_column_sql = "SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'region' LIMIT 1";
    $region_column_result = $conn->query($check_region_column_sql);
    if ($region_column_result && $region_column_result->num_rows > 0) {
        $region_column_exists = true;
        $sql_reports_by_region = "SELECT u.region, COUNT(*) AS count FROM reports r JOIN users u ON r.user_id = u.user_id WHERE u.region IS NOT NULL AND u.region != '' GROUP BY u.region ORDER BY count DESC LIMIT 5";
        $result = $conn->query($sql_reports_by_region);
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $summary_data['reports_by_region'][] = ['name' => $row['region'], 'count' => (int)$row['count']];
            }
        } else {
            $fetch_errors[] = "Error fetching reports by region: " . $conn->error;
        }
    } elseif (!$region_column_result) {
        $fetch_errors[] = "Error checking for users.region column: " . $conn->error;
    }

} catch (Exception $e) {
    $fetch_errors[] = "Exception during data fetching: " . $e->getMessage();
}

// Log any errors encountered
if (!empty($fetch_errors)) {
    foreach($fetch_errors as $err) {
        error_log("Download PDF Summary Data Fetch Error: " . $err);
    }
}

// 6. PDF Generation
class PDF extends FPDF {
    // Page header
    function Header() {
        // Logo (optional, if you have kementerian.jpeg and want to include it)
        // Ensure the path is correct or remove if not needed
        if (file_exists('kementerian.jpeg')) {
           $this->Image('kementerian.jpeg', 10, 6, 20); // X, Y, Width
        }
        $this->SetFont('Arial', 'B', 15);
        $this->Cell(80); // Move to the right
        $this->Cell(30, 10, 'MOSRS Report Summary', 0, 0, 'C'); // Title
        $this->Ln(15); // Line break
        $this->SetFont('Arial', '', 10);
        $this->Cell(0, 6, 'Generated on: ' . date('Y-m-d H:i:s'), 0, 1, 'C');
        $this->Ln(5); // Line break
    }

    // Page footer
    function Footer() {
        $this->SetY(-15); // Position at 1.5 cm from bottom
        $this->SetFont('Arial', 'I', 8);
        $this->Cell(0, 10, 'Page ' . $this->PageNo() . '/{nb}', 0, 0, 'C'); // Page number
    }

    // Chapter title
    function ChapterTitle($title) {
        $this->SetFont('Arial', 'B', 12);
        $this->SetFillColor(200, 220, 255); // Light blue
        $this->Cell(0, 7, $title, 0, 1, 'L', true);
        $this->Ln(4);
    }

    // Simple table
    function BasicTable($header, $data, $widths = [90, 90]) {
        $this->SetFont('Arial', 'B', 10);
        $this->SetFillColor(230,230,230); // Light grey for header
        $this->SetTextColor(0);
        $fill = true;
        // Header
        for($i=0; $i<count($header); $i++) {
            $this->Cell($widths[$i], 7, $header[$i], 1, 0, 'C', $fill);
        }
        $this->Ln();
        $fill = false;
        // Data
        $this->SetFont('Arial', '', 9);
        foreach($data as $row) {
            $this->Cell($widths[0], 6, html_entity_decode($row[0]), 'LRB', 0); // Use html_entity_decode for special chars
            $this->Cell($widths[1], 6, $row[1], 'RB', 1);
        }
        $this->Ln(5);
    }

    // Key-Value list
    function KeyValueList($title, $data_array) {
        $this->ChapterTitle($title);
        $this->SetFont('Arial', '', 10);
        foreach($data_array as $key => $value) {
            $this->SetFont('Arial', 'B', 10);
            $this->Cell(70, 6, html_entity_decode(ucwords(str_replace('_', ' ', $key))) . ':', 0, 0);
            $this->SetFont('Arial', '', 10);
            $this->Cell(0, 6, html_entity_decode($value), 0, 1);
        }
        $this->Ln(5);
    }
}

$pdf = new PDF();
$pdf->AliasNbPages(); // Enables page numbering {nb}
$pdf->AddPage();
$pdf->SetFont('Arial', '', 10);


// Section 1: General Statistics
$general_stats_data = [
    'Total Reports Submitted' => $summary_data['total_reports'] ?? 'N/A',
    'Total Registered Users' => $summary_data['total_users'] ?? 'N/A',
    'Reports Assigned to Authority' => $summary_data['assigned_reports_to_authority'] ?? 'N/A'
];
$pdf->KeyValueList('Overall System Statistics', $general_stats_data);


// Section 2: Reports by Status
$pdf->ChapterTitle('Report Counts by Status');
$status_table_header = ['Status', 'Count'];
$status_table_data = [];
if (!empty($summary_data['status_counts'])) {
    foreach ($summary_data['status_counts'] as $status => $count) {
        $status_table_data[] = [$status, $count];
    }
} else {
    $status_table_data[] = ['No status data available', ''];
}
$pdf->BasicTable($status_table_header, $status_table_data, [90, 30]);

// Section 3: Top 5 Reports by Category
$pdf->ChapterTitle('Top 5 Scam Reports by Category');
$category_table_header = ['Category', 'Count'];
$category_table_data = [];
if (!empty($summary_data['reports_by_category'])) {
    foreach ($summary_data['reports_by_category'] as $item) {
        $category_table_data[] = [$item['name'], $item['count']];
    }
} else {
    $category_table_data[] = ['No category data available', ''];
}
$pdf->BasicTable($category_table_header, $category_table_data, [140, 30]);

// Section 4: Reports by Assigned Authority Type
$pdf->ChapterTitle('Report Counts by Assigned Authority Type');
$authority_table_header = ['Authority Type', 'Count'];
$authority_table_data = [];
if (!empty($summary_data['reports_by_authority_type'])) {
    foreach ($summary_data['reports_by_authority_type'] as $item) {
        $authority_table_data[] = [$item['name'], $item['count']];
    }
} else {
    $authority_table_data[] = ['No authority assignment data', ''];
}
$pdf->BasicTable($authority_table_header, $authority_table_data, [90, 30]);

// Section 5: Top 5 Reports by Region
if ($region_column_exists) {
    $pdf->ChapterTitle('Top 5 Scam Reports by Region');
    $region_table_header = ['Region', 'Count'];
    $region_table_data = [];
    if (!empty($summary_data['reports_by_region'])) {
        foreach ($summary_data['reports_by_region'] as $item) {
            $region_table_data[] = [$item['name'], $item['count']];
        }
    } else {
        $region_table_data[] = ['No region data available', ''];
    }
    $pdf->BasicTable($region_table_header, $region_table_data, [90, 30]);
} else {
    $pdf->ChapterTitle('Reports by Region');
    $pdf->SetFont('Arial','',10);
    $pdf->MultiCell(0,6,'Region data not available (users.region column may not exist in the database or no data has been reported for regions).',0,'L');
    $pdf->Ln(5);
}

// Optional: Include any fetching errors in the PDF
if (!empty($fetch_errors)) {
    $pdf->ChapterTitle('Notes/Errors Encountered');
    $pdf->SetFont('Arial', 'I', 9);
    $pdf->SetTextColor(255,0,0); // Red for errors
    foreach($fetch_errors as $err_msg) {
        $pdf->MultiCell(0, 5, html_entity_decode("- " . $err_msg), 0, 'L');
    }
    $pdf->SetTextColor(0); // Reset color
    $pdf->Ln(5);
}


// 7. Output PDF
$pdf->Output('D', $filename_pdf); // 'D' means download the file

if (isset($conn) && $conn instanceof mysqli && !$conn->connect_error) { // Check connection for audit
    // --- Record Audit Log for PDF Download Attempt ---
    $log_action_pdf = "ADMIN_DOWNLOAD_PDF_SUMMARY";
    $log_details_pdf = "Admin ID: {$admin_id_current} attempted to download PDF report summary.";
    if (!empty($fetch_errors)) { // If there were errors fetching data for PDF
        $log_details_pdf .= " Issues encountered: " . implode("; ", $fetch_errors);
    }
    recordAuditLog($conn, $admin_id_current, $log_action_pdf, "system_reports", "pdf_summary", null, $log_details_pdf);
    // --- End Audit Log ---
} else {
    error_log("PDF Download: DB connection not available for audit logging. Admin ID: {$admin_id_current}");
}


// Your existing $pdf->Output() should be here
// $pdf->Output('D', $filename_pdf); // 'D' means download the file

// Close DB Connection if it was opened by this script and not by an include that manages it
if (isset($conn) && $conn instanceof mysqli && $conn->ping()) { // Check if connection is still alive
    $conn->close();
}

exit(); // Important to prevent any further PHP output after PDF
?>