<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

// Adjust paths if PHPMailer is not directly in a 'PHPMailer' subdirectory
require_once __DIR__ . '/PHPMailer/src/Exception.php';
require_once __DIR__ . '/PHPMailer/src/PHPMailer.php';
require_once __DIR__ . '/PHPMailer/src/SMTP.php';

/**
 * Sends notification emails (Report Updates, Password Resets, etc.).
 *
 * @param string $recipientEmail The email address to send to.
 * @param string $subject The full subject line for the email.
 * @param string $messageBody The body content of the email (can be plain text or HTML).
 * @param bool $isHtml Set to true if $messageBody is HTML, false for plain text (default).
 * @return string Returns 'Message has been sent' on success, or an error string on failure.
 */
function sendNotificationEmail(string $recipientEmail, string $subject, string $messageBody, bool $isHtml = false): string {
  $mail = new PHPMailer(true); // Enable exceptions

  try {
    // --- Server settings ---
    // $mail->SMTPDebug = SMTP::DEBUG_SERVER; // UNCOMMENT FOR DETAILED DEBUGGING OUTPUT
    $mail->SMTPDebug = SMTP::DEBUG_OFF;    // Set to OFF for production
    $mail->isSMTP();                       // Send using SMTP
    $mail->Host       = 'smtp.gmail.com';  // Gmail SMTP server
    $mail->SMTPAuth   = true;              // Enable SMTP authentication
    $mail->Username   = 'zikryamin.se2425@gmail.com'; // Your Gmail address
    $mail->Password   = 'cqdx ycqa szdz ofpb';        // Your Gmail App Password
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS; // Enable implicit TLS encryption
    $mail->Port       = 465;                 // TCP port for SMTPS

    // --- Recipients ---
    // Set the "From" address (should match the Username for Gmail usually)
    $mail->setFrom('zikryamin.se2425@gmail.com', 'MOSRS System'); // Use a system name
    // Add the recipient passed to the function
    $mail->addAddress($recipientEmail);
    // Optional: $mail->addReplyTo('no-reply@example.com', 'No Reply');

    // --- Content ---
    $mail->isHTML($isHtml); // Set email format based on parameter
    $mail->Subject = $subject; // Use the subject passed to the function
    $mail->Body    = $messageBody; // Use the body passed to the function

    // Provide a plain text version if sending HTML
    if ($isHtml) {
        // Basic conversion - you might need a more sophisticated library for complex HTML
        $mail->AltBody = strip_tags(str_replace("<br>", "\n", $messageBody)); 
    } else {
         $mail->AltBody = $messageBody; // For plain text, AltBody is the same
    }


    // --- Send the email ---
    $mail->send();
    return 'Message has been sent'; // Specific success message

  } catch (Exception $e) {
    // Log the detailed error for server-side debugging
    $errorMessage = "Mailer Error: " . $mail->ErrorInfo . ". Exception: " . $e->getMessage();
    error_log("sendNotificationEmail failed for {$recipientEmail} - Subject: {$subject} - Error: " . $errorMessage);
    // Return the detailed error (useful for debugging in the calling script)
    return "Message could not be sent. Error: " . $mail->ErrorInfo;
  }
}

/**
 * --- Kept for Backward Compatibility ---
 * Sends a report update email by calling the generic function.
 *
 * @param string $reporter_email
 * @param string $report_title
 * @param string $update_message (Plain text)
 * @return string
 * @deprecated Prefer calling sendNotificationEmail directly.
 */
function sendReportUpdateEmail(string $reporter_email, string $report_title, string $update_message): string {
    $subject = 'Update on Your MOSRS Report: ' . $report_title;
    // Report updates are usually plain text
    return sendNotificationEmail($reporter_email, $subject, $update_message, false);
}

?>