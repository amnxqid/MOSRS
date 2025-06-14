<?php
session_start();

// --- PART 1: CHATBOT API LOGIC (Handles Live AI Chat when activated) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false) {
    header('Content-Type: application/json');
    header('Cache-Control: no-cache');
    // --- PASTE YOUR GOOGLE AI STUDIO API KEY HERE ---
    $googleApiKey = 'YOUR API KEY';
    // ----------------------------------------------

    // --- Grounding Knowledge Base ---
    $system_knowledge = "
    === About MOSRS (Malaysia Online Scam Reporting System) ===
    - MOSRS is a centralized platform for users in Malaysia to report various types of online scams.
    - Our purpose is to streamline the reporting process by forwarding the user's report to the correct Malaysian authorities.
    - MOSRS is a reporting and channeling system, NOT an enforcement or investigative body. We help get your report to the right people.
    - The emergency number for the National Scam Response Centre (NSRC) is 997. This is the top priority for users who have just lost money.

    === How to Use the System ===
    - To Report a Scam: Users must be logged in. They can click the 'Report a Scam' button on their dashboard. The system provides a form to fill in all the details of the incident.
    - To Check Report Status: After logging in, a user can go to the 'View My Reports' section on their dashboard. This page shows a list of all their submitted reports and the current status (e.g., 'Submitted', 'Under Investigation', 'Referred to PDRM').
    - To Upload Evidence: Evidence like screenshots, receipts, or documents can be uploaded after a report is created. On the dashboard, there is an 'Upload Evidence' function where the user must select the relevant report ID to attach the files.

    === Relevant Authorities and Their Roles ===
    - PDRM (Royal Malaysia Police): Handles law enforcement aspects, cybercrime investigations, and any case requiring police action.
    - BNM (Bank Negara Malaysia): Focuses on financial scams, unauthorized banking transactions, illegal deposit schemes, and matters involving regulated financial institutions.
    - MCMC (Malaysian Communications and Multimedia Commission): Deals with the technical aspects of scams. This includes blocking phishing websites, taking down malicious online content, and investigating the misuse of communication networks like scam SMS or phone calls.
    ";

    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    if (!$data || !isset($data['messages'])) { http_response_code(400); echo json_encode(['error' => 'Invalid Request Body']); exit; }
    
    $user_messages = $data['messages'];
    $last_user_question = end($user_messages)['content'];
    
    $grounded_prompt = "
    You are an expert assistant for the Malaysia Online Scam Reporting System (MOSRS).
    Your primary source of truth for any questions about the MOSRS platform itself is the following context.
    
    --- CONTEXT (Source of Truth) ---
    {$system_knowledge}
    --- CONTEXT END ---

    When answering the user's question, follow these rules:
    1. If the user asks about how to use MOSRS (how to report, check status, etc.), you MUST answer using ONLY the information from the context above.
    2. If the user asks a general question about scams in Malaysia (like 'what are common scams?' or 'how to avoid phishing?'), you can use your general knowledge to provide a helpful and safe answer.
    3. After answering a general question, always try to link it back to the purpose of MOSRS. For example, end with 'You can report such incidents through the MOSRS platform.'
    4. Do not answer questions that are off-topic from scams or the MOSRS system.
    
    Now, please answer the following user's question: \"{$last_user_question}\"
    ";

    $geminiContents = [];
    foreach ($user_messages as $msg) {
        $role = ($msg['role'] === 'assistant') ? 'model' : 'user';
        $content = ($msg === end($user_messages)) ? $grounded_prompt : $msg['content'];
        $geminiContents[] = ['role' => $role, 'parts' => [['text' => $content]]];
    }

    $apiUrl = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=' . $googleApiKey;
    $postData = ['contents' => $geminiContents, 'generationConfig' => ['temperature' => 0.6, 'maxOutputTokens' => 2048], 'safetySettings' => [['category' => 'HARM_CATEGORY_HARASSMENT', 'threshold' => 'BLOCK_MEDIUM_AND_ABOVE'],['category' => 'HARM_CATEGORY_HATE_SPEECH', 'threshold' => 'BLOCK_MEDIUM_AND_ABOVE'],['category' => 'HARM_CATEGORY_SEXUALLY_EXPLICIT', 'threshold' => 'BLOCK_MEDIUM_AND_ABOVE'],['category' => 'HARM_CATEGORY_DANGEROUS_CONTENT', 'threshold' => 'BLOCK_MEDIUM_AND_ABOVE'],]];
    
    $ch = curl_init($apiUrl);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_POSTFIELDS => json_encode($postData), CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_CAINFO => 'C:/wamp64/cacert.pem']);
    $response = curl_exec($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    curl_close($ch);

    if ($curl_error) { http_response_code(500); echo json_encode(['error' => 'cURL Error: ' . $curl_error]); } 
    elseif ($httpcode !== 200) { http_response_code($httpcode); $errorData = json_decode($response, true); $errorMessage = $errorData['error']['message'] ?? 'An unknown API error occurred. Status: ' . $httpcode; echo json_encode(['error' => $errorMessage]); } 
    else {
        $responseData = json_decode($response, true);
        if (isset($responseData['candidates'][0]['content']['parts'][0]['text'])) {
            echo json_encode(['ai_response' => $responseData['candidates'][0]['content']['parts'][0]['text']]);
        } else { $blockReason = $responseData['promptFeedback']['blockReason'] ?? 'unknown reason'; $errorMessage = "The response was blocked by Google's safety filters (Reason: " . $blockReason . ")."; echo json_encode(['error' => $errorMessage]); }
    }
    exit;
}

// --- PART 2: MAIN DASHBOARD LOGIC ---
include_once 'db.php'; // Use include_once for db connection

// 1. Authentication Check: Ensure user is logged in and is a 'public' user
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'public') {
    $_SESSION['login_message'] = "Please log in to access your dashboard.";
    $_SESSION['login_message_type'] = "warning";
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$user_name = $_SESSION['name'] ?? 'User'; // Get user name for welcome message

// 2. Retrieve flash message from session if it exists
$display_message = $_SESSION['dashboard_message'] ?? null;
$message_type = $_SESSION['dashboard_message_type'] ?? 'info'; // Default type
unset($_SESSION['dashboard_message'], $_SESSION['dashboard_message_type']);

// 3. Get Unread Message Count
$unread_count = 0;
$fetch_error = '';
if (!$conn || $conn->connect_error) {
    $fetch_error = "Database connection error. Cannot retrieve notifications.";
    error_log("User Dashboard DB Error (Initial): " . ($conn ? $conn->connect_error : "No connection object"));
} else {
    $sql_count = "SELECT COUNT(*) AS unread_count FROM user_inbox WHERE user_id = ? AND is_read = 0";
    if ($stmt_count = $conn->prepare($sql_count)) {
        $stmt_count->bind_param("i", $user_id);
        if ($stmt_count->execute()) {
            $result_count = $stmt_count->get_result();
            if($row_count = $result_count->fetch_assoc()) {
                $unread_count = (int)$row_count['unread_count'];
            }
        } else {
            $fetch_error = "Could not retrieve notification count.";
            error_log("User Dashboard Error (Execute Count): UserID {$user_id} - " . $stmt_count->error);
        }
        $stmt_count->close();
    } else {
        $fetch_error = "Database error fetching notification count.";
        error_log("User Dashboard Error (Prepare Count): UserID {$user_id} - " . $conn->error);
    }
    if ($conn) { $conn->close(); }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard - MOSRS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="global_style.css"> 
    <link rel="stylesheet" href="user_dashboard_styles.css"> 
    <style>
        /* --- Styles for Messenger-Style Chat Modal --- */
        #chatbot-toggle-button { position: fixed; bottom: 25px; right: 25px; width: 70px; height: 70px; border-radius: 50%; background-color: #0d6efd; color: white; border: none; font-size: 28px; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 10px rgba(0,0,0,0.25); z-index: 1050; transition: transform 0.2s ease-in-out; }
        #chatbot-toggle-button:hover { transform: scale(1.1); }
        .modal.fade .modal-dialog { transition: transform .3s ease-out; transform: translate(0, 100px); }
        .modal.show .modal-dialog { transform: none; }
        .modal-dialog-chat { max-width: 420px; margin: 1rem auto; position: fixed; bottom: 100px; right: 25px; }
        .modal-content-chat { height: 70vh; max-height: 600px; background-color: #242526; color: #E4E6EB; border: 1px solid #3E4042; border-radius: 12px; display: flex; flex-direction: column; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
        .modal-header-chat { background-color: #242526; border-bottom: 1px solid #3E4042; padding: 0.75rem 1rem; display: flex; align-items: center; }
        .modal-header-chat .modal-title { font-size: 1rem; font-weight: 600; }
        .modal-header-chat .avatar { width: 32px; height: 32px; font-size: 1rem; }
        .btn-close-white { filter: invert(70%) sepia(10%) saturate(200%) hue-rotate(180deg) brightness(100%) contrast(90%); }
        .modal-body-chat { flex-grow: 1; overflow-y: auto; padding: 1rem; }
        .message-wrapper { display: flex; margin-bottom: 0.25rem; max-width: 85%; align-items: flex-end; }
        .message-bubble { line-height: 1.4; word-wrap: break-word; padding: 8px 12px; font-size: 0.95rem; border-radius: 18px; }
        .message-bubble p:last-child { margin-bottom: 0; }
        .user-message { justify-content: flex-end; margin-left: auto; }
        .user-message .message-bubble { background-color: #0084FF; color: white; }
        .bot-message { justify-content: flex-start; margin-right: auto; }
        .bot-message .message-bubble { background-color: #3E4042; color: #E4E6EB; }
        .avatar { width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1rem; font-weight: 700; color: #fff; margin: 0 8px; flex-shrink: 0; background-color: #0D6EFD; }
        .user-message .avatar { display: none; }
        .chat-options-container { padding: 5px 0 10px 44px; display: flex; flex-wrap: wrap; }
        .chat-option-btn { border: 1px solid #555; color: #E4E6EB; background-color: transparent; border-radius: 15px; padding: 5px 12px; margin: 4px; cursor: pointer; transition: all 0.2s; font-size: 0.85rem; }
        .chat-option-btn:hover { background-color: #3E4042; border-color: #777; }
        .chat-option-btn.live-agent-btn { border-color: #0084FF; color: #0084FF; }
        .chat-option-btn.live-agent-btn:hover { background-color: #0084FF; color: white; }
        .modal-footer-chat { border-top: 1px solid #3E4042; padding: 0.5rem 0.75rem; background-color: #242526; }
        .modal-footer-chat.hidden { display: none; }
        .modal-footer-chat .input-group .form-control { background-color: #3A3B3C; border: none; color: #E4E6EB; border-radius: 18px; padding: 8px 15px; }
        .modal-footer-chat .input-group .form-control::placeholder { color: #B0B3B8; }
        .modal-footer-chat .input-group .btn { background: none; border: none; color: #0084FF; font-size: 1.2rem; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-sm navbar-dark bg-primary sticky-top shadow-sm">
        <div class="container-fluid">
            <a class="navbar-brand" href="index.php"><img src="kementerian.jpg" alt="Logo" class="header-logo-img" onerror="this.onerror=null; this.style.display='none';"> MOSRS</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"><span class="navbar-toggler-icon"></span></button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto align-items-center">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle profile-dropdown-toggler" href="#" id="navbarDropdownMenuLink" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <span class="profile-avatar-sm"><?php echo strtoupper(substr($user_name, 0, 1)); ?></span> <?php echo htmlspecialchars($user_name); ?> <i class="fas fa-chevron-down fa-xs ms-1"></i>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end profile-dropdown-menu" aria-labelledby="navbarDropdownMenuLink">
                            <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user-circle"></i> View Profile</a></li>
                            <li><a class="dropdown-item" href="edit_profile.php"><i class="fas fa-user-edit"></i> Edit Profile</a></li>
                            <li><a class="dropdown-item" href="change_password.php"><i class="fas fa-key"></i> Change Password</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item text-danger" href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container main-container my-4">
        <div class="welcome-banner">
            <h2>Welcome Back, <span class="user-name-display"><?php echo htmlspecialchars($user_name); ?>!</span></h2>
            <p>Ready to manage your reports or get assistance?</p>
        </div>

        <?php if (isset($display_message)) : ?><div class="alert alert-<?php echo htmlspecialchars($message_type); ?> alert-dismissible fade show" role="alert"><?php echo htmlspecialchars($display_message); ?><button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div><?php endif; ?>
        <?php if (!empty($fetch_error)) : ?><div class="alert alert-warning" role="alert"><?php echo htmlspecialchars($fetch_error); ?></div><?php endif; ?>

        <div class="action-card-grid">
            <a href="report.php" class="action-card"><div class="action-icon"><i class="fas fa-flag"></i></div><h5>Report a Scam</h5><p>Submit details about a new incident.</p></a>
            <a href="view_report.php" class="action-card"><div class="action-icon"><i class="fas fa-list-alt"></i></div><h5>View My Reports</h5><p>Check the status and history of your reports.</p></a>
            <a href="inbox.php" class="action-card position-relative"><?php if ($unread_count > 0): ?><span class="badge rounded-pill bg-danger badge-indicator"><?php echo $unread_count; ?><span class="visually-hidden">unread messages</span></span><?php endif; ?><div class="action-icon"><i class="fas fa-envelope"></i></div><h5>My Inbox</h5><p>View messages and notifications.</p></a>
            <a href="upload_evidence.php" class="action-card"><div class="action-icon"><i class="fas fa-upload"></i></div><h5>Upload Evidence</h5><p>Add supporting files to your existing reports.</p></a>
            
            <!-- MODIFICATION: This card now opens the chat modal -->
            <a href="#" class="action-card" data-bs-toggle="modal" data-bs-target="#chatModal">
                <div class="action-icon"><i class="fas fa-comments"></i></div>
                <h5>Chat Assistant</h5>
                <p>Get quick answers to common questions.</p>
            </a>

            <a href="profile.php" class="action-card"><div class="action-icon"><i class="fas fa-user-cog"></i></div><h5>My Profile</h5><p>View or update your account details.</p></a>
        </div>
    </div>

    <!-- Floating Chat Button -->
    <button id="chatbot-toggle-button" data-bs-toggle="modal" data-bs-target="#chatModal" title="Chat with Assistant"><i class="fas fa-comments"></i></button>

    <!-- Chat Modal -->
    <div class="modal fade" id="chatModal" tabindex="-1" aria-hidden="true">
      <div class="modal-dialog modal-dialog-chat">
        <div class="modal-content modal-content-chat">
          <div class="modal-header modal-header-chat"><div class="avatar me-2"><i class="fas fa-robot"></i></div><h5 class="modal-title">MOSRS Assistant</h5><button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button></div>
          <div class="modal-body modal-body-chat" id="chat-messages-container"></div>
          <div class="modal-footer modal-footer-chat hidden" id="chat-input-container"><div class="input-group"><textarea id="chat-user-input" class="form-control" placeholder="Aa" rows="1"></textarea><button id="chat-send-btn" class="btn"><i class="fas fa-paper-plane"></i></button></div></div>
        </div>
      </div>
    </div>

    <footer class="footer"><div class="container"><span>© MALAYSIA ONLINE SCAM REPORTING SYSTEM (MOSRS) <?php echo date("Y"); ?></span></div></footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        const chatModalEl = document.getElementById('chatModal');
        const chatBox = document.getElementById('chat-messages-container');
        const chatInputContainer = document.getElementById('chat-input-container');
        const userInput = document.getElementById('chat-user-input');
        const sendBtn = document.getElementById('chat-send-btn');
        
        const liveChatHistory = [];
        const chatFlow = {
            'start': {'message': "Hello! I'm the MOSRS Assistant. How can I help you?",'options': {'report_info': 'How to Report a Scam?','status_info': 'Check Report Status?','authority_menu': 'Relevant Authorities?','nsrc_contact': 'Contact NSRC (Emergency)?','live_chat': 'Chat with AI Agent'}},
            'report_info': {'message': "To report a scam, please log in and click 'Report a Scam'. You'll be guided through the process.",'options': {'start': 'Main Menu', 'live_chat': 'Chat with AI Agent'}},
            'status_info': {'message': "Log in and navigate to 'View My Reports' on your dashboard to see the status of all your reports.",'options': {'start': 'Main Menu', 'live_chat': 'Chat with AI Agent'}},
            'authority_menu': {'message': "Which authority would you like to know more about?",'options': {'pdrm_info': 'PDRM','bnm_info': 'BNM','mcmc_info': 'MCMC','start': 'Main Menu'}},
            'pdrm_info': {'message': "PDRM (Royal Malaysia Police) handles the law enforcement aspects of cybercrimes and scams requiring police investigation.",'options': {'authority_menu': 'Back to Authorities', 'start': 'Main Menu'}},
            'bnm_info': {'message': "BNM (Bank Negara Malaysia) focuses on financial scams, unauthorized transactions, and issues related to regulated financial institutions.",'options': {'authority_menu': 'Back to Authorities', 'start': 'Main Menu'}},
            'mcmc_info': {'message': "MCMC (Malaysian Communications and Multimedia Commission) handles complaints on online content, phishing websites, and scam calls/SMS.",'options': {'authority_menu': 'Back to Authorities', 'start': 'Main Menu'}},
            'nsrc_contact': {'message': "For immediate assistance if you've just lost money, call the National Scam Response Centre (NSRC) at <strong>997</strong>.",'options': {'start': 'Main Menu', 'live_chat': 'Chat with AI Agent'}},
        };

        function appendMessage(role, text) { const wrapper = document.createElement('div'); wrapper.className = `message-wrapper ${role}-message`; wrapper.innerHTML = `<div class="avatar"><i class="fas fa-robot"></i></div><div class="message-bubble">${marked.parse(text)}</div>`; if (role === 'user') wrapper.querySelector('.avatar')?.remove(); chatBox.appendChild(wrapper); chatBox.scrollTop = chatBox.scrollHeight; return wrapper; }
        function displayOptions(options) { const container = document.createElement('div'); container.className = 'chat-options-container'; for (const key in options) { const btn = document.createElement('button'); btn.className = 'chat-option-btn'; if (key === 'live_chat') btn.classList.add('live-agent-btn'); btn.textContent = options[key]; btn.dataset.key = key; container.appendChild(btn); } chatBox.appendChild(container); chatBox.scrollTop = chatBox.scrollHeight; }
        function handleNode(nodeKey) { const node = chatFlow[nodeKey]; if (!node) return; appendMessage('bot', node.message); if (node.options) displayOptions(node.options); }
        function activateLiveChat() { document.querySelector('.chat-options-container')?.remove(); appendMessage('bot', "You are now connected to the live AI agent. I will answer based on my knowledge of the MOSRS system. Please type your question below."); chatInputContainer.classList.remove('hidden'); userInput.focus(); }
        
        chatBox.addEventListener('click', function(e) {
            if (e.target.matches('.chat-option-btn')) {
                const key = e.target.dataset.key;
                const text = e.target.textContent;
                appendMessage('user', text);
                document.querySelector('.chat-options-container').remove();
                if (key === 'live_chat') {
                    activateLiveChat();
                } else {
                    handleNode(key);
                }
            }
        });
        
        async function sendLiveMessage() {
            const text = userInput.value.trim(); if (!text) return;
            appendMessage('user', text);
            liveChatHistory.push({ role: 'user', content: text });
            userInput.value = '';
            sendBtn.disabled = true;
            const aiBubble = appendMessage('bot', '...').querySelector('.message-bubble');
            try {
                // IMPORTANT: The fetch URL must match the current filename
                const response = await fetch('user_dashboard.php', {method: 'POST',headers: { 'Content-Type': 'application/json' },body: JSON.stringify({ messages: liveChatHistory })});
                const result = await response.json();
                if (result.error) throw new Error(result.error);
                if (result.ai_response) { aiBubble.innerHTML = marked.parse(result.ai_response); liveChatHistory.push({ role: 'assistant', content: result.ai_response }); } else { throw new Error("Empty response from AI."); }
            } catch (error) { aiBubble.innerHTML = `<p><strong>Error:</strong><br>${error.message}</p>`; } finally { sendBtn.disabled = false; userInput.focus(); }
        }

        chatModalEl.addEventListener('show.bs.modal', () => {
            chatBox.innerHTML = '';
            liveChatHistory.length = 0;
            chatInputContainer.classList.add('hidden');
            handleNode('start');
        });

        sendBtn.addEventListener('click', sendLiveMessage);
        userInput.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendLiveMessage(); } });
    });
    </script>
</body>
</html>
