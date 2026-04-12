<?php
session_start(); // Necessario per CSRF e gestione sessione (IDOR)

$host = 'db';
$user = 'root';
$pass = 'password_sicura'; 
$dbname = 'websec_db';

$conn = new mysqli($host, $user, $pass, $dbname);

if($conn->connect_error) {
    die('Connessione fallita'. $conn->connect_error);
}

// Inizializzazione variabili
$login_message = "";
$user_profile = null;
$ping_output = "";
$upload_message = "";
$search_query = "";

// --- MITIGAZIONE CSRF: Generazione Token ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- 1. MITIGAZIONE SQL INJECTION (LOGIN) ---
// Uso di Prepared Statements
if(isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    $stmt = $conn->prepare("SELECT id, username FROM users WHERE username = ? AND password = ?");
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();

    if($result->num_rows > 0) {
        $user_data = $result->fetch_assoc();
        $_SESSION['user_id'] = $user_data['id']; // Salviamo l'ID in sessione per IDOR
        $login_message = "<div class='success'>Benvenuto, " . htmlspecialchars($user_data["username"]) . "!</div>";
    } else {
        $login_message = "<div class='error'>Credenziali errate.</div>";
    }
    $stmt->close();
}

// --- 2. MITIGAZIONE STORED XSS (COMMENTI - PARTE INSERIMENTO) ---
if(isset($_POST['add_comment'])) {
    $comment = $_POST['comment'];
    $stmt = $conn->prepare("INSERT INTO comments (content) VALUES (?)");
    $stmt->bind_param("s", $comment);
    $stmt->execute();
    $stmt->close();
}

// --- 3. MITIGAZIONE CSRF (CAMBIO EMAIL) ---
// Controllo del Token di sessione
if(isset($_POST['update_email'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $login_message = "<div class='error'>Errore Sicurezza: Token CSRF non valido.</div>";
    } else {
        $new_email = $_POST['email'];
        $user_id = $_SESSION['user_id'] ?? 1; // Usa l'utente loggato

        $stmt = $conn->prepare("UPDATE users SET email = ? WHERE id = ?");
        $stmt->bind_param("si", $new_email, $user_id);
        if($stmt->execute()) {
            $login_message = "<div class='success'>Email aggiornata con successo!</div>";
        }
        $stmt->close();
    }
}

// --- 4. MITIGAZIONE IDOR (VISUALIZZA PROFILO) ---
// Controllo di accesso incrociato
if(isset($_GET['view_profile'])) {
    $id_richiesto = intval($_GET['view_profile']);
    
    // Verifica che l'utente possa vedere solo il proprio profilo
    if (!isset($_SESSION['user_id']) || $id_richiesto !== intval($_SESSION['user_id'])) {
        $login_message = "<div class='error'>Accesso Negato: Non puoi visualizzare profili altrui.</div>";
    } else {
        $stmt = $conn->prepare("SELECT username, email, role FROM users WHERE id = ?");
        $stmt->bind_param("i", $id_richiesto);
        $stmt->execute();
        $user_profile = $stmt->get_result()->fetch_assoc();
        $stmt->close();
    }
}

// --- 5. MITIGAZIONE LOCAL FILE INCLUSION (LFI) ---
// Whitelisting dei file permessi
if (isset($_GET['load_page'])) {
    $allowed = ['info.txt', 'contact.txt']; // Lista bianca
    $page = $_GET['load_page'];
    
    if (!in_array($page, $allowed)) {
        $lfi_error = "File non consentito.";
        $page_to_include = null;
    } else {
        $page_to_include = $page;
    }
}

// --- 6. MITIGAZIONE COMMAND INJECTION (PING) ---
// Uso di escapeshellarg()
if (isset($_POST['ping'])) {
    $ip = $_POST['ip'];
    $safe_ip = escapeshellarg($ip); // Rende l'input una stringa sicura
    $ping_output = shell_exec("ping -c 3 " . $safe_ip);
}

// --- 7. MITIGAZIONE UNRESTRICTED FILE UPLOAD ---
// Whitelist estensioni e ridenominazione file
if (isset($_POST['upload'])) {
    $target_dir = __DIR__ . "/uploads/";
    $file_name = $_FILES["fileToUpload"]["name"];
    $file_type = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
    $allowed_types = array("jpg", "png", "jpeg", "gif");

    if (in_array($file_type, $allowed_types)) {
        $new_name = uniqid() . "." . $file_type; // Nome casuale per evitare RCE
        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_dir . $new_name)) {
            $upload_message = "<div class='success'>Immagine caricata correttamente.</div>";
        }
    } else {
        $upload_message = "<div class='error'>Errore: Sono consentite solo immagini (JPG, PNG, GIF).</div>";
    }
}

// --- 8. MITIGAZIONE REFLECTED XSS (RICERCA) ---
// Encoding in fase di ricezione/output
if (isset($_GET['query'])) {
    $search_query = htmlspecialchars($_GET['query'], ENT_QUOTES, 'UTF-8');
}

?>

<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <title>WebSec-Lab: Versione SICURA</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #e8f5e9; padding: 20px; color: #333; }
        .container { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); max-width: 900px; margin: auto; }
        h1 { color: #2e7d32; border-bottom: 3px solid #2e7d32; padding-bottom: 10px; }
        .section { margin-bottom: 40px; padding: 20px; border: 1px solid #c8e6c9; border-radius: 8px; background: #fff; }
        .success { background: #dff0d8; color: #3c763d; padding: 10px; border-radius: 4px; }
        .error { background: #f2dede; color: #a94442; padding: 10px; border-radius: 4px; }
        pre { background: #272822; color: #f8f8f2; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>

<div class="container">
    <h1>WebSec-Lab 🛡️ <small style="font-size: 0.5em; color: #666;">Versione Mitigata</small></h1>
    <p>Questo ambiente è stato messo in sicurezza applicando le best practice OWASP.</p>

    <div class="section">
        <h2>1. Autenticazione (Protetta da SQLi)</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" name="login">Accedi</button>
        </form>
        <?php echo $login_message; ?>
    </div>

    <div class="section">
        <h2>2. Bacheca Commenti (Protetta da Stored XSS)</h2>
        <form method="POST">
            <textarea name="comment" placeholder="Lascia un commento..."></textarea>
            <button type="submit" name="add_comment">Invia</button>
        </form>
        <hr>
        <?php
        $res = $conn->query("SELECT content FROM comments ORDER BY id DESC");
        while ($row = $res->fetch_assoc()) {
            // Mitigazione: Encoding in output
            echo "<div style='border-bottom: 1px solid #eee; padding: 10px;'>" . htmlspecialchars($row['content'], ENT_QUOTES, 'UTF-8') . "</div>";
        }
        ?>
    </div>

    <div class="section">
        <h2>3. Ricerca Globale (Protetta da Reflected XSS)</h2>
        <form method="GET">
            <input type="text" name="query" placeholder="Cerca...">
            <button type="submit">Cerca</button>
        </form>
        <?php if ($search_query): ?>
            <p>Risultati per: <strong><?php echo $search_query; ?></strong></p>
        <?php endif; ?>
    </div>

    <div class="section">
        <h2>4. Gestione Account (Protetta da CSRF)</h2>
        <form method="POST">
            <input type="email" name="email" placeholder="Nuova Email" required>
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <button type="submit" name="update_email">Aggiorna Email</button>
        </form>
    </div>

    <div class="section">
        <h2>5. Elenco Utenti (Protetta da IDOR)</h2>
        <a href="?view_profile=1">Il mio Profilo (Admin)</a> | <a href="?view_profile=2">Profilo Bob</a>
        <?php if ($user_profile): ?>
            <div style="background: #f1f8e9; padding: 15px; border-left: 5px solid #2e7d32; margin-top: 15px;">
                <strong>Username:</strong> <?php echo htmlspecialchars($user_profile['username']); ?><br>
                <strong>Email:</strong> <?php echo htmlspecialchars($user_profile['email']); ?><br>
                <strong>Ruolo:</strong> <?php echo htmlspecialchars($user_profile['role']); ?>
            </div>
        <?php endif; ?>
    </div>

    <div class="section">
        <h2>6. Strumenti di Rete (Protetta da Command Injection)</h2>
        <form method="POST">
            <input type="text" name="ip" placeholder="8.8.8.8" required>
            <button type="submit" name="ping">Test Ping</button>
        </form>
        <?php if ($ping_output): ?>
            <pre><?php echo htmlspecialchars($ping_output); ?></pre>
        <?php endif; ?>
    </div>

    <div class="section">
        <h2>7. Visualizzatore Documenti (Protetta da LFI)</h2>
        <ul>
            <li><a href="?load_page=info.txt">Note di rilascio</a></li>
        </ul>
        <div style="background: #f4f4f4; padding: 10px; font-family: monospace;">
            <?php 
                if (isset($page_to_include)) {
                    include($page_to_include); 
                } elseif (isset($lfi_error)) {
                    echo "<span class='error'>$lfi_error</span>";
                }
            ?>
        </div>
    </div>

    <div class="section">
        <h2>8. Caricamento Documenti (Protetta da RCE)</h2>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="fileToUpload">
            <button type="submit" name="upload">Carica Foto</button>
        </form>
        <?php echo $upload_message; ?>
    </div>

</div>

<p style="text-align: center; color: #666; font-size: 0.8em;">&copy; 2026 WebSec-Lab Secure Version</p>

</body>
</html>