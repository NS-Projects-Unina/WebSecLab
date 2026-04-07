<?php

$host = 'db';
$user = 'root';
$pass = 'password_sicura'; 
$dbname = 'websec_db';

$conn = new mysqli($host, $user, $pass, $dbname);

if($conn->connect_error) {
    die('Connessione fallita'. $conn->connect_error);
}

$login_message = "";
$user_profile = null;
$ping_output = "";
$upload_message = "";
$search_query = "";

// --- VULNERABILITÀ 1: SQL INJECTION (LOGIN) ---
if(isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $conn->query($sql);

    if($result ->num_rows > 0) {
        $user_data = $result -> fetch_assoc();
        $login_message = "<div class='success'>Benvenuto, " . $user_data["username"] . "! (ID: " . $user_data["id"] . ")</div>";
    } else {
        $login_message = "<div class='error'>Credenziali errate. Query eseguita: <code>$sql</code></div>";
    }
}

// --- VULNERABILITÀ 2: STORED XSS (COMMENTI) ---
if(isset($_POST['add_comment'])) {
    $comment = $_POST['comment'];
    $stmt = $conn->prepare("INSERT INTO comments (content) VALUES (?)");
    $stmt->bind_param("s", $comment);
    $stmt->execute();
}

// --- VULNERABILITÀ 3: CSRF (CAMBIO EMAIL) ---
if(isset($_POST['update_email'])) {
    $new_email = $_POST['email'];
    $user_id = 1; // Target fisso per l'esempio di vulnerabilità

    // PREPARAZIONE QUERY
    $stmt = $conn->prepare("UPDATE users SET email = ? WHERE id = ?");

    // Passiamo esattamente due variabili per due segnaposti (?)
    $stmt->bind_param("si", $new_email, $user_id);

    if($stmt->execute()) {
        $login_message = "<div style='color: green;'>Email aggiornata con successo in: " . htmlspecialchars($new_email) . "</div>";
    } else {
        $login_message = "<div style='color: red;'>Errore durante l'aggiornamento.</div>";
    }
    
    $stmt->close();
}

// --- VULNERABILITÀ 4: IDOR (VISUALIZZA PROFILO) ---
if(isset($_GET['view_profile'])) {
    $id = $_GET['view_profile'];
    $sql_idor = "SELECT username, email, role FROM users WHERE id = $id";
    $res = $conn->query($sql_idor);
    if ($res && $res->num_rows > 0) {
        $user_profile = $res->fetch_assoc();
    }
}

// --- VULNERABILITÀ 5: LOCAL FILE INCLUSION (LFI) ---
if (isset($_GET['load_page'])) {
    $page = $_GET['load_page'];
    // L'inclusione diretta permette di leggere file di sistema o navigare tra le directory
}

// --- VULNERABILITÀ 6: COMMAND INJECTION (PING) ---
if (isset($_POST['ping'])) {
    $ip = $_POST['ip'];
    // VULNERABILE: Concatenazione di comandi shell senza filtraggio
    $ping_output = shell_exec("ping -c 3 " . $ip);
}

// --- VULNERABILITÀ 7: UNRESTRICTED FILE UPLOAD ---
if (isset($_POST['upload'])) {
    // Usiamo __DIR__ per essere sicuri di puntare alla cartella dove si trova index.php
    $target_dir = __DIR__ . "/uploads/"; 
    
    $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
    
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        // Per il link HTML usiamo il percorso relativo al browser
        $upload_message = "<div class='success'>File caricato in: <a href='uploads/" . basename($_FILES["fileToUpload"]["name"]) . "'>uploads/" . basename($_FILES["fileToUpload"]["name"]) . "</a></div>";
    } else {
        $upload_message = "<div class='error'>Errore nel caricamento. Verifica i permessi e che la cartella /var/www/html/uploads esista nel container.</div>";
    }
}

// --- VULNERABILITÀ 8: REFLECTED XSS (RICERCA) ---
if (isset($_GET['query'])) {
    $search_query = $_GET['query'];
}

?>

<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <title>WebSec-Lab: Testbed Completo</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; padding: 20px; color: #333; }
        .container { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); max-width: 900px; margin: auto; }
        h1 { color: #d9534f; border-bottom: 3px solid #d9534f; padding-bottom: 10px; }
        h2 { color: #2c3e50; margin-top: 0; }
        .section { margin-bottom: 40px; padding: 20px; border: 1px solid #e1e4e8; border-radius: 8px; background: #fff; }
        .section:hover { border-color: #d9534f; }
        .success { background: #dff0d8; color: #3c763d; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .error { background: #f2dede; color: #a94442; padding: 10px; border-radius: 4px; margin: 10px 0; }
        code { background: #f8f9fa; border: 1px solid #ddd; padding: 2px 5px; border-radius: 3px; font-family: monospace; color: #c7254e; }
        textarea, input[type="text"], input[type="password"], input[type="email"] { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { background: #2c3e50; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        button:hover { background: #d9534f; }
        pre { background: #272822; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>

<div class="container">
    <h1>WebSec-Lab 🛡️💉 <small style="font-size: 0.5em; color: #777;">v2.0</small></h1>
    <p>Ambiente di test vulnerabile per analisi OWASP Top 10.</p>

    <div class="section">
        <h2>1. Autenticazione (SQLi)</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" name="login">Accedi</button>
        </form>
        <?php echo $login_message; ?>
    </div>

    <div class="section">
        <h2>2. Bacheca Commenti (Stored XSS)</h2>
        <form method="POST">
            <textarea name="comment" placeholder="Lascia un commento pubblico..."></textarea>
            <button type="submit" name="add_comment">Invia</button>
        </form>
        <hr>
        <?php
        $res = $conn->query("SELECT content FROM comments ORDER BY id DESC");
        while ($row = $res->fetch_assoc()) {
            echo "<div style='border-bottom: 1px solid #eee; padding: 10px;'>" . $row['content'] . "</div>";
        }
        ?>
    </div>

    <div class="section">
        <h2>3. Ricerca Globale (Reflected XSS)</h2>
        <form method="GET">
            <input type="text" name="query" placeholder="Cerca nel sito...">
            <button type="submit">Cerca</button>
        </form>
        <?php if ($search_query): ?>
            <p>Risultati per la ricerca: <strong><?php echo $search_query; ?></strong></p>
            <p style="color: #777;">Nessun documento trovato corrispondente alla query.</p>
        <?php endif; ?>
    </div>

    <div class="section">
        <h2>4. Gestione Account (CSRF)</h2>
        <p>Modifica Email (Simulazione sessione Admin attiva):</p>
        <form method="POST">
            <input type="email" name="email" placeholder="nuova@email.it" required>
            <button type="submit" name="update_email">Aggiorna Email</button>
        </form>
    </div>

    <div class="section">
        <h2>5. Elenco Utenti (IDOR)</h2>
        <a href="?view_profile=1">Il mio Profilo</a> | <a href="?view_profile=2">Profilo Bob</a>
        <?php if ($user_profile): ?>
            <div style="background: #f9f9f9; padding: 15px; border-left: 5px solid #2c3e50; margin-top: 15px;">
                <strong>Username:</strong> <?php echo $user_profile['username']; ?><br>
                <strong>Email:</strong> <?php echo $user_profile['email']; ?><br>
                <strong>Ruolo:</strong> <?php echo $user_profile['role']; ?>
            </div>
        <?php endif; ?>
    </div>

    <div class="section">
        <h2>6. Strumenti di Rete (Command Injection)</h2>
        <form method="POST">
            <input type="text" name="ip" placeholder="Inserisci IP (es. 8.8.8.8)" required>
            <button type="submit" name="ping">Test Ping</button>
        </form>
        <?php if ($ping_output): ?>
            <pre><?php echo $ping_output; ?></pre>
        <?php endif; ?>
    </div>

    <div class="section">
        <h2>7. Visualizzatore Documenti (LFI)</h2>
        <ul>
            <li><a href="?load_page=info.txt">Note di rilascio</a></li>
            <li><a href="?load_page=../../../../etc/passwd">Tenta exploit LFI</a></li>
        </ul>
        <div style="background: #f4f4f4; padding: 10px; font-family: monospace; min-height: 20px;">
            <?php if (isset($_GET['load_page'])) include($_GET['load_page']); ?>
        </div>
    </div>

    <div class="section">
        <h2>8. Caricamento Documenti (File Upload RCE)</h2>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="fileToUpload">
            <button type="submit" name="upload">Carica File</button>
        </form>
        <?php echo $upload_message; ?>
    </div>

</div>

<p style="text-align: center; color: #777; font-size: 0.8em;">&copy; 2026 WebSec-Lab Project - Solo per scopi educativi.</p>

</body>
</html>