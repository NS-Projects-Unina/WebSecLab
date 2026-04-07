-- Creazione della tabella Utenti
CREATE TABLE IF NOT EXISTS users(
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user'
);

-- Inserimento di utenti per testing
INSERT INTO users (username, password, email, role) VALUES
('admin', 'SuperAdmin9000!?', 'admin@webseclab.local', 'admin'),
('bob', 'boboilgrande26?!', 'bobo26@esempio2.it', 'user'),
('mario', 'supermario2026?', 'mariosuper@esempio.it', 'user');

-- Creazione tabella per i Commenti
CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Inserimento di un commento esempio
INSERT INTO comments (content) VALUES
('Benvenuti nel forum del WebSec-Lab!!'),
('Qualcuno sa come funzione BurpSuite :)');