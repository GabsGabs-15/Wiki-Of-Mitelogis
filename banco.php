<?php
declare(strict_types=1);

$host   = 'localhost';
$dbname = 'meu_site';
$dbuser = 'root';
$dbpass = '';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Método não permitido.');
}

$usuario     = trim($_POST['usuario'] ?? '');
$email       = trim($_POST['email'] ?? '');
$senha       = $_POST['senha'] ?? '';
$repitasenha = $_POST['repitasenha'] ?? '';

$erros = [];

if ($usuario === '' || mb_strlen($usuario) < 3 || mb_strlen($usuario) > 50) {
    $erros[] = 'O usuário deve ter entre 3 e 50 caracteres.';
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $erros[] = 'E-mail inválido.';
}

if (strlen($senha) < 8) {
    $erros[] = 'A senha deve ter pelo menos 8 caracteres.';
}

if ($senha !== $repitasenha) {
    $erros[] = 'As senhas não conferem.';
}

if (!empty($erros)) {
    http_response_code(400);
    echo '<h3>Corrija os erros abaixo:</h3><ul>';
    foreach ($erros as $erro) {
        echo '<li>' . htmlspecialchars($erro, ENT_QUOTES, 'UTF-8') . '</li>';
    }
    echo '</ul><a href="javascript:history.back()">Voltar</a>';
    exit;
}


try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
        $dbuser,
        $dbpass,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]

    );

    $senhaHash = password_hash($senha, PASSWORD_DEFAULT);

    $stmt = $pdo->prepare(
        'INSERT INTO usuarios (usuario, email, senha_hash)
         VALUES (:usuario, :email, :senha_hash)'
    );

    $stmt->execute([
        ':usuario'    => $usuario,
        ':email'      => $email,
        ':senha_hash' => $senhaHash,
    ]);

    echo '<h3>Conta criada com sucesso!</h3>';
    echo '<p>Bem-vindo(a), ' . htmlspecialchars($usuario, ENT_QUOTES, 'UTF-8') . '!</p>';
};
