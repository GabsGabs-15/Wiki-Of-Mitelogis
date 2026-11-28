<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: login.html');
    exit;
}

$email = trim($_POST['email'] ?? '');
$senha = $_POST['senha'] ?? '';

if ($email === '' || $senha === '') {
    exit('Preencha e-mail e senha. <a href="login.html">Voltar</a>');
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    exit('E-mail inválido. <a href="login.html">Voltar</a>');
}

$host    = 'localhost';
$banco   = 'meu_banco';
$usuario = 'root';
$senhaDb = '';

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$banco;charset=utf8mb4",
        $usuario,
        $senhaDb,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (PDOException $e) {
    exit('Erro ao conectar ao banco de dados.');
}


$stmt = $pdo->prepare('SELECT id, usuario, senha FROM usuarios WHERE email = :email LIMIT 1');
$stmt->execute([':email' => $email]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);


if ($user && hash_equals($user['senha'], $senha)) {
    session_regenerate_id(true);
    $_SESSION['usuario_id']   = $user['id'];
    $_SESSION['usuario_nome'] = $user['usuario'];

    header('Location: painel.php'); 
    exit;
}

exit('E-mail ou senha incorretos. <a href="login.html">Tentar de novo</a>');

