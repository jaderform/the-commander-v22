<?php
/**
 * Login alternativo (compatibilidade). Agora usa usuarios.json com senha
 * em hash (password_verify) — sem lista fixa nem senhas em texto puro.
 * Mantem: bloqueio manual, strikes, validade (expira_em) e sessao unica.
 */

// ---- Hardening de sessao (cookie) ----
$__https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['SERVER_PORT'] ?? '') == 443)
    || (strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
@ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => $__https,
]);
session_start();

$arquivo_usuarios = __DIR__ . '/usuarios.json';
$arquivo_sessoes  = __DIR__ . '/sessoes_ativas.json';
$arquivo_strikes  = __DIR__ . '/contador_strikes.json';
$limite_strikes   = 3;

$email_digitado = trim($_POST['email'] ?? '');
$senha_digitada = $_POST['senha'] ?? '';

if ($email_digitado === '' || $senha_digitada === '') {
    header('Location: login.php?erro=1');
    exit();
}

$usuarios = json_decode(@file_get_contents($arquivo_usuarios), true);
if (!is_array($usuarios)) $usuarios = [];

$sessoes = json_decode(@file_get_contents($arquivo_sessoes), true);
if (!is_array($sessoes)) $sessoes = [];

$strikes = json_decode(@file_get_contents($arquivo_strikes), true);
if (!is_array($strikes)) $strikes = [];

// Busca usuario (email como chave, case-insensitive)
$usuario = null; $emailKeyEncontrado = null;
foreach ($usuarios as $k => $d) {
    if (strtolower($k) === strtolower($email_digitado)) { $usuario = $d; $emailKeyEncontrado = $k; break; }
}

if ($usuario === null) {
    header('Location: login.php?erro=1');
    exit();
}

$contagem_atual = isset($strikes[$emailKeyEncontrado]) ? (int)$strikes[$emailKeyEncontrado] : 0;

// Bloqueio manual
if (!empty($usuario['bloqueado']) && $usuario['bloqueado'] === true) {
    header('Location: login.php?erro=4');
    exit();
}
// Bloqueio automatico por strikes
if ($contagem_atual >= $limite_strikes) {
    header('Location: login.php?erro=4');
    exit();
}

// Verifica senha (hash + fallback legado texto puro)
$stored = (string)($usuario['senha'] ?? '');
$senhaOk = false; $precisaRehash = false;
if ($stored !== '' && (strncmp($stored, '$2', 2) === 0 || strncmp($stored, '$argon', 6) === 0)) {
    $senhaOk = password_verify($senha_digitada, $stored);
} elseif ($stored !== '') {
    $senhaOk = hash_equals($stored, (string)$senha_digitada);
    $precisaRehash = $senhaOk;
}

if (!$senhaOk) {
    header('Location: login.php?erro=1');
    exit();
}

// Validade
$hoje = date('Y-m-d');
$data_expiracao = $usuario['expira_em'] ?? '2099-12-31';
if ($hoje > $data_expiracao) {
    header('Location: login.php?erro=2');
    exit();
}

// Re-hash de senha legada
if ($precisaRehash) {
    $usuarios[$emailKeyEncontrado]['senha'] = password_hash($senha_digitada, PASSWORD_BCRYPT);
    file_put_contents($arquivo_usuarios, json_encode($usuarios, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

// Strike se vai chutar outra sessao
if (isset($sessoes[$emailKeyEncontrado])) {
    $contagem_atual++;
    $strikes[$emailKeyEncontrado] = $contagem_atual;
    file_put_contents($arquivo_strikes, json_encode($strikes), LOCK_EX);
}

// Previne session fixation
session_regenerate_id(true);

$token_de_acesso = bin2hex(random_bytes(16));
$_SESSION['logado'] = true;
$_SESSION['email'] = $emailKeyEncontrado;
$_SESSION['usuario_email'] = $emailKeyEncontrado;
$_SESSION['usuario_nome'] = $usuario['nome'] ?? $emailKeyEncontrado;
$_SESSION['eh_admin'] = $usuario['eh_admin'] ?? false;
$_SESSION['utm_cloaker_ativo'] = $usuario['utm_cloaker_ativo'] ?? false;
$_SESSION['ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
$_SESSION['login_time'] = time();
$_SESSION['token_de_acesso'] = $token_de_acesso;

$sessoes[$emailKeyEncontrado] = $token_de_acesso;
file_put_contents($arquivo_sessoes, json_encode($sessoes), LOCK_EX);

header('Location: index.php');
exit();
