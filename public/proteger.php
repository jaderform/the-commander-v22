<?php
/**
 * Middleware de Protecao Simplificado
 * Inclua no topo de paginas protegidas: require_once __DIR__ . '/proteger.php';
 */

if (session_status() === PHP_SESSION_NONE) {
    // Hardening de cookie de sessao
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
}

// Verifica se esta logado
if (!isset($_SESSION['logado']) || $_SESSION['logado'] !== true) {
    header('Location: /login.php');
    exit;
}

// Verifica timeout da sessao (2 horas)
if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > 7200) {
    session_destroy();
    header('Location: /login.php?erro=sessao_expirada');
    exit;
}

// Disponibiliza dados do usuario logado
$GLOBALS['usuario_logado'] = [
    'email' => $_SESSION['usuario_email'] ?? ($_SESSION['email'] ?? ''),
    'nome' => $_SESSION['usuario_nome'] ?? '',
    'eh_admin' => $_SESSION['eh_admin'] ?? false,
    'utm_cloaker_ativo' => $_SESSION['utm_cloaker_ativo'] ?? false
];
