<?php
/**
 * Sistema de Login v3 - senhas com hash (bcrypt), CSRF, anti-brute-force
 * Compativel com usuarios.json existente.
 */

// ---- Hardening de sessao (cookie) antes de iniciar ----
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

// ============================================
// CONFIGURACOES
// ============================================

define('ARQUIVO_USUARIOS', __DIR__ . '/usuarios.json');
define('ARQUIVO_SESSOES', __DIR__ . '/sessoes_ativas.json');
define('ARQUIVO_TENTATIVAS', __DIR__ . '/tentativas_login.json');

// Anti-brute-force (mesmos limites do sistema: 5 tentativas / 900s)
define('LOGIN_MAX_TENTATIVAS', 5);
define('LOGIN_BLOQUEIO_SEGUNDOS', 900);

// ============================================
// FUNCOES
// ============================================

function carregarJSON($arquivo) {
    if (!file_exists($arquivo)) {
        file_put_contents($arquivo, '{}');
        return [];
    }
    $conteudo = @file_get_contents($arquivo);
    if (empty($conteudo)) {
        return [];
    }
    $dados = @json_decode($conteudo, true);
    return is_array($dados) ? $dados : [];
}

function salvarJSON($arquivo, $dados) {
    file_put_contents($arquivo, json_encode($dados, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

function obterIP() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) return $_SERVER['HTTP_CF_CONNECTING_IP'];
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) return $_SERVER['HTTP_X_REAL_IP'];
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function gerarToken() {
    return bin2hex(random_bytes(32));
}

// ---- Anti-brute-force por IP ----
function login_tentativas_carregar() {
    $t = carregarJSON(ARQUIVO_TENTATIVAS);
    return is_array($t) ? $t : [];
}
function login_tentativas_salvar($t) {
    salvarJSON(ARQUIVO_TENTATIVAS, $t);
}
// Retorna [bloqueado(bool), espera(int seg)]
function login_bloqueado($ip) {
    $t = login_tentativas_carregar();
    if (!isset($t[$ip]) || !is_array($t[$ip])) return [false, 0];
    $count = (int)($t[$ip]['count'] ?? 0);
    $last = (int)($t[$ip]['last'] ?? 0);
    if ($count >= LOGIN_MAX_TENTATIVAS) {
        $desde = time() - $last;
        if ($desde < LOGIN_BLOQUEIO_SEGUNDOS) {
            return [true, LOGIN_BLOQUEIO_SEGUNDOS - $desde];
        }
        // janela expirou: zera
        unset($t[$ip]);
        login_tentativas_salvar($t);
    }
    return [false, 0];
}
function login_registrar_tentativa($ip, $sucesso) {
    $t = login_tentativas_carregar();
    if ($sucesso) {
        unset($t[$ip]);
    } else {
        if (!isset($t[$ip]) || !is_array($t[$ip])) $t[$ip] = ['count' => 0, 'last' => 0];
        $t[$ip]['count'] = (int)($t[$ip]['count'] ?? 0) + 1;
        $t[$ip]['last'] = time();
    }
    login_tentativas_salvar($t);
}

// ---- CSRF ----
if (empty($_SESSION['csrf_login']) || !is_string($_SESSION['csrf_login'])) {
    $_SESSION['csrf_login'] = bin2hex(random_bytes(32));
}

// ============================================
// VERIFICA SE JA ESTA LOGADO
// ============================================

if (isset($_SESSION['logado']) && $_SESSION['logado'] === true && isset($_SESSION['usuario_email'])) {
    header('Location: home.php');
    exit;
}

// ============================================
// PROCESSA LOGIN
// ============================================

$erro = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ip = obterIP();

    // CSRF
    $csrf = $_POST['csrf_token'] ?? '';
    if (!is_string($csrf) || !hash_equals($_SESSION['csrf_login'], $csrf)) {
        $erro = 'Sessao expirada. Recarregue a pagina e tente novamente.';
    } else {
        [$bloqueado, $espera] = login_bloqueado($ip);
        if ($bloqueado) {
            $min = (int)ceil($espera / 60);
            $erro = 'Muitas tentativas. Tente novamente em ' . $min . ' min.';
        } else {
            $email = trim($_POST['email'] ?? '');
            $senha = $_POST['senha'] ?? '';

            if (empty($email) || empty($senha)) {
                $erro = 'Preencha todos os campos.';
            } else {
                $usuarios = carregarJSON(ARQUIVO_USUARIOS);

                $usuarioEncontrado = null;
                $emailEncontrado = null;
                foreach ($usuarios as $emailKey => $dados) {
                    if (strtolower($emailKey) === strtolower($email)) {
                        $usuarioEncontrado = $dados;
                        $emailEncontrado = $emailKey;
                        break;
                    }
                }

                // Verificacao de senha: hash (bcrypt/argon) + fallback legado texto puro
                $senhaOk = false;
                $precisaRehash = false;
                if ($usuarioEncontrado) {
                    $stored = (string)($usuarioEncontrado['senha'] ?? '');
                    if ($stored !== '' && (strncmp($stored, '$2', 2) === 0 || strncmp($stored, '$argon', 6) === 0)) {
                        $senhaOk = password_verify($senha, $stored);
                    } elseif ($stored !== '') {
                        // Legado em texto puro: aceita e marca para re-hash
                        $senhaOk = hash_equals($stored, (string)$senha);
                        $precisaRehash = $senhaOk;
                    }
                }

                if (!$usuarioEncontrado) {
                    login_registrar_tentativa($ip, false);
                    $erro = 'Email ou senha incorretos.';
                } elseif ($usuarioEncontrado['bloqueado'] ?? false) {
                    $erro = 'Esta conta esta bloqueada.';
                } elseif (!$senhaOk) {
                    login_registrar_tentativa($ip, false);
                    $erro = 'Email ou senha incorretos.';
                } else {
                    // Login OK!
                    login_registrar_tentativa($ip, true);

                    // Re-hash de senha legada em texto puro
                    if ($precisaRehash) {
                        $usuarios[$emailEncontrado]['senha'] = password_hash($senha, PASSWORD_BCRYPT);
                        salvarJSON(ARQUIVO_USUARIOS, $usuarios);
                    }

                    // Previne session fixation
                    session_regenerate_id(true);

                    $_SESSION['logado'] = true;
                    $_SESSION['usuario_email'] = $emailEncontrado;
                    $_SESSION['email'] = $emailEncontrado; // compat
                    $_SESSION['usuario_nome'] = $usuarioEncontrado['nome'] ?? $emailEncontrado;
                    $_SESSION['eh_admin'] = $usuarioEncontrado['eh_admin'] ?? false;
                    $_SESSION['utm_cloaker_ativo'] = $usuarioEncontrado['utm_cloaker_ativo'] ?? false;
                    $_SESSION['ip'] = $ip;
                    $_SESSION['login_time'] = time();

                    $sessoes = carregarJSON(ARQUIVO_SESSOES);
                    $token = gerarToken();
                    $sessoes[$emailEncontrado] = $token;
                    salvarJSON(ARQUIVO_SESSOES, $sessoes);

                    header('Location: home.php');
                    exit;
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: #000000; min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
        .login-box { background: #0a0a0a; border: 1px solid rgba(255, 0, 80, 0.3); border-radius: 20px; padding: 40px; width: 100%; max-width: 400px; box-shadow: 0 0 40px rgba(255, 0, 80, 0.1); }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { font-size: 26px; background: linear-gradient(135deg, #ff0050, #00f2ea); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; color: #fff; font-size: 14px; margin-bottom: 8px; }
        .form-group input { width: 100%; padding: 14px; background: #121212; border: 1px solid #252525; border-radius: 10px; color: #fff; font-size: 15px; transition: all 0.3s; }
        .form-group input:focus { outline: none; border-color: #ff0050; box-shadow: 0 0 0 3px rgba(255, 0, 80, 0.2); }
        .btn { width: 100%; padding: 14px; background: #ff0050; border: none; border-radius: 10px; color: #fff; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s; }
        .btn:hover { background: #e6004a; box-shadow: 0 0 20px rgba(255, 0, 80, 0.4); }
        .erro { background: rgba(255, 0, 80, 0.1); border: 1px solid rgba(255, 0, 80, 0.3); color: #ff6b8a; padding: 12px; border-radius: 10px; margin-bottom: 20px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">
            <h1>COMMANDER</h1>
        </div>

        <?php if ($erro): ?>
            <div class="erro"><?php echo htmlspecialchars($erro); ?></div>
        <?php endif; ?>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_login']); ?>">
            <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" required autofocus placeholder="seu@email.com">
            </div>

            <div class="form-group">
                <label>Senha</label>
                <input type="password" name="senha" required placeholder="Sua senha">
            </div>

            <button type="submit" class="btn">Entrar</button>
        </form>
    </div>
</body>
</html>
