
<?php
/**
 * COMMANDER V10.5 - Configuracao Central
 *
 * Revisao:
 * - Validacao de segredo HMAC
 * - Persistencia JSON com gravacao atomica
 * - Tratamento de erros de leitura e escrita
 * - Protecao contra sobrescrita de arquivos
 * - Compatibilidade com constantes existentes
 *
 * Requer PHP 7.4+.
 */

if (!defined('COMMANDER_ACCESS')) {
    http_response_code(403);
    exit('Acesso negado');
}

// ============================================
// SISTEMA
// ============================================

define('COMMANDER_VERSION', '10.5');
define('COMMANDER_NAME', 'COMMANDER');

date_default_timezone_set('America/Sao_Paulo');

// ============================================
// DEBUG E TRATAMENTO DE ERROS
// ============================================

define('DEBUG_MODE', false);
define('LOG_ALL_REQUESTS', false);

if (!DEBUG_MODE) {
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
}

// ============================================
// SEGURANCA - SEGREDO HMAC
// ============================================

/**
 * Ordem de carregamento:
 *
 * 1. COMMANDER_API_TOKEN (ambiente)
 * 2. $_SERVER['COMMANDER_API_TOKEN']
 * 3. COMMANDER_SECRET_FILE
 *
 * O fallback previsivel foi removido.
 *
 * IMPORTANTE:
 * Configure um segredo persistente de pelo
 * menos 32 caracteres antes da implantacao.
 */

if (!defined('API_TOKEN')) {
    $cmdToken = getenv('COMMANDER_API_TOKEN');

    if (
        (!is_string($cmdToken) || strlen($cmdToken) < 32)
        && isset($_SERVER['COMMANDER_API_TOKEN'])
        && is_string($_SERVER['COMMANDER_API_TOKEN'])
    ) {
        $cmdToken = $_SERVER['COMMANDER_API_TOKEN'];
    }

    if (!is_string($cmdToken) || strlen($cmdToken) < 32) {
        $secretFile = getenv('COMMANDER_SECRET_FILE');

        if (!is_string($secretFile) || $secretFile === '') {
            $secretFile = '/etc/commander/api_token';
        }

        if (is_file($secretFile) && is_readable($secretFile)) {
            $fileContent = @file_get_contents($secretFile);
            $cmdToken = $fileContent !== false
                ? trim($fileContent)
                : '';
        }
    }

    if (!is_string($cmdToken) || strlen($cmdToken) < 32) {
        error_log(
            '[COMMANDER] ERRO: segredo HMAC ausente ou invalido.'
        );

        if (PHP_SAPI === 'cli') {
            throw new RuntimeException(
                'Configure COMMANDER_API_TOKEN com 32+ caracteres.'
            );
        }

        http_response_code(503);
        exit('Falha na configuracao do servidor.');
    }

    define('API_TOKEN', $cmdToken);
    unset($cmdToken, $secretFile, $fileContent);
}

if (!defined('API_TOKEN_IS_LEGACY')) {
    define('API_TOKEN_IS_LEGACY', false);
}

// ============================================
// AUTENTICACAO E SESSOES
// ============================================

// O login efetivo depende de proteger.php.
define(
    'ADMIN_PASSWORD',
    (string) (getenv('COMMANDER_ADMIN_PASSWORD') ?: '')
);

define('SESSION_TIMEOUT', 7200);
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_BLOCK_TIME', 900);

// ============================================
// DIRETORIOS
// ============================================

define('DATA_DIR', __DIR__ . '/data/');
define('LOGS_DIR', __DIR__ . '/logs/');
define('CACHE_DIR', __DIR__ . '/cache/');

// ============================================
// ARQUIVOS PRINCIPAIS
// ============================================

define('FILE_CAMPAIGNS', DATA_DIR . 'campaigns.json');
define('FILE_STATS', DATA_DIR . 'stats.json');
define('FILE_BLOCKED_IPS', DATA_DIR . 'blocked_ips.json');
define('FILE_WHITELIST_IPS', DATA_DIR . 'whitelist.json');
define('FILE_BOT_LOG', LOGS_DIR . 'bot_log.json');
define('FILE_ACCESS_LOG', LOGS_DIR . 'access_log.json');
define('FILE_LOGIN_ATTEMPTS', DATA_DIR . 'login_attempts.json');

// ============================================
// CONFIGURACOES DE DETECCAO EXISTENTES
// ============================================

// Valores preservados da instalacao original.
define('ALLOWED_COUNTRIES', ['BR']);
define('GEO_BLOCKING_ENABLED', true);

define('MOBILE_ONLY_MODE', true);
define('RISK_THRESHOLD', 60);
define('BLOCK_EMPTY_UA', true);
define('MIN_UA_LENGTH', 20);

// ============================================
// RATE LIMITING
// ============================================

define('RATE_LIMIT_REQUESTS', 60);
define('RATE_LIMIT_WINDOW', 60);

// ============================================
// DESAFIO DE ABUSO
// ============================================

define('ABUSE_SOFT_REQUESTS', 25);
define('CHALLENGE_PASS_TTL', 1800);

// ============================================
// CACHE
// ============================================

define('GEO_CACHE_TIME', 3600);
define('STATS_CACHE_TIME', 300);

// ============================================
// INTEGRACOES
// ============================================

define('TIKTOK_API_VERSION', 'v1.3');
define('FACEBOOK_API_VERSION', 'v18.0');

// ============================================
// INICIALIZACAO DE DIRETORIOS
// ============================================

/**
 * Cria diretorio apenas quando necessario.
 * Nunca remove ou recria pastas existentes.
 */
function commanderConfigEnsureDir($directory)
{
    if (is_dir($directory)) {
        return true;
    }

    if (@mkdir($directory, 0755, true)) {
        return true;
    }

    if (is_dir($directory)) {
        return true;
    }

    error_log(
        '[COMMANDER] Falha ao criar diretorio: ' . $directory
    );

    return false;
}

/**
 * Escreve todos os bytes de uma string.
 */
function commanderConfigWriteAll($handle, $content)
{
    $length = strlen($content);
    $offset = 0;

    while ($offset < $length) {
        $written = @fwrite(
            $handle,
            substr($content, $offset)
        );

        if ($written === false || $written === 0) {
            return false;
        }

        $offset += $written;
    }

    return true;
}

/**
 * Cria arquivos padrao sem sobrescrever existentes.
 *
 * O modo x impede substituir um arquivo
 * criado simultaneamente por outra requisicao.
 */
function commanderConfigEnsureFiles($files)
{
    foreach ($files as $file => $defaultContent) {
        if (is_file($file)) {
            continue;
        }

        if (!commanderConfigEnsureDir(dirname($file))) {
            continue;
        }

        $handle = @fopen($file, 'x');

        if ($handle === false) {
            if (!is_file($file)) {
                error_log(
                    '[COMMANDER] Nao foi possivel criar: ' . $file
                );
            }
            continue;
        }

        $ok = false;

        try {
            if (@flock($handle, LOCK_EX)) {
                $ok = commanderConfigWriteAll(
                    $handle,
                    (string) $defaultContent
                );

                if ($ok) {
                    $ok = @fflush($handle);
                }

                @flock($handle, LOCK_UN);
            }
        } finally {
            fclose($handle);
        }

        if (!$ok) {
            @unlink($file);
            error_log(
                '[COMMANDER] Gravacao inicial incompleta: ' . $file
            );
        }
    }
}

foreach ([DATA_DIR, LOGS_DIR, CACHE_DIR] as $directory) {
    commanderConfigEnsureDir($directory);
}

// ============================================
// ARQUIVOS PADRAO
// ============================================

$defaultFiles = [
    FILE_CAMPAIGNS => '[]',
    FILE_STATS =>
        '{"total_clicks":0,"total_blocks":0,"total_passes":0,"by_campaign":{},"by_date":{},"by_platform":{}}',
    FILE_BLOCKED_IPS => '[]',
    FILE_WHITELIST_IPS => '[]',
    FILE_BOT_LOG => '[]',
    FILE_ACCESS_LOG => '[]',
    FILE_LOGIN_ATTEMPTS => '{}'
];

commanderConfigEnsureFiles($defaultFiles);

// ============================================
// CONFIGURACAO DINAMICA
// ============================================

/**
 * Consulta uma configuracao armazenada.
 *
 * Mantem cache durante o request.
 * O cache e invalidado apos setConfig().
 */
function getConfig($key, $default = null)
{
    static $config = null;

    if (!is_string($key) && !is_int($key)) {
        return $default;
    }

    if (!empty($GLOBALS['__commander_settings_dirty'])) {
        $config = null;
        $GLOBALS['__commander_settings_dirty'] = false;
    }

    if ($config === null) {
        $configFile = DATA_DIR . 'settings.json';
        $config = [];

        if (is_file($configFile)) {
            $content = @file_get_contents($configFile);

            if ($content !== false && trim($content) !== '') {
                $decoded = json_decode($content, true);

                if (
                    json_last_error() === JSON_ERROR_NONE
                    && is_array($decoded)
                ) {
                    $config = $decoded;
                } else {
                    error_log(
                        '[COMMANDER] settings.json invalido: '
                        . json_last_error_msg()
                    );
                }
            }
        }
    }

    return $config[$key] ?? $default;
}

/**
 * Salva uma configuracao sem sobrescrever
 * as demais chaves.
 *
 * Usa:
 * - lock persistente entre requisicoes
 * - validacao de JSON
 * - arquivo temporario no mesmo diretorio
 * - rename atomico
 *
 * Nao substitui um JSON corrompido por [].
 */
function setConfig($key, $value)
{
    if (
        (!is_string($key) && !is_int($key))
        || $key === ''
    ) {
        return false;
    }

    if (!commanderConfigEnsureDir(DATA_DIR)) {
        return false;
    }

    $configFile = DATA_DIR . 'settings.json';
    $lockFile = DATA_DIR . 'settings.json.lock';

    $lock = @fopen($lockFile, 'c');

    if ($lock === false) {
        error_log('[COMMANDER] Falha ao abrir lock de settings.');
        return false;
    }

    if (!@flock($lock, LOCK_EX)) {
        fclose($lock);
        return false;
    }

    $tmpFile = false;

    try {
        $config = [];

        if (is_file($configFile)) {
            $original = @file_get_contents($configFile);

            if ($original === false) {
                error_log(
                    '[COMMANDER] Falha ao ler settings.json.'
                );
                return false;
            }

            if (trim($original) !== '') {
                $decoded = json_decode($original, true);

                if (
                    json_last_error() !== JSON_ERROR_NONE
                    || !is_array($decoded)
                ) {
                    error_log(
                        '[COMMANDER] JSON invalido: escrita cancelada.'
                    );
                    return false;
                }

                $config = $decoded;
            }
        }

        $config[$key] = $value;

        $json = json_encode(
            $config,
            JSON_PRETTY_PRINT
            | JSON_UNESCAPED_UNICODE
            | JSON_UNESCAPED_SLASHES
        );

        if ($json === false) {
            error_log(
                '[COMMANDER] Erro ao codificar settings: '
                . json_last_error_msg()
            );
            return false;
        }

        $tmpFile = @tempnam(
            DATA_DIR,
            '.settings_'
        );

        if ($tmpFile === false) {
            return false;
        }

        $handle = @fopen($tmpFile, 'wb');

        if ($handle === false) {
            return false;
        }

        $writtenOk = false;

        try {
            $writtenOk = commanderConfigWriteAll(
                $handle,
                $json
            );

            if ($writtenOk) {
                $writtenOk = @fflush($handle);
            }
        } finally {
            fclose($handle);
        }

        if (!$writtenOk) {
            error_log(
                '[COMMANDER] Falha na escrita de settings.'
            );
            return false;
        }

        // Arquivo de configuracoes pode conter segredos.
        @chmod($tmpFile, 0600);

        if (!@rename($tmpFile, $configFile)) {
            error_log(
                '[COMMANDER] Falha ao substituir settings.json.'
            );
            return false;
        }

        $tmpFile = false;

        $GLOBALS['__commander_settings_dirty'] = true;

        return true;
    } finally {
        if ($tmpFile !== false && is_file($tmpFile)) {
            @unlink($tmpFile);
        }

        @flock($lock, LOCK_UN);
        fclose($lock);
    }
}

// ============================================
// DETECCAO AVANCADA - CONSTANTES ORIGINAIS
// ============================================

define('ADVANCED_DETECTION_ENABLED', true);
define('JS_CHALLENGE_ENABLED', true);
define('MIN_LOAD_TIME_MS', 500);
define('FINGERPRINT_ENABLED', true);
define('MOUSE_DETECTION_ENABLED', true);

// ============================================
// WEBHOOKS
// ============================================

define('WEBHOOK_TELEGRAM_ENABLED', false);
define('WEBHOOK_TELEGRAM_BOT_TOKEN', '');
define('WEBHOOK_TELEGRAM_CHAT_ID', '');

define('WEBHOOK_DISCORD_ENABLED', false);
define('WEBHOOK_DISCORD_URL', '');

define('WEBHOOK_ALERT_THRESHOLD', 50);

// ============================================
// ROTACAO DE URLS / A-B TESTING
// ============================================

define('URL_ROTATION_ENABLED', false);
define('URL_ROTATION_MODE', 'weight');

// ============================================
// PAUSA AUTOMATICA
// ============================================

define('AUTO_PAUSE_ENABLED', false);
define('AUTO_PAUSE_BLOCK_THRESHOLD', 80);
define('AUTO_PAUSE_MIN_CLICKS', 100);

// ============================================
// GRAFICOS
// ============================================

define('CHARTS_ENABLED', true);
define('CHARTS_DAYS_HISTORY', 30);

// ============================================
// CONFIGURACOES LEGADAS DE EXIBICAO
// ============================================

// Mantidas sem alteracao de comportamento.
define('STEALTH_MODE_ENABLED', false);

define('BEHAVIORAL_GATE_ENABLED', false);
define('BEHAVIORAL_MIN_SCROLLS', 2);
define('BEHAVIORAL_MIN_TIME_MS', 3000);
define('BEHAVIORAL_MIN_MOUSE_MOVES', 5);
define('BEHAVIORAL_MIN_VISITS', 1);

define('INTERACTION_GATE_GLOBAL', true);
define('INTERACTION_GATE_GLOBAL_TIMEOUT_MS', 2500);

define('AUTO_FORCE_WHITE_ON_BLOCK', true);
define('AUTO_FORCE_WHITE_INCLUDE_DESKTOP', true);
define('AUTO_FORCE_WHITE_INCLUDE_SPLIT', false);

define('PROGRESSIVE_REVEAL_ENABLED', true);
define('RISK_SCORE_THRESHOLD', 70);
define('TIME_BASED_PROTECTION', true);
define('COLLECT_REVIEWER_FP', true);

// ============================================
// ARQUIVOS DAS MELHORIAS
// ============================================

define('FILE_WEBHOOKS', DATA_DIR . 'webhooks.json');
define('FILE_URL_ROTATION', DATA_DIR . 'url_rotation.json');
define('FILE_ADVANCED_STATS', DATA_DIR . 'advanced_stats.json');
define('FILE_HOURLY_STATS', DATA_DIR . 'hourly_stats.json');

define(
    'FILE_WAF_LEARNED',
    DATA_DIR . 'waf_learned_prefixes.json'
);

define(
    'FILE_WAF_SCANNERS',
    DATA_DIR . 'waf_scanners.json'
);

// ============================================
// FREQUENCY CAP
// ============================================

define('FREQ_CAP_ENABLED', true);
define('FREQ_CAP_MAX', 2);
define('FREQ_CAP_WINDOW', 86400);

define('FILE_FREQ_CAP', DATA_DIR . 'freq_cap.json');

// ============================================
// FINGERPRINT VELOCITY
// ============================================

define('FP_VELOCITY_ENABLED', true);
define('FP_VELOCITY_MAX_NETS', 3);
define('FP_VELOCITY_WINDOW', 3600);

define('FILE_FP_VELOCITY', DATA_DIR . 'fp_velocity.json');

// ============================================
// REPUTACAO DE IP
// ============================================

define('IP_REP_ENABLED', true);
define('IP_REP_BLOCK_HOSTING', true);
define('IP_REP_BLOCK_PROXY', true);
define('IP_REP_CACHE_TTL', 604800);
define('IP_REP_TIMEOUT', 2);
define('IP_REP_API_KEY', '');

define(
    'FILE_IP_REPUTATION',
    DATA_DIR . 'ip_reputation.json'
);

// ============================================
// ARQUIVOS PADRAO DAS MELHORIAS
// ============================================

$newDefaultFiles = [
    FILE_WEBHOOKS =>
        '{"telegram":{"enabled":false,"bot_token":"","chat_id":""},"discord":{"enabled":false,"url":""}}',

    FILE_URL_ROTATION => '{}',

    FILE_ADVANCED_STATS =>
        '{"by_hour":{},"js_challenges":{"passed":0,"failed":0},"fingerprints":{}}',

    FILE_HOURLY_STATS => '{}',
    FILE_WAF_LEARNED => '[]',
    FILE_WAF_SCANNERS => '{}',
    FILE_FREQ_CAP => '{}',
    FILE_FP_VELOCITY => '{}',
    FILE_IP_REPUTATION => '{}'
];

commanderConfigEnsureFiles($newDefaultFiles);

// ============================================
// V3 - TRANSACOES E GATEWAYS
// ============================================

define(
    'FILE_TRANSACTIONS',
    DATA_DIR . 'transactions.json'
);

define(
    'FILE_GATEWAYS',
    DATA_DIR . 'gateways.json'
);

$v3DefaultFiles = [
    FILE_TRANSACTIONS => '[]',
    FILE_GATEWAYS => '{}'
];

commanderConfigEnsureFiles($v3DefaultFiles);

// ============================================
// DIRETORIOS ADICIONAIS
// ============================================

commanderConfigEnsureDir(
    DATA_DIR . 'webhook_logs/'
);

commanderConfigEnsureDir(
    DATA_DIR . 'transactions/'
);

// ============================================
// FIM DO ARQUIVO
// ============================================
