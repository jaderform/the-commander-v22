<?php
/**
 * COMMANDER V10.5 - Arquivo de Configuração Central
 * 
 * INSTRUÇÕES: Crie este arquivo na raiz do COMMANDER
 * V10.5: Adicionado MOBILE_ONLY_MODE e thresholds ajustados
 */

// Previne acesso direto
if (!defined('COMMANDER_ACCESS')) {
    http_response_code(403);
    exit('Acesso negado');
}

// ============================================
// CONFIGURAÇÕES DO SISTEMA
// ============================================

define('COMMANDER_VERSION', '10.5');
define('COMMANDER_NAME', 'COMMANDER');

// Timezone
date_default_timezone_set('America/Sao_Paulo');

// ============================================
// CONFIGURAÇÕES DE SEGURANÇA
// ============================================

// Token de API (altere para um valor único e seguro)
define('API_TOKEN', 'seu_token_secreto_aqui_' . md5(__DIR__));

// Senha do painel (será hasheada automaticamente)
define('ADMIN_PASSWORD', 'SuaSenhaForte123!');

// Tempo de sessão em segundos (4 horas)
define('SESSION_TIMEOUT', 14400);

// Máximo de tentativas de login antes de bloquear
define('MAX_LOGIN_ATTEMPTS', 5);

// Tempo de bloqueio após tentativas excedidas (em segundos)
define('LOGIN_BLOCK_TIME', 900); // 15 minutos

// ============================================
// CONFIGURAÇÕES DE ARQUIVOS
// ============================================

define('DATA_DIR', __DIR__ . '/data/');
define('LOGS_DIR', __DIR__ . '/logs/');
define('CACHE_DIR', __DIR__ . '/cache/');

// Arquivos de dados
define('FILE_CAMPAIGNS', DATA_DIR . 'campaigns.json');
define('FILE_STATS', DATA_DIR . 'stats.json');
define('FILE_BLOCKED_IPS', DATA_DIR . 'blocked_ips.json');
define('FILE_WHITELIST_IPS', DATA_DIR . 'whitelist.json');
define('FILE_BOT_LOG', LOGS_DIR . 'bot_log.json');
define('FILE_ACCESS_LOG', LOGS_DIR . 'access_log.json');
define('FILE_LOGIN_ATTEMPTS', DATA_DIR . 'login_attempts.json');

// ============================================
// CONFIGURAÇÕES DE DETECÇÃO
// ============================================

// Países permitidos (ISO 3166-1 alpha-2)
define('ALLOWED_COUNTRIES', ['BR']);

// Habilitar geo-blocking
define('GEO_BLOCKING_ENABLED', true);

// ============================================
// V10.5: MODO APENAS MOBILE
// ============================================
// Se true, desktop vai automaticamente para WHITE
// Revisores usam desktop, usuarios reais usam celular
define('MOBILE_ONLY_MODE', true);

// Threshold de risco para bloquear (60 = equilibrado)
// Valores mais altos = menos bloqueios (menos falsos positivos)
// Valores mais baixos = mais bloqueios (mais seguro, mas pode bloquear usuarios reais)
define('RISK_THRESHOLD', 60);

// Bloquear User-Agent vazio
define('BLOCK_EMPTY_UA', true);

// Tamanho mínimo do User-Agent
define('MIN_UA_LENGTH', 20);

// ============================================
// CONFIGURAÇÕES DE RATE LIMITING
// ============================================

// Máximo de requisições por IP por minuto
define('RATE_LIMIT_REQUESTS', 60);

// Tempo da janela de rate limiting (em segundos)
define('RATE_LIMIT_WINDOW', 60);

// ============================================
// DETECCAO DE ABUSO -> DESAFIO (Cloudflare Turnstile)
// ============================================
// Limite "suave" de requisicoes por IP dentro da janela de rate limiting.
// Fica ABAIXO do RATE_LIMIT_REQUESTS (bloqueio rigido): ao atingir esse valor,
// o visitante ainda nao e bloqueado, mas passa a ser tratado como comportamento
// anormal e recebe o desafio (captcha) antes de ser liberado para a oferta.
define('ABUSE_SOFT_REQUESTS', 25);

// Validade (em segundos) do "passe" emitido apos resolver o desafio.
// Enquanto valido, o visitante nao e desafiado de novo nas etapas seguintes.
define('CHALLENGE_PASS_TTL', 1800);

// ============================================
// CONFIGURAÇÕES DE CACHE
// ============================================

// Tempo de cache para verificação de geo (em segundos)
define('GEO_CACHE_TIME', 3600);

// Tempo de cache para estatísticas (em segundos)
define('STATS_CACHE_TIME', 300);

// ============================================
// CONFIGURAÇÕES DE INTEGRAÇÃO
// ============================================

// APIs de terceiros
define('TIKTOK_API_VERSION', 'v1.3');
define('FACEBOOK_API_VERSION', 'v18.0');

// ============================================
// CONFIGURAÇÕES DE DEBUG
// ============================================

// Habilitar modo debug (DESABILITE EM PRODUÇÃO!)
define('DEBUG_MODE', false);

// Log de todas as requisições
define('LOG_ALL_REQUESTS', false);

// ============================================
// INICIALIZAÇÃO
// ============================================

// Criar diretórios se não existirem
$directories = [DATA_DIR, LOGS_DIR, CACHE_DIR];
foreach ($directories as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}

// Criar arquivos padrão se não existirem
$defaultFiles = [
    FILE_CAMPAIGNS => '[]',
    FILE_STATS => '{"total_clicks":0,"total_blocks":0,"total_passes":0,"by_campaign":{},"by_date":{},"by_platform":{}}',
    FILE_BLOCKED_IPS => '[]',
    FILE_WHITELIST_IPS => '[]',
    FILE_BOT_LOG => '[]',
    FILE_ACCESS_LOG => '[]',
    FILE_LOGIN_ATTEMPTS => '{}'
];

foreach ($defaultFiles as $file => $defaultContent) {
    if (!file_exists($file)) {
        file_put_contents($file, $defaultContent);
    }
}

// ============================================
// FUNÇÕES DE CONFIGURAÇÃO
// ============================================

/**
 * Obtém configuração dinâmica do arquivo de settings
 */
function getConfig($key, $default = null) {
    static $config = null;
    
    if ($config === null) {
        $configFile = DATA_DIR . 'settings.json';
        if (file_exists($configFile)) {
            $config = json_decode(file_get_contents($configFile), true) ?: [];
        } else {
            $config = [];
        }
    }
    
    return $config[$key] ?? $default;
}

/**
 * Salva configuração dinâmica
 */
function setConfig($key, $value) {
    $configFile = DATA_DIR . 'settings.json';
    $config = [];
    
    if (file_exists($configFile)) {
        $config = json_decode(file_get_contents($configFile), true) ?: [];
    }
    
    $config[$key] = $value;
    return file_put_contents($configFile, json_encode($config, JSON_PRETTY_PRINT));
}

// ============================================
// V10.4 - NOVAS CONFIGURACOES (MELHORIAS)
// ============================================

// Deteccao Avancada de Bots
define('ADVANCED_DETECTION_ENABLED', true);
define('JS_CHALLENGE_ENABLED', true);
define('MIN_LOAD_TIME_MS', 500);
define('FINGERPRINT_ENABLED', true);
define('MOUSE_DETECTION_ENABLED', true);

// Webhooks (Telegram e Discord)
define('WEBHOOK_TELEGRAM_ENABLED', false);
define('WEBHOOK_TELEGRAM_BOT_TOKEN', '');
define('WEBHOOK_TELEGRAM_CHAT_ID', '');
define('WEBHOOK_DISCORD_ENABLED', false);
define('WEBHOOK_DISCORD_URL', '');
define('WEBHOOK_ALERT_THRESHOLD', 50); // Alerta se taxa de bloqueio > 50%

// Rotacao de URLs / A/B Testing
define('URL_ROTATION_ENABLED', false);
define('URL_ROTATION_MODE', 'weight'); // weight, sequential, random

// Pausa Automatica de Campanhas
define('AUTO_PAUSE_ENABLED', false);
define('AUTO_PAUSE_BLOCK_THRESHOLD', 80); // Pausa se bloqueio > 80%
define('AUTO_PAUSE_MIN_CLICKS', 100); // Minimo de cliques antes de avaliar

// Graficos e Dashboard
define('CHARTS_ENABLED', true);
define('CHARTS_DAYS_HISTORY', 30);

// ============================================
// V10.5 - STEALTH MODE (MODO FURTIVO)
// ============================================
// DESABILITADO para funcionamento direto (bot=white, humano=black)
define('STEALTH_MODE_ENABLED', false);

// Behavioral Gate - Exige comportamento humano antes de mostrar black
define('BEHAVIORAL_GATE_ENABLED', false);
define('BEHAVIORAL_MIN_SCROLLS', 2);          // Minimo de scrolls
define('BEHAVIORAL_MIN_TIME_MS', 3000);       // 3 segundos
define('BEHAVIORAL_MIN_MOUSE_MOVES', 5);      // Minimo de movimentos de mouse
define('BEHAVIORAL_MIN_VISITS', 1);           // 1 visita ja basta (nao precisa recarregar)

// Progressive Reveal - Mostra teaser antes da black completa
define('PROGRESSIVE_REVEAL_ENABLED', true);

// Risk Score - Limite para bloquear visitante suspeito
define('RISK_SCORE_THRESHOLD', 70); // 0-100, quanto maior mais restritivo

// Time-based - Mais conservador em horario comercial
define('TIME_BASED_PROTECTION', true);

// Coletar fingerprints de revisores
define('COLLECT_REVIEWER_FP', true);

// Arquivos de dados das melhorias
define('FILE_WEBHOOKS', DATA_DIR . 'webhooks.json');
define('FILE_URL_ROTATION', DATA_DIR . 'url_rotation.json');
define('FILE_ADVANCED_STATS', DATA_DIR . 'advanced_stats.json');
define('FILE_HOURLY_STATS', DATA_DIR . 'hourly_stats.json');

// Prefixos de IP aprendidos automaticamente pelo WAF via DNS reverso
// (ByteDance/TikTok/datacenters detectados sozinhos, sem cadastro manual)
define('FILE_WAF_LEARNED', DATA_DIR . 'waf_learned_prefixes.json');

// IPs marcados como "scanner" (bateram sem UTM em varias campanhas em
// poucos segundos) - uma vez marcados, nunca mais viram BLACK.
define('FILE_WAF_SCANNERS', DATA_DIR . 'waf_scanners.json');

// ============================================
// FREQUENCY CAP (limite de visualizacoes da BLACK por visitante)
// ============================================
// Observacao de trafego: acessos reais saturam em ate 2 visualizacoes da
// oferta (BLACK); bots insistem e tentam passar mais vezes. A partir da
// 3a tentativa (acima de FREQ_CAP_MAX) dentro da janela, o visitante e
// desviado para a White Page automaticamente.
define('FREQ_CAP_ENABLED', true);   // liga/desliga a regra
define('FREQ_CAP_MAX', 2);          // quantas vezes o mesmo visitante pode ver a BLACK
define('FREQ_CAP_WINDOW', 86400);   // janela de contagem, em segundos (86400 = 24h)

// Contagem de visualizacoes da BLACK por visitante (chave = prefixo do IP).
define('FILE_FREQ_CAP', DATA_DIR . 'freq_cap.json');

// ============================================
// FINGERPRINT VELOCITY (anti-farm / bots "humanos")
// ============================================
// Farms residenciais reusam a MESMA imagem de device/emulador, entao o mesmo
// fingerprint (canvas+webgl+audio+tela+timezone) aparece em muitas REDES
// diferentes em pouco tempo. Humano real = 1 fingerprint por rede. Se um
// mesmo fingerprint for visto em >= FP_VELOCITY_MAX_NETS redes distintas
// (contadas por prefixo /64 no IPv6, IP cheio no IPv4) dentro da janela, o
// fingerprint e considerado farm e vai para force-white permanente.
define('FP_VELOCITY_ENABLED', true);   // liga/desliga a regra
define('FP_VELOCITY_MAX_NETS', 4);     // redes distintas com o MESMO fingerprint p/ considerar farm
define('FP_VELOCITY_WINDOW', 3600);    // janela de contagem, em segundos (3600 = 1h)

// Contagem de redes por fingerprint (deteccao de farm).
define('FILE_FP_VELOCITY', DATA_DIR . 'fp_velocity.json');

// Criar arquivos padrao das melhorias
$newDefaultFiles = [
    FILE_WEBHOOKS => '{"telegram":{"enabled":false,"bot_token":"","chat_id":""},"discord":{"enabled":false,"url":""}}',
    FILE_URL_ROTATION => '{}',
    FILE_ADVANCED_STATS => '{"by_hour":{},"js_challenges":{"passed":0,"failed":0},"fingerprints":{}}',
    FILE_HOURLY_STATS => '{}',
    FILE_WAF_LEARNED => '[]',
    FILE_WAF_SCANNERS => '{}',
    FILE_FREQ_CAP => '{}',
    FILE_FP_VELOCITY => '{}'
];

foreach ($newDefaultFiles as $file => $defaultContent) {
    if (!file_exists($file)) {
        file_put_contents($file, $defaultContent);
    }
}

// ============================================
// V3 - TRANSACOES E GATEWAYS
// ============================================

// Arquivos de dados de transacoes
define('FILE_TRANSACTIONS', DATA_DIR . 'transactions.json');
define('FILE_GATEWAYS', DATA_DIR . 'gateways.json');

// Criar arquivos padrao do V3
$v3DefaultFiles = [
    FILE_TRANSACTIONS => '[]',
    FILE_GATEWAYS => '{}'
];

foreach ($v3DefaultFiles as $file => $defaultContent) {
    if (!file_exists($file)) {
        file_put_contents($file, $defaultContent);
    }
}

// Pasta de logs de webhook
if (!is_dir(DATA_DIR . 'webhook_logs/')) {
    mkdir(DATA_DIR . 'webhook_logs/', 0755, true);
}

// Pasta de transacoes por dia
if (!is_dir(DATA_DIR . 'transactions/')) {
    mkdir(DATA_DIR . 'transactions/', 0755, true);
}
