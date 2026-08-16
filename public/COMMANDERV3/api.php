<?php
/**
 * COMMANDER V10.3 - API de Cloaking
 * 
 * Endpoint principal para verificação de tráfego
 * 
 * INSTRUÇÕES: Substitua o arquivo api.php existente por este
 */

// Define constante de acesso
define('COMMANDER_ACCESS', true);

// Carrega dependências
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/functions.php';

// Carrega novos sistemas avancados (se existirem)
if (file_exists(__DIR__ . '/tls-fingerprint.php')) {
    require_once __DIR__ . '/tls-fingerprint.php';
}
if (file_exists(__DIR__ . '/ml-detector.php')) {
    require_once __DIR__ . '/ml-detector.php';
}

// Force White - lista manual de bots que vao DIRETO para a white page
if (file_exists(__DIR__ . '/force-white.php')) {
    require_once __DIR__ . '/force-white.php';
}

// Inicializa segurança
$security = CommanderSecurity::getInstance();

// Headers de segurança
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// CORS para requisições do tracker
$allowedOrigins = ['*']; // Em produção, especifique domínios permitidos
$origin = $_SERVER['HTTP_ORIGIN'] ?? '*';
header("Access-Control-Allow-Origin: {$origin}");
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-API-Token, X-Requested-With');

// Trata preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// =============================================
// IFRAME (STEALTH) - Codigo mostra WHITE, visual mostra BLACK
// Chamado via GET ?action=iframe&white=URL&black=URL
// Bot ve HTML da white, humano ve black via Shadow DOM
// =============================================
if (isset($_GET['action']) && ($_GET['action'] === 'iframe' || $_GET['action'] === 'stealth')) {
    $stealthFile = __DIR__ . '/proxy-stealth.php';
    
    if (!file_exists($stealthFile)) {
        http_response_code(500);
        echo json_encode(['error' => 'Proxy iframe nao disponivel']);
        exit;
    }
    
    require_once $stealthFile;
    
    $whiteUrl = $_GET['white'] ?? '';
    $blackUrl = $_GET['black'] ?? '';
    
    if (empty($whiteUrl) || empty($blackUrl)) {
        http_response_code(400);
        echo json_encode(['error' => 'URLs white e black sao obrigatorias']);
        exit;
    }
    
    proxyStealthRequest($whiteUrl, $blackUrl);
}

// =============================================
// IFRAME PROXY - Serve conteudo para ser carregado em iframe
// Remove X-Frame-Options que bloqueiam iframe
// Chamado via GET ?action=iframeproxy&url=...
// =============================================
if (isset($_GET['action']) && $_GET['action'] === 'iframeproxy' && isset($_GET['url'])) {
    $proxyFile = __DIR__ . '/proxy-universal.php';
    
    if (!file_exists($proxyFile)) {
        http_response_code(500);
        echo json_encode(['error' => 'Proxy nao disponivel']);
        exit;
    }
    
    require_once $proxyFile;
    
    $targetUrl = filter_var($_GET['url'], FILTER_VALIDATE_URL);
    if (!$targetUrl) {
        http_response_code(400);
        echo json_encode(['error' => 'URL invalida']);
        exit;
    }
    
    serveForIframe($targetUrl);
}

// =============================================
// PROXY UNIVERSAL - Funciona com qualquer site
// Chamado via GET ?action=proxy&url=... ou ?action=proxy&_asset=... ou ?action=proxy&_nav=...
// =============================================
if (isset($_GET['action']) && $_GET['action'] === 'proxy') {
    // Carrega proxy universal (prioridade) ou fallback para v4
    $proxyFile = __DIR__ . '/proxy-universal.php';
    if (!file_exists($proxyFile)) {
        $proxyFile = __DIR__ . '/proxy-v4.php';
    }
    
    if (!file_exists($proxyFile)) {
        http_response_code(500);
        echo json_encode(['error' => 'Proxy nao disponivel']);
        exit;
    }
    
    require_once $proxyFile;
    
    // Modo iframe (mais compativel)
    if (isset($_GET['iframe'])) {
        proxyRequest(null);
    }
    // Asset (CSS, JS, imagem, fonte)
    elseif (isset($_GET['_asset'])) {
        proxyRequest(null);
    }
    // Navegacao interna
    elseif (isset($_GET['_nav'])) {
        proxyRequest(null);
    }
    // URL principal
    elseif (isset($_GET['url'])) {
        $proxyUrl = filter_var($_GET['url'], FILTER_VALIDATE_URL);
        if (!$proxyUrl) {
            http_response_code(400);
            echo json_encode(['error' => 'URL invalida']);
            exit;
        }
        proxyRequest($proxyUrl);
    }
    else {
        http_response_code(400);
        echo json_encode(['error' => 'URL nao especificada']);
        exit;
    }
}

// =============================================
// LOG ENDPOINT - Recebe logs de acesso dos trackers
// Chamado via POST ?action=log ou /log
// =============================================
if ((isset($_GET['action']) && $_GET['action'] === 'log') || 
    (strpos($_SERVER['REQUEST_URI'] ?? '', '/log') !== false && $_SERVER['REQUEST_METHOD'] === 'POST')) {
    
    // Recebe dados do log
    $logData = json_decode(file_get_contents('php://input'), true);
    if (!$logData) {
        $logData = $_POST;
    }
    
    // Valida dados minimos
    if (empty($logData['campaign_slug'])) {
        http_response_code(400);
        echo json_encode(['error' => 'campaign_slug obrigatorio']);
        exit;
    }
    
    // Salva o log usando a funcao do functions.php
    if (function_exists('saveAccessLog')) {
        saveAccessLog($logData);
        echo json_encode(['success' => true]);
    } else {
        // Fallback: salva em arquivo local
        $logDir = DATA_DIR . 'access_logs/';
        if (!is_dir($logDir)) {
            @mkdir($logDir, 0755, true);
        }
        
        $date = date('Y-m-d');
        $filename = $logDir . $date . '.json';
        
        $existingLogs = [];
        if (file_exists($filename)) {
            $existingLogs = json_decode(file_get_contents($filename), true) ?: [];
        }
        
        $existingLogs[] = $logData;
        file_put_contents($filename, json_encode($existingLogs, JSON_PRETTY_PRINT), LOCK_EX);
        
        echo json_encode(['success' => true]);
    }
    exit;
}

/**
 * Classe principal da API
 */
class CommanderAPI {
    
    private $security;
    private $requestData;
    private $clientIP;
    private $userAgent;
    
    public function __construct() {
        global $security;
        $this->security = $security;
        $this->clientIP = $this->security->getRealIP();
        $this->userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $this->requestData = $this->getRequestData();
    }
    
    /**
     * Processa a requisição
     */
    public function handle() {
        try {
            // =====================================================
            // NAVEGACAO INTERNA DO BLACK - PULA TODA VERIFICACAO
            // Quando usuario ja validado clica em link dentro do black,
            // _blacknav indica que nao precisa re-verificar
            // =====================================================
            if (isset($_GET['_blacknav']) && !empty($_GET['_blacknav'])) {
                return $this->handleInternalBlackNavigation();
            }
            
            // Rate limiting
            if (!$this->security->checkRateLimit($this->clientIP)) {
                $this->respond(['error' => 'Rate limit exceeded'], 429);
            }
            
            // Obtém ação
            // IMPORTANTE: todos os trackers legitimos enviam 'action' => 'check'
            // explicitamente (via cURL servidor->servidor). Uma requisicao SEM
            // 'action' e, portanto, acesso direto pelo navegador — nao deve
            // disparar o cloaking (evita que a raiz do diretorio "vaze" uma
            // decisao de cloaking em vez de abrir o painel).
            $action = $this->requestData['action'] ?? '';

            // =====================================================
            // PROTECAO: acesso direto pelo navegador ao api.php
            // =====================================================
            // Todos os trackers legitimos chamam o api.php via cURL POST com
            // 'action' => 'check'. Se chegou um GET SEM 'action', e um humano
            // abrindo o api.php no navegador (ex.: quando o servidor resolve o
            // indice do diretorio /COMMANDERV3/ como api.php em vez de
            // index.php). Nesse caso, redirecionamos para o PAINEL em vez de
            // rodar o cloaking e "vazar" um JSON de decisao. Isso funciona
            // mesmo que o .htaccess (DirectoryIndex) seja ignorado pelo servidor.
            $requestMethod = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
            if ($action === '' && $requestMethod === 'GET') {
                header('Location: index.php');
                exit;
            }

            switch ($action) {
                case 'check':
                    return $this->checkTraffic();
                
                case 'conversion':
                    return $this->registerConversion();
                
                case 'pixel':
                    return $this->handlePixel();
                
                case 'health':
                    return $this->healthCheck();
                
                // V10.4 - Novas acoes
                case 'js_challenge':
                    return $this->getJSChallenge();
                
                case 'charts':
                    return $this->getChartData();
                
                case 'proxy':
                    return $this->handleProxy();
                
                case 'summary':
                    return $this->getDashboardData();
                
                case 'webhook_test':
                    return $this->testWebhook();
                
                // V10.5 - Behavioral tracking
                case 'update_behavior':
                    return $this->updateBehaviorData();
                
                // V11 - Machine Learning
                case 'ml_train_human':
                    return $this->mlTrainHuman();
                
                case 'ml_train_bot':
                    return $this->mlTrainBot();
                
                case 'ml_stats':
                    return $this->mlGetStats();
                
                case 'biometrics':
                    return $this->processBiometrics();
                
                // COMMANDER V3 - Transacoes e Gateways
                case 'get_transactions':
                    return $this->getTransactionsList();
                
                case 'get_revenue':
                    return $this->getRevenueData();
                
                case 'get_sales_stats':
                    return $this->getSalesStatistics();
                
                case 'get_gateways':
                    return $this->getGatewaysList();
                
                case 'save_gateway':
                    return $this->saveGatewayConfig();
                
                case 'remove_gateway':
                    return $this->removeGatewayConfig();
                
                case 'get_webhook_url':
                    return $this->getGatewayWebhookUrl();
                
                default:
                    $this->respond(['error' => 'Invalid action'], 400);
            }
            
        } catch (Exception $e) {
            debugLog('API Error', ['message' => $e->getMessage()]);
            $this->respond(['error' => 'Internal error'], 500);
        }
    }
    
    /**
     * Navegacao interna do black - pula verificacao de bot
     * Usuario ja foi validado na primeira visita
     */
    private function handleInternalBlackNavigation() {
        $blackNav = $_GET['_blacknav'] ?? '';
        $whiteUrl = $_GET['white'] ?? '';
        
        // Decodifica URL do black
        $blackUrl = base64_decode($blackNav);
        
        if (empty($blackUrl) || !filter_var($blackUrl, FILTER_VALIDATE_URL)) {
            $this->respond(['error' => 'URL invalida'], 400);
            return;
        }
        
        // Se nao tem white, tenta pegar da campanha ou usa placeholder
        if (empty($whiteUrl)) {
            $whiteUrl = 'https://example.com';
        }
        
        // Carrega proxy-stealth e serve black diretamente
        $proxyFile = __DIR__ . '/proxy-stealth.php';
        if (file_exists($proxyFile)) {
            require_once $proxyFile;
            if (function_exists('serveBlackDirectly')) {
                serveBlackDirectly($whiteUrl, $blackUrl);
                exit;
            }
        }
        
        // Fallback: usa proxy-universal para servir iframe
        $proxyUniversal = __DIR__ . '/proxy-universal.php';
        if (file_exists($proxyUniversal)) {
            require_once $proxyUniversal;
            if (function_exists('serveForIframe')) {
                serveForIframe($blackUrl);
                exit;
            }
        }
        
        // Ultimo fallback: redirect direto
        header('Location: ' . $blackUrl);
        exit;
    }
    
    /**
     * Proxy reverso universal - usa proxy-v4.php
     */
    private function handleProxy() {
        $url = $this->sanitize($this->requestData['url'] ?? '');
        
        if (empty($url) || !filter_var($url, FILTER_VALIDATE_URL)) {
            $this->respond(['error' => 'URL invalida'], 400);
        }
        
        // Carrega o proxy-v4.php
        $proxyFile = __DIR__ . '/proxy-v4.php';
        if (!file_exists($proxyFile)) {
            $this->respond(['error' => 'Proxy nao disponivel'], 500);
        }
        
        require_once $proxyFile;
        
        // Executa o proxy (isso vai dar output e exit)
        proxyRequest($url);
    }
    
    /**
     * Verifica tráfego (função principal de cloaking)
     */
    private function checkTraffic() {
        // Dados do tracker
        $visitorIP = $this->sanitize($this->requestData['ip'] ?? $this->clientIP);
        $visitorUA = $this->sanitize($this->requestData['ua'] ?? $this->userAgent);
        $campaignSlug = $this->sanitize($this->requestData['campaign'] ?? '');
        $utmSource = $this->sanitize($this->requestData['utm_source'] ?? '');
        $utmMedium = $this->sanitize($this->requestData['utm_medium'] ?? '');
        $utmCampaign = $this->sanitize($this->requestData['utm_campaign'] ?? '');
        $utmContent = $this->sanitize($this->requestData['utm_content'] ?? '');
        $utmTerm = $this->sanitize($this->requestData['utm_term'] ?? '');
        $referer = $this->sanitize($this->requestData['referer'] ?? '');
        $timestamp = time();
        
        // Busca campanha
        $campaign = null;
        $campaignId = null;
        if (!empty($campaignSlug)) {
            $campaign = getCampaignBySlug($campaignSlug);
            $campaignId = $campaign['id'] ?? $campaignSlug;
        }
        
        // =====================================================
        // VERIFICACAO DE ASSINATURA DO USUARIO
        // =====================================================
        // Se o usuario dono da campanha tiver assinatura vencida,
        // o cloaker para de funcionar (vai sempre para WHITE)
        // =====================================================
        if ($campaign && !empty($campaign['user_id'])) {
            $usuariosFile = __DIR__ . '/usuarios.json';
            if (file_exists($usuariosFile)) {
                $usuarios = json_decode(file_get_contents($usuariosFile), true) ?? [];
                $ownerId = $campaign['user_id'];
                $ownerData = null;
                
                // Busca usuario pelo ID/email
                foreach ($usuarios as $emailKey => $userData) {
                    if ($emailKey === $ownerId || ($userData['id'] ?? '') === $ownerId) {
                        $ownerData = $userData;
                        break;
                    }
                }
                
                if ($ownerData) {
                    // Verifica se esta bloqueado
                    if (!empty($ownerData['bloqueado']) && $ownerData['bloqueado'] === true) {
                        $this->respond([
                            'action' => 'white',
                            'reason' => 'subscription_blocked',
                            'message' => 'Usuario bloqueado'
                        ]);
                        return;
                    }
                    
                    // Verifica data de expiracao
                    if (!empty($ownerData['expira_em'])) {
                        $expiraEm = strtotime($ownerData['expira_em']);
                        if ($expiraEm !== false && $expiraEm < time()) {
                            $this->respond([
                                'action' => 'white',
                                'reason' => 'subscription_expired',
                                'message' => 'Assinatura vencida em ' . $ownerData['expira_em']
                            ]);
                            return;
                        }
                    }
                }
            }
        }
        
        // Detecta plataforma
        $platform = detectPlatform($utmSource);
        
        // Verifica se o IP está na whitelist (Admin/Testes) - vai direto pra black
        $isWhitelisted = false;
        $whitelistFile = DATA_DIR . 'whitelist_ips.json';
        if (file_exists($whitelistFile)) {
            $whitelistData = json_decode(file_get_contents($whitelistFile), true);
            if (is_array($whitelistData)) {
                // Match exato
                if (isset($whitelistData[$visitorIP])) {
                    $isWhitelisted = true;
                } else {
                    // Para IPv6, faz match dos primeiros 4 segmentos (prefixo da rede)
                    // Isso cobre casos onde o IP muda parcialmente (comum em IPv6)
                    if (strpos($visitorIP, ':') !== false) {
                        $visitorPrefix = implode(':', array_slice(explode(':', $visitorIP), 0, 4));
                        foreach (array_keys($whitelistData) as $whitelistedIP) {
                            if (strpos($whitelistedIP, ':') !== false) {
                                $whitePrefix = implode(':', array_slice(explode(':', $whitelistedIP), 0, 4));
                                if ($visitorPrefix === $whitePrefix) {
                                    $isWhitelisted = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // =====================================================
        // WAF: FIREWALL DE PREFIXOS DE IP (Data Centers / Scrapers)
        // =====================================================
        // Se o IP do visitante bate com um prefixo conhecido de cloud/bot,
        // vai direto para a White Page. Rodando AQUI (e nao no tracker), o
        // bloqueio fica REGISTRADO em Logs de Bots e IPs de teste (whitelist)
        // sao ignorados, permitindo testar a black normalmente.
        // =====================================================
        if (!$isWhitelisted) {
            $wafPrefixes = [
    // --- ByteDance / TikTok Ads ---
    "103.136.", "43.", "170.106.", "49.51.", "165.154.", "202.47.",
    "103.173.", "103.152.", "103.24.", "101.33.", "101.36.", "101.53.",
    "111.92.", "118.193.", "118.194.", "124.156.", "124.220.", "124.221.",
    "129.204.", "129.226.", "139.155.", "122.161.", "202.181.", "223.233.",
    "39.109.", "113.31.",

    // --- AWS (Amazon Cloud) ---
    "3.", "13.", "15.", "18.", "34.", "35.", "44.", "50.19.", "52.", "54.",
    "99.", "100.26.", "107.20.", "107.21.", "107.22.", "107.23.", "174.129.",
    "184.72.", "184.73.", "204.236.",

    // --- Google Cloud Platform (GCP) / Googlebot ---
    "34.64.", "34.65.", "34.66.", "34.67.", "34.68.", "34.69.", "34.70.", "34.71.",
    "35.184.", "35.185.", "35.186.", "35.187.", "35.188.", "35.189.", "35.190.",
    "66.249.", "66.102.", "104.154.", "104.155.", "104.196.", "104.197.", "104.198.",
    "104.199.", "107.178.", "130.211.", "146.148.",

    // --- Azure (Microsoft Cloud) / Oracle Cloud ---
    "13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.", "20.", "40.",
    "51.103.", "51.104.", "51.105.", "52.136.", "52.137.", "52.138.", "104.40.",
    "104.41.", "104.42.", "129.146.", "129.150.", "130.35.", "130.61.", "132.145.",
    "137.116.", "140.238.", "140.245.", "147.154.", "150.136.", "152.67.", "168.61.",
    "172.161.", "191.232.", "192.9.",

    // --- DigitalOcean ---
    "104.131.", "104.236.", "104.248.", "134.209.", "138.68.", "138.197.", "142.93.",
    "143.110.", "143.198.", "143.244.", "157.230.", "157.245.", "159.65.", "159.89.",
    "159.203.", "161.35.", "164.90.", "165.227.", "167.99.", "167.172.", "172.233.",
    "178.62.", "188.166.", "206.189.", "207.154.",

    // --- Hetzner Online (Europa) ---
    "5.9.", "78.46.", "78.47.", "88.198.", "94.130.", "135.181.", "136.243.",
    "138.201.", "142.132.", "144.76.", "148.251.", "159.69.", "162.55.", "168.119.",
    "176.9.", "178.63.", "178.156.", "188.40.", "195.201.",

    // --- OVH Cloud ---
    "51.38.", "51.68.", "51.75.", "51.77.", "51.79.", "51.81.", "51.83.", "51.89.",
    "51.91.", "51.178.", "51.210.", "51.254.", "51.255.", "57.128.", "137.74.",
    "142.4.", "147.135.", "149.56.", "151.80.", "167.114.", "178.32.", "178.33.",
    "192.99.", "198.27.", "198.50.", "213.186.",

    // --- Linode / Akamai Cloud ---
    "45.33.", "45.56.", "45.79.", "50.116.", "96.126.", "109.74.", "139.162.",
    "172.104.", "172.105.", "173.255.", "176.58.", "178.79.", "192.155.", "198.58.",
    "198.74.", "212.71.",

    // --- Vultr / Choopa ---
    "45.32.", "45.63.", "45.76.", "45.77.", "66.42.", "95.179.", "108.61.",
    "140.82.", "144.202.", "149.28.", "155.138.", "207.246.", "208.167.", "217.69.",

    // --- ColoCrossing / RackNerd / Hostwinds ---
    "107.172.", "107.173.", "107.174.", "107.175.", "168.144.", "172.245.",
    "192.3.", "192.210.", "192.240.", "198.12.", "198.23.", "198.46.", "198.144.",
    "198.252.", "204.13.",

    // --- Alibaba Cloud / Tencent / China Cloud ---
    "8.208.", "8.209.", "8.210.", "8.211.", "8.212.", "8.213.", "8.228.", "8.229.",
    "39.96.", "39.97.", "39.98.", "47.52.", "47.74.", "47.87.", "47.236.", "47.254.",
    "101.32.", "101.37.", "119.28.", "119.29.", "120.76.", "129.211.", "150.109.",
    "182.254.", "203.107.",

    // --- Cloudflare WARP / Outros Scrapers ---
    "4.184.", "4.185.", "5.83.", "5.133.", "5.161.", "5.182.", "5.224.",
    "13.51.", "13.63.", "13.222.", "14.18.", "14.192.", "15.204.", "17.22.",
    "17.241.", "17.246.", "23.19.", "23.80.", "23.111.", "27.125.", "31.56.",
    "32.193.", "32.194.", "32.195.", "32.197.", "32.198.", "32.199.", "36.75.",
    "37.1.", "37.111.", "37.113.", "38.110.", "38.154.", "38.250.", "38.253.",
    "39.34.", "39.48.", "39.55.", "39.60.", "39.63.", "40.87.", "41.56.",
    "42.117.", "42.118.", "45.9.", "45.10.", "45.39.", "45.41.", "45.45.",
    "45.55.", "45.56.", "45.61.", "45.74.", "45.88.", "45.92.", "45.94.",
    "45.138.", "45.148.", "45.153.", "45.163.", "45.168.", "45.172.", "45.174.",
    "45.181.", "45.182.", "45.183.", "45.194.", "45.225.", "45.230.", "45.234.",
    "45.237.", "46.17.", "46.174.", "47.79.", "51.75.", "58.65.", "58.187.",
    "59.14.", "59.103.", "62.197.", "64.23.", "64.89.", "67.215.", "68.221.",
    "72.1.", "72.153.", "72.255.", "74.7.", "74.179.", "74.248.", "76.35.",
    "77.74.", "77.78.", "77.83.", "77.90.", "78.85.", "80.9.", "80.89.",
    "80.246.", "81.56.", "81.196.", "82.22.", "82.77.", "82.156.", "83.29.",
    "84.32.", "84.55.", "84.233.", "85.137.", "85.208.", "86.57.", "87.58.",
    "87.99.", "87.205.", "87.222.", "88.148.", "88.164.", "89.248.", "91.73.",
    "91.92.", "91.98.", "91.134.", "91.148.", "91.207.", "91.211.", "91.224.",
    "92.128.", "93.123.", "93.158.", "94.47.", "94.154.", "94.247.", "94.254.",
    "95.40.", "95.181.", "95.211.", "98.80.", "98.84.", "98.86.", "98.91.",
    "98.93.", "99.79.", "100.31.", "100.56.", "100.57.", "100.59.", "102.22.",
    "104.28.", "105.77.", "105.188.", "106.54.", "106.161.", "108.", "109.205.",
    "119.252.", "130.12.", "138.199.", "138.201.", "141.148.", "154.36.",
    "157.143.", "158.158.", "170.246.", "170.254.", "185.92.", "185.225.",
    "192.210.", "192.255.", "195.70.", "195.178.", "204.101.", "209.54.",
    "213.188.", "216.194.", "216.251.", "216.73.",

    // --- Bots IPv6 ---
    "2a06:98c0:", "2a03:2880:", "2001:41d0:", "2a04:c300:", "2a09:bac1:",
    "2001:818:", "2600:3000:", "2404:9dc0:", "2a01:4f9:"
];
            // Mescla com os prefixos APRENDIDOS AUTOMATICAMENTE (via DNS reverso)
            // guardados em data/waf_learned_prefixes.json - assim IPs que ja
            // foram identificados uma vez sao bloqueados instantaneamente,
            // sem precisar cadastrar na mao nem repetir a consulta de DNS.
            $wafPrefixes = array_merge($wafPrefixes, getWafLearnedPrefixes());

            $wafHit = null;
            foreach ($wafPrefixes as $pfx) {
                if (strncmp($visitorIP, $pfx, strlen($pfx)) === 0) {
                    $wafHit = $pfx;
                    break;
                }
            }

            if ($wafHit !== null) {
                $this->logBotAccess($visitorIP, $visitorUA, "WAF: IP de datacenter/bot ({$wafHit}*) -> White Page", $campaignId, $utmSource, $platform);
                recordHourlyClick(true);
                recordClick($campaignId, true, $platform);
                logBot([
                    'ip' => $visitorIP,
                    'user_agent' => substr($visitorUA, 0, 200),
                    'reason' => "WAF: IP de datacenter ({$wafHit}*)",
                    'result' => 'white',
                    'campaign' => $campaignSlug,
                    'campaign_id' => $campaignId,
                    'platform' => $platform,
                    'referer' => ''
                ]);
                jsonResponse([
                    'action'   => 'white',
                    'url'      => $campaign['white_url'] ?? '',
                    'redirect' => $campaign['white_url'] ?? '',
                    'method'   => $campaign['white_method'] ?? 'redirect',
                    'reason'   => 'waf_datacenter'
                ]);
            }

            // =====================================================
            // AUTO-DETECCAO: DNS reverso para bots/datacenters desconhecidos
            // =====================================================
            // Se o IP NAO bateu em nenhum prefixo (fixo ou aprendido), tenta
            // identificar via DNS reverso (PTR) se pertence a ByteDance/TikTok
            // ou a um provedor de nuvem/datacenter. Se identificar, BLOQUEIA
            // e SALVA o prefixo automaticamente na lista aprendida - nas
            // proximas visitas desse mesmo bloco de IP, o bloqueio e
            // instantaneo, sem precisar de DNS de novo e sem cadastro manual.
            // =====================================================
            $autoDetect = detectDatacenterByReverseDNS($visitorIP);
            if ($autoDetect) {
                $learnedPrefix = learnWafPrefix($visitorIP, $autoDetect['hostname'], $autoDetect['keyword']);
                $this->logBotAccess($visitorIP, $visitorUA, "WAF Auto: PTR '{$autoDetect['hostname']}' -> prefixo {$learnedPrefix} aprendido -> White Page", $campaignId, $utmSource, $platform);
                recordHourlyClick(true);
                recordClick($campaignId, true, $platform);
                logBot([
                    'ip' => $visitorIP,
                    'user_agent' => substr($visitorUA, 0, 200),
                    'reason' => "WAF Auto (DNS reverso): {$autoDetect['hostname']} [{$autoDetect['keyword']}] -> prefixo {$learnedPrefix} aprendido",
                    'result' => 'white',
                    'campaign' => $campaignSlug,
                    'campaign_id' => $campaignId,
                    'platform' => $platform,
                    'referer' => ''
                ]);
                jsonResponse([
                    'action'   => 'white',
                    'url'      => $campaign['white_url'] ?? '',
                    'redirect' => $campaign['white_url'] ?? '',
                    'method'   => $campaign['white_method'] ?? 'redirect',
                    'reason'   => 'waf_datacenter_auto'
                ]);
            }

            // =====================================================
            // REPUTACAO DE IP (ip-api.com): datacenter / proxy / VPN
            // =====================================================
            // Ultima camada de rede: consulta a natureza da conexao numa base
            // externa (com cache local). Pega revisores/crawlers que saem de
            // nuvem ou VPN e escaparam da lista de prefixos e do DNS reverso.
            // Fail-open: se a consulta falhar, NAO bloqueia (deixa as outras
            // camadas decidirem). Residencial/movel real nao dispara aqui.
            // =====================================================
            if (defined('IP_REP_ENABLED') && IP_REP_ENABLED && function_exists('getIpReputation')) {
                $rep = getIpReputation($visitorIP);
                if (!empty($rep['checked'])) {
                    $blockHosting = defined('IP_REP_BLOCK_HOSTING') ? IP_REP_BLOCK_HOSTING : true;
                    $blockProxy   = defined('IP_REP_BLOCK_PROXY') ? IP_REP_BLOCK_PROXY : true;
                    $repHit = '';
                    if ($blockHosting && !empty($rep['hosting'])) {
                        $repHit = 'datacenter/hosting';
                    } elseif ($blockProxy && !empty($rep['proxy'])) {
                        $repHit = 'proxy/VPN';
                    }
                    if ($repHit !== '') {
                        $repInfo = trim(($rep['as'] ?? '') . ' ' . ($rep['isp'] ?? ''));
                        $this->logBotAccess($visitorIP, $visitorUA, "Reputacao IP: {$repHit} ({$repInfo}) -> White Page", $campaignId, $utmSource, $platform);
                        recordHourlyClick(true);
                        recordClick($campaignId, true, $platform);
                        logBot([
                            'ip' => $visitorIP,
                            'user_agent' => substr($visitorUA, 0, 200),
                            'reason' => "Reputacao IP ({$repHit}): {$repInfo}",
                            'result' => 'white',
                            'campaign' => $campaignSlug,
                            'campaign_id' => $campaignId,
                            'platform' => $platform,
                            'referer' => ''
                        ]);
                        jsonResponse([
                            'action'   => 'white',
                            'url'      => $campaign['white_url'] ?? '',
                            'redirect' => $campaign['white_url'] ?? '',
                            'method'   => $campaign['white_method'] ?? 'redirect',
                            'reason'   => 'ip_reputation'
                        ]);
                    }
                }
            }
        }

        // =====================================================
        // TRAVA DE PLATAFORMA: TikTok = so mobile + dentro do app
        // =====================================================
        // Campanhas com plataforma 'tiktok' so aceitam visitantes de CELULAR e
        // de DENTRO do app do TikTok/ByteDance. Desktop ou navegador externo ->
        // White Page. Fica REGISTRADO e IPs de teste (whitelist) sao ignorados.
        // =====================================================
        if (!$isWhitelisted && ($campaign['platform'] ?? '') === 'tiktok') {
            $ttIsMobile = preg_match('/(Android|iPhone|iPad|iPod)/i', $visitorUA);
            $ttIsInApp  = preg_match('/(BytedanceWebview|TikTok|Musical_ly|Bytedance|trill|Aweme)/i', $visitorUA);
            // MODO TESTE: quando ligado, basta ser mobile (nao exige o app do TikTok),
            // permitindo testar pelo celular em qualquer navegador com os parametros.
            // Desligado (padrao): exige mobile E dentro do app do TikTok, como em producao.
            $ttTestMode = ($campaign['tiktok_test_mode'] ?? '0') === '1';
            $ttBlocked  = $ttTestMode ? !$ttIsMobile : (!$ttIsMobile || !$ttIsInApp);
            if ($ttBlocked) {
                $motivo = !$ttIsMobile ? 'nao-mobile' : 'fora do app TikTok';
                $this->logBotAccess($visitorIP, $visitorUA, "TikTok: acesso {$motivo} -> White Page", $campaignId, $utmSource, $platform);
                recordHourlyClick(true);
                recordClick($campaignId, true, $platform);
                logBot([
                    'ip' => $visitorIP,
                    'user_agent' => substr($visitorUA, 0, 200),
                    'reason' => "TikTok: acesso {$motivo}",
                    'result' => 'white',
                    'campaign' => $campaignSlug,
                    'campaign_id' => $campaignId,
                    'platform' => $platform,
                    'referer' => ''
                ]);
                jsonResponse([
                    'action'   => 'white',
                    'url'      => $campaign['white_url'] ?? '',
                    'redirect' => $campaign['white_url'] ?? '',
                    'method'   => $campaign['white_method'] ?? 'redirect',
                    'reason'   => 'tiktok_platform_lock'
                ]);
            }
        }

// --- INICIO DA TRAVA DE HARDWARE ANTI-BOT ---
            $_secMobile = $_SERVER['HTTP_SEC_CH_UA_MOBILE'] ?? '';
            $_secPlatform = $_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? '';

            if (!empty($_secMobile) && trim($_secMobile) === '?0') {
                $this->logBotAccess($visitorIP, $visitorUA, "Hardware: Confessou ser Desktop (?0) -> White Page", $campaignId, $utmSource, $platform);
                recordHourlyClick(true); recordClick($campaignId, true, $platform);
                jsonResponse([
                    'action'   => 'white',
                    'url'      => $campaign['white_url'] ?? '',
                    'method'   => $campaign['white_method'] ?? 'redirect',
                    'reason'   => 'hardware_not_mobile'
                ]);
            }

            if (!empty($_secPlatform)) {
                $_plat = strtolower(trim($_secPlatform, '"\' '));
                if (in_array($_plat, ['windows', 'linux', 'macos', 'chrome os'])) {
                    $this->logBotAccess($visitorIP, $visitorUA, "Hardware: Confessou SO Desktop ({$_plat}) -> White Page", $campaignId, $utmSource, $platform);
                    recordHourlyClick(true); recordClick($campaignId, true, $platform);
                    jsonResponse([
                        'action'   => 'white',
                        'url'      => $campaign['white_url'] ?? '',
                        'method'   => $campaign['white_method'] ?? 'redirect',
                        'reason'   => 'hardware_desktop_os'
                    ]);
                }
            }
            // --- FIM DA TRAVA DE HARDWARE ---

        // =====================================================
        // HORARIO DE PAUSA (White Mode / Agendamento)
        // =====================================================
        // Quando ativado, DENTRO da janela [inicio, fim] (no fuso da campanha)
        // TODO o trafego vai para a White Page - a campanha fica "pausada".
        // Suporta janelas que cruzam a meia-noite (ex.: 23:30 -> 06:00).
        // Aplica-se a todos (inclusive whitelist) para refletir a pausa real.
        // =====================================================
        if (($campaign['schedule_enabled'] ?? '0') === '1') {
            $schedTz    = $campaign['schedule_timezone'] ?? 'America/Sao_Paulo';
            $schedStart = $campaign['schedule_start'] ?? '23:30';
            $schedEnd   = $campaign['schedule_end'] ?? '06:00';

            try {
                $schedNow = new DateTime('now', new DateTimeZone($schedTz));
            } catch (Exception $e) {
                $schedNow = new DateTime('now');
            }
            $nowMinutes = (int)$schedNow->format('H') * 60 + (int)$schedNow->format('i');

            $toMinutes = function ($hhmm) {
                $p = explode(':', (string)$hhmm);
                return ((int)($p[0] ?? 0)) * 60 + ((int)($p[1] ?? 0));
            };
            $startMin = $toMinutes($schedStart);
            $endMin   = $toMinutes($schedEnd);

            // Janela normal (start < end) OU que vira a meia-noite (start > end)
            $inPauseWindow = ($startMin <= $endMin)
                ? ($nowMinutes >= $startMin && $nowMinutes < $endMin)
                : ($nowMinutes >= $startMin || $nowMinutes < $endMin);

            if ($inPauseWindow) {
                // FORCE-WHITE: quem acessa durante a pausa e desviado para a
                // White. Como a campanha esta "fechada", esse trafego e
                // considerado suspeito -> marca o IP permanentemente para que,
                // quando a campanha voltar a ativa, ele ja va direto para White.
                // Whitelist (Admin/Teste) nunca e bloqueada.
                if (!$isWhitelisted && defined('FREQ_CAP_ENABLED') && FREQ_CAP_ENABLED
                    && function_exists('freqBlockForever')) {
                    freqBlockForever($visitorIP);
                }
                $this->logBotAccess($visitorIP, $visitorUA, "Horario de pausa ativo ({$schedStart}-{$schedEnd}) -> White Page (force-white)", $campaignId, $utmSource, $platform);
                recordHourlyClick(true);
                recordClick($campaignId, true, $platform);
                logBot([
                    'ip' => $visitorIP,
                    'user_agent' => substr($visitorUA, 0, 200),
                    'reason' => "Horario de pausa ({$schedStart}-{$schedEnd})",
                    'result' => 'schedule_pause',
                    'campaign' => $campaignSlug,
                    'campaign_id' => $campaignId,
                    'platform' => $platform,
                    'referer' => ''
                ]);
                jsonResponse([
                    'action'   => 'white',
                    'url'      => $campaign['white_url'] ?? '',
                    'redirect' => $campaign['white_url'] ?? '',
                    'method'   => $campaign['white_method'] ?? 'redirect',
                    'reason'   => 'schedule_pause'
                ]);
            }
        }

        // =====================================================
        // WARM-UP: Aquecimento da Campanha
        // =====================================================
        // Se a campanha tem cliques de aquecimento configurados
        // e ainda nao atingiu o limite, todos vao para WHITE
        // =====================================================
        $warmupClicks = (int)($campaign['warmup_clicks'] ?? 0);
        if ($warmupClicks > 0 && !$isWhitelisted) {
            $campStats = getCampaignStats($campaignId);
            $totalClicks = (int)($campStats['clicks'] ?? 0);
            if ($totalClicks < $warmupClicks) {
                // Ainda em aquecimento - manda todos para WHITE
                $remaining = $warmupClicks - $totalClicks;

                // FORCE-WHITE: quem acessa durante o aquecimento e desviado para
                // a White. Esse trafego chega antes da campanha "abrir" de fato,
                // entao e considerado suspeito -> marca o IP permanentemente para
                // que, quando o aquecimento terminar, ele ja va direto para White.
                // Whitelist ja foi descartada na condicao do bloco ($isWhitelisted).
                if (defined('FREQ_CAP_ENABLED') && FREQ_CAP_ENABLED
                    && function_exists('freqBlockForever')) {
                    freqBlockForever($visitorIP);
                }
                $this->logBotAccess($visitorIP, $visitorUA, "Aquecimento: {$totalClicks}/{$warmupClicks} cliques (faltam {$remaining}) -> force-white", $campaignId, $utmSource, $platform);
                
                // IMPORTANTE: Registra o clique para o contador de aquecimento funcionar!
                recordHourlyClick(false);
                recordClick($campaignId, false, $platform); // <-- CORRECAO: Conta clique na campanha
                
                $response = [
                    'action' => 'white',
                    'url' => $campaign['white_url'],
                    'method' => $campaign['white_method'] ?? 'redirect',
                    'warmup' => true,
                    'warmup_progress' => $totalClicks + 1, // +1 porque acabou de registrar
                    'warmup_total' => $warmupClicks
                ];
                jsonResponse($response);
            }
        }

        // NOTA: A DIVISAO DE TRAFEGO (Traffic Split) foi movida para DEPOIS da
        // deteccao de bots (mais abaixo). Antes ela rodava aqui, no inicio, e a
        // fatia que "continuava" acabava sendo mandada para a white pelas regras
        // de desktop/sem-UTM, mascarando a divisao. Agora ela so afeta humanos
        // reais (isBot=false), tornando a % observavel e correta.

        // =====================================================
        // FILTRO DE PAISES
        // =====================================================
        $allowedCountries = array_filter(explode(',', $campaign['allowed_countries'] ?? ''));
        if (!empty($allowedCountries) && !$isWhitelisted) {
            $allowedUpper = array_map('strtoupper', $allowedCountries);

            // CORRECAO PAIS (1/2): confia no pais enviado pelo TRACKER.
            // O tracker fica atras do Cloudflare e ve o IP REAL do visitante.
            // A api.php e chamada via cURL (servidor->servidor), entao detectar
            // o pais aqui veria o IP do VPS - por isso priorizamos o valor do tracker.
            $visitorCountry = strtoupper(trim($this->requestData['country'] ?? ''));

            // Fallback: so usa getIPCountry() se o tracker nao enviou nada.
            if ($visitorCountry === '') {
                $visitorCountry = strtoupper(getIPCountry($visitorIP) ?? 'XX');
            }

            // CORRECAO PAIS (2/2): rede de seguranca - pais desconhecido (XX) NAO bloqueia.
            // Antes, quando a geo falhava, TODO mundo (inclusive brasileiros) ia pra white.
            // Agora, se o pais nao foi detectado, o filtro e ignorado e as outras camadas decidem.
            $countryDetected = ($visitorCountry !== 'XX' && $visitorCountry !== '');

            if ($countryDetected && !in_array($visitorCountry, $allowedUpper)) {
                $reason = "Pais bloqueado: {$visitorCountry} (permitidos: " . implode(',', $allowedCountries) . ")";
                
                // Registra no log para aparecer no painel
                logBot([
                    'ip' => $visitorIP,
                    'user_agent' => substr($visitorUA, 0, 300),
                    'reason' => $reason,
                    'campaign' => $campaignSlug,
                    'campaign_id' => $campaignId,
                    'platform' => $platform,
                    'referer' => ''
                ]);
                
                recordHourlyClick(true);
                jsonResponse([
                    'action' => 'white',
                    'url' => $campaign['white_url'],
                    'method' => $campaign['white_method'] ?? 'redirect',
                    'reason' => 'country_blocked',
                    'country' => $visitorCountry
                ]);
            }
        }

        // =====================================================
        // CLOAKING PROFISSIONAL V11 - NOTA 10
        // =====================================================
        // Sistema multi-camada para Google, TikTok e Facebook
        // =====================================================
        
        $isBot = false;
        $blockReason = '';
        $riskScore = 0;
        $riskFactors = [];
        
        // Verifica se veio de plataforma de ads (tem UTMs ou click IDs)
        $hasAdsParams = !empty($utmSource) || !empty($utmMedium) || 
                        !empty($this->requestData['ttclid']) || 
                        !empty($this->requestData['fbclid']) ||
                        !empty($this->requestData['gclid']);
        
        // Dados do cliente para analise
        $clientData = [
            'webdriver' => $this->requestData['webdriver'] ?? false,
            'plugins_count' => (int)($this->requestData['plugins_count'] ?? -1),
            'languages' => $this->requestData['languages'] ?? '',
            'screen_width' => (int)($this->requestData['screen_width'] ?? 0),
            'screen_height' => (int)($this->requestData['screen_height'] ?? 0),
            'timezone' => $this->requestData['timezone'] ?? '',
            'platform' => $this->requestData['platform'] ?? '',
            'touch_support' => $this->requestData['touch_support'] ?? false,
            'advanced_bot_score' => (int)($this->requestData['advanced_bot_score'] ?? 50),
            'advanced_bot_flags' => explode('|', $this->requestData['advanced_bot_flags'] ?? '')
        ];
        
        // ========== CAMADA 0: WHITELIST (PRIORIDADE MAXIMA) ==========
        if ($isWhitelisted) {
            $isBot = false;
            $blockReason = 'Whitelist - Admin/Teste';
        }
        
        // ========== CAMADA 0.5: DESKTOP = SEMPRE WHITE ==========
        // Revisores do Facebook/Google/TikTok usam desktop
        // Usuarios reais de anuncios em redes sociais usam celular
        // Isso reduz drasticamente os falsos positivos
        elseif (!$this->isMobileDevice($visitorUA)) {
            $isBot = true;
            $blockReason = 'Desktop detectado - enviado para WHITE (apenas mobile passa)';
            $riskScore = 100;
            $this->logBotAccess($visitorIP, $visitorUA, $blockReason, $campaignId, $utmSource, $platform);
        }
        
        // ========== CAMADA 1: BOT APRENDIDO (lista global) ==========
        // Verifica se já foi detectado como bot anteriormente
        elseif (function_exists('isLearnedBot')) {
            $learned = isLearnedBot($visitorIP, $visitorUA);
            if ($learned['isBot']) {
                $isBot = true;
                $blockReason = $learned['reason'];
                $riskScore = 100;
            }
        }
        
        // ========== CAMADA 1.5: FORCE WHITE (lista manual data/force_white.txt) ==========
        // IPs/faixas cadastrados manualmente vao DIRETO para a WHITE page
        if (!$isBot && !$isWhitelisted && function_exists('isForcedWhite') && isForcedWhite($visitorIP)) {
            $isBot = true;
            $blockReason = 'Force White - lista manual';
            $riskScore = 100;
            $this->logBotAccess($visitorIP, $visitorUA, $blockReason, $campaignId, $utmSource, $platform);
        }
        
        // ========== CAMADA 2: USER-AGENT DE BOT CONHECIDO ==========
        if (!$isBot && !$isWhitelisted && isBotByUserAgent($visitorUA)) {
            $isBot = true;
            $blockReason = 'User-Agent de bot/crawler';
            $riskScore = 100;
            $this->logBotAccess($visitorIP, $visitorUA, $blockReason, $campaignId, $utmSource, $platform);
        }
        
        // ========== CAMADA 3: IP NA BLACKLIST ==========
        elseif (!$isBot && !$isWhitelisted && isIPBlocked($visitorIP)) {
            $isBot = true;
            $blockReason = 'IP bloqueado manualmente';
            $riskScore = 100;
        }
        
        // ========== CAMADA 4: TLS/HTTP FINGERPRINT ==========
        // SIMPLIFICADO: Apenas detecta bots CONHECIDOS (cURL, Python, Selenium)
        // NAO penaliza mais por headers faltantes ou diferentes
        $tlsEnabled = $campaign['tls_fp_enabled'] ?? $campaign['tls_enabled'] ?? true; // Ativado por padrao
        $tlsAnalysis = ['score' => 100, 'flags' => [], 'details' => []]; // Default = OK
        if (!$isBot && !$isWhitelisted && $tlsEnabled && class_exists('TLSFingerprint')) {
            $tlsAnalysis = TLSFingerprint::analyze();
            
            // APENAS penaliza se detectou bot CONHECIDO (cURL, Python, etc)
            if (!empty($tlsAnalysis['details']['bot_match'])) {
                $isBot = true;
                $blockReason = 'Bot conhecido detectado: ' . $tlsAnalysis['details']['bot_match'];
                $riskScore = 100;
            }
            
            // Registra flags apenas para log (sem penalidade)
            foreach ($tlsAnalysis['flags'] as $flag) {
                $riskFactors[] = 'tls_' . $flag;
            }
        }
        
        // ========== CAMADA 4.5: MACHINE LEARNING ==========
        // Usa ML para classificar baseado em padroes aprendidos
        $mlEnabled = $campaign['ml_enabled'] ?? true; // Ativado por padrao
        $mlResult = ['score' => 50, 'classification' => 'unknown', 'flags' => []];
        if (!$isBot && !$isWhitelisted && $mlEnabled && class_exists('MLBotDetector')) {
            // Prepara dados para ML
            $mlData = [
                'is_mobile' => $this->isMobileDevice($visitorUA),
                'has_touch' => !empty($clientData['touch_support']),
                'screen_width' => intval($clientData['screen_width'] ?? 0),
                'screen_height' => intval($clientData['screen_height'] ?? 0),
                'plugins_count' => intval($clientData['plugins_count'] ?? 0),
                'languages_count' => count(explode(',', $clientData['languages'] ?? '')),
                'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
                'header_count' => count($_SERVER),
                'behavioral_score' => intval($clientData['advanced_bot_score'] ?? 50),
                'tls_score' => $tlsAnalysis['score'] ?? 100,
                'advanced_bot_score' => intval($clientData['emulator_score'] ?? 0),
                'time_on_page' => 0
            ];
            
            $mlResult = MLBotDetector::classify($mlData);
            
            // Se ML classifica como bot com alta confianca
            if ($mlResult['classification'] === 'bot' && $mlResult['score'] < 30) {
                $isBot = true;
                $blockReason = 'ML detectou padrao de bot (score: ' . $mlResult['score'] . ')';
                $riskScore = 100 - $mlResult['score'];
            }
            
            // Registra flags do ML
            foreach ($mlResult['flags'] as $flag) {
                $riskFactors[] = 'ml_' . $flag;
            }
        }
        
        // ========== CAMADA 5: ANALISE SIMPLES (apenas bots REAIS) ==========
        // SIMPLIFICADO: Apenas detecta bots CONFIRMADOS, sem penalidades por headers
        if (!$isBot && !$isWhitelisted && $hasAdsParams) {
            
            // 5.1 - WebDriver detectado = BOT CONFIRMADO
            if (!empty($clientData['webdriver']) && $clientData['webdriver'] !== 'false' && $clientData['webdriver'] !== '0') {
                $isBot = true;
                $blockReason = 'WebDriver detectado (Selenium/Puppeteer)';
                $riskScore = 100;
            }
            
            // 5.2 - IP de datacenter = BOT CONFIRMADO
            elseif (function_exists('isDatacenterIP') && isDatacenterIP($visitorIP)) {
                $isBot = true;
                $blockReason = 'IP de datacenter';
                $riskScore = 100;
            }
            
            // 5.3 - EMULADOR DETECTADO (via fingerprinting)
            elseif (!empty($clientData['emulator_score']) && intval($clientData['emulator_score']) >= 40) {
                $isBot = true;
                $emulatorFlags = $clientData['advanced_bot_flags'] ?? '';
                $blockReason = 'Emulador detectado (score: ' . $clientData['emulator_score'] . ', flags: ' . $emulatorFlags . ')';
                $riskScore = 100;
            }
            
            // 5.4 - WebGL com software renderer (emulador)
            elseif (!empty($clientData['webgl_fp'])) {
                $webglFP = strtolower($clientData['webgl_fp']);
                if (strpos($webglFP, 'swiftshader') !== false || 
                    strpos($webglFP, 'llvmpipe') !== false || 
                    strpos($webglFP, 'virtualbox') !== false ||
                    strpos($webglFP, 'vmware') !== false) {
                    $isBot = true;
                    $blockReason = 'Software renderer detectado: ' . $clientData['webgl_fp'];
                    $riskScore = 100;
                }
            }
            
            // 5.5 - Canvas fingerprint vazio ou erro
            elseif (!empty($clientData['canvas_fp']) && ($clientData['canvas_fp'] === 'err' || $clientData['canvas_fp'] === '0')) {
                $isBot = true;
                $blockReason = 'Canvas fingerprint invalido (emulador ou headless)';
                $riskScore = 100;
            }
            
            // 5.6 - User-Agent mobile mas sem touch = SUSPEITO (mas nao bloqueia)
            $isMobileUA = preg_match('/Mobile|Android|iPhone|iPad/i', $visitorUA);
            if (!$isBot && $isMobileUA && empty($clientData['touch_support'])) {
                // Apenas registra, nao bloqueia
                $riskFactors[] = 'UA mobile sem touch (monitorando)';
            }
            
            // Se nao foi detectado como bot, PASSA
            if (!$isBot) {
                $blockReason = '[PASSOU] Score: ' . $riskScore;
            }
        }
        
        // ========== CAMADA 5: ACESSO DIRETO (SEM UTMs) ==========
        // IMPORTANTE: so aplica "sem UTMs" quando REALMENTE nao ha UTMs E o
        // visitante ainda nao foi classificado. Antes, este else rodava para
        // QUALQUER visitante ja marcado como bot em camadas anteriores e
        // sobrescrevia o motivo real com "sem UTMs" — mascarando a causa real
        // (ex.: bot aprendido, desktop) e ainda quebrava a whitelist.
        elseif (!$isBot && !$isWhitelisted && !$hasAdsParams) {
            // SEM UTMs = SEMPRE vai para WHITE (pode ser revisor)
            // Apenas trafego com UTMs vai para BLACK
            $isBot = true;
            $blockReason = 'Acesso sem UTMs - enviado para WHITE';
            $riskScore = 100;
        }
        
        // =====================================================
        // FINGERPRINT VELOCITY: anti-farm / bots "humanos"
        // =====================================================
        // Pega o tipo de trafego que engana as camadas anteriores: IPs
        // residenciais legitimos (indistinguiveis por IP), score de emulador
        // baixo, mas que na verdade sao uma farm reusando a MESMA imagem de
        // device. Assinatura: um unico fingerprint (canvas+webgl+audio+tela+
        // timezone) aparecendo em muitas REDES distintas em pouco tempo.
        // Humano real tem fingerprint diverso e fica em 1 rede -> nao dispara.
        // Ao detectar farm, o IP vai para force-white permanente.
        // =====================================================
        if (!$isBot && !$isWhitelisted && $hasAdsParams
            && defined('FP_VELOCITY_ENABLED') && FP_VELOCITY_ENABLED
            && function_exists('buildDeviceFingerprint')) {
            $fpData = [
                'canvas_fp'     => $this->requestData['canvas_fp'] ?? '',
                'webgl_fp'      => $this->requestData['webgl_fp'] ?? '',
                'audio_fp'      => $this->requestData['audio_fp'] ?? '',
                'screen_width'  => $clientData['screen_width'] ?? 0,
                'screen_height' => $clientData['screen_height'] ?? 0,
                'timezone'      => $clientData['timezone'] ?? '',
                'platform'      => $clientData['platform'] ?? ''
            ];
            $fpHash = buildDeviceFingerprint($fpData);
            if ($fpHash !== '') {
                $fpNets = fpTrackAndCountNetworks($fpHash, $visitorIP);
                $fpMax = defined('FP_VELOCITY_MAX_NETS') ? FP_VELOCITY_MAX_NETS : 4;
                if ($fpNets >= $fpMax) {
                    // Farm confirmada: bloqueia e marca o IP permanentemente
                    if (function_exists('freqBlockForever')) {
                        freqBlockForever($visitorIP);
                    }
                    $isBot = true;
                    $riskScore = 100;
                    $blockReason = "Fingerprint farm: mesmo device em {$fpNets} redes distintas (limite {$fpMax}) -> force-white";
                    $this->logBotAccess($visitorIP, $visitorUA, $blockReason, $campaignId, $utmSource, $platform);
                }
            }
        }

        // =====================================================
        // DIVISAO DE TRAFEGO (Traffic Split) - APLICADA AO HUMANO REAL
        // =====================================================
        // Posicionada DEPOIS de toda a deteccao: so afeta visitantes que
        // passariam para a BLACK (isBot=false, humano real). Uma % configuravel
        // deles e desviada para a White Page; o restante segue para a oferta.
        // Assim a divisao e observavel e nao e mascarada pelas regras de
        // desktop / sem-UTM que rodam antes. Whitelist (Admin/Teste) e ignorada.
        // =====================================================
        $trafficSplit = $campaign['traffic_split'] ?? '0';
        $trafficSplitEnabled = in_array($trafficSplit, ['1', 1, true], true);
        if (!$isBot && !$isWhitelisted && $trafficSplitEnabled) {
            $splitPercent = (int)($campaign['traffic_split_percent'] ?? 20);
            $splitPercent = max(1, min(100, $splitPercent));
            // random_int(1,100) <= X%  =>  X% dos humanos vao para a White Page
            if (random_int(1, 100) <= $splitPercent) {
                // Roteia para WHITE reaproveitando todo o fluxo abaixo
                // (metricas, log e montagem da resposta ja tratam isBot=true).
                $isBot = true;
                $riskScore = 100;
                $blockReason = "Divisao de trafego: {$splitPercent}% -> White Page";
            }
        }

        // =====================================================
        // FREQUENCY CAP: limite de visualizacoes da BLACK por visitante
        // =====================================================
        // So chega aqui quem passaria para a BLACK (isBot=false). Whitelist
        // (Admin/Teste) e sempre ignorada. Duas verificacoes:
        //   1) Se o IP ja esta bloqueado PERMANENTEMENTE (passou do limite
        //      em algum momento), vai direto para a White Page.
        //   2) Se acabou de estourar FREQ_CAP_MAX visualizacoes na janela,
        //      e bloqueado para sempre AGORA e desviado para a White.
        // Acessos reais saturam em FREQ_CAP_MAX; bots insistem alem disso.
        // =====================================================
        if (!$isBot && !$isWhitelisted && defined('FREQ_CAP_ENABLED') && FREQ_CAP_ENABLED
            && function_exists('freqIsBlocked')) {
            if (freqIsBlocked($visitorIP)) {
                // Bloqueio permanente ja existente -> force white
                $isBot = true;
                $riskScore = 100;
                $blockReason = "Frequency cap: IP bloqueado permanentemente (force white) -> White Page";
            } else {
                $freqViews = freqCountBlackViews($visitorIP);
                if ($freqViews >= FREQ_CAP_MAX) {
                    // Passou do limite: marca como force-white PARA SEMPRE
                    freqBlockForever($visitorIP);
                    $isBot = true;
                    $riskScore = 100;
                    $blockReason = "Frequency cap: {$freqViews} acessos a BLACK (limite " . FREQ_CAP_MAX . ") -> bloqueado permanentemente";
                }
            }
        }

        // ========== REGISTRO E METRICAS ==========
        $advancedData = [
            'risk_score' => $riskScore,
            'risk_factors' => $riskFactors,
            'client_data' => $clientData,
            'has_ads_params' => $hasAdsParams
        ];
        
        // Registra clique por hora
        recordHourlyClick($isBot);
        
        // Registra estatísticas
        $campaignId = $campaign['id'] ?? 'unknown';
        recordClick($campaignId, $isBot, $platform);
        
        // Log SEMPRE para debug (mesmo passes)
        logBot([
            'ip' => $visitorIP,
            'user_agent' => substr($visitorUA, 0, 500),
            'reason' => $isBot ? $blockReason : '[PASSOU] Score: ' . $riskScore,
            'campaign' => $campaignSlug,
            'campaign_id' => $campaignId,
            'platform' => $platform,
            'referer' => substr($referer, 0, 200)
        ]);
        
        // Log de bot se bloqueado
        if ($isBot) {
            
            // Adiciona IP à blacklist automaticamente se for padrão conhecido de bot
            if (in_array($blockReason, ['User-Agent de bot', 'Headless browser'])) {
                blockIP($visitorIP, $blockReason);
            }
        }
        
// Determina URLs de destino
        $whiteUrl = $campaign['white_url'] ?? '';
        $blackUrl = $campaign['black_url'] ?? '';
        
        // V10.4 - Rotacao de URLs (A/B Testing)
        if (!$isBot && URL_ROTATION_ENABLED && !empty($campaign['black_urls'])) {
            $blackUrls = $campaign['black_urls'];
            if (is_array($blackUrls) && count($blackUrls) > 1) {
                $selectedUrl = selectRotatedUrl($campaign['id'], $blackUrls);
                $urlIndex = array_search($selectedUrl, $blackUrls);
                $blackUrl = $selectedUrl;
                recordRotatedUrlClick($campaign['id'], $urlIndex);
            }
        }
        
        // V10.4 - Verifica pausa automatica
        if (!$isBot) {
            checkAutoPause($campaign['id'] ?? 'unknown');
        }
        
        // V10.4 - Verifica alerta de taxa de bloqueio
        checkAndAlertBlockRate();
        
        // BYPASS PARA TESTES: ?force_black=1 ou force_black no JSON forca exibir BLACK
        // REMOVA ISSO EM PRODUCAO!
        $forceBlackFromJson = isset($data['force_black']) && ($data['force_black'] === '1' || $data['force_black'] === 1 || $data['force_black'] === true);
        if (isset($_GET['force_black']) || isset($_POST['force_black']) || $forceBlackFromJson) {
            $isBot = false;
            $blockReason = '[BYPASS] force_black=1 ativo';
        }
        
        // =====================================================
        // DETECCAO DE ABUSO -> DESAFIO (Cloudflare Turnstile)
        // =====================================================
        // Quando um visitante REAL (iria para a BLACK) apresenta comportamento
        // anormal, em vez de liberar direto exibimos um desafio interativo.
        // So depois de resolver o desafio ele e direcionado para a oferta.
        // Controlado por campanha via 'abuse_challenge_enabled'.
        $challengePassValue = ''; // passe assinado devolvido ao tracker quando resolvido
        $challengeEnabled = in_array(($campaign['abuse_challenge_enabled'] ?? '0'), ['1', 1, true], true);
        $tsSiteKey   = trim($campaign['turnstile_site_key'] ?? '');
        $tsSecretKey = trim($campaign['turnstile_secret_key'] ?? '');

        if (!$isBot && !$isWhitelisted && $hasAdsParams && $challengeEnabled && $tsSiteKey !== '' && $tsSecretKey !== '') {
            // 1) Ja possui um passe valido (resolveu o desafio ha pouco)?
            $challengePass = $this->requestData['challenge_pass'] ?? '';
            $hasValidPass  = function_exists('verifyChallengePass') && verifyChallengePass($challengePass, $visitorIP);

            // 2) Acabou de resolver o Turnstile agora? (token no request)
            if (!$hasValidPass) {
                $tsToken = $this->requestData['cf_turnstile_response'] ?? '';
                if ($tsToken !== '' && function_exists('verifyTurnstile')) {
                    $tsResult = verifyTurnstile($tsToken, $tsSecretKey, $visitorIP);

                    // Falha de REDE no servidor (VPS nao conseguiu falar com a
                    // Cloudflare: erro de SSL/CA, timeout, etc.) NAO pode punir um
                    // humano que comprovadamente resolveu o widget no navegador.
                    // Nesse caso aceitamos o solve para nao mandar o humano para a
                    // white indevidamente. So uma rejeicao EXPLICITA da Cloudflare
                    // (success=false com resposta valida) mantem o visitante barrado.
                    $networkError = in_array(($tsResult['error'] ?? ''), ['request_failed', 'missing_params'], true);

                    if (!empty($tsResult['success']) || $networkError) {
                        $hasValidPass = true;
                        // Emite passe curto para nao desafiar de novo nas proximas etapas
                        if (function_exists('makeChallengePass')) {
                            $challengePassValue = makeChallengePass($visitorIP);
                        }
                        $motivo = !empty($tsResult['success'])
                            ? 'Desafio Turnstile resolvido -> liberado'
                            : 'Desafio Turnstile: verificacao offline (rede) -> liberado';
                        $this->logBotAccess($visitorIP, $visitorUA, $motivo, $campaignId, $utmSource, $platform);
                    }
                }
            }

            // 3) Sem passe valido: avalia se o comportamento e anormal
            if (!$hasValidPass) {
                $abuseSuspicious = false;
                $abuseReasons = [];

                // (a) Flood: muitas requisicoes recentes do mesmo IP,
                //     abaixo do bloqueio rigido de rate limit
                $softLimit = defined('ABUSE_SOFT_REQUESTS') ? ABUSE_SOFT_REQUESTS : 25;
                if (method_exists($this->security, 'getRecentRequestCount')) {
                    $recentCount = $this->security->getRecentRequestCount($visitorIP);
                    if ($recentCount >= $softLimit) {
                        $abuseSuspicious = true;
                        $abuseReasons[] = 'flood(' . $recentCount . ')';
                    }
                }

                // (b) Score comportamental limitrofe (ML incerto - zona cinzenta)
                if (($mlResult['classification'] ?? '') === 'uncertain') {
                    $abuseSuspicious = true;
                    $abuseReasons[] = 'ml_uncertain(' . ($mlResult['score'] ?? 0) . ')';
                }

                // (c) Multiplas flags leves de automacao acumuladas
                if (count($riskFactors) >= 2) {
                    $abuseSuspicious = true;
                    $abuseReasons[] = 'risk_factors(' . count($riskFactors) . ')';
                }

                // (d) Amostragem por porcentagem: uma % configuravel dos humanos
                //     que passariam recebe o desafio mesmo SEM sinal de abuso.
                //     Ex.: challenge_percent = 30  =>  30% dos humanos sao desafiados.
                $challengePercent = (int)($campaign['challenge_percent'] ?? 0);
                $challengePercent = max(0, min(100, $challengePercent));
                if (!$abuseSuspicious && $challengePercent > 0 && random_int(1, 100) <= $challengePercent) {
                    $abuseSuspicious = true;
                    $abuseReasons[] = 'amostragem(' . $challengePercent . '%)';
                }

                if ($abuseSuspicious) {
                    $this->logBotAccess(
                        $visitorIP,
                        $visitorUA,
                        'Comportamento anormal -> Desafio Turnstile [' . implode(', ', $abuseReasons) . ']',
                        $campaignId,
                        $utmSource,
                        $platform
                    );
                    $this->respond([
                        'status' => 'success',
                        'action' => 'challenge',
                        'site_key' => $tsSiteKey,
                        'challenge_mode' => (($campaign['challenge_mode'] ?? 'managed') === 'visible') ? 'visible' : 'managed',
                        'timestamp' => $timestamp,
                        'request_id' => bin2hex(random_bytes(8))
                    ]);
                }
            }
        }

        // Monta resposta
        // isBot = true  → visitante é bot/revisor → manda para WHITE (página segura)
        // isBot = false → visitante é humano real  → manda para BLACK (oferta real)
        $response = [
            'status' => 'success',
            'action' => $isBot ? 'white' : 'black',
            'blocked' => $isBot,
            'timestamp' => $timestamp,
            'request_id' => bin2hex(random_bytes(8))
        ];

        // Passe assinado devolvido ao tracker apos resolver o desafio: evita
        // novo captcha nas etapas seguintes (pre-checagem JS / navegacao).
        if ($challengePassValue !== '') {
            $response['challenge_pass'] = $challengePassValue;
        }
        
        // URLs da campanha
        $whiteUrl = $campaign['white_url'] ?? '';
        $blackUrl = $campaign['black_url'] ?? '';
        
        // Adiciona URLs de destino - OBRIGATÓRIO ter a URL na resposta
        if ($isBot) {
            // Bot → white page (página segura/homepagem)
            $whiteMethod = $campaign['white_method'] ?? 'redirect';
            $response['redirect'] = $whiteUrl;
            $response['url'] = $whiteUrl;
            $response['method'] = $whiteMethod;
            
            // Se for proxy, fornece URL do proxy centralizado do COMMANDER
            if ($whiteMethod === 'proxy' && !empty($whiteUrl)) {
                $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
                $commanderHost = $protocol . '://' . $_SERVER['HTTP_HOST'];
                $commanderPath = dirname($_SERVER['SCRIPT_NAME']);
                $proxyUrl = $commanderHost . $commanderPath . '/api.php?action=proxy&url=' . urlencode($whiteUrl);
                $response['proxy_url'] = $proxyUrl;
            }
            
            // SEMPRE loga quando vai para white (para debug)
            $this->logBotAccess($visitorIP, $visitorUA, $blockReason, $campaignId, $utmSource, $platform);
        } else {
            // FREQUENCY CAP: contabiliza esta visualizacao da BLACK. Quando o
            // visitante estourar FREQ_CAP_MAX, a camada de checagem acima
            // passara a desvia-lo para a White Page nos proximos acessos.
            if (defined('FREQ_CAP_ENABLED') && FREQ_CAP_ENABLED && function_exists('freqRecordBlackView')) {
                freqRecordBlackView($visitorIP);
            }
            // Humano → black page (oferta real) com UTMs preservados
            $finalBlackUrl = $blackUrl ?? '';
            if (!empty($finalBlackUrl) && !empty($utmSource)) {
                $finalBlackUrl = $this->appendUtmsToUrl($finalBlackUrl, [
                    'utm_source' => $utmSource,
                    'utm_medium' => $utmMedium,
                    'utm_campaign' => $utmCampaign,
                    'utm_content' => $utmContent,
                    'utm_term' => $utmTerm
                ]);
            }
            
            $blackMethod = $campaign['black_method'] ?? 'redirect';
            $response['redirect'] = $finalBlackUrl;
            $response['url'] = $finalBlackUrl;
            $response['method'] = $blackMethod;
            
            // Se for proxy, fornece URL do proxy centralizado do COMMANDER
            if ($blackMethod === 'proxy') {
                $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
                $commanderHost = $protocol . '://' . $_SERVER['HTTP_HOST'];
                $commanderPath = dirname($_SERVER['SCRIPT_NAME']);
                $proxyUrl = $commanderHost . $commanderPath . '/api.php?action=proxy&url=' . urlencode($finalBlackUrl);
                $response['proxy_url'] = $proxyUrl;
            }
            
            // Se for iframe (stealth), fornece URL com white e black
            // Bot ve HTML da white, humano ve black via Shadow DOM
            if ($blackMethod === 'iframe') {
                $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
                $commanderHost = $protocol . '://' . $_SERVER['HTTP_HOST'];
                $commanderPath = dirname($_SERVER['SCRIPT_NAME']);
                $iframeUrl = $commanderHost . $commanderPath . '/api.php?action=iframe'
                           . '&white=' . urlencode($whiteUrl)
                           . '&black=' . urlencode($finalBlackUrl);
                $response['iframe_url'] = $iframeUrl;
            }

            // Registra TAMBEM os visitantes reais (BLACK) nos Logs de Bots,
            // para ter a analise completa de TODOS os acessos, com ou sem
            // limite de cliques de aquecimento.
            $this->logBotAccess($visitorIP, $visitorUA, 'Visitante real -> BLACK (oferta)', $campaignId, $utmSource, $platform);
        }
        
        // Adiciona informações extras em modo debug
        if (DEBUG_MODE) {
            $response['debug'] = [
                'visitor_ip' => $visitorIP,
                'is_bot' => $isBot,
                'reason' => $blockReason,
                'platform' => $platform,
                'campaign' => $campaignSlug
            ];
        }
        
        $this->respond($response);
    }
    
    /**
     * Registra conversão
     */
    private function registerConversion() {
        $campaignSlug = $this->sanitize($this->requestData['campaign'] ?? '');
        $value = (float) ($this->requestData['value'] ?? 0);
        $type = $this->sanitize($this->requestData['type'] ?? 'sale');
        $transactionId = $this->sanitize($this->requestData['transaction_id'] ?? '');
        
        if (empty($campaignSlug)) {
            $this->respond(['error' => 'Campaign required'], 400);
        }
        
        $campaign = getCampaignBySlug($campaignSlug);
        if (!$campaign) {
            $this->respond(['error' => 'Campaign not found'], 404);
        }
        
        recordConversion($campaign['id'], $value, $type);
        
        $this->respond([
            'status' => 'success',
            'message' => 'Conversion registered',
            'campaign' => $campaignSlug,
            'value' => $value,
            'type' => $type
        ]);
    }
    
    /**
     * Endpoint para pixel de tracking
     */
    private function handlePixel() {
        // Retorna imagem 1x1 transparente
        header('Content-Type: image/gif');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        
        // GIF 1x1 transparente
        echo base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
        exit;
    }
    
/**
     * Health check
     */
    private function healthCheck() {
        $this->respond([
            'status' => 'ok',
            'version' => COMMANDER_VERSION,
            'timestamp' => time()
        ]);
    }
    
    // ============================================
    // V10.4 - NOVOS METODOS
    // ============================================
    
    /**
     * Gera JS Challenge token
     */
    private function getJSChallenge() {
        $challenge = $this->security->generateJSChallengeToken();
        $this->respond([
            'status' => 'success',
            'challenge' => $challenge
        ]);
    }
    
    /**
     * Retorna dados para graficos
     */
    private function getChartData() {
        $type = $this->sanitize($this->requestData['type'] ?? 'all');
        
        $data = [];
        
        switch ($type) {
            case 'daily':
                $data = getChartDataByDay(CHARTS_DAYS_HISTORY);
                break;
            case 'hourly':
                $data = getChartDataByHour();
                break;
            case 'bot_vs_human':
                $data = getChartDataBotVsHuman();
                break;
            case 'platform':
                $data = getChartDataByPlatform();
                break;
            case 'heatmap':
                $data = getHeatmapData();
                break;
            case 'all':
            default:
                $data = [
                    'daily' => getChartDataByDay(CHARTS_DAYS_HISTORY),
                    'hourly' => getChartDataByHour(),
                    'bot_vs_human' => getChartDataBotVsHuman(),
                    'platform' => getChartDataByPlatform(),
                    'heatmap' => getHeatmapData()
                ];
        }
        
        $this->respond([
            'status' => 'success',
            'data' => $data
        ]);
    }
    
    /**
     * Retorna resumo do dashboard
     */
    private function getDashboardData() {
        $summary = getDashboardSummary();
        $this->respond([
            'status' => 'success',
            'data' => $summary
        ]);
    }
    
    /**
     * Testa webhook
     */
    private function testWebhook() {
        $type = $this->sanitize($this->requestData['type'] ?? 'telegram');
        $message = "Teste de webhook COMMANDER V10.4\nData: " . date('d/m/Y H:i:s');
        
        $result = false;
        
        if ($type === 'telegram') {
            $result = sendTelegramNotification($message);
        } elseif ($type === 'discord') {
            $result = sendDiscordNotification($message, 'Teste de Webhook');
        }
        
        $this->respond([
            'status' => $result ? 'success' : 'error',
            'message' => $result ? 'Webhook enviado com sucesso' : 'Falha ao enviar webhook'
        ]);
    }
    
    /**
     * V10.5 - Atualiza dados comportamentais do visitante
     */
    private function updateBehaviorData() {
        $visitorId = $this->sanitize($this->requestData['visitor_id'] ?? '');
        $campaignId = $this->sanitize($this->requestData['campaign'] ?? 'unknown');
        
        if (empty($visitorId)) {
            $this->respond(['error' => 'visitor_id required'], 400);
            return;
        }
        
        $behaviorData = [
            'scrolls' => (int)($this->requestData['scrolls'] ?? 0),
            'mouse_moves' => (int)($this->requestData['mouse_moves'] ?? 0),
            'time_on_page' => (int)($this->requestData['time_on_page'] ?? 0),
            'fingerprint' => $this->sanitize($this->requestData['fingerprint'] ?? ''),
            'has_mouse' => (bool)($this->requestData['has_mouse'] ?? false),
            'has_touch' => (bool)($this->requestData['has_touch'] ?? false),
            'webdriver' => (bool)($this->requestData['webdriver'] ?? false),
            'timezone' => $this->sanitize($this->requestData['timezone'] ?? ''),
            'plugins' => (int)($this->requestData['plugins'] ?? 0),
            'canvas_hash' => $this->sanitize($this->requestData['canvas_hash'] ?? '')
        ];
        
        // Atualiza dados comportamentais na funcao V10.5
        updateBehavioralData($visitorId, $campaignId, $behaviorData);
        
        // Coleta fingerprint de revisores suspeitos
        if (COLLECT_REVIEWER_FP && !empty($behaviorData['fingerprint'])) {
            collectReviewerFingerprint($behaviorData['fingerprint'], $behaviorData);
        }
        
        $this->respond([
            'status' => 'ok',
            'visitor_id' => $visitorId,
            'gate_status' => checkBehavioralGate($visitorId, $campaignId)
        ]);
    }
    
    /**
     * Verifica referer suspeito
     */
    private function isSuspiciousReferer($referer) {
        if (empty($referer)) {
            return false;
        }
        
        $suspicious = [
            'semrush.com', 'ahrefs.com', 'moz.com', 'majestic.com',
            'similarweb.com', 'spyfu.com', 'searchmetrics.com'
        ];
        
        $refererLower = strtolower($referer);
        foreach ($suspicious as $pattern) {
            if (strpos($refererLower, $pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Verifica se é headless browser
     */
    private function isHeadlessBrowser($userAgent) {
        $headlessIndicators = [
            'headless', 'phantomjs', 'nightmare', 'selenium',
            'webdriver', 'puppeteer', 'playwright', 'cypress'
        ];
        
        $uaLower = strtolower($userAgent);
        foreach ($headlessIndicators as $indicator) {
            if (strpos($uaLower, $indicator) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Verifica se IP é de datacenter conhecido
     */
    private function isDatacenterIP($ip) {
        // Ranges de datacenters conhecidos (simplificado)
        $datacenterRanges = [
            '34.0.0.0/8',      // Google Cloud
            '35.0.0.0/8',      // Google Cloud
            '52.0.0.0/8',      // AWS
            '54.0.0.0/8',      // AWS
            '13.0.0.0/8',      // AWS/Azure
            '20.0.0.0/8',      // Azure
            '40.0.0.0/8',      // Azure
            '104.0.0.0/8',     // Azure/Cloudflare
            '157.0.0.0/8',     // Azure
            '199.0.0.0/8',     // DigitalOcean
            '159.65.0.0/16',   // DigitalOcean
            '167.99.0.0/16',   // DigitalOcean
            '206.189.0.0/16',  // DigitalOcean
        ];
        
        foreach ($datacenterRanges as $range) {
            if (ipInRange($ip, $range)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Loga acesso de bot e adiciona à lista de aprendidos
     */
    private function logBotAccess($ip, $userAgent, $reason, $campaignId = '', $utmSource = '', $platform = '') {
        // ==========================================================
        // DETALHES RICOS DO ACESSO (para analise de padroes)
        // Puxa os sinais que o cliente enviou em $this->requestData e grava
        // junto de cada acesso. Serve para diferenciar humano real de bot
        // "humano" ao revisar os logs depois. Vale para bots e humanos.
        // ==========================================================
        $rd = is_array($this->requestData) ? $this->requestData : [];

        $sw = (int)($rd['screen_width'] ?? 0);
        $sh = (int)($rd['screen_height'] ?? 0);

        // Fingerprint combinado do device (mesmo criterio da regra anti-farm).
        // Guardamos so um hash curto para comparar linhas sem inchar o arquivo.
        $fpHash = '';
        if (function_exists('buildDeviceFingerprint')) {
            $fpFull = buildDeviceFingerprint([
                'canvas_fp'     => $rd['canvas_fp'] ?? '',
                'webgl_fp'      => $rd['webgl_fp'] ?? '',
                'audio_fp'      => $rd['audio_fp'] ?? '',
                'screen_width'  => $sw,
                'screen_height' => $sh,
                'timezone'      => $rd['timezone'] ?? '',
                'platform'      => $rd['platform'] ?? ''
            ]);
            $fpHash = $fpFull !== '' ? substr($fpFull, 0, 12) : '';
        }

        $shortHash = function($v) {
            $v = trim((string)$v);
            if ($v === '' || stripos($v, 'err') !== false) return '';
            return substr(md5($v), 0, 8);
        };

        $details = [
            // Ambiente / device
            'screen'          => ($sw && $sh) ? ($sw . 'x' . $sh) : '',
            'timezone'        => (string)($rd['timezone'] ?? ''),
            'languages'       => substr((string)($rd['languages'] ?? ($rd['client_languages'] ?? '')), 0, 60),
            'platform_js'     => (string)($rd['platform'] ?? ''),
            'country'         => strtoupper((string)($rd['country'] ?? ($rd['client_country'] ?? ''))),
            // Sinais de automacao
            'webdriver'       => !empty($rd['webdriver']) && $rd['webdriver'] !== 'false' ? 1 : 0,
            'plugins_count'   => isset($rd['plugins_count']) ? (int)$rd['plugins_count'] : -1,
            'touch_support'   => !empty($rd['touch_support']) && $rd['touch_support'] !== 'false' ? 1 : 0,
            'bot_score'       => isset($rd['advanced_bot_score']) ? (int)$rd['advanced_bot_score'] : -1,
            'emulator_score'  => isset($rd['emulator_score']) ? (int)$rd['emulator_score'] : -1,
            'bot_flags'       => substr((string)($rd['advanced_bot_flags'] ?? ''), 0, 120),
            // Fingerprints (hash curto para comparar entre linhas)
            'fp_device'       => $fpHash,
            'fp_canvas'       => $shortHash($rd['canvas_fp'] ?? ''),
            'fp_webgl'        => $shortHash($rd['webgl_fp'] ?? ''),
            'fp_audio'        => $shortHash($rd['audio_fp'] ?? ''),
            // Origem
            'referer'         => substr((string)($rd['referer'] ?? ''), 0, 120)
        ];

        // Registra no log de bots
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $ip,
            'ua' => substr($userAgent, 0, 200),
            'reason' => $reason,
            'campaign_id' => $campaignId,
            'utm_source' => $utmSource,
            'platform' => $platform,
            'details' => $details
        ];
        
        // Mostra ate 2.000 registros nos Logs de Bots. Ao atingir 2.000, o
        // arquivo e apagado sozinho e recomeca do zero, evitando sobrecarregar a VPS.
        appendCappedResetJsonFile(DATA_DIR . 'bot_logs.json', $logEntry, 2000);
        
        // Adiciona à lista de bots aprendidos (global)
        // Só "aprende" quando foi um bot REALMENTE confirmado. NUNCA aprende em
        // situacoes de roteamento suave (desktop), aquecimento, pais, sem UTMs,
        // divisao de trafego, nem em visitantes reais (BLACK).
        // IMPORTANTE: "Desktop detectado" NAO e bot — antes ele poluia a lista e
        // fazia o MESMO IP ser bloqueado depois no celular (falso positivo).
        if (strpos($reason, 'Aquecimento') === false && 
            strpos($reason, 'Pais bloqueado') === false &&
            strpos($reason, 'sem UTMs') === false &&
            strpos($reason, 'Desktop detectado') === false &&
            strpos($reason, 'Divisao de trafego') === false &&
            strpos($reason, 'Horario de pausa') === false &&
            strpos($reason, 'Desafio Turnstile') === false &&
            strpos($reason, 'Visitante real') === false &&
            strpos($reason, 'BLACK') === false) {
            addLearnedBot($ip, $userAgent, $reason, $campaignId);
        }
        
        return true;
    }

    /**
     * Adiciona UTMs à URL
     */
    private function appendUtmsToUrl($url, $utms) {
        $utms = array_filter($utms);
        
        if (empty($utms)) {
            return $url;
        }
        
        $separator = (strpos($url, '?') !== false) ? '&' : '?';
        return $url . $separator . http_build_query($utms);
    }
    
    /**
     * Obtém dados da requisição
     */
    private function getRequestData() {
        $data = [];
        
        // GET params
        $data = array_merge($data, $_GET);
        
        // POST params
        $data = array_merge($data, $_POST);
        
        // JSON body
        $rawBody = file_get_contents('php://input');
        if (!empty($rawBody)) {
            $jsonData = json_decode($rawBody, true);
            if (is_array($jsonData)) {
                $data = array_merge($data, $jsonData);
            }
        }
        
        return $data;
    }
    
    /**
     * Sanitiza entrada
     */
    private function sanitize($value, $type = 'string') {
        if ($value === null) {
            return '';
        }
        
        // Remove null bytes
        $value = str_replace("\0", '', $value);
        
        switch ($type) {
            case 'ip':
                // Valida e sanitiza IP (v4 ou v6)
                $value = trim($value);
                if (filter_var($value, FILTER_VALIDATE_IP)) {
                    return $value;
                }
                // Tenta extrair IP de formatos como "ip, proxy_ip"
                if (strpos($value, ',') !== false) {
                    $parts = explode(',', $value);
                    $value = trim($parts[0]);
                    if (filter_var($value, FILTER_VALIDATE_IP)) {
                        return $value;
                    }
                }
                return '';
                
            case 'slug':
                // Apenas alfanumericos, hifen e underscore
                return preg_replace('/[^a-zA-Z0-9_-]/', '', $value);
                
            case 'url':
                // Valida URL
                $value = filter_var($value, FILTER_SANITIZE_URL);
                if (filter_var($value, FILTER_VALIDATE_URL)) {
                    return $value;
                }
                return '';
                
            case 'int':
                return (int) $value;
                
            case 'float':
                return (float) $value;
                
            case 'bool':
                return filter_var($value, FILTER_VALIDATE_BOOLEAN);
                
            case 'email':
                return filter_var($value, FILTER_SANITIZE_EMAIL);
                
            case 'string':
            default:
                // Remove tags HTML e limita tamanho
                $value = strip_tags($value);
                $value = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
                // Limita a 1000 caracteres por padrao
                return mb_substr($value, 0, 1000);
        }
    }
    
    /**
     * Valida dados de entrada com regras especificas
     */
    private function validateInput($data, $rules) {
        $errors = [];
        
        foreach ($rules as $field => $rule) {
            $value = $data[$field] ?? null;
            
            // Campo obrigatorio
            if (isset($rule['required']) && $rule['required'] && empty($value)) {
                $errors[$field] = 'Campo obrigatorio';
                continue;
            }
            
            // Tamanho minimo
            if (isset($rule['min_length']) && strlen($value) < $rule['min_length']) {
                $errors[$field] = 'Minimo ' . $rule['min_length'] . ' caracteres';
            }
            
            // Tamanho maximo
            if (isset($rule['max_length']) && strlen($value) > $rule['max_length']) {
                $errors[$field] = 'Maximo ' . $rule['max_length'] . ' caracteres';
            }
            
            // Regex pattern
            if (isset($rule['pattern']) && !preg_match($rule['pattern'], $value)) {
                $errors[$field] = $rule['pattern_message'] ?? 'Formato invalido';
            }
        }
        
        return $errors;
    }
    
    /**
     * Detecta se o dispositivo e mobile (celular/tablet)
     * IMPORTANTE: Apenas dispositivos mobile passam para BLACK
     * Desktop SEMPRE vai para WHITE (revisores usam desktop)
     */
    private function isMobileDevice($userAgent) {
        // Se MOBILE_ONLY_MODE estiver desabilitado, permite tudo
        if (defined('MOBILE_ONLY_MODE') && !MOBILE_ONLY_MODE) {
            return true; // Permite passar como se fosse mobile
        }
        
        if (empty($userAgent)) {
            return false; // Sem UA = suspeito, trata como desktop
        }
        
        // Verifica se e tablet
        $isTablet = (bool) preg_match('/iPad|Android(?!.*Mobile)|Tablet/i', $userAgent);
        
        // Se for tablet e ALLOW_TABLETS estiver desabilitado, trata como desktop
        if ($isTablet && defined('ALLOW_TABLETS') && !ALLOW_TABLETS) {
            return false;
        }
        
        // Padroes de dispositivos mobile (celulares)
        $mobilePatterns = [
            // Sistemas operacionais mobile
            '/Android.*Mobile/i',     // Android phone (nao tablet)
            '/iPhone/i',
            '/iPod/i',
            '/webOS/i',
            '/BlackBerry/i',
            '/IEMobile/i',
            '/Opera Mini/i',
            '/Opera Mobi/i',
            '/Windows Phone/i',
            '/Windows CE/i',
            '/Symbian/i',
            '/PalmOS/i',
            
            // Navegadores mobile especificos
            '/Mobile Safari/i',
            '/Chrome.*Mobile/i',
            '/Firefox.*Mobile/i',
            '/Samsung.*Browser.*Mobile/i',
            '/UCBrowser.*Mobile/i',
            '/MiuiBrowser/i',
            '/HuaweiBrowser/i',
            '/OppoBrowser/i',
            '/VivoBrowser/i',
            
            // Generico - deve ter "Mobile" explicito
            '/\bMobile\b/i'
        ];
        
        // Padroes de tablets (se permitido)
        $tabletPatterns = [
            '/iPad/i',
            '/Android(?!.*Mobile)/i',  // Android sem "Mobile" = tablet
            '/Tablet/i',
            '/PlayBook/i',
            '/Kindle/i',
            '/Silk/i'
        ];
        
        // Padroes que indicam desktop (prioridade alta)
        $desktopPatterns = [
            '/Windows NT/i',           // Windows desktop
            '/Macintosh/i',            // Mac
            '/X11.*Linux(?!.*Android)/i', // Linux desktop
            '/CrOS/i',                 // Chrome OS
        ];
        
        // Primeiro verifica se e claramente um desktop
        foreach ($desktopPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                // Excecoes: Android e Windows Phone sao mobile
                if (preg_match('/Android/i', $userAgent)) {
                    continue; // Pula, pode ser mobile
                }
                if (preg_match('/Windows Phone/i', $userAgent)) {
                    return true; // Windows Phone e mobile
                }
                return false; // E desktop
            }
        }
        
        // Verifica se e tablet (se permitido)
        if (defined('ALLOW_TABLETS') && ALLOW_TABLETS) {
            foreach ($tabletPatterns as $pattern) {
                if (preg_match($pattern, $userAgent)) {
                    return true; // Tablet permitido
                }
            }
        }
        
        // Verifica se e celular
        foreach ($mobilePatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true; // E mobile
            }
        }
        
        // Fallback: verifica screen width se disponivel
        $screenWidth = (int)($this->requestData['screen_width'] ?? 0);
        $maxMobileWidth = defined('MAX_MOBILE_SCREEN_WIDTH') ? MAX_MOBILE_SCREEN_WIDTH : 1024;
        
        if ($screenWidth > 0 && $screenWidth <= $maxMobileWidth) {
            return true; // Tela pequena = provavelmente mobile
        }
        
        // Se chegou aqui, assume desktop (mais seguro)
        return false;
    }
    
    // ==========================================
    // METODOS V11 - MACHINE LEARNING
    // ==========================================
    
    /**
     * Treina ML com exemplo de humano (chamado apos conversao)
     */
    private function mlTrainHuman() {
        $visitorData = $this->collectVisitorDataForML();
        
        $result = MLBotDetector::trainFromConversion($visitorData);
        
        $this->respond([
            'success' => $result,
            'message' => $result ? 'Modelo treinado com exemplo humano' : 'Erro ao treinar modelo'
        ]);
    }
    
    /**
     * Treina ML com exemplo de bot (chamado apos bloqueio confirmado)
     */
    private function mlTrainBot() {
        $visitorData = $this->collectVisitorDataForML();
        
        $result = MLBotDetector::trainFromBlock($visitorData);
        
        $this->respond([
            'success' => $result,
            'message' => $result ? 'Modelo treinado com exemplo bot' : 'Erro ao treinar modelo'
        ]);
    }
    
    /**
     * Retorna estatisticas do modelo ML
     */
    private function mlGetStats() {
        $stats = MLBotDetector::getModelStats();
        
        $this->respond([
            'success' => true,
            'stats' => $stats
        ]);
    }
    
    /**
     * Processa dados de behavioral biometrics
     */
    private function processBiometrics() {
        $biometricsData = $this->requestData['biometrics'] ?? [];
        
        if (empty($biometricsData)) {
            $this->respond(['error' => 'No biometrics data'], 400);
        }
        
        // Extrai metricas do behavioral biometrics
        $humanScore = $biometricsData['humanProbability'] ?? 50;
        $scores = $biometricsData['scores'] ?? [];
        $flags = $biometricsData['flags'] ?? [];
        $summary = $biometricsData['summary'] ?? [];
        
        // Analisa resultados
        $analysis = [
            'human_probability' => $humanScore,
            'is_likely_human' => $humanScore >= 60,
            'is_likely_bot' => $humanScore < 40,
            'confidence' => 'medium'
        ];
        
        // Calcula confianca baseado na quantidade de dados
        $totalInteractions = ($summary['mouseMovements'] ?? 0) + 
                            ($summary['keyPresses'] ?? 0) + 
                            ($summary['touchEvents'] ?? 0);
        
        if ($totalInteractions > 100) {
            $analysis['confidence'] = 'high';
        } elseif ($totalInteractions < 20) {
            $analysis['confidence'] = 'low';
        }
        
        // Flags criticas que indicam bot
        $criticalFlags = array_filter($flags, function($flag) {
            return strpos($flag, 'mouse_velocity_inhuman') !== false ||
                   strpos($flag, 'keyboard_speed_inhuman') !== false ||
                   strpos($flag, 'no_interaction_detected') !== false ||
                   strpos($flag, 'sensor_motion_zero') !== false;
        });
        
        if (!empty($criticalFlags)) {
            $analysis['critical_flags'] = $criticalFlags;
            $analysis['is_likely_bot'] = true;
        }
        
        $this->respond([
            'success' => true,
            'analysis' => $analysis,
            'raw_score' => $humanScore,
            'flags_count' => count($flags)
        ]);
    }
    
    /**
     * Coleta dados do visitante para treinamento ML
     */
    private function collectVisitorDataForML() {
        return [
            'is_mobile' => $this->isMobileDevice($this->userAgent),
            'has_touch' => !empty($this->requestData['touch_support']),
            'screen_width' => (int)($this->requestData['screen_width'] ?? 0),
            'screen_height' => (int)($this->requestData['screen_height'] ?? 0),
            'color_depth' => (int)($this->requestData['color_depth'] ?? 24),
            'pixel_ratio' => (float)($this->requestData['pixel_ratio'] ?? 1),
            'timezone_offset' => (int)($this->requestData['timezone_offset'] ?? 0),
            'plugins_count' => (int)($this->requestData['plugins_count'] ?? 0),
            'languages_count' => count(explode(',', $this->requestData['languages'] ?? '')),
            'behavioral' => [
                'mouse_movements' => (int)($this->requestData['mouse_movements'] ?? 0),
                'mouse_velocity_mean' => (float)($this->requestData['mouse_velocity_mean'] ?? 0),
                'mouse_velocity_std' => (float)($this->requestData['mouse_velocity_std'] ?? 0),
                'key_presses' => (int)($this->requestData['key_presses'] ?? 0),
                'key_interval_mean' => (float)($this->requestData['key_interval_mean'] ?? 0),
                'key_interval_std' => (float)($this->requestData['key_interval_std'] ?? 0),
                'scroll_events' => (int)($this->requestData['scroll_events'] ?? 0),
                'touch_events' => (int)($this->requestData['touch_events'] ?? 0),
            ],
            'sensors' => [
                'motion_count' => (int)($this->requestData['motion_count'] ?? 0),
                'orientation_count' => (int)($this->requestData['orientation_count'] ?? 0),
                'motion_variance' => (float)($this->requestData['motion_variance'] ?? 0),
                'orientation_variance' => (float)($this->requestData['orientation_variance'] ?? 0),
            ],
            'time_on_page' => (int)($this->requestData['time_on_page'] ?? 0),
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'accept' => $_SERVER['HTTP_ACCEPT'] ?? '',
            'has_sec_ch_ua' => !empty($_SERVER['HTTP_SEC_CH_UA']),
            'has_sec_fetch' => !empty($_SERVER['HTTP_SEC_FETCH_MODE']),
            'header_count' => count(getallheaders() ?: []),
            'behavioral_score' => (int)($this->requestData['behavioral_score'] ?? 50),
            'tls_score' => (int)($this->requestData['tls_score'] ?? 50),
            'advanced_bot_score' => (int)($this->requestData['advanced_bot_score'] ?? 50)
        ];
    }
    
    /**
     * =============================================
     * COMMANDER V3 - METODOS DE TRANSACOES/GATEWAYS
     * =============================================
     */
    
    /**
     * Lista transacoes com filtros
     */
    private function getTransactionsList() {
        $filters = [
            'status' => $this->sanitize($this->requestData['status'] ?? ''),
            'gateway' => $this->sanitize($this->requestData['gateway'] ?? ''),
            'campaign_slug' => $this->sanitize($this->requestData['campaign_slug'] ?? ''),
            'date_from' => $this->sanitize($this->requestData['date_from'] ?? ''),
            'date_to' => $this->sanitize($this->requestData['date_to'] ?? ''),
            'limit' => (int)($this->requestData['limit'] ?? 500)
        ];
        
        // Verifica permissao (se nao for admin, filtra por usuario)
        $userId = $this->sanitize($this->requestData['user_id'] ?? '');
        $isAdmin = (bool)($this->requestData['is_admin'] ?? false);
        
        if (!$isAdmin && $userId) {
            $filters['user_id'] = $userId;
        }
        
        $transactions = getTransactions($filters);
        
        $this->respond([
            'transactions' => $transactions,
            'count' => count($transactions)
        ]);
    }
    
    /**
     * Retorna dados de faturamento
     */
    private function getRevenueData() {
        $filters = [
            'campaign_slug' => $this->sanitize($this->requestData['campaign_slug'] ?? ''),
            'date_from' => $this->sanitize($this->requestData['date_from'] ?? ''),
            'date_to' => $this->sanitize($this->requestData['date_to'] ?? '')
        ];
        
        $userId = $this->sanitize($this->requestData['user_id'] ?? '');
        $isAdmin = (bool)($this->requestData['is_admin'] ?? false);
        
        if (!$isAdmin && $userId) {
            $filters['user_id'] = $userId;
        }
        
        $revenue = calculateRevenue($filters);
        
        $this->respond(['revenue' => $revenue]);
    }
    
    /**
     * Retorna estatisticas de vendas para dashboard
     */
    private function getSalesStatistics() {
        $userId = $this->sanitize($this->requestData['user_id'] ?? '');
        $isAdmin = (bool)($this->requestData['is_admin'] ?? false);
        
        $stats = getSalesStats($userId, $isAdmin);
        
        $this->respond(['stats' => $stats]);
    }
    
    /**
     * Lista gateways disponiveis e configurados
     */
    private function getGatewaysList() {
        $userId = $this->sanitize($this->requestData['user_id'] ?? '');
        
        $supported = getSupportedGateways();
        $configured = getUserGateways($userId);
        
        $this->respond([
            'supported' => $supported,
            'configured' => $configured
        ]);
    }
    
    /**
     * Salva configuracao de gateway
     */
    private function saveGatewayConfig() {
        $userId = $this->sanitize($this->requestData['user_id'] ?? '');
        $gatewayId = $this->sanitize($this->requestData['gateway_id'] ?? '', 'slug');
        
        // Se user_id vazio, usa 'default'
        if (empty($userId)) {
            $userId = 'default';
        }
        
        if (!$gatewayId) {
            $this->respond(['error' => 'gateway_id obrigatorio', 'success' => false], 400);
            return;
        }
        
        $config = [
            'enabled' => (bool)($this->requestData['enabled'] ?? true),
            'token' => $this->sanitize($this->requestData['token'] ?? ''),
            'webhook_secret' => $this->sanitize($this->requestData['webhook_secret'] ?? '')
        ];
        
        // Tenta salvar e captura erros
        try {
            $result = saveUserGateway($userId, $gatewayId, $config);
            $webhookUrl = generateWebhookUrl($gatewayId, $userId);
            
            $this->respond([
                'success' => $result,
                'webhook_url' => $webhookUrl,
                'user_id' => $userId,
                'gateway_id' => $gatewayId
            ]);
        } catch (Exception $e) {
            $this->respond([
                'success' => false,
                'error' => $e->getMessage()
            ], 500);
        }
    }
    
    /**
     * Remove configuracao de gateway
     */
    private function removeGatewayConfig() {
        $userId = $this->sanitize($this->requestData['user_id'] ?? '');
        $gatewayId = $this->sanitize($this->requestData['gateway_id'] ?? '', 'slug');
        
        if (!$userId || !$gatewayId) {
            $this->respond(['error' => 'user_id e gateway_id obrigatorios'], 400);
            return;
        }
        
        $result = removeUserGateway($userId, $gatewayId);
        
        $this->respond(['success' => $result]);
    }
    
    /**
     * Retorna URL do webhook para um gateway
     */
    private function getGatewayWebhookUrl() {
        $userId = $this->sanitize($this->requestData['user_id'] ?? '');
        $gatewayId = $this->sanitize($this->requestData['gateway_id'] ?? '', 'slug');
        
        if (!$userId || !$gatewayId) {
            $this->respond(['error' => 'user_id e gateway_id obrigatorios'], 400);
            return;
        }
        
        $webhookUrl = generateWebhookUrl($gatewayId, $userId);
        
        $this->respond(['webhook_url' => $webhookUrl]);
    }
    
    /**
     * Envia resposta JSON
     */
    private function respond($data, $statusCode = 200) {
        jsonResponse($data, $statusCode);
    }
}

// Executa API
$api = new CommanderAPI();
$api->handle();
