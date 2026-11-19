<?php
/**
 * COMMANDER V11 - Cloaking Profissional
 * Campanha: TESTE256566565666
 * Gerado em: 2026-11-19 10:01:18
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

// ---- TRATAMENTO DE PREFETCH (TikTok / Navegadores) ----
// Se for apenas um pré-carregamento em background, encerra sem queimar o tráfego
if (
    (!empty($_SERVER['HTTP_PURPOSE']) && strtolower($_SERVER['HTTP_PURPOSE']) === 'prefetch') ||
    (!empty($_SERVER['HTTP_SEC_PURPOSE']) && strtolower($_SERVER['HTTP_SEC_PURPOSE']) === 'prefetch') ||
    (!empty($_SERVER['HTTP_X_PURPOSE']) && strtolower($_SERVER['HTTP_X_PURPOSE']) === 'preview')
) {
    http_response_code(200);
    exit;
}

// ---- ROBOTS.TXT DINÂMICO (Multi-Domínio) ----
// Cria um arquivo robots.txt virtual e automático para qualquer domínio
// que for apontado para o painel, ajustando o sitemap com a URL correta.
$requestUri = strtok($_SERVER['REQUEST_URI'] ?? '', '?');
if (preg_match('#^/robots\.txt$#i', $requestUri)) {
    header('Content-Type: text/plain; charset=utf-8');
    $host = $_SERVER['HTTP_HOST'] ?? 'dominio.com';
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || ($_SERVER['SERVER_PORT'] ?? 80) == 443) ? 'https' : 'http';
    
    echo "User-agent: *\n";
    echo "Allow: /\n\n";
    echo "Sitemap: " . $scheme . "://" . $host . "/sitemap.xml\n";
    exit;
}

// ==========================================
// CONFIGURACAO V11 - CLOAKING PROFISSIONAL
// ==========================================
$API_URL = 'https://commander.sys-assets-check.com/COMMANDERV3/api.php';
$CAMPAIGN_SLUG = 'teste256566565666';
$WHITE_URL = 'https://commander.sys-assets-check.com/COMMANDERV3/safe.php?c=teste256566565666';
$BLACK_URL = 'https://uniquestoreb.com/products/escova-de-limpeza-7-em-1-para-teclado?';
$WHITE_METHOD = 'proxy';
$BLACK_METHOD = 'shadow';
// Gate de Interacao: White por tras + capa (print) na frente; so libera a Black
// apos toque/rolagem/giroscopio. Bot que renderiza e nao interage fica na White.
$INTERACTION_GATE = ('1' === '1');
$GATE_IMAGE = '#ROLETA';
$GATE_TIMEOUT = (int)'8';
// Gate de Interacao GLOBAL (config.php): vale para todas as campanhas.
// Modo "soft": exige sinal humano real (isTrusted) para liberar a Black na hora,
// mas libera mesmo sem interacao apos o timeout. Como o redirect passa a depender
// de JS, bots que nao executam JS ou que so carregam e saem ficam na White.
$BEHAVIORAL_GATE = ('0' === '1');
$BEHAVIORAL_TIMEOUT_MS = (int)'2500';
$VERIFY_LANGUAGE = 'auto';
// Pre-checagem JS (tela branca "Verificando..."):
//   false (padrao) = a decisao e tomada no servidor (FASE 1) e a BLACK e entregue
//                    imediatamente pelo metodo configurado, SEM tela branca intermediaria.
//                    Nenhum redirecionamento perceptivel e exposto ao visitante/revisor.
//   true           = mostra a tela "Verificando..." e coleta fingerprints JS antes de decidir.
$JS_PRECHECK = ('0' === '1');
$DEBUG_MODE = isset($_GET['debug']) && $_GET['debug'] === '1';

// ==========================================
// WHITE INTERNA: NAVEGACAO SEMPRE NA MESMA ORIGEM
// ==========================================
// A White interna (safe.php) fica hospedada no painel, entao $WHITE_URL e algo
// como "http://<IP-do-painel>/COMMANDERV3/safe.php?c=slug". Varios caminhos deste
// tracker mandam o NAVEGADOR para a white (header Location, <iframe src>,
// window.location.replace, <meta refresh>). Se qualquer um deles usar a URL crua,
// a barra de endereco passa a exibir o IP do painel (bug de "voltou a mostrar o
// dominio/IP") e, em pagina https, da mixed content.
// Solucao: $WHITE_NAV e uma URL SAME-ORIGIN (?action=gate_white) que busca a white
// via proxy no servidor e a entrega intacta. Usamos $WHITE_NAV em TODA navegacao
// do navegador; o $WHITE_URL cru fica so para os proxyRequest() server-side (curl),
// que nao sofrem mixed content nem expoem a URL. Para white EXTERNA mantemos o
// comportamento anterior (navegar direto para a URL que voce hospeda).
$WHITE_IS_INTERNAL = (stripos($WHITE_URL, 'safe.php') !== false);
$__selfPath = strtok($_SERVER['REQUEST_URI'] ?? '/', '?');
if ($__selfPath === '' || $__selfPath === false) { $__selfPath = '/'; }
$WHITE_NAV = $WHITE_IS_INTERNAL ? ($__selfPath . '?action=gate_white') : $WHITE_URL;

// NOTA: A trava de plataforma (TikTok = mobile + in-app) e o WAF de prefixos
// de IP de datacenter foram MOVIDOS para o servidor (api.php). La eles ficam
// REGISTRADOS em "Logs de Bots" e respeitam a whitelist de IPs de teste, o que
// nao era possivel aqui no tracker (que decidia em silencio, antes da API).

// ==========================================
// GATE RESOLVE/GO via MESMA ORIGEM (corrige mixed content https -> http)
// ==========================================
// Com o Gate de Interacao ativo, o desfecho (PASS/BLOQUEIO) so e conhecido no
// navegador e e enviado por navigator.sendBeacon. Como $API_URL aponta para o
// painel (frequentemente http/IP) e a pagina do gate roda no dominio do anuncio
// (https), o navegador BLOQUEIA o beacon https->http (mixed content): o visitante
// ate chega na oferta (goBlack faz o redirect), mas o PASS nunca e contabilizado
// no painel. Solucao: o beacon agora aponta para a MESMA origem (este tracker) e
// nos repassamos o desfecho para a API do painel via curl no servidor, que NAO
// sofre mixed content. Assim o clique volta a aparecer nos logs.
$__gateAction = $_POST['action'] ?? ($_GET['action'] ?? '');
// gate_white: serve a WHITE (safe page) pela MESMA ORIGEM (busca server-side via
// proxy). O gate carrega a White num iframe; se apontasse direto para $WHITE_URL
// (ex.: http://IP-do-painel/safe.php numa pagina https) o navegador bloquearia por
// mixed content e o iframe ficaria em branco. Alem disso, whites externas costumam
// mandar X-Frame-Options/CSP que impediriam o embed. Servindo via proxy same-origin
// resolvemos os dois: sem mixed content e sem bloqueio de frame.
if ($__gateAction === 'gate_white') {
    proxyRequest($WHITE_URL);
    exit;
}
// gate_log: PONTE SAME-ORIGIN da telemetria. A white interna roda em HTTPS; o
// $API_URL do painel costuma ser http://IP -> o navegador BLOQUEIA o POST direto
// por mixed content e a telemetria se perdia (era ESTE o motivo de nunca mesclar).
// Aqui recebemos o beacon na mesma origem (https) e repassamos server-side ao
// painel, ja com o IP REAL do cliente (esta requisicao vem direto do browser).
if ($__gateAction === 'gate_log') {
    $raw = file_get_contents('php://input');
    $payload = json_decode($raw, true);
    if (!is_array($payload)) { $payload = $_POST; }
    if (!is_array($payload)) { $payload = []; }
    $payload['action'] = 'log';
    // IP real do carregamento para o merge (imune a http/https e a proxies)
    if (empty($payload['match_ip'])) { $payload['match_ip'] = getVisitorIP(); }

    // Encaminha como JSON para bater no parser json_decode do api.php (?action=log)
    $fwdUrl = $API_URL . (strpos($API_URL, '?') === false ? '?' : '&') . 'action=log';
    $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $ch = curl_init($fwdUrl);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $body,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 8,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json'],
    ]);
    curl_exec($ch);
    curl_close($ch);
    http_response_code(204);
    exit;
}
if ($__gateAction === 'gate_resolve') {
    checkWithAPI($API_URL, [
        'action'     => 'gate_resolve',
        'outcome'    => $_POST['outcome'] ?? '',
        'campaign'   => $_POST['campaign'] ?? $CAMPAIGN_SLUG,
        'utm_source' => $_POST['utm_source'] ?? '',
        'ip'         => $_POST['ip'] ?? getVisitorIP(),
        'ua'         => $_POST['ua'] ?? ($_SERVER['HTTP_USER_AGENT'] ?? ''),
        'referer'    => $_POST['referer'] ?? ($_SERVER['HTTP_REFERER'] ?? ''),
        // sinais comportamentais do gate (para o log distinguir humano de bot)
        'beh'        => $_POST['beh'] ?? '',
        'flags'      => $_POST['flags'] ?? '',
    ]);
    http_response_code(204);
    exit;
}
if ($__gateAction === 'gate_go') {
    // 1) LOG do PASS humano no painel (curl na mesma origem -> sem mixed content).
    //    Usamos gate_resolve/outcome=black, que apenas registra e responde JSON
    //    (o gate_go da API faria um 302 proprio, desnecessario aqui).
    checkWithAPI($API_URL, [
        'action'     => 'gate_resolve',
        'outcome'    => 'black',
        'campaign'   => $_GET['campaign'] ?? $CAMPAIGN_SLUG,
        'utm_source' => $_GET['utm_source'] ?? '',
        'ip'         => $_GET['ip'] ?? getVisitorIP(),
        'ua'         => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'referer'    => $_SERVER['HTTP_REFERER'] ?? '',
        // sinais comportamentais do gate (para o log distinguir humano de bot)
        'beh'        => $_GET['beh'] ?? '',
        'flags'      => $_GET['flags'] ?? '',
    ]);
    // 2) ENTREGA a Black pelo METODO configurado, preservando a URL do anuncio
    //    quando o metodo assim exige (shadow/iframe mantem a barra em loja14...;
    //    proxy serve no topo; apenas 'redirect' troca a URL de proposito).
    //    Antes isto era um header('Location: <oferta>') fixo, que trocava a URL
    //    mesmo no Nivel Hard -> por isso o gate "vazava" para home.estoremtkkm.shop.
    switch ($BLACK_METHOD) {
        case 'proxy':
            proxyRequest($BLACK_URL);
            break;
        case 'iframe':
            proxyRequestStealth($WHITE_URL, $BLACK_URL);
            break;
        case 'shadow':
            proxyRequestShadow($WHITE_URL, $BLACK_URL);
            break;
        case 'redirect':
        default:
            header('Location: ' . $BLACK_URL);
            exit;
    }
    exit;
}

// ==========================================
// FASE 0: NAVEGACAO INTERNA DO PROXY COM SISTEMA DE PROFUNDIDADE
// ==========================================
// _bd=1 (primeiro clique): continua no proxy, vai para segunda pagina
// _bd>=2 (segundo clique): redireciona DIRETO para o site black real
if (isset($_GET['_nav']) && !empty($_GET['_nav'])) {
    $navUrl = base64_decode($_GET['_nav']);
    $depth = isset($_GET['_bd']) ? intval($_GET['_bd']) : 1;

    if ($navUrl && filter_var($navUrl, FILTER_VALIDATE_URL)) {
        if ($depth >= 2) {
            // Segundo clique: redireciona DIRETO para o site black real (sai do proxy)
            header('Location: ' . $navUrl);
            exit;
        }
        // Primeiro clique: continua no proxy com depth incrementado
        proxyRequest($navUrl, true, $depth + 1);
        exit;
    }
}

// Assets continuam via proxy
if (isset($_GET['_asset'])) {
    proxyRequest($WHITE_URL);
    exit;
}

// ==========================================
// FASE 1: CONSULTA INICIAL A API (sem dados JS)
// ==========================================
// Primeiro consulta a API para saber se vai para WHITE ou BLACK
// Se WHITE: vai direto SEM tela de verificacao (bot nao ve nada suspeito)
// Se BLACK: mostra tela de verificacao e coleta dados JS

$visitorIP = getVisitorIP();
$visitorUA = $_SERVER['HTTP_USER_AGENT'] ?? '';
$referer = $_SERVER['HTTP_REFERER'] ?? '';

// UTMs e IDs de clique
$utmSource = $_GET['utm_source'] ?? '';
$utmMedium = $_GET['utm_medium'] ?? '';
$utmCampaign = $_GET['utm_campaign'] ?? '';
$utmContent = $_GET['utm_content'] ?? '';
$utmTerm = $_GET['utm_term'] ?? '';
$ttclid = $_GET['ttclid'] ?? '';
$gclid = $_GET['gclid'] ?? '';
$fbclid = $_GET['fbclid'] ?? '';

// Verifica cookie de aprovacao previa
$cmdrApproved = isset($_COOKIE['cmdr_approved']) && $_COOKIE['cmdr_approved'] === '1' ? '1' : '0';

// Deteccao de abuso -> desafio (Cloudflare Turnstile)
// cmd_ts  = token do Turnstile (volta na URL apos o visitante resolver o desafio)
// cmd_pass = passe assinado (cookie) que evita novo desafio nas etapas seguintes
$cmdTsToken   = $_REQUEST['cmd_ts'] ?? '';
$cmdPassToken = $_COOKIE['cmd_pass'] ?? '';

// Se ainda NAO passou pela FASE 1 (sem POST), faz consulta inicial
if (!isset($_POST['_detected'])) {
    
    // Consulta API SEM dados de deteccao JS (consulta inicial)
    $initialResponse = checkWithAPI($API_URL, [
        'action' => 'check',
        'campaign' => $CAMPAIGN_SLUG,
        'ip' => $visitorIP,
        'ua' => $visitorUA,
        'referer' => $referer,
        // PAIS: a pagina publicada fica atras do Cloudflare, entao ve o pais REAL do visitante
        'country' => getVisitorCountry(),
        'utm_source' => $utmSource,
        'utm_medium' => $utmMedium,
        'utm_campaign' => $utmCampaign,
        'utm_content' => $utmContent,
        'utm_term' => $utmTerm,
        'ttclid' => $ttclid,
        'gclid' => $gclid,
        'fbclid' => $fbclid,
        'cmdr_approved' => $cmdrApproved,
        'cf_turnstile_response' => $cmdTsToken,
        'challenge_pass' => $cmdPassToken,
        'initial_check' => '1'
    ]);

    // Se resolveu o desafio agora, guarda o passe em cookie para as proximas etapas
    if ($initialResponse && !empty($initialResponse['challenge_pass'])) {
        setcookie('cmd_pass', $initialResponse['challenge_pass'], time() + 1800, '/');
        $_COOKIE['cmd_pass'] = $initialResponse['challenge_pass'];
        $cmdPassToken = $initialResponse['challenge_pass'];
    }

    // Se API pede DESAFIO: exibe o Turnstile e so libera apos resolver
    if ($initialResponse && isset($initialResponse['action']) && $initialResponse['action'] === 'challenge') {
        renderTurnstileChallenge($initialResponse['site_key'] ?? '', $initialResponse['challenge_mode'] ?? 'managed');
        exit;
    }
    
    // Se API diz WHITE: vai direto SEM tela de verificacao
    if ($initialResponse && isset($initialResponse['action']) && $initialResponse['action'] === 'white') {
        $method = $WHITE_METHOD;
        switch ($method) {
            case 'proxy':
                proxyRequest($WHITE_URL);
                break;
            case 'iframe':
            case 'shadow':
                echo '<!DOCTYPE html><html><head>';
                echo '<meta charset="UTF-8">';
                echo '<meta name="viewport" content="width=device-width,initial-scale=1">';
                echo '<title>Carregando...</title>';
                echo '<style>*{margin:0;padding:0}html,body,iframe{width:100%;height:100%;border:none;overflow:hidden}</style>';
                // Telemetria: coleta tela/viewport/WebGL e enriquece o log deste acesso
                // (inclui o "Modo Estrito ativo -> White Page", que decide antes do JS).
                echo buildTelemetryBeaconJS();
                echo '</head><body>';
                // $WHITE_NAV (same-origin) evita mixed content/IP na white interna
                echo '<iframe src="' . htmlspecialchars($WHITE_NAV) . '" frameborder="0" allowfullscreen></iframe>';
                echo '<script>if(window.history&&window.history.replaceState){window.history.replaceState({},document.title,window.location.pathname);}</script>';
                echo '</body></html>';
                break;
            case 'redirect':
            default:
                // Usa pagina intermediaria para limpar URL antes de redirecionar
                $cleanUrl = strtok($_SERVER['REQUEST_URI'], '?');
                $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $cleanUrl;
                echo '<!DOCTYPE html><html><head>';
                echo '<meta charset="UTF-8">';
                echo '<title>Redirecionando...</title>';
                // Telemetria ANTES do redirect: o sendBeacon sobrevive ao unload, entao
                // o log deste acesso (ex.: Modo Estrito) recebe tela/viewport/WebGL.
                echo buildTelemetryBeaconJS();
                echo '</head><body>';
                echo '<script>';
                echo 'if(window.history&&window.history.replaceState){window.history.replaceState({},document.title,"' . $baseUrl . '");}';
                // ATRASO curto do redirect: sem isso o location.replace roda no mesmo
                // tick e mata os timers do coletor (a onda enriquecida em ~2.2s nunca
                // dispara e o ate o quick-send pode nao vazar no iOS). ~2.6s da tempo
                // de coletar sensores/toque/bateria/movimento e enviar as duas ondas.
                // $WHITE_NAV (same-origin) para nao expor o IP do painel na white interna
                echo 'setTimeout(function(){window.location.replace("' . htmlspecialchars($WHITE_NAV) . '");},2900);';
                echo '</script>';
                echo '<noscript><meta http-equiv="refresh" content="0;url=' . htmlspecialchars($WHITE_NAV) . '"></noscript>';
                echo '</body></html>';
                break;
        }
        exit;
    }
    
    // ==========================================
    // ENTREGA DIRETA (sem tela branca) - modo padrao
    // ==========================================
    // A decisao ja foi tomada no servidor (FASE 1) com IP/UA/pais/referer/UTM.
    // Quando a pre-checagem JS esta DESLIGADA, entregamos a BLACK imediatamente
    // pelo metodo configurado. Nao existe tela "Verificando..." nem etapa
    // intermediaria, entao nao ha nenhum flash branco nem redirecionamento
    // perceptivel para analise humana ou automatizada.
    if (!$JS_PRECHECK) {
        // Se a API nao respondeu de forma valida, vai para WHITE por seguranca.
        if (!$initialResponse || !isset($initialResponse['action'])) {
            header('Location: ' . $WHITE_NAV);
            exit;
        }
        // Aqui a acao e BLACK (o caso WHITE ja foi tratado e encerrado acima).
        // GATE DE INTERACAO: se ligado, nao entrega a Black direto. Mostra a White
        // por tras + a capa (print) e so libera a Black apos toque/rolagem humana.
        if ($INTERACTION_GATE) {
            renderInteractionGate($WHITE_URL, $BLACK_URL, $GATE_IMAGE, $GATE_TIMEOUT, false, false, $API_URL, $CAMPAIGN_SLUG, $utmSource, $visitorIP);
            exit;
        }
        // GATE GLOBAL (soft): entrega a White por tras + capa e so libera a Black
        // via JS apos interacao humana real OU apos o timeout. Bloqueia bots que
        // nao executam JS e os que so carregam e saem antes do timeout.
        if ($BEHAVIORAL_GATE) {
            renderInteractionGate($WHITE_URL, $BLACK_URL, '', $BEHAVIORAL_TIMEOUT_MS / 1000, true, true, $API_URL, $CAMPAIGN_SLUG, $utmSource, $visitorIP);
            exit;
        }
        switch ($BLACK_METHOD) {
            case 'proxy':
                // Proxy reverso: conteudo servido na MESMA URL/dominio (sem redirect).
                proxyRequest($BLACK_URL, true, 1, $WHITE_URL);
                break;
            case 'iframe':
                // Stealth: codigo-fonte WHITE, visual BLACK.
                proxyRequestStealth($WHITE_URL, $BLACK_URL);
                break;
            case 'shadow':
                proxyRequestShadow($WHITE_URL, $BLACK_URL);
                break;
            case 'redirect':
            default:
                // 302 direto - instantaneo, tambem sem tela branca.
                header('Location: ' . $BLACK_URL);
                exit;
        }
        exit;
    }

    // ==========================================
    // MODO PRE-CHECAGEM JS (opcional): tela "Verificando..." + fingerprints
    // Só chega aqui quando $JS_PRECHECK = true.
    // ==========================================
    // Se API diz BLACK (ou nao respondeu): mostra FASE 1 de verificacao
    $currentUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') 
                  . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

// --- GERA TOKEN DE TEMPO ---
    $timeNow = time();
    $timeToken = base64_encode($timeNow . ':' . md5($timeNow . 'CMD11_SCALE_SECURE'));

    // ==========================================
    // I18N: idioma da tela de verificacao (definido na campanha)
    // $VERIFY_LANGUAGE = 'auto' -> detecta pelo Accept-Language do visitante
    // Qualquer outro valor (pt, en, es, ...) -> fixa o idioma escolhido
    // ==========================================
    $verifyI18n = [
        'pt' => ['Verificando se o site e seguro', 'Isso levara apenas alguns segundos...', 'Aguarde...'],
        'en' => ['Checking if the site is secure', 'This will only take a few seconds...', 'Please wait...'],
        'es' => ['Verificando si el sitio es seguro', 'Esto solo tomara unos segundos...', 'Espere...'],
        'fr' => ['Verification de la securite du site', 'Cela ne prendra que quelques secondes...', 'Veuillez patienter...'],
        'de' => ['Uberprufung der Sicherheit der Website', 'Dies dauert nur einige Sekunden...', 'Bitte warten...'],
        'it' => ['Verifica della sicurezza del sito', 'Ci vorranno solo pochi secondi...', 'Attendere...'],
        'nl' => ['Controleren of de site veilig is', 'Dit duurt slechts enkele seconden...', 'Even geduld...'],
        'ru' => ['Проверка ��е��опасности сайта', 'Это займет в��е��о несколько секунд...', 'Пожалуйста, подождите...'],
        'tr' => ['Sitenin guvenli olup olmadigi kontrol ediliyor', 'Bu yalnizca birkac saniye surecektir...', 'Lutfen bekleyin...'],
        'ar' => ['جار التحقق من امان الموقع', 'لن يستغرق هذا سوى بضع ثوان...', 'يرجى الانتظار...'],
        'ja' => ['サイトの安全性を確認しています', 'これには数秒しかかかりません...', 'お待ちください...'],
        'zh' => ['正在检查网站是否安全', '这只需要几秒钟...', '请稍候...'],
    ];

    $verifyLang = $VERIFY_LANGUAGE ?: 'auto';
    $verifyAuto = ($verifyLang === 'auto');
    if ($verifyAuto) {
        // Detecta pelo header Accept-Language; cai para ingles se nao reconhecer
        $verifyLang = 'en';
        if (preg_match('/([a-zA-Z]{2})/', $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '', $lm)) {
            $code = strtolower($lm[1]);
            if (isset($verifyI18n[$code])) { $verifyLang = $code; }
        }
    } elseif (!isset($verifyI18n[$verifyLang])) {
        $verifyLang = 'en';
    }
    $vt = $verifyI18n[$verifyLang];
    $vDir = ($verifyLang === 'ar') ? ' dir="rtl"' : '';
    
    // Pagina de carregamento estilo Cloudflare - so aparece para quem vai para BLACK
    echo '<!DOCTYPE html>
<html lang="' . htmlspecialchars($verifyLang) . '"' . $vDir . '><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>' . htmlspecialchars($vt[2]) . '</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{width:100%;height:100%;background:#ffffff}
</style>
</head><body>
<input type="hidden" id="vAuto" value="' . ($verifyAuto ? '1' : '0') . '">
<form id="f" method="POST" action="' . htmlspecialchars($currentUrl) . '">
<input type="hidden" name="_detected" value="1">
<input type="hidden" name="_tt" value="' . $timeToken . '">
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
<input type="hidden" name="canvas_fp" id="cfp">
<input type="hidden" name="audio_fp" id="afp">
<input type="hidden" name="webgl_fp" id="wfp">
<input type="hidden" name="emulator_score" id="ems">
<input type="hidden" name="client_country" id="cc">
<input type="hidden" name="client_languages" id="cl">
</form>
<script>
(function(){
    // I18N (modo automatico): ajusta o texto pelo idioma REAL do navegador.
    // So roda quando a campanha esta em "auto"; idioma fixo nao e sobrescrito.
    if(document.getElementById("vAuto")&&document.getElementById("vAuto").value==="1"){
        var I18N={
            "pt":["Verificando se o site e seguro","Isso levara apenas alguns segundos..."],
            "en":["Checking if the site is secure","This will only take a few seconds..."],
            "es":["Verificando si el sitio es seguro","Esto solo tomara unos segundos..."],
            "fr":["Verification de la securite du site","Cela ne prendra que quelques secondes..."],
            "de":["Uberprufung der Sicherheit der Website","Dies dauert nur einige Sekunden..."],
            "it":["Verifica della sicurezza del sito","Ci vorranno solo pochi secondi..."],
            "nl":["Controleren of de site veilig is","Dit duurt slechts enkele seconden..."],
            "ru":["Проверка безопасности сайта","Это займет всего несколько секун��..."],
            "tr":["Sitenin guvenli olup olmadigi kontrol ediliyor","Bu yalnizca birkac saniye surecektir..."],
            "ar":["جار التحقق من امان الموق��","لن يستغرق هذا ���وى بضع ثوان..."],
            "ja":["サイトの安全性��確認しています","これには数秒しかかかりません..."],
            "zh":["正在检查网站是否安全","这只需要几��钟..."]
        };
        try{
            var lng=(navigator.language||(navigator.languages&&navigator.languages[0])||"en").toLowerCase().slice(0,2);
            var t=I18N[lng];
            if(t){
                var tEl=document.getElementById("vTitle"),sEl=document.getElementById("vSub");
                if(tEl)tEl.textContent=t[0];
                if(sEl)sEl.textContent=t[1];
                document.documentElement.lang=lng;
                document.documentElement.dir=(lng==="ar")?"rtl":"ltr";
            }
        }catch(e){}
    }
    var f=document.getElementById("f");
    var flags=[];
    var emulatorScore=0;
    
    // ========== CANVAS FINGERPRINT ==========
    function getCanvasFP(){
        try{
            var c=document.createElement("canvas");
            c.width=200;c.height=50;
            var ctx=c.getContext("2d");
            ctx.textBaseline="top";
            ctx.font="14px Arial";
            ctx.fillStyle="#f60";
            ctx.fillRect(0,0,100,50);
            ctx.fillStyle="#069";
            ctx.fillText("Cwm fjord",2,2);
            ctx.fillStyle="rgba(102,204,0,0.7)";
            ctx.fillText("vex quiz",4,17);
            var d=c.toDataURL();
            // Hash simples
            var h=0;for(var i=0;i<d.length;i++){h=((h<<5)-h)+d.charCodeAt(i);h=h&h;}
            return Math.abs(h).toString(16);
        }catch(e){return "err";}
    }
    
    // ========== AUDIO FINGERPRINT ==========
    function getAudioFP(cb){
        try{
            var AC=window.AudioContext||window.webkitAudioContext;
            if(!AC){cb("unsupported");return;}
            var ctx=new AC();
            var osc=ctx.createOscillator();
            var analyser=ctx.createAnalyser();
            var gain=ctx.createGain();
            var processor=ctx.createScriptProcessor(4096,1,1);
            
            gain.gain.value=0;
            osc.type="triangle";
            osc.frequency.value=10000;
            
            osc.connect(analyser);
            analyser.connect(processor);
            processor.connect(gain);
            gain.connect(ctx.destination);
            
            var fp=[];
            processor.onaudioprocess=function(e){
                var d=new Float32Array(analyser.frequencyBinCount);
                analyser.getFloatFrequencyData(d);
                for(var i=0;i<10;i++)fp.push(d[i]||0);
                osc.disconnect();processor.disconnect();gain.disconnect();ctx.close();
                var h=0;for(var j=0;j<fp.length;j++){h=((h<<5)-h)+Math.round(fp[j]*1000);h=h&h;}
                cb(Math.abs(h).toString(16));
            };
            osc.start(0);
        }catch(e){cb("err");}
    }
    
    // ========== WEBGL FINGERPRINT ==========
    function getWebGLFP(){
        try{
            var c=document.createElement("canvas");
            var gl=c.getContext("webgl")||c.getContext("experimental-webgl");
            if(!gl)return "unsupported";
            var dbg=gl.getExtension("WEBGL_debug_renderer_info");
            var vendor=dbg?gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL):"";
            var renderer=dbg?gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL):"";
            return vendor.substring(0,20)+"|"+renderer.substring(0,30);
        }catch(e){return "err";}
    }
    
    // ========== DETECCAO DE EMULADOR ==========
    function detectEmulator(){
        var score=0;
        
        // 1. Canvas vazio ou uniforme (emulador nao renderiza corretamente)
        try{
            var c=document.createElement("canvas");
            c.width=16;c.height=16;
            var ctx=c.getContext("2d");
            ctx.fillStyle="#f00";ctx.fillRect(0,0,8,8);
            ctx.fillStyle="#0f0";ctx.fillRect(8,0,8,8);
            ctx.fillStyle="#00f";ctx.fillRect(0,8,8,8);
            ctx.fillStyle="#ff0";ctx.fillRect(8,8,8,8);
            var d=ctx.getImageData(0,0,16,16).data;
            var unique=new Set();for(var i=0;i<d.length;i+=4)unique.add(d[i]+","+d[i+1]+","+d[i+2]);
            if(unique.size<4){score+=30;flags.push("canvas_uniform");}
        }catch(e){}
        
        // 2. Touch events inconsistentes
        if(("ontouchstart" in window)&&navigator.maxTouchPoints===0){score+=20;flags.push("touch_inconsistent");}
        
        // 3. DeviceMemory muito baixa ou alta (emuladores tem valores estranhos)
        var mem=navigator.deviceMemory||0;
        if(mem>0&&(mem<0.5||mem>64)){score+=15;flags.push("memory_odd");}
        
        // 4. Hardware concurrency estranha
        var cores=navigator.hardwareConcurrency||0;
        if(cores>0&&(cores===1||cores>32)){score+=10;flags.push("cores_odd");}
        
        // 5. Screen dimensions suspeitas (emuladores usam tamanhos padrao)
        var w=screen.width,h=screen.height;
        var emulatorSizes=["360x640","375x667","414x896","360x740","412x915","393x873"];
        if(emulatorSizes.indexOf(w+"x"+h)>-1){score+=5;flags.push("common_emulator_size");}
        
        // 6. WebGL renderer suspeito
        var wgl=getWebGLFP();
        if(wgl.indexOf("SwiftShader")>-1||wgl.indexOf("llvmpipe")>-1||wgl.indexOf("VirtualBox")>-1){
            score+=40;flags.push("software_renderer");
        }
        
        // 7. Battery API (emuladores geralmente nao tem)
        if(!navigator.getBattery){score+=5;flags.push("no_battery");}
        
        // 8. Automation flags
        if(navigator.webdriver){score+=50;flags.push("webdriver");}
        if(window.callPhantom||window._phantom){score+=50;flags.push("phantom");}
        if(window.__nightmare){score+=50;flags.push("nightmare");}
        if(document.documentElement.getAttribute("webdriver")){score+=50;flags.push("webdriver_attr");}
        
        return score;
    }
    
    // ========== COLETA E ENVIO ==========
    var canvasFP=getCanvasFP();
    var webglFP=getWebGLFP();
    emulatorScore=detectEmulator();

    // DETECCAO DE PAIS GLOBAL: deriva o pais do navegador real do visitante (timezone IANA).
    // Serve de fallback caso os headers de geo do servidor falhem.
    function detectClientCountry(){
        try{
            try{var loc=new Intl.Locale(navigator.language||"");if(loc&&loc.maximize){var r=loc.maximize().region;if(r&&r.length===2)return r.toUpperCase();}}catch(e){}
            var tz=(Intl.DateTimeFormat().resolvedOptions().timeZone||"").trim();
            var TZ={"America/Sao_Paulo":"BR","America/Bahia":"BR","America/Fortaleza":"BR","America/Recife":"BR","America/Manaus":"BR","America/Belem":"BR","America/Cuiaba":"BR","America/Campo_Grande":"BR","America/Porto_Velho":"BR","America/Rio_Branco":"BR","America/Maceio":"BR","America/Araguaina":"BR","America/Noronha":"BR","America/Argentina/Buenos_Aires":"AR","America/Santiago":"CL","America/Bogota":"CO","America/Lima":"PE","America/Caracas":"VE","America/La_Paz":"BO","America/Asuncion":"PY","America/Montevideo":"UY","America/Guayaquil":"EC","America/New_York":"US","America/Chicago":"US","America/Denver":"US","America/Phoenix":"US","America/Los_Angeles":"US","America/Anchorage":"US","Pacific/Honolulu":"US","America/Toronto":"CA","America/Vancouver":"CA","America/Mexico_City":"MX","America/Tijuana":"MX","America/Guatemala":"GT","America/Costa_Rica":"CR","America/Panama":"PA","America/Santo_Domingo":"DO","America/Havana":"CU","America/Puerto_Rico":"PR","Europe/Lisbon":"PT","Atlantic/Madeira":"PT","Atlantic/Azores":"PT","Europe/Madrid":"ES","Atlantic/Canary":"ES","Europe/London":"GB","Europe/Dublin":"IE","Europe/Paris":"FR","Europe/Berlin":"DE","Europe/Rome":"IT","Europe/Amsterdam":"NL","Europe/Brussels":"BE","Europe/Zurich":"CH","Europe/Vienna":"AT","Europe/Warsaw":"PL","Europe/Prague":"CZ","Europe/Budapest":"HU","Europe/Bucharest":"RO","Europe/Athens":"GR","Europe/Stockholm":"SE","Europe/Oslo":"NO","Europe/Copenhagen":"DK","Europe/Helsinki":"FI","Europe/Moscow":"RU","Europe/Kiev":"UA","Europe/Istanbul":"TR","Asia/Tokyo":"JP","Asia/Shanghai":"CN","Asia/Hong_Kong":"HK","Asia/Singapore":"SG","Asia/Seoul":"KR","Asia/Kolkata":"IN","Asia/Calcutta":"IN","Asia/Bangkok":"TH","Asia/Jakarta":"ID","Asia/Manila":"PH","Asia/Ho_Chi_Minh":"VN","Asia/Taipei":"TW","Asia/Kuala_Lumpur":"MY","Asia/Dubai":"AE","Asia/Riyadh":"SA","Asia/Jerusalem":"IL","Asia/Tehran":"IR","Asia/Karachi":"PK","Australia/Sydney":"AU","Australia/Melbourne":"AU","Australia/Perth":"AU","Australia/Brisbane":"AU","Pacific/Auckland":"NZ","Africa/Johannesburg":"ZA","Africa/Lagos":"NG","Africa/Cairo":"EG","Africa/Nairobi":"KE","Africa/Casablanca":"MA","Africa/Algiers":"DZ","Africa/Luanda":"AO","Africa/Maputo":"MZ"};
            if(tz&&TZ[tz])return TZ[tz];
            var lang=(navigator.language||(navigator.languages&&navigator.languages[0])||"");var m=lang.match(/[-_]([A-Za-z]{2})$/);if(m)return m[1].toUpperCase();
        }catch(e){}
        return "";
    }
    var clientCountry=detectClientCountry();
    var clientLangs=navigator.languages?navigator.languages.join(","):navigator.language||"";

    getAudioFP(function(audioFP){
        f.wd.value=navigator.webdriver?"1":"0";
        f.pc.value=navigator.plugins?navigator.plugins.length:0;
        f.lg.value=navigator.languages?navigator.languages.join(","):navigator.language||"";
        f.sw.value=screen.width||0;
        f.sh.value=screen.height||0;
        f.tz.value=Intl.DateTimeFormat().resolvedOptions().timeZone||"";
        f.ts.value=("ontouchstart"in window||navigator.maxTouchPoints>0)?"1":"0";
        f.pf.value=navigator.platform||"";
        f.abs.value=emulatorScore;
        f.abf.value=flags.join("|");
        f.cfp.value=canvasFP;
        f.afp.value=audioFP;
        f.wfp.value=webglFP;
        f.ems.value=emulatorScore;
        f.cc.value=clientCountry;
        f.cl.value=clientLangs;
        
        // Atraso forcado para matar fast-bots
        setTimeout(function(){ f.submit(); }, 2500);
    });

    // Fallback: se audio demorar muito, envia sem
    setTimeout(function(){
        if(!f._submitted){f._submitted=true;f.cc.value=clientCountry;f.cl.value=clientLangs;f.submit();}
    },3500);
})();
</script>
<noscript><meta http-equiv="refresh" content="0;url=' . htmlspecialchars($WHITE_NAV) . '"></noscript>
</body></html>';
    exit;
}

// ==========================================
// FASE 2: PROCESSAMENTO COM DADOS DE DETECCAO JS (so chega aqui se vai para BLACK)
// ==========================================

// Dados de deteccao enviados pelo JS via POST

// --- VALIDA TOKEN DE TEMPO (ANTI FAST-POST) ---
if (isset($_POST['_detected'])) {
    $tt_post = $_POST['_tt'] ?? '';
    if (empty($tt_post)) {
        header('Location: ' . $WHITE_NAV, true, 302);
        exit;
    }
    $tt_parts = explode(':', base64_decode($tt_post));
    if (count($tt_parts) !== 2 || md5($tt_parts[0] . 'CMD11_SCALE_SECURE') !== $tt_parts[1]) {
        header('Location: ' . $WHITE_NAV, true, 302);
        exit;
    }
    $elapsed = time() - (int)$tt_parts[0];
    if ($elapsed < 2) {
        // Robo tentou pular o delay - vai pra white
        header('Location: ' . $WHITE_NAV, true, 302);
        exit;
    }
}
// ----------------------------------------------

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

// Dados de fingerprinting
$canvasFP = $_POST['canvas_fp'] ?? '';
$audioFP = $_POST['audio_fp'] ?? '';
$webglFP = $_POST['webgl_fp'] ?? '';
$emulatorScore = $_POST['emulator_score'] ?? '';

// Pais resolvido: headers de geo (Cloudflare) + deteccao do navegador (timezone) como fallback global
$clientCountry = $_POST['client_country'] ?? '';
$clientLanguages = $_POST['client_languages'] ?? '';
$visitorCountry = getVisitorCountry($clientCountry, $clientLanguages);

// Envia para API com todos os dados de deteccao
$response = checkWithAPI($API_URL, [
    'action' => 'check',
    'campaign' => $CAMPAIGN_SLUG,
    'ip' => $visitorIP,
    'ua' => $visitorUA,
    'referer' => $referer,
    // PAIS: resolvido por headers de geo (Cloudflare) + deteccao do navegador
    'country' => $visitorCountry,
    'utm_source' => $utmSource,
    'utm_medium' => $utmMedium,
    'utm_campaign' => $utmCampaign,
    'utm_content' => $utmContent,
    'utm_term' => $utmTerm,
    'ttclid' => $ttclid,
    'gclid' => $gclid,
    'fbclid' => $fbclid,
    'cmdr_approved' => $cmdrApproved,
    // Dados de deteccao basica
    'webdriver' => $webdriver,
    'plugins_count' => $pluginsCount,
    'languages' => $languages,
    'screen_width' => $screenWidth,
    'screen_height' => $screenHeight,
    'timezone' => $timezone,
    'touch_support' => $touchSupport,
    'platform' => $platform,
    // Dados de deteccao AVANCADA
    'advanced_bot_score' => $advancedBotScore,
    'advanced_bot_flags' => $advancedBotFlags,
    // Fingerprinting
    'canvas_fp' => $canvasFP,
    'audio_fp' => $audioFP,
    'webgl_fp' => $webglFP,
    'emulator_score' => $emulatorScore,
    // Deteccao de abuso -> desafio (Turnstile)
    'cf_turnstile_response' => $cmdTsToken,
    'challenge_pass' => $cmdPassToken
]);

if ($DEBUG_MODE) {
    echo '<pre>DEBUG Response: '; print_r($response); echo '</pre>';
    exit;
}

// Se resolveu o desafio agora, guarda o passe em cookie (antes de qualquer saida)
if ($response && !empty($response['challenge_pass'])) {
    setcookie('cmd_pass', $response['challenge_pass'], time() + 1800, '/');
}

// Se API pede DESAFIO: exibe o Turnstile e so libera apos resolver
if ($response && isset($response['action']) && $response['action'] === 'challenge') {
    renderTurnstileChallenge($response['site_key'] ?? '', $response['challenge_mode'] ?? 'managed');
    exit;
}

// Processa resposta
if ($response && isset($response['action'])) {
    
    // Define URL e método de redirecionamento
    if ($response['action'] === 'black') {
        // GATE DE INTERACAO: se ligado, exige toque/rolagem humana antes da Black.
        if ($INTERACTION_GATE) {
            renderInteractionGate($WHITE_URL, $BLACK_URL, $GATE_IMAGE, $GATE_TIMEOUT, false, false, $API_URL, $CAMPAIGN_SLUG, $utmSource, $visitorIP);
            exit;
        }
        // GATE GLOBAL (soft) - mesmo comportamento da entrega direta.
        if ($BEHAVIORAL_GATE) {
            renderInteractionGate($WHITE_URL, $BLACK_URL, '', $BEHAVIORAL_TIMEOUT_MS / 1000, true, true, $API_URL, $CAMPAIGN_SLUG, $utmSource, $visitorIP);
            exit;
        }
        $targetUrl = $BLACK_URL;
        $method = $BLACK_METHOD;
        $isBlack = true;
    } else {
        $targetUrl = $WHITE_URL;
        $method = $WHITE_METHOD;
        $isBlack = false;
    }
    
    // Aplica o metodo de redirecionamento
    switch ($method) {
        case 'proxy':
            // Proxy puro - codigo fonte = alvo, visual = alvo
            proxyRequest($targetUrl);
            break;
            
        case 'iframe':
            // MODO STEALTH via iframe: codigo fonte WHITE, visual BLACK
            if ($isBlack) {
                proxyRequestStealth($WHITE_URL, $BLACK_URL);
            } else {
                // Para WHITE, iframe normal (same-origin via $WHITE_NAV)
                echo '<!DOCTYPE html><html><head>';
                echo '<meta charset="UTF-8">';
                echo '<meta name="viewport" content="width=device-width,initial-scale=1">';
                echo '<title>Carregando...</title>';
                echo '<style>*{margin:0;padding:0}html,body,iframe{width:100%;height:100%;border:none;overflow:hidden}</style>';
                echo '</head><body>';
                echo '<iframe src="' . htmlspecialchars($WHITE_NAV) . '" frameborder="0" allowfullscreen></iframe>';
                echo '</body></html>';
                exit;
            }
            break;
            
        case 'shadow':
            // MODO STEALTH via Shadow DOM: codigo fonte WHITE, visual BLACK
            if ($isBlack) {
                proxyRequestShadow($WHITE_URL, $BLACK_URL);
            } else {
                // Para WHITE, proxy normal
                proxyRequest($targetUrl);
            }
            break;
            
        case 'redirect':
        default:
            // BLACK: 302 direto a oferta (troca a URL de proposito).
            if ($isBlack) {
                header('Location: ' . $targetUrl);
                exit;
            }
            // WHITE interna: serve INLINE via proxy (URL limpa e no dominio, sem
            // expor o IP do painel). WHITE externa: mantem o 302 para a URL que
            // voce hospeda (comportamento original).
            if ($WHITE_IS_INTERNAL) {
                proxyRequest($WHITE_URL);
            } else {
                header('Location: ' . $WHITE_URL);
                exit;
            }
            break;
    }
    
} else {
    // Erro na API - vai para white page por seguranca.
    if ($WHITE_IS_INTERNAL) {
        proxyRequest($WHITE_URL);
    } else {
        header('Location: ' . $WHITE_URL);
        exit;
    }
}

// ============================================
// FUNCOES
// ============================================

/**
 * TELEMETRIA DE UI E COMPATIBILIDADE (inline, para paginas intermediarias)
 *
 * Retorna o JS (dentro de <script>) que coleta tela, viewport, DPR e suporte a
 * WebGL e despacha para o api.php via navigator.sendBeacon (com fallback para
 * fetch keepalive). O api.php mescla esses dados no registro de roteamento mais
 * recente do mesmo IP, entao os detalhes aparecem JUNTO da linha de motivo (ex.:
 * "Modo Estrito ativo -> White Page") em vez de virar uma linha separada.
 *
 * Roda IMEDIATAMENTE (sem esperar DOMContentLoaded) porque estas paginas
 * redirecionam na sequencia. O sendBeacon foi desenhado para sobreviver ao
 * unload, por isso ele e disparado ANTES do redirecionamento.
 */
function buildTelemetryBeaconJS() {
    // SEED do servidor: o generated tracker define estes globais no seu escopo.
    //  - $API_URL   : endpoint ABSOLUTO do api.php (a white pode estar em iframe/
    //                 proxy/dominio diferente; "api.php" relativo apontaria para o
    //                 dominio da white -> 404 e a telemetria se perdia).
    //  - $visitorIP : IP REAL do carregamento da pagina. No iOS o IPv6 rotaciona
    //                 (privacy extensions), entao o IP do beacon costuma ser outro
    //                 e o merge por IP FALHAVA. Enviamos o IP correto como match_ip.
    global $API_URL, $__selfPath, $CAMPAIGN_SLUG;
    // Endpoint SAME-ORIGIN (?action=gate_log): a white roda em https e o beacon
    // POSTa para a MESMA origem, sem mixed content. O gate_log repassa ao painel.
    $selfPath = (!empty($__selfPath) && is_string($__selfPath)) ? $__selfPath : '';
    if ($selfPath === '') { $selfPath = strtok($_SERVER['REQUEST_URI'] ?? '/', '?') ?: '/'; }
    $seedApi = $selfPath . '?action=gate_log';
    // IP REAL do carregamento via getVisitorIP() (o global $visitorIP ainda nao
    // existe no fluxo gate_white, que da exit antes de defini-lo).
    $seedIp = function_exists('getVisitorIP') ? (string)getVisitorIP() : '';
    $seed = json_encode([
        'api'      => $seedApi,
        'match_ip' => $seedIp,
        'campaign' => isset($CAMPAIGN_SLUG) ? (string)$CAMPAIGN_SLUG : '',
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($seed === false) { $seed = '{}'; }
    $seedScript = '<script>window.__telSeed=' . $seed . ';</script>';

    // NOWDOC: o conteudo JS nao sofre interpolacao PHP. Coleta 2 ondas:
    //  (1) ONDA RAPIDA: tela/viewport/WebGL/chipset -> sobrevive a redirect.
    //  (2) ONDA ENRIQUECIDA (~2.2s): sensores fisicos, biometria de toque, ruido
    //      de audio, bateria e curva de movimento (Lei de Fitts). O api.php mescla
    //      as duas ondas na MESMA linha de log pelo match_ip/IP.
    // Valores avancados sao enviados ja como strings legiveis para nao colidirem
    // com a regra de "0 = placeholder" da mesclagem no backend.
    $js = <<<'JS'
<script>
(function(){
  try {
    // Endpoint SAME-ORIGIN vindo do seed (?action=gate_log): a white roda em https
    // e o beacon posta na MESMA origem, sem mixed content. O gate_log repassa ao
    // painel server-side. So caimos no relativo api.php?action=log se o seed faltar.
    var seed = (window.__telSeed && typeof window.__telSeed === "object") ? window.__telSeed : {};
    var api = (seed.api && seed.api.length) ? seed.api : new URL("api.php?action=log", window.location.href).href;
    var data = { action:"log", reason:"UI Compatibility Diagnostics", timestamp:new Date().toISOString() };
    // IP real do carregamento -> o backend mescla por ele (imune a rotacao de IPv6 no iOS)
    if (seed.match_ip) data.match_ip = seed.match_ip;
    if (seed.campaign) data.campaign = seed.campaign;

    // ---------- TELA / VIEWPORT (anti-zero em WebView TikTok / Safari iOS) ----------
    function pick(){ for(var i=0;i<arguments.length;i++){ var v=Number(arguments[i]); if(v&&v>0) return Math.round(v); } return 0; }
    function measureScreen(){
      var el = document.documentElement || {};
      var sw = pick(window.screen&&screen.width, el.clientWidth, window.innerWidth);
      var sh = pick(window.screen&&screen.height, el.clientHeight, window.innerHeight);
      data.screen_width = sw||null; data.screen_height = sh||null;
      data.viewport_width = pick(window.innerWidth, el.clientWidth)||null;
      data.viewport_height = pick(window.innerHeight, el.clientHeight)||null;
      data.device_pixel_ratio = Number(window.devicePixelRatio)||1;
    }

    // ---------- RUIDO DE HARDWARE E CHIPSET (WebGL Concurrency) ----------
    function collectWebGL(){
      try {
        var c = document.createElement("canvas");
        var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
        data.webgl_supported = !!gl;
        if (navigator.hardwareConcurrency) data.hw_cores = navigator.hardwareConcurrency + " nucleos logicos";
        if (navigator.deviceMemory) data.hw_memory = navigator.deviceMemory + " GB RAM";
        if (gl) {
          var dbg = gl.getExtension("WEBGL_debug_renderer_info");
          if (dbg) {
            data.gpu_vendor = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)||"").slice(0,120);
            data.gpu_renderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)||"").slice(0,160);
          }
          data.gl_limits = "Textura max " + gl.getParameter(gl.MAX_TEXTURE_SIZE)
            + " / Unidades " + gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS)
            + " / Varying " + gl.getParameter(gl.MAX_VARYING_VECTORS);
        }
      } catch(e){}
    }

    // ---------- RUIDO DE HARDWARE DE AUDIO (AudioContext fingerprint) ----------
    function collectAudio(cb){
      try {
        var AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if(!AC){ cb(); return; }
        var ctx = new AC(1, 44100, 44100);
        var osc = ctx.createOscillator(); osc.type="triangle"; osc.frequency.value=10000;
        var comp = ctx.createDynamicsCompressor();
        osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
        var done=false; function finish(){ if(done)return; done=true; cb(); }
        ctx.oncomplete = function(ev){
          try { var buf=ev.renderedBuffer.getChannelData(0); var s=0; for(var i=4000;i<5000;i++){ s+=Math.abs(buf[i]); } data.audio_fp = s.toString().slice(0,24); } catch(e){}
          finish();
        };
        ctx.startRendering();
        setTimeout(finish, 500);
      } catch(e){ cb(); }
    }

    // ---------- STATUS REAL DE BATERIA (Battery API) ----------
    function collectBattery(cb){
      try {
        if (navigator.getBattery) {
          navigator.getBattery().then(function(b){
            var pct = Math.round((b.level||0)*100);
            var estado = b.charging ? "Carregando" : "Descarregando";
            var extra = "";
            if (b.charging && isFinite(b.chargingTime) && b.chargingTime>0) extra = " • cheia em ~" + Math.round(b.chargingTime/60) + "min";
            else if (!b.charging && isFinite(b.dischargingTime) && b.dischargingTime>0) extra = " • dura ~" + Math.round(b.dischargingTime/60) + "min";
            data.battery_status = pct + "% • " + estado + extra;
            cb();
          }).catch(function(){ cb(); });
        } else { cb(); }
      } catch(e){ cb(); }
    }

    // ---------- SENSORES FISICOS (Acelerometro & Giroscopio) ----------
    var mo = { n:0, maxA:0, maxR:0, last:null };
    function onMotion(e){
      mo.n++;
      var a = e.accelerationIncludingGravity || e.acceleration;
      if(a){ var m=Math.sqrt((a.x||0)*(a.x||0)+(a.y||0)*(a.y||0)+(a.z||0)*(a.z||0)); if(m>mo.maxA) mo.maxA=m; }
      var r = e.rotationRate;
      if(r){ var rm=Math.abs(r.alpha||0)+Math.abs(r.beta||0)+Math.abs(r.gamma||0); if(rm>mo.maxR) mo.maxR=rm; }
    }
    function onOrient(e){ mo.last=[Math.round(e.alpha||0),Math.round(e.beta||0),Math.round(e.gamma||0)]; }
    function startSensors(){
      try {
        data.__motionSupport = (typeof DeviceMotionEvent!=="undefined");
        window.addEventListener("devicemotion", onMotion, {passive:true});
        window.addEventListener("deviceorientation", onOrient, {passive:true});
      } catch(e){}
    }
    // iOS 13+ exige um GESTO do usuario para liberar acelerometro/giroscopio via
    // DeviceMotionEvent.requestPermission(). Sem isso o WebKit devolve zero leituras
    // ("Suportado, sem leituras"). Pedimos no primeiro toque; se concedido, os
    // listeners passam a receber dados reais para a onda tardia.
    var sensorPermAsked=false;
    function requestSensorPermission(){
      if(sensorPermAsked) return; sensorPermAsked=true;
      try {
        if(typeof DeviceMotionEvent!=="undefined" && typeof DeviceMotionEvent.requestPermission==="function"){
          DeviceMotionEvent.requestPermission().then(function(res){
            data.sensor_permission = (res==="granted") ? "Concedida (gesto)" : "Negada (gesto)";
            if(res==="granted"){ startSensors(); }
          }).catch(function(){ data.sensor_permission="Erro no pedido"; });
        }
      } catch(e){}
    }
    function stopSensors(){
      try { window.removeEventListener("devicemotion",onMotion); window.removeEventListener("deviceorientation",onOrient); } catch(e){}
    }
    function finishSensors(){
      if (mo.n>0) {
        data.sensor_status = "Vivo • " + mo.n + " leituras • accel max " + mo.maxA.toFixed(2) + " • rot max " + mo.maxR.toFixed(2);
        data.interaction_sensor = "Sim";
      } else if (data.__motionSupport) {
        data.sensor_status = "Suportado, sem leituras (sem permissao/gesto ou ambiente estatico)";
        data.interaction_sensor = "Nao";
      } else {
        data.sensor_status = "Nao suportado (provavel desktop/headless)";
        data.interaction_sensor = "Nao";
      }
      if (mo.last) data.sensor_orientation = "a" + mo.last[0] + " b" + mo.last[1] + " g" + mo.last[2];
      delete data.__motionSupport;
    }

    // ---------- BIOMETRIA DO TOQUE + CURVA DE MOVIMENTO (Lei de Fitts) ----------
    var tc = { n:0, maxT:0, fSum:0, fN:0, rSum:0, rN:0 };
    var mv = { pts:[], hes:0, peak:0, first:0 };
    function onTouch(e){
      tc.n++;
      if(e.touches && e.touches.length>tc.maxT) tc.maxT=e.touches.length;
      var t = e.touches && e.touches[0];
      if(t){
        if(typeof t.force==="number" && t.force>0){ tc.fSum+=t.force; tc.fN++; }
        var rx=t.radiusX||0, ry=t.radiusY||0;
        if(rx||ry){ tc.rSum+=(rx+ry)/2; tc.rN++; }
      }
    }
    function track(x,y){
      var now = (window.performance&&performance.now)?performance.now():Date.now();
      if(!mv.first) mv.first=now;
      var pts = mv.pts;
      if(pts.length){
        var p=pts[pts.length-1], dt=now-p.t;
        var dist=Math.sqrt((x-p.x)*(x-p.x)+(y-p.y)*(y-p.y));
        if(dt>0){ var v=dist/dt; if(v>mv.peak) mv.peak=v; }
        if(dt>120 && dt<2000) mv.hes++;   // hesitacao: micro-pausa no meio do gesto
      }
      pts.push({x:x,y:y,t:now});
      if(pts.length>240) pts.shift();
    }
    // Marca de interacao mais recente. Se o usuario mexer DEPOIS da onda tardia,
    // agendamos uma onda extra para nao perder a curva de movimento/toque.
    var lastInteractionAt=0;
    function markInteraction(){ lastInteractionAt=Date.now(); }
    function onPointer(e){ track(e.clientX, e.clientY); markInteraction(); }
    function onTouchMove(e){ var t=e.touches&&e.touches[0]; if(t) track(t.clientX,t.clientY); onTouch(e); markInteraction(); }
    function onFirstGesture(){ requestSensorPermission(); markInteraction(); }
    function startMovement(){
      try {
        window.addEventListener("pointermove", onPointer, {passive:true});
        window.addEventListener("mousemove", onPointer, {passive:true});
        window.addEventListener("touchstart", onTouch, {passive:true});
        window.addEventListener("touchmove", onTouchMove, {passive:true});
        // Primeiro gesto de qualquer tipo -> pede permissao de sensor (iOS)
        window.addEventListener("touchstart", onFirstGesture, {passive:true, once:true});
        window.addEventListener("pointerdown", onFirstGesture, {passive:true, once:true});
        window.addEventListener("click", onFirstGesture, {passive:true, once:true});
      } catch(e){}
    }
    function stopMovement(){
      try {
        window.removeEventListener("pointermove",onPointer);
        window.removeEventListener("mousemove",onPointer);
        window.removeEventListener("touchstart",onTouch);
        window.removeEventListener("touchmove",onTouchMove);
      } catch(e){}
    }
    function finishMovement(){
      // Biometria do toque
      if (tc.n>0) {
        var bio = tc.n + " toques • max " + tc.maxT + " dedos";
        if (tc.fN) bio += " • forca media " + (tc.fSum/tc.fN).toFixed(3);
        if (tc.rN) bio += " • area ~" + (tc.rSum/tc.rN).toFixed(1) + "px";
        data.touch_bio = bio;
      }
      // Curva de movimento / Lei de Fitts
      var pts = mv.pts, humano = false;
      if (pts.length>=3) {
        var path=0;
        for(var i=1;i<pts.length;i++){ path+=Math.sqrt((pts[i].x-pts[i-1].x)*(pts[i].x-pts[i-1].x)+(pts[i].y-pts[i-1].y)*(pts[i].y-pts[i-1].y)); }
        var straight=Math.sqrt((pts[pts.length-1].x-pts[0].x)*(pts[pts.length-1].x-pts[0].x)+(pts[pts.length-1].y-pts[0].y)*(pts[pts.length-1].y-pts[0].y));
        var eff = path>0 ? (straight/path) : 0;  // ~1.0 = reta perfeita (robotico) ; <0.95 = curva humana
        data.move_curve = "eficiencia " + eff.toFixed(3) + " • hesitacoes " + mv.hes + " • pico " + mv.peak.toFixed(2) + "px/ms • " + pts.length + " amostras";
        humano = (mv.hes>0 || eff<0.95);
      } else {
        data.move_curve = "Sem movimento capturado";
      }
      data.interaction_verdict = humano ? "Humano provavel (movimento curvo/hesitante)" : "Sem interacao humana clara";
    }

    // ---------- DESPACHO ----------
    function dispatch(){
      var body = JSON.stringify(data);
      try { if(navigator.sendBeacon && navigator.sendBeacon(api, new Blob([body],{type:"application/json"}))) return; } catch(e){}
      try { fetch(api,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:body,keepalive:true}).catch(function(){}); } catch(e){}
    }
    var sent1=false, finalAt=0, sent3=false;
    function quickSend(){ if(sent1) return; measureScreen(); if(!data.screen_width && !data.viewport_width) return; sent1=true; dispatch(); }
    // Onda tardia: recomputa sensores/movimento mas MANTEM a escuta ativa, para
    // que uma onda extra possa capturar interacao que so acontece depois.
    function finalSend(){ finishSensors(); finishMovement(); measureScreen(); finalAt=Date.now(); dispatch(); }
    // Onda extra: so vale a pena se houve interacao humana DEPOIS da onda tardia
    // (ex.: usuario so encostou no dedo em ~3s). Recomputa a curva e reenvia.
    function extraSend(){
      if(sent3) return;
      var mexeuDepois = lastInteractionAt>0 && (finalAt===0 || lastInteractionAt>=finalAt-50);
      stopSensors(); stopMovement();
      if(mexeuDepois){ sent3=true; finishSensors(); finishMovement(); measureScreen(); data.telemetry_wave="extra (interacao tardia)"; dispatch(); }
    }

    // ---------- ARRANQUE ----------
    measureScreen(); collectWebGL(); startSensors(); startMovement();
    collectAudio(function(){ collectBattery(function(){}); });

    // Onda rapida (garante os essenciais mesmo com redirect)
    if(window.requestAnimationFrame){ requestAnimationFrame(function(){ requestAnimationFrame(quickSend); }); }
    setTimeout(quickSend, 60); setTimeout(quickSend, 250);
    // Onda enriquecida apos janela de coleta dos sinais assincronos
    setTimeout(finalSend, 2500);
    // Onda extra: janela maior escutando toque/movimento e sensores pos-permissao
    setTimeout(extraSend, 5200);
    // Redes de seguranca no unload: envia o que houver
    window.addEventListener("pagehide", function(){ quickSend(); finalSend(); }, {once:true});
    window.addEventListener("beforeunload", function(){ quickSend(); finalSend(); }, {once:true});
  } catch(e){}
})();
</script>
JS;
    // O seed precisa vir ANTES do coletor para ja estar disponivel na execucao.
    return $seedScript . $js;
}

/**
 * GATE DE INTERACAO
 * Renderiza uma pagina onde a WHITE fica por tras (iframe) e uma capa por cima.
 * A Black so e liberada (redirect) depois de um sinal humano real: toque,
 * rolagem, wheel ou micro-movimento de giroscopio. Um bot que apenas renderiza
 * e vai embora NAO gera esses sinais e permanece na White (a capa some no
 * timeout, revelando a White utilizavel). O codigo-fonte nunca contem a Black.
 */
function renderInteractionGate($whiteUrl, $blackUrl, $imgUrl, $timeout, $timeoutToBlack = false, $requireTrusted = false, $apiUrl = '', $campaignSlug = '', $utmSource = '', $visitorIp = '') {
    $wp  = htmlspecialchars($whiteUrl, ENT_QUOTES);
    $img = trim((string)$imgUrl);
    $imgEsc = htmlspecialchars($img, ENT_QUOTES);
    $t   = (float)$timeout;
    $reqJs = $requireTrusted ? 'true' : 'false';
    $tbJs  = $timeoutToBlack ? 'true' : 'false';
    
    // A URL DA BLACK PAGE FOI REMOVIDA DO CÓDIGO-FONTE AQUI
    
    $apiJs  = json_encode($apiUrl);
    $slugJs = json_encode($campaignSlug);
    $utmJs  = json_encode($utmSource);
    $ipJs   = json_encode($visitorIp);

if ($img === '#ROLETA') {
        // ==========================================
        // CAPA INTERATIVA: ROLETA DE DESCONTO (40% OFF)
        // ==========================================
        $coverInner = '
        <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;width:100%;font-family:sans-serif;padding:15px;box-sizing:border-box;">
            <div style="text-align:center;width:100%;">
                <h2 id="roleta-titulo" style="color:#ffffff;font-size:22px;margin:0 0 10px 0;">🎉 Gire e Ganhe seu Desconto!</h2>
                <p id="roleta-sub" style="color:#8b949e;font-size:14px;margin:0 0 25px 0;">Toque no botão para sortear seu cupom exclusivo</p>

                <div style="position:relative;width:260px;height:260px;flex-shrink:0;margin:0 auto 24px auto;">
                    <div style="position:absolute;top:-14px;left:50%;transform:translateX(-50%);width:0;height:0;border-left:13px solid transparent;border-right:13px solid transparent;border-top:22px solid #ffb800;z-index:10;filter:drop-shadow(0 2px 4px rgba(0,0,0,0.4));"></div>

                    <div style="position:absolute;inset:0;border-radius:50%;padding:8px;background:linear-gradient(135deg,#ff7a3d,#e42c46);box-shadow:0 0 25px rgba(0,0,0,0.6);box-sizing:border-box;">
                        <div style="width:100%;height:100%;border-radius:50%;background:#fff;"></div>
                    </div>

                    <div id="roleta-disco" style="position:absolute;inset:14px;border-radius:50%;overflow:hidden;background:conic-gradient(from -22.5deg, #fff3e9 0deg 45deg, #e42c46 45deg 90deg, #fff3e9 90deg 135deg, #e42c46 135deg 180deg, #fff3e9 180deg 225deg, #e42c46 225deg 270deg, #fff3e9 270deg 315deg, #e42c46 315deg 360deg);transition:transform 4.5s cubic-bezier(0.12,0.75,0.06,1);">
                        <span style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%) rotate(0deg) translateY(-82px);color:#e42c46;font-size:12px;font-weight:900;text-transform:uppercase;white-space:nowrap;">5% OFF</span>
                        <span style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%) rotate(45deg) translateY(-82px);color:#fff3e9;font-size:11px;font-weight:900;text-transform:uppercase;white-space:nowrap;">Quase!</span>
                        <span style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%) rotate(90deg) translateY(-82px);color:#e42c46;font-size:17px;font-weight:900;text-transform:uppercase;white-space:nowrap;">40% OFF</span>
                        <span style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%) rotate(135deg) translateY(-82px);color:#fff3e9;font-size:11px;font-weight:900;text-transform:uppercase;white-space:nowrap;text-align:center;line-height:1.2;">Tente<br>de novo</span>
                        <span style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%) rotate(180deg) translateY(-82px);color:#e42c46;font-size:12px;font-weight:900;text-transform:uppercase;white-space:nowrap;">10% OFF</span>
                        <span style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%) rotate(225deg) translateY(-82px);color:#fff3e9;font-size:11px;font-weight:900;text-transform:uppercase;white-space:nowrap;">Nada</span>
                        <span style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%) rotate(270deg) translateY(-82px);color:#e42c46;font-size:11px;font-weight:900;text-transform:uppercase;white-space:nowrap;text-align:center;line-height:1.2;">Passou<br>perto</span>
                        <span style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%) rotate(315deg) translateY(-82px);color:#fff3e9;font-size:12px;font-weight:900;text-transform:uppercase;white-space:nowrap;">15% OFF</span>
                    </div>

                    <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:64px;height:64px;border-radius:50%;background:#ffffff;box-shadow:0 0 0 4px rgba(228,44,70,0.15),0 4px 10px rgba(0,0,0,0.35);z-index:5;display:flex;align-items:center;justify-content:center;">
                        <span style="font-size:12px;font-weight:900;letter-spacing:0.04em;color:#e42c46;text-transform:uppercase;">Gire!</span>
                    </div>
                </div>

                <button id="btn-girar" onclick="girarRoleta()" style="background:linear-gradient(90deg,#ff7a3d,#e42c46);color:#ffffff;border:none;padding:18px 30px;font-size:16px;font-weight:bold;border-radius:50px;cursor:pointer;width:100%;max-width:280px;box-shadow:0 4px 15px rgba(228,44,70,0.5);text-transform:uppercase;letter-spacing:0.05em;">Girar agora</button>

                <button id="btn-ir-oferta" onclick="window.__gateGoBlack&&window.__gateGoBlack()" style="display:none;background:linear-gradient(90deg,#ff7a3d,#e42c46);color:#ffffff;border:none;padding:18px 30px;font-size:16px;font-weight:bold;border-radius:50px;cursor:pointer;width:100%;max-width:280px;box-shadow:0 0 15px rgba(228,44,70,0.6);">👉 IR PARA A OFERTA COM 40%</button>

                <style>
                    #btn-ir-oferta { animation: pulsar 1.2s infinite; }
                    @keyframes pulsar { 0% { transform: scale(1); } 50% { transform: scale(1.05); } 100% { transform: scale(1); } }
                </style>
                <script>
                    function girarRoleta() {
                        var btn = document.getElementById("btn-girar");
                        if (btn.disabled) return;
                        btn.disabled = true;
                        btn.style.opacity = "0.6";
                        btn.style.cursor = "not-allowed";
                        btn.textContent = "Girando...";

                        // Registra sinal humano real para o gate de interacao nao bloquear o clique
                        if (window.__gateRecMove) {
                            window.__gateRecMove(130, 420);
                            window.__gateRecMove(133, 423);
                            window.__gateRecMove(129, 426);
                        }

                        // O usuario ja provou interacao real ao tocar em "Girar agora".
                        // Estende o timeout de fallback (que revelaria a White) para dar
                        // tempo de sobra a animacao de 4.5s + o segundo clique em
                        // "Ver oferta", mesmo se a pagina tiver demorado a carregar por
                        // causa de internet fraca ou do navegador interno do TikTok.
                        if (window.__gateExtendTimeout) {
                            window.__gateExtendTimeout(12);
                        }

                        var voltas = 6;
                        var indiceVencedor = 2; // posicao do "40% OFF" no disco
                        var anguloFatia = 45;
                        var jitter = (Math.random() - 0.5) * (anguloFatia * 0.4);
                        var rotacaoFinal = (voltas * 360) - (indiceVencedor * anguloFatia) + jitter;

                        document.getElementById("roleta-disco").style.transform = "rotate(" + rotacaoFinal + "deg)";

                        setTimeout(function() {
                            document.getElementById("roleta-titulo").textContent = "🎉 Parabens! Voce ganhou 40% OFF!";
                            document.getElementById("roleta-titulo").style.color = "#e42c46";
                            document.getElementById("roleta-sub").textContent = "Seu cupom foi aplicado automaticamente.";
                            btn.style.display = "none";
                            document.getElementById("btn-ir-oferta").style.display = "inline-block";
                        }, 4500);
                    }
                </script>
            </div>
        </div>';
        $coverBg = '#0d1117'; // Fundo escuro
    } elseif ($img === '#BOTAO') {
        $coverInner = '
        <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;width:100%;font-family:sans-serif;padding:20px;box-sizing:border-box;">
            <div style="text-align:center;max-width:360px;width:100%;">
                <div style="font-size:14px;color:#8b949e;margin-bottom:15px;text-transform:uppercase;letter-spacing:1px;">Oferta Exclusiva Liberada</div>
                <h2 style="color:#ffffff;font-size:24px;margin:0 0 30px 0;">Clique abaixo para desbloquear seu acesso</h2>
                <button onclick="window.__gateGoBlack&&window.__gateGoBlack()" style="background: linear-gradient(135deg, #ff0050, #00f2fe);color: #ffffff;border: none;padding: 20px 36px;font-size: 18px;font-weight: bold;border-radius: 50px;cursor: pointer;width: 100%;max-width: 280px;box-shadow: 0 0 20px rgba(255, 0, 80, 0.6);outline: none;animation: pulsarBtn 1.5s infinite;">
                    👉 VER OFERTA
                </button>
                <style>
                    @keyframes pulsarBtn { 0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(255, 0, 80, 0.7); } 70% { transform: scale(1.05); box-shadow: 0 0 0 15px rgba(255, 0, 80, 0); } 100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(255, 0, 80, 0); } }
                </style>
            </div>
        </div>';
        $coverBg = '#0d1117';
    } elseif ($img !== '') {
        $coverInner = '<img src="' . $imgEsc . '" alt="" draggable="false">';
        $coverBg = '#ffffff';
    } else {
        $coverInner = '';
        $coverBg = 'transparent';
    }

    $gateSelfPath = strtok($_SERVER['REQUEST_URI'] ?? '/', '?');
    if ($gateSelfPath === '' || $gateSelfPath === false) { $gateSelfPath = '/'; }
    $wp = htmlspecialchars($gateSelfPath . '?action=gate_white', ENT_QUOTES);

    header('Content-Type: text/html; charset=UTF-8');
    header('X-Robots-Tag: noindex, nofollow', true);
    echo '<!DOCTYPE html><html lang="pt-BR"><head>';
    echo '<meta charset="UTF-8">';
    echo '<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">';
    echo '<meta name="robots" content="noindex,nofollow">';
    echo '<title>Carregando...</title>';
    echo '<style>';
    echo '*{margin:0;padding:0;box-sizing:border-box}';
    echo 'html,body{width:100%;height:100%;overflow:hidden;background:#fff;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}';
    echo '#wp{position:fixed;inset:0;width:100%;height:100%;border:0;z-index:1}';
    echo '#cover{position:fixed;inset:0;z-index:2;background:' . $coverBg . ';overflow-y:auto;-webkit-overflow-scrolling:touch;touch-action:pan-y}';
    echo '#cover img{width:100%;height:auto;display:block;pointer-events:none;-webkit-user-select:none;user-select:none}';
    echo '#cover.gate-hidden{display:none}';
    echo '</style></head><body>';
    echo '<iframe id="wp" src="' . $wp . '" frameborder="0" allowfullscreen></iframe>';
    echo '<div id="cover">' . $coverInner . '</div>';
    echo '<script>';
    echo '(function(){';
    
    // VARIÁVEL BLACK REMOVIDA DA RENDERIZAÇÃO JS
    echo 'var done=false,T=' . $t . ',REQ=' . $reqJs . ',TB=' . $tbJs . ';';
    
    echo 'var API=(location.origin+location.pathname),SLUG=' . $slugJs . ',UTM=' . $utmJs . ',VIP=' . $ipJs . ';';
    echo 'var cover=document.getElementById("cover");';
    echo 'var t0=Date.now();';
    echo 'var MIN_DWELL=900,NEED_SAMPLES=3,NEED_DIST=30,NEED_SPAN=220,PASS_SCORE=3;';
    echo 'var flags=[];function flag(f){if(flags.indexOf(f)<0)flags.push(f);}';

    echo 'function detectAuto(){try{';
    echo 'if(navigator.webdriver===true)flag("webdriver");';
    echo 'if(window._phantom||window.__nightmare||window.callPhantom)flag("phantom");';
    echo 'if(window.domAutomation||window.domAutomationController)flag("domauto");';
    echo 'if(/HeadlessChrome/i.test(navigator.userAgent||""))flag("headlessua");';
    echo 'if(/Chrome\//.test(navigator.userAgent||"")&&!window.chrome&&!/Mobile|Android|iPhone/i.test(navigator.userAgent||""))flag("nochrome");';
    // "nolang" (navigator.languages vazio) e "hc0" (hardwareConcurrency===0)
    // tem FALSOS POSITIVOS CONHECIDOS dentro de in-app webviews de apps como
    // TikTok/Instagram no iOS: por sandboxing/privacidade, essas APIs podem
    // retornar vazio/zero mesmo em visitantes humanos reais, sobretudo nos
    // primeiros instantes de inicializacao do webview (exatamente quando a
    // pagina "demora um pouco pra carregar"). Sem esta exclusao de mobile,
    // esses visitantes reais eram marcados como isAuto=true e a capa/roleta
    // era escondida em 60ms (setTimeout(revealWhite,60) mais abaixo), indo
    // direto pra White sem o usuario nunca ver ou poder interagir com nada.
    // A mesma exclusao ja existe em "nochrome" e "noouter" acima/abaixo;
    // aqui so a estendemos as duas checagens que estavam sem ela.
    echo 'if((!navigator.languages||navigator.languages.length===0)&&!/Mobile|Android|iPhone/i.test(navigator.userAgent||""))flag("nolang");';
    echo 'if(navigator.hardwareConcurrency===0&&!/Mobile|Android|iPhone/i.test(navigator.userAgent||""))flag("hc0");';
    echo 'if(navigator.deviceMemory && navigator.deviceMemory > 16 && /Mobile|Android|iPhone/i.test(navigator.userAgent||""))flag("ram_fake");';
    echo 'if(/Chrome\/15[0-9]\.0\.0\.0/.test(navigator.userAgent||""))flag("fake_chrome");';
    echo 'if((window.outerWidth===0||window.outerHeight===0)&&!/Mobile|Android|iPhone/i.test(navigator.userAgent||""))flag("noouter");';
    echo 'try{var c=document.createElement("canvas");var gl=c.getContext("webgl")||c.getContext("experimental-webgl");if(gl){var dbg=gl.getExtension("WEBGL_debug_renderer_info");if(dbg){var r=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)||"";if(/swiftshader|llvmpipe|virtualbox|vmware/i.test(r))flag("wgl_emu");}}}catch(e){}';
    echo '}catch(e){}return flags.length>0;}';
    echo 'var isAuto=detectAuto();';
    
    echo 'var samples=[],lastX=null,lastY=null,dist=0,firstT=0,lastT=0,lastSY=null;';
    echo 'function mark(){var now=Date.now();if(!firstT)firstT=now;lastT=now;samples.push(now);}';
    echo 'function recMove(x,y){if(lastX!==null){var dx=x-lastX,dy=y-lastY;dist+=Math.sqrt(dx*dx+dy*dy);}lastX=x;lastY=y;mark();}';
    echo 'function pt(e){if(e.touches&&e.touches[0])return[e.touches[0].clientX,e.touches[0].clientY];if(typeof e.clientX==="number")return[e.clientX,e.clientY];return null;}';

    // ---- NOVA Tolerância Zero Blindada ----
    echo 'var batBonus = false, isEmu = false;';
    echo 'try{if(navigator.getBattery){navigator.getBattery().then(function(b){';
    echo '  if(b.level<0.99||!b.charging){batBonus=true;}';
    // Morte súbita para baterias falsas de datacenter (Ex: 93% descarregando em menos de 5 min)
    echo '  if(!b.charging && b.dischargingTime < 300 && b.level > 0.30){isEmu=true;}';
    echo '});}}catch(e){}';
    
    echo 'var isClick = false;';
    
    echo 'function human(){';
    echo 'if(isEmu)return false;'; // Bot da bateria pego no pulo
    echo 'if((Date.now()-t0)<500)return false;'; // 500ms cravados de exigência biológica
    echo 'if(isAuto)return false;';
    
    echo 'if(samples.length>=5){var g=[],i;for(i=1;i<samples.length;i++)g.push(samples[i]-samples[i-1]);var m=g.reduce(function(a,b){return a+b;},0)/g.length;var v=g.reduce(function(a,b){return a+(b-m)*(b-m);},0)/g.length;if(v<=2){flag("periodic");}}';
    echo 'if(flags.indexOf("periodic")>-1)return false;';
    
    // NENHUM dedo humano marca 0 pixels. O "esmagamento" da carne na tela gera no mínimo de 2 a 3 pixels.
    echo 'var reqDist = isClick ? 3 : (batBonus ? 15 : NEED_DIST);';
    echo 'var reqSpan = isClick ? 20 : NEED_SPAN;';
    echo 'var reqSamp = isClick ? 2 : NEED_SAMPLES;';
    
    echo 'if(samples.length<reqSamp)return false;';
    echo 'if(dist<reqDist)return false;';
	// Anti-Macro: Bloqueia o robô exato que simula 11 toques em ~2 segundos no TikTok
    echo 'if(samples.length === 11 && dist >= 160 && dist <= 190 && (lastT-firstT) >= 1900 && (lastT-firstT) <= 2200) return false;';
    echo 'if((lastT-firstT)<reqSpan)return false;';
    
    echo 'document.cookie="cmdr_approved=1;path=/;max-age=1800;SameSite=Lax";';
    echo 'return true;}';
    
    echo 'function beh(){return "n="+samples.length+";d="+Math.round(dist)+";t="+(Date.now()-t0)+(flags.length?(";f="+flags.join("|")):"");}';
    echo 'function sendResolve(outcome){try{if(navigator.sendBeacon){var fd=new FormData();fd.append("action","gate_resolve");fd.append("outcome",outcome);fd.append("campaign",SLUG);fd.append("utm_source",UTM);if(VIP){fd.append("ip",VIP);}fd.append("ua",navigator.userAgent);fd.append("referer",document.referrer||"");fd.append("beh",beh());fd.append("flags",flags.join("|"));navigator.sendBeacon(API,fd);}}catch(e){}}';
    
    // O Redirecionamento é 100% Server-Side agora. O JavaScript não sabe qual é o link da Black.
    echo 'function gateGoUrl(){return API+"?action=gate_go&campaign="+encodeURIComponent(SLUG)+"&utm_source="+encodeURIComponent(UTM)+(VIP?"&ip="+encodeURIComponent(VIP):"")+"&beh="+encodeURIComponent(beh())+"&flags="+encodeURIComponent(flags.join("|"));}';
    
    echo 'function goBlack(){if(done)return;if(!human())return;done=true;window.location.replace(gateGoUrl());}';
    echo 'function goBlackTimeout(){if(done)return;if(isAuto){revealWhite();return;}done=true;window.location.replace(gateGoUrl());}';
    echo 'function revealWhite(){if(done)return;done=true;sendResolve("white");if(cover){cover.className="gate-hidden";}}';
    // Timer do fallback (revela a White, ou vai pra Black se TB=true) guardado
    // numa variavel para poder ser CANCELADO/ESTENDIDO quando o usuario ja
    // comecou a interagir com a capa (ex.: girou a roleta). Isso evita que uma
    // pagina lenta (internet fraca, in-app browser do TikTok) "coma" o tempo
    // do timeout antes do usuario terminar o fluxo de girar + clicar em
    // "Ver oferta", o que fazia a capa ser escondida (ida direto pra White)
    // mesmo com o visitante ja engajado.
    echo 'var gateTimer=null;';
    echo 'function armTimer(seconds){if(gateTimer){clearTimeout(gateTimer);gateTimer=null;}if(done||!(seconds>0))return;gateTimer=setTimeout(function(){if(done)return;if(TB){goBlackTimeout();}else{revealWhite();}},seconds*1000);}';
    // A CAPA (roleta / #BOTAO / imagem) e injetada no HTML antes deste
    // <script>, mas isso NAO significa que ela ja apareceu na tela do
    // usuario: se a capa usa uma <img>, o navegador ainda precisa BAIXAR
    // essa imagem (pode demorar em rede fraca / navegador interno do
    // TikTok), e mesmo sem imagem o webview pode levar um instante extra
    // pra efetivamente pintar o conteudo. Se o timer T comecasse a contar
    // aqui, o "relogio de 8s" corria escondido enquanto a tela ainda estava
    // branca/carregando, e podia estourar (goBlackTimeout/revealWhite) antes
    // do usuario ter visto qualquer coisa pra interagir -- caindo direto na
    // White. whenCoverReady() so libera o callback (armar o timer inicial)
    // depois que a capa de fato terminou de carregar/pintar: espera todas as
    // <img> dentro de #cover carregarem (load/error) e, alem disso, espera o
    // "load" da janela + dois frames de pintura (rAF x2) como garantia extra
    // pros casos sem imagem (roleta/#BOTAO, que sao só HTML/CSS inline).
    echo 'function whenCoverReady(cb){';
    echo '  var imgs=cover?cover.querySelectorAll("img"):[];';
    echo '  var afterPaint=function(){requestAnimationFrame(function(){requestAnimationFrame(cb);});};';
    echo '  var afterLoad=function(){if(document.readyState==="complete"){afterPaint();}else{window.addEventListener("load",afterPaint,{once:true});}};';
    echo '  if(!imgs||imgs.length===0){afterLoad();return;}';
    echo '  var pending=imgs.length,settled=false;';
    echo '  function finish(){if(settled)return;settled=true;afterLoad();}';
    echo '  var maxWait=setTimeout(finish,15000);'; // seguranca: nunca trava o timer pra sempre se uma imagem nunca disparar load/error
    echo '  Array.prototype.forEach.call(imgs,function(im){';
    echo '    if(im.complete){pending--;}else{';
    echo '      im.addEventListener("load",function(){if(--pending<=0){clearTimeout(maxWait);finish();}},{once:true});';
    echo '      im.addEventListener("error",function(){if(--pending<=0){clearTimeout(maxWait);finish();}},{once:true});';
    echo '    }';
    echo '  });';
    echo '  if(pending<=0){clearTimeout(maxWait);finish();}';
    echo '}';
    // Expoe as funcoes internas do gate para os botoes da capa (roleta) chamarem com onclick
    echo 'window.__gateGoBlack=goBlack;window.__gateMark=mark;window.__gateRecMove=recMove;';
    echo 'window.__gateCancelTimeout=function(){armTimer(0);};';
    echo 'window.__gateExtendTimeout=function(extra){armTimer((typeof extra==="number"&&extra>0)?extra:12);};';
    
    // Qualquer sinal REAL (isTrusted) de toque/scroll/clique reinicia o
    // relogio do timeout para os T segundos completos novamente. Isso
    // transforma T de um "prazo fixo desde o carregamento do script" em um
    // "prazo de INATIVIDADE" -- ou seja, só cai em White/timeout se o
    // visitante ficar T segundos sem fazer absolutamente nada. Isso resolve
    // o caso de internet lenta / navegador do TikTok: se a pagina demorou
    // 5s pra carregar e so depois disso o usuario tocou na tela, o toque
    // renova os T segundos a partir dali, em vez de deixar o relogio antigo
    // (que já tinha comecado a contar desde o load do script) estourar
    // antes mesmo do primeiro toque acontecer.
    echo 'function onMove(e){if(e&&e.isTrusted===false){flag("untrusted");return;}var p=pt(e);if(p)recMove(p[0],p[1]);armTimer(T);goBlack();}';
    echo 'function onScroll(e){if(e&&e.isTrusted===false){flag("untrusted");return;}var sy=(window.pageYOffset||document.documentElement.scrollTop||0);if(lastSY!==null){dist+=Math.abs(sy-lastSY);}lastSY=sy;mark();armTimer(T);goBlack();}';
    echo 'function onClick(e){if(e&&e.isTrusted===false){flag("untrusted");return;}isClick=true;mark();armTimer(T);goBlack();}';
    
    echo 'var opt={passive:true};';
    echo '["touchstart","pointerdown","touchmove","pointermove","mousemove"].forEach(function(ev){window.addEventListener(ev,onMove,opt);});';
    echo '["scroll","wheel"].forEach(function(ev){window.addEventListener(ev,onScroll,opt);});';
    echo '["touchend","pointerup","click"].forEach(function(ev){window.addEventListener(ev,onClick,opt);});';
    
    echo 'if(cover){';
    echo '  cover.addEventListener("touchstart",onMove,opt);';
    echo '  cover.addEventListener("touchmove",onMove,opt);';
    echo '  cover.addEventListener("touchend",onClick,opt);';
    echo '  cover.addEventListener("click",onClick,opt);';
    echo '  cover.addEventListener("scroll",onScroll,opt);';
    echo '}';
    
    echo 'if(isAuto){setTimeout(revealWhite,60);}';
    // O timer inicial de T segundos so comeca a valer DEPOIS que a capa
    // (roleta, #BOTAO ou imagem) realmente apareceu na tela -- nao no
    // instante em que o script foi parseado. Assim, pagina lenta pra
    // carregar (rede fraca / navegador do TikTok) nao consome os segundos
    // do usuario antes dele conseguir ver e interagir com a capa.
    echo 'if(T>0){whenCoverReady(function(){armTimer(T);});}';
    echo '})();';
    echo '</script>';
    echo '</body></html>';
}

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

function getVisitorCountry($clientCountry = '', $clientLanguages = '') {
    // METODO 1: Cloudflare (a pagina publicada fica atras do CF e ve o IP REAL do visitante)
    if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
        $c = strtoupper(trim($_SERVER['HTTP_CF_IPCOUNTRY']));
        if (strlen($c) === 2 && $c !== 'XX' && $c !== 'T1') { return $c; }
    }
    // METODO 2: Vercel
    if (!empty($_SERVER['HTTP_X_VERCEL_IP_COUNTRY'])) {
        $c = strtoupper(trim($_SERVER['HTTP_X_VERCEL_IP_COUNTRY']));
        if (strlen($c) === 2) { return $c; }
    }
    // METODO 3: outros headers de geo do servidor
    foreach (['GEOIP_COUNTRY_CODE','HTTP_X_COUNTRY_CODE','HTTP_X_GEO_COUNTRY','HTTP_X_REAL_COUNTRY'] as $h) {
        if (!empty($_SERVER[$h])) {
            $c = strtoupper(trim($_SERVER[$h]));
            if (strlen($c) === 2 && $c !== 'XX') { return $c; }
        }
    }
    // METODO 4 (GLOBAL): pais detectado pelo navegador do visitante (timezone) na FASE 2
    // Serve de fallback caso o header de geo do Cloudflare nao chegue.
    $clientCountry = strtoupper(trim($clientCountry));
    if (preg_match('/^[A-Z]{2}$/', $clientCountry) && $clientCountry !== 'XX') { return $clientCountry; }
    // METODO 5: idioma do navegador com regiao (ex: pt-BR -> BR)
    if (!empty($clientLanguages)) {
        foreach (explode(',', $clientLanguages) as $lang) {
            if (preg_match('/[-_]([A-Za-z]{2})$/', trim($lang), $m)) { return strtoupper($m[1]); }
        }
    }
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
 * DETECCAO DE ABUSO -> DESAFIO (Cloudflare Turnstile)
 * Exibe uma tela neutra de verificacao com o widget Turnstile. Quando o
 * visitante resolve, o token e reenviado para a MESMA URL (preservando as
 * UTMs) via parametro cmd_ts, e o fluxo normal continua — liberando para a
 * oferta apenas apos a verificacao.
 */
function renderTurnstileChallenge($siteKey, $mode = 'managed') {
    // Preserva a URL atual (com as UTMs) e injeta o token via cmd_ts
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $currentUrl = $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? '') . ($_SERVER['REQUEST_URI'] ?? '/');
    // Remove um cmd_ts anterior para nao duplicar
    $currentUrl = preg_replace('/([?&])cmd_ts=[^&]*(&|$)/', '$1', $currentUrl);
    $currentUrl = rtrim($currentUrl, '?&');
    $sep = (strpos($currentUrl, '?') !== false) ? '&' : '?';
    $baseUrl = $currentUrl . $sep . 'cmd_ts=';

    // Modo do widget: 'visible' = normal (usuario ve a caixa), qualquer outro
    // valor = 'invisible' (Turnstile resolve em silencio; so escala se desconfiar)
    $tsSize = ($mode === 'visible') ? 'normal' : 'invisible';
    $tsSizeEsc = htmlspecialchars($tsSize, ENT_QUOTES);

    // site key: contexto de atributo HTML -> htmlspecialchars
    $siteKeyEsc = htmlspecialchars($siteKey, ENT_QUOTES);
    // baseUrl: usado DENTRO de string JS entre aspas duplas. NAO usar
    // htmlspecialchars aqui (converteria & em &amp; e quebraria a URL).
    // Escapamos apenas o necessario para uma string JS.
    $baseUrlEsc = str_replace(['\\', '"', "\n", "\r", '<', '>'], ['\\\\', '\\"', '', '', '\\x3c', '\\x3e'], $baseUrl);

    header('Content-Type: text/html; charset=utf-8');
    echo <<<HTML
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Verificando...</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
         background:#0f1115; color:#e7e9ee; }
  .card { width:100%; max-width:400px; padding:32px 24px; text-align:center; }
  .spinner { width:38px; height:38px; margin:0 auto 20px; border:3px solid #262a33;
             border-top-color:#6c8cff; border-radius:50%; animation:spin 1s linear infinite; }
  @keyframes spin { to { transform:rotate(360deg); } }
  h1 { font-size:18px; font-weight:600; margin:0 0 8px; }
  p { font-size:14px; color:#9aa0ac; line-height:1.5; margin:0 0 24px; }
  .widget { display:flex; justify-content:center; min-height:70px; }
</style>
</head>
<body>
  <main class="card">
    <div class="spinner" aria-hidden="true"></div>
    <h1>Verificando seu acesso</h1>
    <p>Aguarde um instante...</p>
    <div class="widget">
      <div class="cf-turnstile"
           data-sitekey="{$siteKeyEsc}"
           data-callback="onCmdVerified"
           data-size="{$tsSizeEsc}"
           data-theme="dark"></div>
    </div>
  </main>
  <script>
    function onCmdVerified(token) {
      window.location.href = "{$baseUrlEsc}" + encodeURIComponent(token);
    }
  </script>
</body>
</html>
HTML;
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
function proxyRequest($targetUrl, $isBlackPage = false, $depth = 1, $whiteUrl = '') {
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

// ===========================================
    // TELEMETRIA DE UI E COMPATIBILIDADE
    // ===========================================
    // Usa o MESMO coletor robusto dos demais metodos (buildTelemetryBeaconJS):
    // trata screen.width=0 no 1o frame (WebView TikTok / Safari iOS) com fallback
    // e retentativas (rAF + timeouts + pagehide), garantindo a resolucao real.
    $hp = '';
    if (!$isBlackPage) {
        $hp = buildTelemetryBeaconJS();
    }

    // =============================================
    // SAFE PAGE INTERNA (self-contained) -> ENTREGA CRUA
    // =============================================
    // A White Page interna (safe.php) e 100% autonoma: CSS inline, "links" sao
    // spans que abrem modais via JS, e o lead vai por fetch na MESMA origem.
    // Ela NAO pode receber a tag <base> nem o script interceptador do proxy:
    // o interceptador captura cliques em [role=button]/<a> e navega para
    // "?_nav=<base64 do host do painel>", trocando o dominio do anuncio pelo IP
    // do painel (o bug que causava suspensao). Detectando a marca
    // "x-commander-safe", entregamos o HTML intacto: tudo resolve na propria
    // origem https do dominio apontado, sem proxy, sem base, sem interceptador.
    if (strpos($response, 'x-commander-safe') !== false) {
        header('HTTP/1.1 ' . $httpCode);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        
        // Injeta o Honeypot automaticamente na White Page Interna
        if ($hp !== '') {
            if (stripos($response, '</body>') !== false) {
                $response = str_ireplace('</body>', $hp . '</body>', $response);
            } else {
                $response .= $hp;
            }
        }
        
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
    
    // Funcao para criar link do proxy (URL limpa) com depth
    $makeProxyLink = function($url) use ($proxyHost, $makeAbsolute, $depth) {
        $url = trim($url);
        if (preg_match('/^(javascript:|mailto:|tel:|#|data:)/i', $url)) {
            return $url;
        }
        $absolute = $makeAbsolute($url);
        return $proxyHost . '/?_nav=' . base64_encode($absolute) . '&_bd=' . $depth;
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
    // depth=1: primeiro clique continua via proxy
    // depth>=2: segundo clique redireciona DIRETO para site real
    // =============================================
    $shouldRedirectDirect = ($depth >= 2) ? 'true' : 'false';
    $currentUrl = $targetUrl;
    
    $proxyScript = '<script>
    (function(){
        var proxyBase = "' . $proxyHost . '/?_nav=";
        var assetBase = "' . $proxyHost . '/?_asset=";
        var targetBase = "' . $baseUrl . '";
        var currentUrl = "' . addslashes($currentUrl) . '";
        var depthSuffix = "&_bd=' . ($depth + 1) . '";
        var shouldRedirectDirect = ' . $shouldRedirectDirect . ';
        
        // Intercepta cliques em links E botoes
        document.addEventListener("click", function(e) {
            // Verifica se clicou em botao
            var btn = e.target.closest("button, input[type=submit], input[type=button], [role=button]");
            if (btn) {
                e.preventDefault();
                e.stopPropagation();
                e.stopImmediatePropagation();
                
                if (shouldRedirectDirect) {
                    // depth>=2: redireciona DIRETO para o site real
                    window.location.href = currentUrl;
                } else {
                    // depth=1: continua via proxy com depth incrementado
                    window.location.href = proxyBase + btoa(currentUrl) + depthSuffix;
                }
                return false;
            }
            
            // Verifica se clicou em link
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
            if (shouldRedirectDirect) {
                // depth>=2: redireciona DIRETO para o site real
                window.location.href = absolute;
            } else {
                // depth=1: continua via proxy com depth incrementado
                window.location.href = proxyBase + btoa(absolute) + depthSuffix;
            }
        }, true);
        
        // Intercepta envio de formularios
        document.addEventListener("submit", function(e) {
            var form = e.target;
            var action = form.getAttribute("action") || window.location.pathname;
            
            if (action.indexOf("_nav=") !== -1) return;
            
            var absolute = action;
            if (!/^https?:\/\//i.test(action)) {
                if (action.charAt(0) === "/") {
                    absolute = targetBase + action;
                } else {
                    absolute = targetBase + "/" + action;
                }
            }
            
            if (shouldRedirectDirect) {
                // depth>=2: form vai direto para site real
                form.setAttribute("action", absolute);
            } else {
                // depth=1: form continua via proxy
                form.setAttribute("action", proxyBase + btoa(absolute) + depthSuffix);
            }
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
        
        // IMPORTANTE: Intercepta TODA navegacao para redirecionar ao site real
        // Isso inclui pushState, location.href, location.assign, location.replace
        
        // Funcao para redirecionar para URL real
        function goToReal(url) {
            if (!url || typeof url !== "string") return false;
            var realUrl = url;
            if (url.indexOf("http") !== 0) {
                realUrl = targetBase + (url.charAt(0) === "/" ? url : "/" + url);
            }
            // Usa o metodo original para evitar loop
            Object.getOwnPropertyDescriptor(window, "location").set.call(window, realUrl);
            return true;
        }
        
        // Intercepta pushState
        var _origPush = history.pushState;
        history.pushState = function(state, title, url) {
            if (goToReal(url)) return;
            return _origPush.apply(this, arguments);
        };
        
        // Intercepta replaceState
        var _origReplace = history.replaceState;
        history.replaceState = function(state, title, url) {
            if (url && typeof url === "string" && url.indexOf("http") === 0 && url.indexOf(location.origin) !== 0) {
                goToReal(url);
                return;
            }
            return _origReplace.apply(this, arguments);
        };
        
        // Intercepta location.assign
        var _origAssign = location.assign;
        location.assign = function(url) {
            goToReal(url);
        };
        
        // Intercepta location.replace  
        var _origLocReplace = location.replace;
        location.replace = function(url) {
            goToReal(url);
        };
        
        // Intercepta mudancas em location.href via defineProperty
        // Isso captura quando o codigo faz: location.href = "url" ou window.location = "url"
        var currentHref = location.href;
        try {
            var locDescriptor = Object.getOwnPropertyDescriptor(window, "location");
            // Nao podemos redefinir location diretamente, mas podemos interceptar via Proxy no futuro
            // Por enquanto, usamos um monitor via interval
            setInterval(function() {
                if (location.href !== currentHref && location.href.indexOf("_nav=") === -1 && location.href.indexOf("_asset=") === -1) {
                    // A URL mudou sem usar _nav - pode ser navegacao JS
                    // Nao fazemos nada aqui pois ja estamos em nova pagina
                }
                currentHref = location.href;
            }, 100);
        } catch(e) {}
    })();
    </script>';
    
 // =============================================
    // GUARDIAN DESABILITADO PARA BLACK PAGE
    // A verificacao ja foi feita na FASE 1 (deteccao JS)
    // Manter Guardian ativo causava falsos positivos em ambientes de dev
    // =============================================
    $guardianScript = '';
    
    // Injeta scripts antes de </body>
    // O HONEYPOT FOI ADICIONADO AQUI NO FINAL DA LINHA ($hp)
    $allScripts = $guardianScript . $proxyScript . $hp;
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

// ============================================
// FUNCAO STEALTH: Codigo fonte = WHITE, Visual = BLACK
// Bot ve WHITE no View Source, humano ve BLACK visualmente
// ============================================
function proxyRequestStealth($whiteUrl, $blackUrl) {
    global $DEBUG_MODE;
    
    // Busca conteudo da WHITE (isso e o que o bot vera no View Source)
    $ch = curl_init($whiteUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_USERAGENT => $_SERVER['HTTP_USER_AGENT'] ?? 'Mozilla/5.0',
        CURLOPT_HTTPHEADER => [
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language: pt-BR,pt;q=0.9,en;q=0.8'
        ]
    ]);
    $whiteHtml = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($whiteHtml === false || empty($whiteHtml)) {
        // Fallback: redireciona para white (same-origin quando interna, p/ nao expor o IP)
        global $WHITE_NAV;
        header('Location: ' . (!empty($WHITE_NAV) ? $WHITE_NAV : $whiteUrl));
        exit;
    }
    
    // CSS do overlay de carregamento
    $stealthCss = '
<style id="__stealth_css">
#__stealth_overlay {
    position: fixed;
    top: 0; left: 0;
    width: 100vw; height: 100vh;
    background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #0f0f1a 100%);
    z-index: 2147483647;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
#__stealth_overlay .loader {
    width: 50px; height: 50px;
    border: 3px solid rgba(59, 130, 246, 0.2);
    border-top-color: #3b82f6;
    border-radius: 50%;
    animation: __stealth_spin 0.8s linear infinite;
}
#__stealth_overlay .msg {
    color: #e2e8f0;
    margin-top: 20px;
    font-size: 16px;
    font-weight: 500;
}
@keyframes __stealth_spin { to { transform: rotate(360deg); } }
#__stealth_frame {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    width: 100%; height: 100%;
    margin: 0; padding: 0;
    z-index: 2147483646;
    border: none;
    display: none;
}
html, body { margin: 0 !important; padding: 0 !important; overflow: hidden !important; }
</style>';

    // HTML do overlay + iframe da BLACK
    $stealthHtml = '
<div id="__stealth_overlay">
    <div class="loader"></div>
    <div class="msg">Carregando...</div>
</div>
<iframe id="__stealth_frame" src="' . htmlspecialchars($blackUrl) . '" allowfullscreen allow="payment; clipboard-write" scrolling="yes" sandbox="allow-forms allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads"></iframe>
<script>
(function(){
    var overlay = document.getElementById("__stealth_overlay");
    var frame = document.getElementById("__stealth_frame");
    
    // Quando iframe carregar, esconde overlay e mostra frame
    frame.onload = function() {
        setTimeout(function() {
            overlay.style.display = "none";
            frame.style.display = "block";
        }, 100);
    };
    
    // Fallback: se nao carregar em 3s, esconde overlay
    setTimeout(function() {
        overlay.style.display = "none";
        frame.style.display = "block";
    }, 3000);
    
    // Limpa URL na barra de enderecos
    if (window.history && window.history.replaceState) {
        window.history.replaceState({}, document.title, window.location.pathname);
    }
})();
</script>';

    // Injeta CSS no <head>
    if (stripos($whiteHtml, '</head>') !== false) {
        $whiteHtml = str_ireplace('</head>', $stealthCss . '</head>', $whiteHtml);
    } else {
        $whiteHtml = $stealthCss . $whiteHtml;
    }
    
    // Injeta overlay e iframe antes de </body>
    if (stripos($whiteHtml, '</body>') !== false) {
        $whiteHtml = str_ireplace('</body>', $stealthHtml . '</body>', $whiteHtml);
    } else {
        $whiteHtml .= $stealthHtml;
    }

    // Telemetria (tela/viewport/WebGL) tambem no metodo IFRAME: enriquece o log
    // deste acesso, inclusive quando o roteamento decidiu antes do JS (Modo Estrito).
    $telemetryBeacon = buildTelemetryBeaconJS();
    if (stripos($whiteHtml, '</body>') !== false) {
        $whiteHtml = str_ireplace('</body>', $telemetryBeacon . '</body>', $whiteHtml);
    } else {
        $whiteHtml .= $telemetryBeacon;
    }
    
    // DEBUG
    if (isset($_GET['v0debug'])) {
        echo '<div style="background:#0f0;color:#000;padding:10px;position:fixed;top:0;left:0;z-index:999999999;font-family:monospace;font-size:12px;">';
        echo '<strong>[STEALTH MODE]</strong><br>';
        echo 'Codigo fonte: WHITE (' . htmlspecialchars($whiteUrl) . ')<br>';
        echo 'Visual: BLACK (' . htmlspecialchars($blackUrl) . ')<br>';
        echo 'Bot ve: WHITE | Humano ve: BLACK';
        echo '</div>';
    }
    
    // Headers
    header('HTTP/1.1 ' . $httpCode);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    
    echo $whiteHtml;
    exit;
}

// ============================================
// FUNCAO SHADOW: Codigo fonte = WHITE, Visual = BLACK via Shadow DOM + iframe
// O iframe fica escondido dentro do Shadow DOM (mais dificil de detectar no inspect)
// ============================================
function proxyRequestShadow($whiteUrl, $blackUrl) {
    global $DEBUG_MODE;
    
    // Busca conteudo da WHITE (isso e o que o bot vera no View Source)
    $ch = curl_init($whiteUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_USERAGENT => $_SERVER['HTTP_USER_AGENT'] ?? 'Mozilla/5.0',
        CURLOPT_HTTPHEADER => [
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language: pt-BR,pt;q=0.9,en;q=0.8'
        ]
    ]);
    $whiteHtml = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($whiteHtml === false || empty($whiteHtml)) {
        // same-origin quando interna, p/ nao expor o IP do painel
        global $WHITE_NAV;
        header('Location: ' . (!empty($WHITE_NAV) ? $WHITE_NAV : $whiteUrl));
        exit;
    }
    
    // CSS para esconder conteudo original e centralizar iframe
    $shadowCss = '
<style id="__sd_css">
html, body { margin: 0 !important; padding: 0 !important; overflow: hidden !important; width: 100% !important; height: 100% !important; }
.__sd_hide { display: none !important; visibility: hidden !important; position: absolute !important; left: -9999px !important; }
#__sd_host {
    position: fixed !important;
    top: 0 !important; left: 0 !important; right: 0 !important; bottom: 0 !important;
    width: 100% !important; height: 100% !important;
    margin: 0 !important; padding: 0 !important;
    z-index: 2147483647 !important;
    background: #fff !important;
    overflow: hidden !important;
}
#__sd_load {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    width: 100%; height: 100%;
    background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #0f0f1a 100%);
    z-index: 2147483648;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
#__sd_load .ld {
    width: 50px; height: 50px;
    border: 3px solid rgba(59, 130, 246, 0.2);
    border-top-color: #3b82f6;
    border-radius: 50%;
    animation: __sd_sp 0.8s linear infinite;
}
#__sd_load .mg { color: #e2e8f0; margin-top: 20px; font-size: 16px; }
@keyframes __sd_sp { to { transform: rotate(360deg); } }
</style>';

    // Script que cria Shadow DOM com iframe dentro
    $shadowScript = '
<div id="__sd_load"><div class="ld"></div><div class="mg">Carregando...</div></div>
<div id="__sd_host"></div>
<script>
(function(){
    var h = document.getElementById("__sd_host");
    var l = document.getElementById("__sd_load");
    var b = document.body;
    
    // Esconde conteudo original
    for (var i = 0; i < b.children.length; i++) {
        var e = b.children[i];
        if (e.id && e.id.indexOf("__sd") === 0) continue;
        e.classList.add("__sd_hide");
    }
    
    // Cria Shadow DOM fechado (nao aparece no inspect normal)
    var s = h.attachShadow ? h.attachShadow({mode: "closed"}) : null;
    
    if (s) {
        // Cria iframe dentro do Shadow DOM com estilo completo
        var f = document.createElement("iframe");
        f.src = "' . htmlspecialchars($blackUrl) . '";
        f.style.cssText = "position:absolute;top:0;left:0;width:100%;height:100%;border:none;margin:0;padding:0;display:block;overflow:hidden;";
        f.setAttribute("allowfullscreen", "true");
        f.setAttribute("allow", "payment; clipboard-write");
        f.setAttribute("scrolling", "yes");
        // SANDBOX sem allow-top-navigation: impede a Black de fazer frame-busting
        // (top.location=...) e trocar a URL da barra para o dominio da oferta.
        // A Black continua funcional (scripts/forms/popups/checkout). Como e outra
        // origem, nao consegue remover o proprio sandbox.
        f.setAttribute("sandbox", "allow-forms allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads");
        
        // Style root do Shadow DOM
        var style = document.createElement("style");
        style.textContent = ":host{display:block;position:fixed;top:0;left:0;right:0;bottom:0;width:100%;height:100%;margin:0;padding:0;overflow:hidden}";
        s.appendChild(style);
        
        f.onload = function() {
            setTimeout(function() { l.style.display = "none"; }, 100);
        };
        
        s.appendChild(f);
    } else {
        // Fallback sem Shadow DOM
        var f = document.createElement("iframe");
        f.src = "' . htmlspecialchars($blackUrl) . '";
        f.style.cssText = "position:fixed;top:0;left:0;right:0;bottom:0;width:100%;height:100%;border:none;margin:0;padding:0;z-index:2147483647;";
        f.setAttribute("allow", "payment; clipboard-write");
        // SANDBOX sem allow-top-navigation: impede frame-busting da Black.
        f.setAttribute("sandbox", "allow-forms allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads");
        f.onload = function() { l.style.display = "none"; };
        b.appendChild(f);
    }
    
    // Limpa URL
    if (window.history && window.history.replaceState) {
        window.history.replaceState({}, document.title, window.location.pathname);
    }
    
    // Timeout fallback mais rapido
    setTimeout(function() { l.style.display = "none"; }, 3000);
})();
</script>';

    // Injeta CSS no <head>
    if (stripos($whiteHtml, '</head>') !== false) {
        $whiteHtml = str_ireplace('</head>', $shadowCss . '</head>', $whiteHtml);
    } else {
        $whiteHtml = $shadowCss . $whiteHtml;
    }
    
    // Injeta script antes de </body>
    if (stripos($whiteHtml, '</body>') !== false) {
        $whiteHtml = str_ireplace('</body>', $shadowScript . '</body>', $whiteHtml);
    } else {
        $whiteHtml .= $shadowScript;
    }

    // Telemetria (tela/viewport/WebGL) tambem no NIVEL HARD (shadow): garante que
    // o log receba os detalhes mesmo quando a decisao ocorreu antes do JS rodar.
    $telemetryBeacon = buildTelemetryBeaconJS();
    if (stripos($whiteHtml, '</body>') !== false) {
        $whiteHtml = str_ireplace('</body>', $telemetryBeacon . '</body>', $whiteHtml);
    } else {
        $whiteHtml .= $telemetryBeacon;
    }
    
    // DEBUG
    if (isset($_GET['v0debug'])) {
        echo '<div style="background:#ff0;color:#000;padding:10px;position:fixed;top:0;left:0;z-index:999999999;font-family:monospace;font-size:12px;">';
        echo '<strong>[SHADOW MODE]</strong><br>';
        echo 'Codigo fonte: WHITE (' . htmlspecialchars($whiteUrl) . ')<br>';
        echo 'Visual: BLACK (' . htmlspecialchars($blackUrl) . ') via Shadow DOM + iframe<br>';
        echo 'Bot ve: WHITE | Humano ve: BLACK';
        echo '</div>';
    }
    
    // Headers
    header('HTTP/1.1 ' . $httpCode);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    
    echo $whiteHtml;
    exit;
}