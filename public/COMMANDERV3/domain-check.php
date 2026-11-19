
<?php
/**
 * COMMANDER - DOMAIN CHECK
 *
 * Autorizacao de dominios para SSL on-demand.
 * Compatível com o endpoint ask do Caddy.
 *
 * GET /domain-check?domain=exemplo.com
 *
 * 200 = dominio autorizado
 * 400 = parametro ausente ou invalido
 * 404 = dominio nao autorizado
 * 405 = metodo nao permitido
 */

header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

// Somente GET
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method !== 'GET') {
    header('Allow: GET');
    http_response_code(405);
    exit('method not allowed');
}

/**
 * Normaliza e valida dominios.
 *
 * $legacy = true:
 * Aceita URLs antigas armazenadas nos JSONs.
 *
 * Preserva a normalizacao de www utilizada
 * pelo painel COMMANDER existente.
 */
function dcNormalizeDomain($value, $legacy = false)
{
    if (!is_string($value)) {
        return '';
    }

    $domain = strtolower(trim($value));

    if ($domain === '' || strlen($domain) > 1024) {
        return '';
    }

    if ($legacy) {
        $domain = preg_replace(
            '#^https?://#i',
            '',
            $domain
        );

        $domain = explode('/', $domain, 2)[0];

        $domain = preg_replace(
            '/:[0-9]+$/',
            '',
            $domain
        );
    }

    // Permite ponto final de FQDN.
    if (substr($domain, -1) === '.') {
        $domain = substr($domain, 0, -1);
    }

    // Compatibilidade com o index.php existente.
    if (strpos($domain, 'www.') === 0) {
        $domain = substr($domain, 4);
    }

    if (
        $domain === '' ||
        strlen($domain) > 253 ||
        strpos($domain, '.') === false
    ) {
        return '';
    }

    // Nao autoriza IP como nome de dominio.
    if (filter_var($domain, FILTER_VALIDATE_IP)) {
        return '';
    }

    // Rejeita caracteres invalidos em vez de remove-los.
    if (
        filter_var(
            $domain,
            FILTER_VALIDATE_DOMAIN,
            FILTER_FLAG_HOSTNAME
        ) === false
    ) {
        return '';
    }

    return $domain;
}

/**
 * Carrega uma lista JSON com tratamento de erros.
 */
function dcReadJsonList($file)
{
    if (!is_file($file) || !is_readable($file)) {
        return [];
    }

    $content = @file_get_contents($file);

    if ($content === false || trim($content) === '') {
        return [];
    }

    $data = json_decode($content, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log(
            '[COMMANDER] JSON invalido em ' .
            basename($file) .
            ': ' .
            json_last_error_msg()
        );

        return [];
    }

    return is_array($data) ? $data : [];
}

/**
 * Verifica se o dominio existe em um registro.
 */
function dcDomainIsRegistered($domain, $file)
{
    $entries = dcReadJsonList($file);

    foreach ($entries as $entry) {
        if (!is_array($entry)) {
            continue;
        }

        $registered = dcNormalizeDomain(
            $entry['domain'] ?? null,
            true
        );

        if (
            $registered !== '' &&
            hash_equals($registered, $domain)
        ) {
            return true;
        }
    }

    return false;
}

/**
 * Valida parametro da requisicao.
 */
$rawDomain = $_GET['domain'] ?? null;

if ($rawDomain === null || $rawDomain === '') {
    http_response_code(400);
    exit('missing domain');
}

$domain = dcNormalizeDomain($rawDomain);

if ($domain === '') {
    http_response_code(400);
    exit('invalid domain');
}

/**
 * 1. Dominios registrados pelo painel.
 */
$domainsFile = __DIR__ . '/data/domains.json';

if (dcDomainIsRegistered($domain, $domainsFile)) {
    http_response_code(200);
    exit('ok');
}

/**
 * 2. Dominios associados a campanhas existentes.
 *
 * Mantido para compatibilidade com os dados antigos.
 */
$campaignsFile = __DIR__ . '/data/campaigns.json';

if (dcDomainIsRegistered($domain, $campaignsFile)) {
    http_response_code(200);
    exit('ok');
}

/**
 * 3. Dominio principal do painel.
 */
$panelDomain = dcNormalizeDomain(
    getenv('COMMANDER_PANEL_DOMAIN') ?: '',
    true
);

if (
    $panelDomain !== '' &&
    hash_equals($panelDomain, $domain)
) {
    http_response_code(200);
    exit('ok');
}

/**
 * Dominio nao encontrado.
 * Falha fechada: nenhuma autorizacao implicita.
 */
http_response_code(404);
exit('not allowed');
