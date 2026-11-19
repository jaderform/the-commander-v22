
<?php
/**
 * COMMANDER V10.5
 * cloak-engine.php
 *
 * Motor de carregamento de campanhas por dominio.
 *
 * CORRECOES:
 * - Validacao rigorosa de identificadores.
 * - Protecao contra caminhos invalidos.
 * - Verificacao de arquivos e permissoes.
 * - Validacao de URLs de redirecionamento.
 * - Tratamento seguro de dados incorretos.
 * - Compatibilidade com o roteador existente.
 *
 * IMPORTANTE:
 * Este arquivo e carregado pelo index.php.
 * A campanha deve estar disponivel em:
 *
 * $GLOBALS['__CLOAK_CAMPAIGN']
 */

// ============================================
// VALIDACAO DA CAMPANHA
// ============================================

$campaign = $GLOBALS['__CLOAK_CAMPAIGN'] ?? null;

if (!is_array($campaign)) {
    http_response_code(404);
    exit;
}

// ============================================
// IDENTIFICADOR DA CAMPANHA
// ============================================

$rawSlug = $campaign['slug'] ?? '';

$slug = '';

if (is_string($rawSlug)) {
    $rawSlug = trim($rawSlug);

    if (
        $rawSlug !== '' &&
        preg_match(
            '/\A[a-zA-Z0-9_-]+\z/',
            $rawSlug
        ) === 1
    ) {
        $slug = $rawSlug;
    }
}

// ============================================
// DIRETORIO DE ARQUIVOS
// ============================================

$liveDirectory = __DIR__ . '/live';

$liveFile = null;

// Somente identifica arquivos quando o
// slug informado e valido.
if ($slug !== '') {

    $realDirectory = realpath($liveDirectory);

    if (
        $realDirectory !== false &&
        is_dir($realDirectory)
    ) {

        $candidate = $realDirectory
            . DIRECTORY_SEPARATOR
            . $slug
            . '.php';

        $resolvedFile = realpath($candidate);

        // Impede inclusao de caminhos localizados
        // fora da pasta live.
        if ($resolvedFile !== false) {

            $requiredPrefix = $realDirectory
                . DIRECTORY_SEPARATOR;

            $insideDirectory = (
                strpos(
                    $resolvedFile,
                    $requiredPrefix
                ) === 0
            );

            if (
                $insideDirectory &&
                is_file($resolvedFile) &&
                is_readable($resolvedFile)
            ) {
                $liveFile = $resolvedFile;
            }
        }
    }
}

// ============================================
// CARREGAMENTO DO MODULO
// ============================================

if ($liveFile !== null) {

    require $liveFile;

    exit;
}

// ============================================
// FALLBACK DA CAMPANHA
// ============================================

// Mantem o comportamento original:
// se o modulo nao existir, utiliza a
// pagina alternativa configurada.

$rawWhiteUrl = $campaign['white_url'] ?? '';

$whiteUrl = '';

if (is_string($rawWhiteUrl)) {
    $whiteUrl = trim($rawWhiteUrl);
}

// ============================================
// VALIDACAO DO REDIRECIONAMENTO
// ============================================

$validRedirect = false;

if ($whiteUrl !== '') {

    $parsedUrl = parse_url($whiteUrl);

    if (is_array($parsedUrl)) {

        $scheme = strtolower(
            (string) ($parsedUrl['scheme'] ?? '')
        );

        $host = $parsedUrl['host'] ?? '';

        $validScheme = in_array(
            $scheme,
            ['http', 'https'],
            true
        );

        $validHost = (
            is_string($host) &&
            $host !== ''
        );

        $validUrl = (
            filter_var(
                $whiteUrl,
                FILTER_VALIDATE_URL
            ) !== false
        );

        // Impede caracteres de controle
        // em cabecalhos HTTP.
        $validHeader = (
            preg_match(
                '/[\x00-\x1F\x7F]/',
                $whiteUrl
            ) !== 1
        );

        $validRedirect = (
            $validScheme &&
            $validHost &&
            $validUrl &&
            $validHeader
        );
    }
}

// ============================================
// EXECUCAO DO FALLBACK
// ============================================

if ($validRedirect) {

    header(
        'Location: ' . $whiteUrl,
        true,
        302
    );

    exit;
}

// ============================================
// CAMPANHA NAO CONFIGURADA
// ============================================

http_response_code(404);

header(
    'Content-Type: text/plain; charset=utf-8'
);

header(
    'X-Content-Type-Options: nosniff'
);

header(
    'Cache-Control: no-store'
);

echo 'Campanha nao configurada.';

exit;

// ============================================
// FIM DO ARQUIVO
// ============================================
