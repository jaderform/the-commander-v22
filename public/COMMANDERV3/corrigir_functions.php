
<?php
/**
 * COMMANDER - Aplicador de correcoes do functions.php
 *
 * Uso:
 *   php corrigir_functions.php
 *
 * Entrada:
 *   functions.php
 *
 * Saida:
 *   functions.revisado.php
 *
 * O original nunca e sobrescrito.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("Execute somente pelo terminal.\n");
}

$entrada = __DIR__ . '/functions.php';
$saida = __DIR__ . '/functions.revisado.php';

if (!is_file($entrada) || !is_readable($entrada)) {
    exit("ERRO: functions.php nao encontrado.\n");
}

$codigo = file_get_contents($entrada);

if ($codigo === false || strpos($codigo, '<?php') === false) {
    exit("ERRO: arquivo PHP invalido ou ilegivel.\n");
}

$hashOriginal = hash('sha256', $codigo);

/**
 * Localiza uma funcao PHP usando o tokenizer.
 *
 * Preserva exatamente o restante do arquivo,
 * inclusive comentarios e espacos originais.
 */
function substituirFuncao($codigo, $nome, $novoCodigo)
{
    $tokens = token_get_all($codigo);

    $offsets = [];
    $posicao = 0;

    foreach ($tokens as $token) {
        $offsets[] = $posicao;
        $texto = is_array($token) ? $token[1] : $token;
        $posicao += strlen($texto);
    }

    $encontradas = [];

    for ($i = 0; $i < count($tokens); $i++) {
        $token = $tokens[$i];

        if (
            !is_array($token) ||
            $token[0] !== T_FUNCTION
        ) {
            continue;
        }

        $j = $i + 1;

        while ($j < count($tokens)) {
            $atual = $tokens[$j];

            if (
                is_array($atual) &&
                $atual[0] === T_WHITESPACE
            ) {
                $j++;
                continue;
            }

            if ($atual === '&') {
                $j++;
                continue;
            }

            break;
        }

        if (
            !isset($tokens[$j]) ||
            !is_array($tokens[$j]) ||
            $tokens[$j][0] !== T_STRING ||
            $tokens[$j][1] !== $nome
        ) {
            continue;
        }

        $inicio = $offsets[$i];
        $profundidade = 0;
        $abriu = false;
        $fim = null;

        for ($k = $j + 1; $k < count($tokens); $k++) {
            $parte = $tokens[$k];

            $abertura = $parte === '{';

            if (is_array($parte)) {
                $abertura = in_array(
                    $parte[0],
                    [
                        T_CURLY_OPEN,
                        T_DOLLAR_OPEN_CURLY_BRACES
                    ],
                    true
                );
            }

            if ($abertura) {
                $profundidade++;
                $abriu = true;
                continue;
            }

            if ($parte === '}' && $abriu) {
                $profundidade--;

                if ($profundidade === 0) {
                    $fim = $offsets[$k] + 1;
                    break;
                }
            }
        }

        if ($fim === null) {
            throw new RuntimeException(
                "Funcao incompleta: {$nome}"
            );
        }

        $encontradas[] = [$inicio, $fim];
    }

    if (count($encontradas) !== 1) {
        throw new RuntimeException(
            "Esperada uma declaracao de {$nome}; encontradas "
            . count($encontradas)
        );
    }

    [$inicio, $fim] = $encontradas[0];

    return substr($codigo, 0, $inicio)
        . trim($novoCodigo)
        . substr($codigo, $fim);
}

// ============================================
// 1. LEITURA JSON
// ============================================

$correcoes = [];

$correcoes['readJsonFile'] = <<<'PHP'
function readJsonFile($file, $default = [])
{
    if (!is_string($file) || $file === '') {
        return $default;
    }

    if (!is_file($file)) {
        return $default;
    }

    $content = @file_get_contents($file);

    if ($content === false) {
        error_log(
            '[COMMANDER] Erro lendo JSON: ' . $file
        );
        return $default;
    }

    $data = json_decode($content, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log(
            '[COMMANDER] JSON invalido: '
            . $file . ' - ' . json_last_error_msg()
        );

        return $default;
    }

    return $data === null ? $default : $data;
}
PHP;

// ============================================
// 2. GRAVACAO JSON
// ============================================

$correcoes['writeJsonFile'] = <<<'PHP'
function writeJsonFile($file, $data)
{
    if (!is_string($file) || $file === '') {
        return false;
    }

    $dir = dirname($file);

    if (
        !is_dir($dir) &&
        !@mkdir($dir, 0755, true) &&
        !is_dir($dir)
    ) {
        error_log(
            '[COMMANDER] Diretorio indisponivel: ' . $dir
        );
        return false;
    }

    $json = json_encode(
        $data,
        JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE
    );

    if ($json === false) {
        error_log(
            '[COMMANDER] JSON encode falhou: '
            . json_last_error_msg()
        );
        return false;
    }

    $lock = @fopen($file . '.lock', 'c');

    if ($lock === false) {
        return false;
    }

    if (!@flock($lock, LOCK_EX)) {
        fclose($lock);
        return false;
    }

    $tmp = false;

    try {
        $tmp = @tempnam($dir, '.tmp_json_');

        if ($tmp === false) {
            return false;
        }

        $bytes = @file_put_contents(
            $tmp,
            $json,
            LOCK_EX
        );

        if (
            $bytes === false ||
            $bytes !== strlen($json)
        ) {
            error_log(
                '[COMMANDER] Gravacao JSON incompleta: '
                . $file
            );
            return false;
        }

        // Preserva permissao do destino quando possivel.
        $mode = is_file($file)
            ? (@fileperms($file) & 0777)
            : 0640;

        if ($mode === 0) {
            $mode = 0640;
        }

        @chmod($tmp, $mode);

        if (!@rename($tmp, $file)) {
            error_log(
                '[COMMANDER] Falha no rename: ' . $file
            );
            return false;
        }

        $tmp = false;
        return true;

    } finally {
        if ($tmp !== false && is_file($tmp)) {
            @unlink($tmp);
        }

        @flock($lock, LOCK_UN);
        fclose($lock);
    }
}
PHP;

// ============================================
// 3. APPEND JSON COM LOCK
// ============================================

$correcoes['appendToJsonFile'] = <<<'PHP'
function appendToJsonFile($file, $item, $maxItems = 10000)
{
    if (!is_string($file) || $file === '') {
        return false;
    }

    $dir = dirname($file);

    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return false;
        }
    }

    $lock = @fopen($file . '.appendlock', 'c');

    if ($lock === false) {
        return false;
    }

    if (!@flock($lock, LOCK_EX)) {
        fclose($lock);
        return false;
    }

    try {
        $data = [];

        if (is_file($file)) {
            $raw = @file_get_contents($file);

            if ($raw === false) {
                return false;
            }

            $data = json_decode($raw, true);

            if (
                json_last_error() !== JSON_ERROR_NONE ||
                !is_array($data)
            ) {
                error_log(
                    '[COMMANDER] Append cancelado: JSON invalido '
                    . $file
                );
                return false;
            }
        }

        array_unshift($data, $item);

        $maxItems = max(1, (int) $maxItems);

        if (count($data) > $maxItems) {
            $data = array_slice($data, 0, $maxItems);
        }

        return writeJsonFile($file, $data);

    } finally {
        @flock($lock, LOCK_UN);
        fclose($lock);
    }
}
PHP;

// ============================================
// 4. APPEND JSON COM RESET
// ============================================

$correcoes['appendCappedResetJsonFile'] = <<<'PHP'
function appendCappedResetJsonFile(
    $file,
    $item,
    $maxItems = 2000
) {
    if (!is_string($file) || $file === '') {
        return false;
    }

    $dir = dirname($file);

    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return false;
        }
    }

    $lock = @fopen($file . '.appendlock', 'c');

    if ($lock === false) {
        return false;
    }

    if (!@flock($lock, LOCK_EX)) {
        fclose($lock);
        return false;
    }

    try {
        $data = [];

        if (is_file($file)) {
            $raw = @file_get_contents($file);

            if ($raw === false) {
                return false;
            }

            $data = json_decode($raw, true);

            if (
                json_last_error() !== JSON_ERROR_NONE ||
                !is_array($data)
            ) {
                error_log(
                    '[COMMANDER] Reset cancelado: JSON invalido '
                    . $file
                );
                return false;
            }
        }

        $maxItems = max(1, (int) $maxItems);

        if (count($data) >= $maxItems) {
            $data = [];
        }

        array_unshift($data, $item);

        return writeJsonFile($file, $data);

    } finally {
        @flock($lock, LOCK_UN);
        fclose($lock);
    }
}
PHP;

// ============================================
// 5. LIMPEZA SQLITE + JSON
// ============================================

$correcoes['clearLearnedBots'] = <<<'PHP'
function clearLearnedBots()
{
    $empty = [
        'fingerprints' => [],
        'ips' => [],
        'stats' => [
            'total' => 0,
            'last_updated' =>
                date('Y-m-d H:i:s') . ' (limpo)'
        ]
    ];

    if (function_exists('botStorageClear')) {
        $result = botStorageClear();

        // Falhou: nao limpar o JSON.
        if ($result === false) {
            error_log(
                '[COMMANDER] Limpeza SQLite falhou.'
            );
            return false;
        }

        if ($result === true) {
            // SQLite limpo; confirma o JSON tambem.
            return writeJsonFile(
                FILE_LEARNED_BOTS,
                $empty
            );
        }

        // null = SQLite indisponivel.
        // Continua com o armazenamento legado.
    }

    return writeJsonFile(
        FILE_LEARNED_BOTS,
        $empty
    );
}
PHP;

// ============================================
// APLICACAO DAS CORRECOES
// ============================================

try {
    foreach ($correcoes as $nome => $novoCodigo) {
        $codigo = substituirFuncao(
            $codigo,
            $nome,
            $novoCodigo
        );

        echo "[OK] {$nome}\n";
    }

    if ($codigo === '') {
        throw new RuntimeException(
            'Resultado vazio.'
        );
    }

    if (is_file($saida)) {
        throw new RuntimeException(
            'O arquivo de saida ja existe. '
            . 'Remova-o somente apos fazer backup.'
        );
    }

    $handle = @fopen($saida, 'x');

    if ($handle === false) {
        throw new RuntimeException(
            'Nao foi possivel criar o arquivo de saida.'
        );
    }

    $length = strlen($codigo);
    $offset = 0;
    $ok = true;

    while ($offset < $length) {
        $written = fwrite(
            $handle,
            substr($codigo, $offset)
        );

        if ($written === false || $written === 0) {
            $ok = false;
            break;
        }

        $offset += $written;
    }

    if ($ok) {
        $ok = fflush($handle);
    }

    fclose($handle);

    if (!$ok || $offset !== $length) {
        @unlink($saida);
        throw new RuntimeException(
            'Falha na gravacao completa da saida.'
        );
    }

    echo "\nARQUIVO GERADO:\n";
    echo $saida . "\n";

    echo "\nSHA256 original:\n";
    echo $hashOriginal . "\n";

    echo "\nSHA256 revisado:\n";
    echo hash_file('sha256', $saida) . "\n";

    echo "\nValidar antes de publicar:\n";
    echo "php -l functions.revisado.php\n";

} catch (Throwable $e) {
    fwrite(
        STDERR,
        '[ERRO] ' . $e->getMessage() . "\n"
    );

    exit(1);
}
