
<?php
/**
 * COMMANDER V10.5
 * bots-storage.php
 *
 * Armazenamento SQLite de registros de bots.
 *
 * Revisao de infraestrutura:
 * - Transacoes para operacoes multiplas.
 * - Tratamento de falhas de conexao e consulta.
 * - Validacao de dados antes da migracao.
 * - Mascaramento de IPv4 e IPv6.
 * - Preservacao da estrutura do banco existente.
 *
 * Compatibilidade:
 * - Mantem os nomes das funcoes publicas.
 * - Mantem as tabelas e colunas originais.
 * - Mantem os identificadores MD5 existentes.
 * - Mantem o retorno null quando SQLite
 *   nao esta disponivel.
 *
 * Requer PHP 7.4+ com PDO_SQLITE.
 */

// ============================================
// DIRETORIO DE DADOS
// ============================================

if (!defined('DATA_DIR')) {
    define('DATA_DIR', __DIR__ . '/data/');
}

// ============================================
// DISPONIBILIDADE DO SQLITE
// ============================================

if (!function_exists('botStorageAvailable')) {

    function botStorageAvailable()
    {
        return class_exists('PDO')
            && in_array(
                'sqlite',
                PDO::getAvailableDrivers(),
                true
            );
    }
}

// ============================================
// CONEXAO COM BANCO
// ============================================

if (!function_exists('botDb')) {

    function botDb()
    {
        static $pdo = null;
        static $tried = false;

        if ($tried) {
            return $pdo;
        }

        $tried = true;

        if (!botStorageAvailable()) {
            return null;
        }

        try {
            if (!is_dir(DATA_DIR)) {
                if (
                    !@mkdir(DATA_DIR, 0755, true)
                    && !is_dir(DATA_DIR)
                ) {
                    throw new RuntimeException(
                        'Nao foi possivel criar DATA_DIR.'
                    );
                }
            }

            if (!is_writable(DATA_DIR)) {
                throw new RuntimeException(
                    'Diretorio de dados sem permissao de escrita.'
                );
            }

            $databaseFile = DATA_DIR . 'bots.db';

            $pdo = new PDO(
                'sqlite:' . $databaseFile
            );

            $pdo->setAttribute(
                PDO::ATTR_ERRMODE,
                PDO::ERRMODE_EXCEPTION
            );

            $pdo->setAttribute(
                PDO::ATTR_DEFAULT_FETCH_MODE,
                PDO::FETCH_ASSOC
            );

            // Aguarda brevemente operacoes concorrentes.
            $pdo->exec(
                'PRAGMA busy_timeout = 5000;'
            );

            // Mantem a configuracao original de WAL.
            $pdo->exec(
                'PRAGMA journal_mode = WAL;'
            );

            $pdo->exec(
                'PRAGMA synchronous = NORMAL;'
            );

            $pdo->exec(
                'PRAGMA temp_store = MEMORY;'
            );

            // ====================================
            // TABELA DE FINGERPRINTS
            // ====================================

            $pdo->exec(
                'CREATE TABLE IF NOT EXISTS bot_fingerprints (
                    fingerprint TEXT PRIMARY KEY,
                    reason      TEXT,
                    date        TEXT,
                    campaign    TEXT,
                    ip_masked   TEXT
                )'
            );

            // ====================================
            // TABELA DE IPS
            // ====================================

            $pdo->exec(
                'CREATE TABLE IF NOT EXISTS bot_ips (
                    ip_hash     TEXT PRIMARY KEY,
                    count       INTEGER DEFAULT 0,
                    first_seen  TEXT,
                    last_seen   TEXT,
                    last_reason TEXT
                )'
            );

            // Mantem indice original.
            $pdo->exec(
                'CREATE INDEX IF NOT EXISTS idx_fp_date
                 ON bot_fingerprints(date)'
            );

            return $pdo;

        } catch (Throwable $e) {

            error_log(
                '[bots-storage] Falha na inicializacao: '
                . $e->getMessage()
            );

            $pdo = null;

            return null;
        }
    }
}

// ============================================
// ROLLBACK SEGURO
// ============================================

if (!function_exists('botStorageRollback')) {

    function botStorageRollback($db)
    {
        if (!$db instanceof PDO) {
            return;
        }

        try {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
        } catch (Throwable $e) {
            error_log(
                '[bots-storage] Falha no rollback: '
                . $e->getMessage()
            );
        }
    }
}

// ============================================
// MASCARAMENTO DE IP
// ============================================

if (!function_exists('botStorageMaskIp')) {

    function botStorageMaskIp($ip)
    {
        $ip = trim((string) $ip);

        if (
            filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV4
            )
        ) {
            $position = strrpos($ip, '.');

            if ($position !== false) {
                return substr(
                    $ip,
                    0,
                    $position
                ) . '.xxx';
            }
        }

        if (
            filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV6
            )
        ) {
            $binary = inet_pton($ip);

            if ($binary !== false) {
                return bin2hex(
                    substr($binary, 0, 4)
                ) . ':xxxx:xxxx:xxxx';
            }
        }

        return 'IP invalido';
    }
}

// ============================================
// CONSULTA DE REGISTROS
// ============================================

if (!function_exists('botStorageIsLearnedBot')) {

    function botStorageIsLearnedBot(
        $ip,
        $userAgent
    ) {
        $db = botDb();

        if (!$db) {
            return null;
        }

        try {
            // Mantem os identificadores originais
            // para nao invalidar dados antigos.
            $fingerprint = md5(
                $ip . '|' . $userAgent
            );

            $ipHash = md5($ip);

            // ====================================
            // CONSULTA POR FINGERPRINT
            // ====================================

            $stmt = $db->prepare(
                'SELECT reason, date
                 FROM bot_fingerprints
                 WHERE fingerprint = ?
                 LIMIT 1'
            );

            $stmt->execute([
                $fingerprint
            ]);

            $row = $stmt->fetch();

            if ($row !== false) {

                return [
                    'isBot' => true,
                    'reason' =>
                        'Bot aprendido: '
                        . (
                            $row['reason']
                            ?: 'detectado anteriormente'
                        ),
                    'learned_at' =>
                        $row['date'] ?? ''
                ];
            }

            // ====================================
            // CONSULTA POR IP
            // ====================================

            $stmt = $db->prepare(
                'SELECT count, last_seen
                 FROM bot_ips
                 WHERE ip_hash = ?
                 LIMIT 1'
            );

            $stmt->execute([
                $ipHash
            ]);

            $row = $stmt->fetch();

            if (
                $row !== false
                && (int) $row['count'] >= 3
            ) {
                return [
                    'isBot' => true,
                    'reason' =>
                        'IP bloqueado: multiplas deteccoes ('
                        . $row['count']
                        . ')',
                    'learned_at' =>
                        $row['last_seen'] ?? ''
                ];
            }

            return [
                'isBot' => false
            ];

        } catch (Throwable $e) {

            error_log(
                '[bots-storage] Falha na consulta: '
                . $e->getMessage()
            );

            // Permite que functions.php execute
            // seu fallback JSON existente.
            return null;
        }
    }
}

// ============================================
// GRAVACAO DE REGISTROS
// ============================================

if (!function_exists('botStorageAddLearnedBot')) {

    function botStorageAddLearnedBot(
        $ip,
        $userAgent,
        $reason,
        $campaignId = ''
    ) {
        $db = botDb();

        if (!$db) {
            return null;
        }

        try {
            $fingerprint = md5(
                $ip . '|' . $userAgent
            );

            $ipHash = md5($ip);

            $date = date('Y-m-d H:i:s');

            $ipMasked = botStorageMaskIp($ip);

            if (!$db->beginTransaction()) {
                throw new RuntimeException(
                    'Falha ao iniciar transacao.'
                );
            }

            // ====================================
            // REGISTRO DO FINGERPRINT
            // ====================================

            $stmt = $db->prepare(
                'INSERT OR IGNORE INTO bot_fingerprints
                 (
                    fingerprint,
                    reason,
                    date,
                    campaign,
                    ip_masked
                 )
                 VALUES (?, ?, ?, ?, ?)'
            );

            $stmt->execute([
                $fingerprint,
                $reason,
                $date,
                $campaignId,
                $ipMasked
            ]);

            // ====================================
            // ATUALIZACAO DO CONTADOR POR IP
            // ====================================

            $stmt = $db->prepare(
                'UPDATE bot_ips
                 SET
                    count = count + 1,
                    last_seen = ?,
                    last_reason = ?
                 WHERE ip_hash = ?'
            );

            $stmt->execute([
                $date,
                $reason,
                $ipHash
            ]);

            if ($stmt->rowCount() === 0) {

                $insert = $db->prepare(
                    'INSERT OR IGNORE INTO bot_ips
                     (
                        ip_hash,
                        count,
                        first_seen,
                        last_seen,
                        last_reason
                     )
                     VALUES (?, 1, ?, ?, ?)'
                );

                $insert->execute([
                    $ipHash,
                    $date,
                    $date,
                    $reason
                ]);
            }

            if (!$db->commit()) {
                throw new RuntimeException(
                    'Falha ao confirmar transacao.'
                );
            }

            return true;

        } catch (Throwable $e) {

            botStorageRollback($db);

            error_log(
                '[bots-storage] Falha na gravacao: '
                . $e->getMessage()
            );

            return false;
        }
    }
}

// ============================================
// ESTATISTICAS
// ============================================

if (!function_exists('botStorageStats')) {

    function botStorageStats()
    {
        $db = botDb();

        if (!$db) {
            return null;
        }

        try {
            $fingerprints = (int) $db
                ->query(
                    'SELECT COUNT(*)
                     FROM bot_fingerprints'
                )
                ->fetchColumn();

            $ips = (int) $db
                ->query(
                    'SELECT COUNT(*)
                     FROM bot_ips'
                )
                ->fetchColumn();

            $last = $db
                ->query(
                    'SELECT MAX(date)
                     FROM bot_fingerprints'
                )
                ->fetchColumn();

            return [
                'total_fingerprints' => $fingerprints,
                'total_ips' => $ips,
                'last_updated' => $last ?: '-'
            ];

        } catch (Throwable $e) {

            error_log(
                '[bots-storage] Falha nas estatisticas: '
                . $e->getMessage()
            );

            return null;
        }
    }
}

// ============================================
// LIMPEZA DOS REGISTROS
// ============================================

if (!function_exists('botStorageClear')) {

    function botStorageClear()
    {
        $db = botDb();

        if (!$db) {
            return null;
        }

        try {
            // As duas tabelas sao limpas juntas.
            // Se alguma operacao falhar,
            // a transacao e revertida.
            if (!$db->beginTransaction()) {
                throw new RuntimeException(
                    'Falha ao iniciar limpeza.'
                );
            }

            $db->exec(
                'DELETE FROM bot_fingerprints'
            );

            $db->exec(
                'DELETE FROM bot_ips'
            );

            if (!$db->commit()) {
                throw new RuntimeException(
                    'Falha ao confirmar limpeza.'
                );
            }

            return true;

        } catch (Throwable $e) {

            botStorageRollback($db);

            error_log(
                '[bots-storage] Falha na limpeza: '
                . $e->getMessage()
            );

            return false;
        }
    }
}

// ============================================
// MIGRACAO JSON -> SQLITE
// ============================================

if (!function_exists('botStorageMigrateFromJson')) {

    function botStorageMigrateFromJson(
        $jsonFile = null
    ) {
        $db = botDb();

        if (!$db) {
            return [
                'ok' => false,
                'error' =>
                    'SQLite indisponivel neste servidor'
            ];
        }

        if ($jsonFile === null || $jsonFile === '') {
            $jsonFile = DATA_DIR . 'learned_bots.json';
        }

        if (
            !is_string($jsonFile)
            || !is_file($jsonFile)
            || !is_readable($jsonFile)
        ) {
            return [
                'ok' => false,
                'error' =>
                    'Arquivo JSON nao encontrado ou ilegivel'
            ];
        }

        $content = @file_get_contents($jsonFile);

        if ($content === false) {
            return [
                'ok' => false,
                'error' =>
                    'Falha ao ler o arquivo JSON'
            ];
        }

        $data = json_decode(
            $content,
            true
        );

        if (
            json_last_error() !== JSON_ERROR_NONE
            || !is_array($data)
        ) {
            return [
                'ok' => false,
                'error' =>
                    'JSON invalido: '
                    . json_last_error_msg()
            ];
        }

        $fingerprints = $data['fingerprints'] ?? [];
        $ips = $data['ips'] ?? [];

        if (
            !is_array($fingerprints)
            || !is_array($ips)
        ) {
            return [
                'ok' => false,
                'error' =>
                    'Estrutura do JSON incompatível'
            ];
        }

        // Validacao antes de iniciar a transacao.
        // Nao descarta registros silenciosamente.
        foreach ($fingerprints as $hash => $info) {
            if (
                !is_string($hash)
                || !is_array($info)
            ) {
                return [
                    'ok' => false,
                    'error' =>
                        'Registro de fingerprint invalido'
                ];
            }

            foreach ([
                'reason',
                'date',
                'campaign',
                'ip_masked'
            ] as $field) {
                if (
                    isset($info[$field])
                    && !is_scalar($info[$field])
                ) {
                    return [
                        'ok' => false,
                        'error' =>
                            'Campo de fingerprint invalido: '
                            . $field
                    ];
                }
            }
        }

        foreach ($ips as $hash => $info) {
            if (
                !is_string($hash)
                || !is_array($info)
            ) {
                return [
                    'ok' => false,
                    'error' =>
                        'Registro de IP invalido'
                ];
            }

            if (
                isset($info['count'])
                && (
                    !is_numeric($info['count'])
                    || (float) $info['count'] < 0
                )
            ) {
                return [
                    'ok' => false,
                    'error' =>
                        'Contador de IP invalido'
                ];
            }

            foreach ([
                'first_seen',
                'last_seen',
                'last_reason'
            ] as $field) {
                if (
                    isset($info[$field])
                    && !is_scalar($info[$field])
                ) {
                    return [
                        'ok' => false,
                        'error' =>
                            'Campo de IP invalido: '
                            . $field
                    ];
                }
            }
        }

        $fpAdded = 0;
        $ipAdded = 0;

        try {
            if (!$db->beginTransaction()) {
                throw new RuntimeException(
                    'Falha ao iniciar migracao.'
                );
            }

            // ====================================
            // IMPORTACAO DE FINGERPRINTS
            // ====================================

            $fpStmt = $db->prepare(
                'INSERT OR IGNORE INTO bot_fingerprints
                 (
                    fingerprint,
                    reason,
                    date,
                    campaign,
                    ip_masked
                 )
                 VALUES (?, ?, ?, ?, ?)'
            );

            foreach ($fingerprints as $hash => $info) {

                $fpStmt->execute([
                    $hash,
                    (string) ($info['reason'] ?? ''),
                    (string) ($info['date'] ?? ''),
                    (string) ($info['campaign'] ?? ''),
                    (string) ($info['ip_masked'] ?? '')
                ]);

                $fpAdded += $fpStmt->rowCount();
            }

            // ====================================
            // IMPORTACAO DE IPS
            // ====================================

            $ipStmt = $db->prepare(
                'INSERT OR IGNORE INTO bot_ips
                 (
                    ip_hash,
                    count,
                    first_seen,
                    last_seen,
                    last_reason
                 )
                 VALUES (?, ?, ?, ?, ?)'
            );

            foreach ($ips as $hash => $info) {

                $ipStmt->execute([
                    $hash,
                    (int) ($info['count'] ?? 1),
                    (string) ($info['first_seen'] ?? ''),
                    (string) ($info['last_seen'] ?? ''),
                    (string) ($info['last_reason'] ?? '')
                ]);

                $ipAdded += $ipStmt->rowCount();
            }

            if (!$db->commit()) {
                throw new RuntimeException(
                    'Falha ao confirmar migracao.'
                );
            }

            // O JSON original nunca e apagado.
            return [
                'ok' => true,
                'fingerprints' => $fpAdded,
                'ips' => $ipAdded
            ];

        } catch (Throwable $e) {

            botStorageRollback($db);

            error_log(
                '[bots-storage] Falha na migracao: '
                . $e->getMessage()
            );

            return [
                'ok' => false,
                'error' => $e->getMessage()
            ];
        }
    }
}

// ============================================
// FIM DO ARQUIVO bots-storage.php
// ============================================
