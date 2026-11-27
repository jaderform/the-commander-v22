<?php
/** Diagnóstico local, somente leitura: php debug_stats.php */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$ok = true;
foreach (['data', 'logs', 'cache'] as $directory) {
    $path = __DIR__ . '/' . $directory;
    if (!is_dir($path)) {
        echo "$directory: diretório ausente\n";
        $ok = false;
        continue;
    }
    $readable = is_readable($path);
    $writable = is_writable($path);
    printf("%s: leitura %s; escrita %s\n", $directory, $readable ? 'permitida' : 'negada', $writable ? 'permitida' : 'negada');
    $ok = $ok && $readable && $writable;
}

foreach (['data/campaigns.json', 'data/stats.json', 'logs/bot_log.json'] as $file) {
    $path = __DIR__ . '/' . $file;
    if (!is_file($path)) {
        echo "$file: ausente\n";
        continue;
    }
    $contents = file_get_contents($path);
    if ($contents === false) {
        echo "$file: leitura falhou\n";
        $ok = false;
        continue;
    }
    $records = json_decode($contents, true);
    if (!is_array($records)) {
        echo "$file: esperado um objeto ou lista JSON\n";
        $ok = false;
    } else {
        printf("%s: %d entradas no primeiro nível\n", $file, count($records));
    }
    unset($contents, $records);
}
exit($ok ? 0 : 1);
