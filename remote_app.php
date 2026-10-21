<?php
/**
 * php2shell test target (server side)  — for authorized lab testing only.
 *
 * The remote chain in php8_remote.py expects:
 *   1. POST parameter "cook" carrying the serialized payload;
 *   2. a class named CachedData implementing Serializable, whose
 *      unserialize() recursively calls unserialize() and then performs one
 *      extra property write (the 9th insert that resizes the arData HT);
 *   3. the endpoint serializes the result, which dispatches through
 *      zend_object_handlers.get_properties_for — the RCE trigger.
 */

ini_set('display_errors', '0');
error_reporting(E_ALL & ~E_DEPRECATED);

class CachedData implements Serializable
{
    public function serialize(): string
    {
        return '';
    }

    public function unserialize(string $data): void
    {
        // The gadget: shared var_hash + the 9th property insert -> arData efree.
        unserialize($data)->x = 0;
    }
}

header('Content-Type: text/plain');
header('X-PHP-Version: ' . PHP_VERSION);
header('X-PHP-SAPI: ' . PHP_SAPI);

if (!isset($_POST['cook'])) {
    http_response_code(400);
    echo "missing cook parameter\n";
    exit;
}

$result = unserialize($_POST['cook']);
if ($result === false && $_POST['cook'] !== 'b:0;') {
    // keep going: false is also a valid unserialize() result for some stages
}

echo serialize($result);
