#!/usr/local/bin/php
<?php
require_once('config.inc');

$models = [
    'general' => new \OPNsense\Adguardhome\General(),
    'sync' => new \OPNsense\Adguardhome\Sync(),
];

$nodes = [];
foreach ($models as $name => $model) {
    $nodes[$name] = $model->getNodes();
}
echo json_encode($nodes, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), PHP_EOL;
