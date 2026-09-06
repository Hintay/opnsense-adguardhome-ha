#!/usr/local/bin/php
<?php
require_once('config.inc');

$model = new \OPNsense\Adguardhome\General();
echo json_encode($model->getNodes(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), PHP_EOL;
