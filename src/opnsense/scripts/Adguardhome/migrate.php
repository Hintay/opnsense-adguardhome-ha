#!/usr/local/bin/php
<?php
require_once('config.inc');

use OPNsense\Adguardhome\General;
use OPNsense\Core\Config;

$runtime = json_decode(
    shell_exec('/usr/local/opnsense/scripts/Adguardhome/dns_settings.py --get'),
    true
);
if (!is_array($runtime) || ($runtime['status'] ?? '') !== 'ok') {
    throw new RuntimeException('Cannot read the current AdGuard Home DNS settings.');
}

$instance = Config::getInstance();
$xml = $instance->object();
$general = $xml->OPNsense->adguardhome->general ?? null;
$model = new General();

if ($general === null || !isset($general->enabled)) {
    exec('/usr/local/etc/rc.d/adguardhome onestatus >/dev/null 2>&1', $output, $serviceStatus);
    $model->enabled = $serviceStatus === 0 ? '1' : '0';
}
if ($general === null || !isset($general->bind_hosts) || (string)$general->bind_hosts === '') {
    $model->bind_hosts = implode(',', $runtime['bind_hosts']);
}
if ($general === null || !isset($general->dns_port) || (string)$general->dns_port === '') {
    $model->dns_port = (string)$runtime['port'];
}
if (count($model->performValidation(true))) {
    throw new RuntimeException('The migrated AdGuard Home settings are invalid.');
}
$model->serializeToConfig();
unset($instance->object()->OPNsense->adguardhome->general->primarydns);
$instance->save(false, 'Update AdGuard Home plugin settings');
