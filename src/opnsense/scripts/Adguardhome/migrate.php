#!/usr/local/bin/php
<?php
require_once('config.inc');

use OPNsense\Adguardhome\General;
use OPNsense\Core\Config;

function adguardhome_service_running()
{
    /* Read the pid file directly, the rc.d exit code is not needed here. */
    $pidfile = '/var/run/adguardhome.pid';
    if (!is_file($pidfile)) {
        return false;
    }
    $pid = (int)trim((string)@file_get_contents($pidfile));
    if ($pid <= 0) {
        return false;
    }
    if (!function_exists('posix_kill')) {
        exec('/bin/kill -0 ' . escapeshellarg((string)$pid) . ' >/dev/null 2>&1', $output, $status);
        return $status === 0;
    }
    if (posix_kill($pid, 0)) {
        return true;
    }
    /* EPERM means the process exists but is owned by another user. */
    return posix_get_last_error() === 1;
}

$runtime = json_decode(
    shell_exec('/usr/local/opnsense/scripts/Adguardhome/dns_settings.py --get'),
    true
);
if (!is_array($runtime) || ($runtime['status'] ?? '') !== 'ok') {
    /* A fresh installation has no AdGuardHome.yaml yet, there is nothing to migrate. */
    syslog(LOG_NOTICE, 'AdGuard Home settings migration skipped, no runtime configuration found.');
    exit(0);
}

$instance = Config::getInstance();
$xml = $instance->object();
$general = $xml->OPNsense->adguardhome->general ?? null;
$model = new General();

if ($general === null || !isset($general->enabled)) {
    $model->enabled = adguardhome_service_running() ? '1' : '0';
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
