<?php

/*
 * Copyright (C) 2021 Michael Muenz <michael.muenz@max-it.de>
 * All rights reserved.
 *
 */

function adguardhome_services()
{
    $services = array();
    $general = new \OPNsense\Adguardhome\General();
    if ($general->enabled->isEqual('1')) {
        $dnsPort = (string)$general->dns_port;
        if ($dnsPort === '') {
            $dnsPort = '53';
        }
        $services[] = array(
            'dns_ports' => [$dnsPort],
            'description' => gettext('AdGuardHome'),
            'configd' => array(
                'restart' => array('adguardhome restart'),
                'start' => array('adguardhome start'),
                'stop' => array('adguardhome stop'),
            ),
            'name' => 'AdGuardHome',
            'pidfile' => '/var/run/adguardhome.pid',
        );
    }

    $sync = new \OPNsense\Adguardhome\Sync();
    if ($sync->enabled->isEqual('1')) {
        $services[] = array(
            'description' => gettext('AdGuard Home synchronization'),
            'configd' => array(
                'restart' => array('adguardhomesync restart'),
                'start' => array('adguardhomesync start'),
                'stop' => array('adguardhomesync stop'),
            ),
            'name' => 'AdGuard Home synchronization',
            'pidfile' => '/var/run/adguardhome-sync.pid',
        );
    }

    return $services;
}

function adguardhome_syslog()
{
    return ['adguardhome' => ['facility' => ['adguardhome-sync']]];
}
