<?php

/*
 * Copyright (C) 2021 Michael Muenz <michael.muenz@max-it.de>
 * All rights reserved.
 */

namespace OPNsense\Adguardhome\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;

class GeneralController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\OPNsense\Adguardhome\General';
    protected static $internalModelName = 'general';

    protected function getModelNodes()
    {
        $nodes = parent::getModelNodes();
        try {
            $output = (new Backend())->configdRun('adguardhome dns_get');
            $settings = json_decode($output, true);
            if (($settings['status'] ?? '') === 'ok') {
                $nodes['bind_hosts'] = [];
                $selected = array_flip($settings['bind_hosts'] ?? []);
                foreach ($settings['available_hosts'] ?? [] as $address => $label) {
                    $nodes['bind_hosts'][$address] = [
                        'value' => $label,
                        'selected' => isset($selected[$address]) ? 1 : 0,
                    ];
                }
                foreach ($settings['bind_hosts'] ?? [] as $address) {
                    if (!isset($nodes['bind_hosts'][$address])) {
                        $nodes['bind_hosts'][$address] = ['value' => $address, 'selected' => 1];
                    }
                }
                $nodes['dns_port'] = (string)($settings['port'] ?? 53);
            }
        } catch (\Throwable $error) {
            // Keep saved model values when the live configuration is unavailable.
        }
        return $nodes;
    }
}
