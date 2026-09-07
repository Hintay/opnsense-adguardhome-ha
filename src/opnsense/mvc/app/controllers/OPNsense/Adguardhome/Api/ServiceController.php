<?php

/*
 * Copyright (C) 2021 Michael Muenz <michael.muenz@max-it.de>
 * All rights reserved.
 */

namespace OPNsense\Adguardhome\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\Adguardhome\General';
    protected static $internalServiceTemplate = 'OPNsense/Adguardhome';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'adguardhome';

    public function reconfigureAction()
    {
        $this->throwReadOnly();
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        try {
            $backend = new Backend();
            $backend->configdRun('template reload OPNsense/Adguardhome');
            $output = $backend->configdRun('adguardhome dns_apply');
            $result = json_decode($output, true);
            if (!is_array($result) || !in_array($result['status'] ?? '', ['updated', 'unchanged'], true)) {
                return is_array($result) ? $result : ['status' => 'failed', 'message' => gettext('Backend unavailable.')];
            }
            if ($result['status'] === 'updated' && ($result['synchronization_role'] ?? '') === 'source') {
                $backend->configdRun('adguardhomesync sync');
            }
            return ['status' => 'ok', 'result' => $result['status'], 'warnings' => $result['warnings'] ?? []];
        } catch (\Throwable $error) {
            return ['status' => 'failed', 'message' => gettext('Backend unavailable.')];
        }
    }
}
