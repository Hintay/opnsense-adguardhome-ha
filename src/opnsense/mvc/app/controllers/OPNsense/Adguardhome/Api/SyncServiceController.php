<?php
namespace OPNsense\Adguardhome\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class SyncServiceController extends ApiControllerBase
{
    private function invoke(string $action): array
    {
        try {
            $output = (new Backend())->configdRun('adguardhomesync ' . $action);
        } catch (\Throwable $error) {
            return ['status' => 'failed', 'message' => gettext('Backend unavailable.')];
        }
        $result = json_decode($output, true);
        return is_array($result) ? $result : ['status' => 'failed', 'message' => gettext('Backend unavailable.')];
    }

    public function statusAction()
    {
        $result = $this->invoke('status');
        $running = !empty($result['enabled']) && !empty($result['service_running']);
        return [
            'status' => $running ? 'running' : 'stopped',
            'widget' => [
                'caption_start' => gettext('Start service'),
                'caption_restart' => gettext('Restart service'),
                'caption_stop' => gettext('Stop service'),
            ],
            'runtime' => [
                'role' => $result['role'] ?? '',
                'local_address' => $result['listen_address'] ?? '',
                'peer_address' => $result['peer_address'] ?? '',
                'port' => $result['port'] ?? '',
                'certificate' => $result['certificate_fingerprint'] ?? '',
                'secret_configured' => !empty($result['secret_configured']),
                'pending_config' => !empty($result['pending_config']),
                'learned_fingerprint' => $result['learned_fingerprint'] ?? '',
                'api_configured' => !empty($result['api_configured']),
                'api_message' => $result['api_message'] ?? '',
                'base_present' => !empty($result['base_present']),
                'peer_carp_master' => $result['peer_carp_master'] ?? null,
                'last_adopted' => is_array($result['last_adopted'] ?? null) ? $result['last_adopted'] : null,
                'last_conflict' => is_array($result['last_conflict'] ?? null) ? $result['last_conflict'] : null,
                'last_overwritten' => is_array($result['last_overwritten'] ?? null) ? $result['last_overwritten'] : null,
                'api_mode' => $result['api_mode'] ?? '',
                'api_account_state' => $result['api_account_state'] ?? '',
                'last_result' => $result['last_result'] ?? '',
                'last_error' => $result['last_error'] ?? '',
            ],
            'message' => $result['message'] ?? '',
        ];
    }

    public function reconfigureAction()
    {
        $this->throwReadOnly();
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        try {
            (new Backend())->configdRun('template reload OPNsense/Adguardhome');
        } catch (\Throwable $error) {
            return ['status' => 'failed', 'message' => gettext('Backend unavailable.')];
        }
        return $this->invoke('apply');
    }

    public function syncAction()
    {
        $this->throwReadOnly();
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $result = $this->invoke('sync');
        if (in_array($result['status'] ?? '', ['updated', 'unchanged'], true)) {
            return ['status' => 'ok', 'result' => $result['status']];
        }
        return $result;
    }

    public function applyPendingAction()
    {
        $this->throwReadOnly();
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $result = $this->invoke('apply_pending');
        if (in_array($result['status'] ?? '', ['updated', 'unchanged', 'hot', 'staged'], true)) {
            return ['status' => 'ok', 'result' => $result['status']];
        }
        return $result;
    }

    public function startAction()
    {
        $this->throwReadOnly();
        return $this->request->isPost() ? $this->invoke('start') : ['status' => 'failed'];
    }

    public function restartAction()
    {
        $this->throwReadOnly();
        return $this->request->isPost() ? $this->invoke('restart') : ['status' => 'failed'];
    }

    public function stopAction()
    {
        $this->throwReadOnly();
        return $this->request->isPost() ? $this->invoke('stop') : ['status' => 'failed'];
    }
}
