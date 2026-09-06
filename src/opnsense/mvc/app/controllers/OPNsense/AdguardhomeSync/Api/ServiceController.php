<?php
namespace OPNsense\AdguardhomeSync\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
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
        return [
            'status' => !empty($result['enabled']) && !empty($result['service_running']) ? 'running' : 'stopped',
            'widget' => [
                'caption_start' => gettext('Start service'),
                'caption_restart' => gettext('Restart service'),
                'caption_stop' => gettext('Stop service'),
            ],
        ];
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
