<?php
namespace OPNsense\Adguardhome\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;

class SyncController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\\OPNsense\\Adguardhome\\Sync';
    protected static $internalModelName = 'sync';

    protected function getModelNodes()
    {
        $nodes = parent::getModelNodes();
        $nodes['secret'] = '';
        $nodes['api_password'] = '';
        return $nodes;
    }

    /**
     * Generate a pairing secret on the backend so the browser never has to.
     * 36 random bytes give 48 base64url characters, inside the 32..256 range
     * the synchronization daemon enforces.  The value is returned once and is
     * never readable again after it has been saved.
     */
    public function generateSecretAction()
    {
        $this->throwReadOnly();
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $secret = rtrim(strtr(base64_encode(random_bytes(36)), '+/', '-_'), '=');
        return ['status' => 'ok', 'secret' => $secret];
    }

    protected function setActionHook()
    {
        $posted = $this->request->getPost(static::$internalModelName);
        if (!is_array($posted)) {
            return;
        }
        $config = Config::getInstance()->object();
        // Keep stored credentials when the matching field is posted empty.
        foreach (['secret', 'api_password'] as $field) {
            if (empty($posted[$field])) {
                $this->getModel()->$field = (string)($config->OPNsense->adguardhome->sync->$field ?? '');
            }
        }
    }
}
