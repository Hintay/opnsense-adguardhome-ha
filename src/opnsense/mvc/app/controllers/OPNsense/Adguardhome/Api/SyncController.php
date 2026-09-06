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
        return $nodes;
    }

    protected function setActionHook()
    {
        $posted = $this->request->getPost(static::$internalModelName);
        if (is_array($posted) && empty($posted['secret'])) {
            $config = Config::getInstance()->object();
            $secret = (string)($config->OPNsense->adguardhome->sync->secret ?? '');
            $this->getModel()->secret = $secret;
        }
    }
}
