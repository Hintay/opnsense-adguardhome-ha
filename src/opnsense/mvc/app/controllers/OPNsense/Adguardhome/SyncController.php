<?php
namespace OPNsense\Adguardhome;

class SyncController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->syncForm = I18n::translateForm($this->getForm('sync'), $this->langcode);
        $this->view->statusForm = I18n::translateForm($this->getForm('status'), $this->langcode);
        $this->view->t = I18n::catalog($this->langcode);
        $this->view->pick('OPNsense/Adguardhome/sync');
    }
}
