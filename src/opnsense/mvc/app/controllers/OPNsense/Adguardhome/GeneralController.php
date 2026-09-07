<?php

/*
 * Copyright (C) 2021 Michael Muenz <michael.muenz@max-it.de>
 * All rights reserved.
 */

namespace OPNsense\Adguardhome;

class GeneralController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = I18n::translateForm($this->getForm('general'), $this->langcode);
        $this->view->t = I18n::catalog($this->langcode);
        $this->view->pick('OPNsense/Adguardhome/general');
    }
}
