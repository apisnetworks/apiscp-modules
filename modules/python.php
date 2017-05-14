<?php

    /**
     *  +------------------------------------------------------------+
     *  | apnscp                                                     |
     *  +------------------------------------------------------------+
     *  | Copyright (c) Apis Networks                                |
     *  +------------------------------------------------------------+
     *  | Licensed under Artistic License 2.0                        |
     *  +------------------------------------------------------------+
     *  | Author: Matt Saladna (msaladna@apisnetworks.com)           |
     *  +------------------------------------------------------------+
     */

    /**
     * Class Python_Module
     *
     * @package core
     */
    class Python_Module extends Module_Skeleton
    {
        public $exportedFunctions = array(
            '*' => PRIVILEGE_SITE
        );

        private function _cmd($method, $module)
        {
            $cmd = 'pip-python %(method)s --install-option ' .
                '"--prefix=/usr/local" -- %(module)s';
        }
    }

?>
