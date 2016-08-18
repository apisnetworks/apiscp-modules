<?php
    /**
     * 
     * 
     * @author Matt Saladna <matt@apisnetworks.com>
     */
    class Python_Module extends Module_Skeleton {
        public $exportedFunctions = array(
            '*' => PRIVILEGE_SITE
        );
        
        private function _cmd($method, $module) {
            $cmd = 'pip-python %(method)s --install-option ' . 
                    '"--prefix=/usr/local" -- %(module)s';
        }
    }
?>
