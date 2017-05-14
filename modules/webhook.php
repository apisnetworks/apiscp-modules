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
     * Webhook functions
     *
     * @package core
     */
    class Webhook_Module extends Module_Skeleton
    {
        const PREFERENCES_KEY = 'webhooks';

        public $exportedFunctions;

        public function __construct()
        {
            parent::__construct();
            $this->exportedFunctions = array(
                '*' => PRIVILEGE_SITE,
            );
        }

        public function dispatch($funcs)
        {
            // todo
        }

        public function init()
        {
            // perform filter fetching
            $prefs = $this->common_load_preferences();
        }
    }

?>
