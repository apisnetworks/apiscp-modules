<?php
declare(strict_types=1);
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
     * Log viewing and manipulation
     *
     * @package core
     */
    class Log_Module extends Module_Skeleton
    {
        public function tail($type)
        {
            $c = 'Log_' . ucwords($type);
            if (!class_exists($c)) {
                return error("unknown log type `%s'", $c);
            }
            $type = new $c;
            return $c->watch();
        }

        public function filter($type, $filter)
        {
            $c = 'Log_' . ucwords($type);
            if (!class_exists($c)) {
                return error("unknown log type `%s'", $c);
            }
            $type = new $c;
            return $c->filter($filter);
        }

        public function get_supported_logs()
        {
            $dir = opendir(INCLUDE_PATH . DIRECTORY_SEPARATOR . 'Log');
        }

    }

?>
