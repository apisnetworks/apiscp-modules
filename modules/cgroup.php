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
     *  Control group interfacing
     *
     * @package core
     */
    class Cgroup_Module extends Module_Skeleton
    {
        const CGROUP_LOCATION = '/.socket/cgroup';
        const CGROUP_ACCOUNT_CONFIG = '/etc/cgconfig.d/cgconfig.conf';
        const MAX_MEMORY = 16384;
        const DEFAULT_MEMORY = 512;
        const DEFAULT_CPU = 10240;
        /** in MB */
        const MAX_PROCS = 25;

        public function __construct()
        {
            parent::__construct();
            if (version_compare(platform_version(), 5, '<')) {
                return;
            }
            $this->exportedFunctions = array(
                '*' => PRIVILEGE_SITE | PRIVILEGE_USER
            );
        }

        public function get_usage($controller)
        {
            if (!in_array($controller, $this->get_controllers())) {
                return error("unknown controller `%s'");
            }
            return call_user_func(array($this, '_get_' . $controller . '_usage'));
        }

        public function get_controllers()
        {
            return array('cpu', 'memory');
        }

        public function _create()
        {
            if (!version_compare(platform_version(), 5, '>=')) {
                return;
            }
            $path = $this->web_site_config_dir();
            $file = $path . '/cgroup';
            $config = '<IfModule cgroup_module>' .
                "\n\t" . "cgroup " . $this->site .
                "\n" . '</IfModule>';
            if (!file_exists($file)) {
                file_put_contents($file, $config);
            }

            foreach ($this->get_controllers() as $controller) {
                $this->_createController($controller);
            }
            $this->_addConfig($this->site, $this->user_id, $this->group_id);
        }

        public function _delete()
        {
            foreach ($this->get_controllers() as $controller) {
                $this->_removeController($controller);
            }
            $this->_removeConfig($this->site);
        }

        public function get_cgroup()
        {
            if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
                return $this->site;
            }
            return null;
        }

        private function _createController($name)
        {
            $cgpath = self::CGROUP_LOCATION . '/' . $name;
            if (!file_exists($cgpath)) {
                return error("cgroup path `%s' doesn't exist",
                    $cgpath);
            }
            $cgname = $this->get_cgroup();
            if (!$cgname) {
                return true;
            }
            $cgpath .= '/' . $cgname;
            if (file_exists($cgpath)) {
                // botched removal
                $this->_removeController($name);
            }
            // ensure web server has an opportunity to set
            // cgroup as well
            $ginfo = posix_getgrgid($this->group_id);
            $args = array(
                'site'   => $this->site,
                'apache' => Web_Module::WEB_USERNAME,
                'group'  => $ginfo['name']
            );
            $ret = Util_Process::exec('cgcreate --dperm=711 -a root:root -g memory:%(site)s ' .
                '-g cpu:%(site)s -t %(apache)s:%(group)s', $args);
            return $ret['success'];
        }

        private function _removeController($name)
        {
            $cgpath = self::CGROUP_LOCATION . '/' . $name;
            if (!file_exists($cgpath)) {
                return error("cgroup path `%s' doesn't exist",
                    $cgpath);
            }
            $cgname = $this->get_cgroup();
            if (!$cgname) {
                return true;
            }
            $cgpath .= '/' . $cgname;
            if (!file_exists($cgpath)) {
                return true;
            }
            // alternatively if this gives us problems, cgdelete cpuacct:site memory:site
            $site = $this->site;
            $ret = Util_Process::exec('cgdelete -r cpuacct:' .
                $site . ' -r memory:' . $site);
            return $ret['success'];
        }

        /**
         * Add account to cgconfig.conf
         *
         * @param $site
         * @param $uid
         * @param $gid
         * @return bool|void
         */
        private function _addConfig($site, $uid, $gid)
        {
            $config = self::CGROUP_ACCOUNT_CONFIG;
            if (!file_exists($config)) {
                if (!is_dir(dirname($config))) {
                    mkdir(dirname($config));
                }
                touch($config);
            }


            $fp = fopen($config, 'r+');
            $blocked = false;
            for ($i = 0; $i < 10; $i++) {
                if (flock($fp, LOCK_EX | LOCK_NB, $blocked)) {
                    break;
                }
                sleep(2);
            }
            if ($blocked) {
                fclose($fp);
                return error("failed to lock cg config for `%s'", $site);
            }
            $search = $site . " ";
            $found = false;
            while (false !== ($line = fgets($fp))) {
                if (0 === strpos($line, $search)) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $cgconf = $this->_formatCgConfig($site, $uid, $gid);
                fwrite($fp, $cgconf . "\n");
            }
            flock($fp, LOCK_UN);
            return fclose($fp);
        }

        private function _formatCgConfig($site, $uid, $gid)
        {
            return 'group ' . $site . ' { perm { task { user = apache; gid = ' . intval($gid) .
                '; } admin { uid = root; gid = root; }}}';
        }

        /**
         * Remove account from cgconfig.conf
         *
         * @param $site
         * @return bool|void
         */
        private function _removeConfig($site)
        {
            $config = self::CGROUP_ACCOUNT_CONFIG;
            if (!file_exists($config)) {
                return false;
            }
            $new = array();
            $fp = fopen($config, 'r');
            if (!flock($fp, LOCK_EX)) {
                fclose($fp);
                return error("failed to remove cg configuration `%s'", $site);
            }
            $search = $site . " ";
            $len = strlen($search);
            while (false !== ($line = fgets($fp))) {
                if (!strncmp($line, $search, $len)) {
                    continue;
                }
                $new[] = $line;
            }
            ftruncate($fp, 0);
            fwrite($fp, join("\n", $new));
            flock($fp, LOCK_UN);
            return fclose($fp);
        }

        /**
         * Get controller memory usage
         *
         * @return array
         */
        private function _get_memory_usage()
        {
            $stats = array(
                'used'     => null,
                'peak'     => null,
                'free'     => null,
                'limit'    => $this->get_service_value('cgroup', 'memory', self::DEFAULT_MEMORY) * 1024 * 1024 * 1024,
                'procs'    => array(),
                'detailed' => array()
            );
            $path = self::CGROUP_LOCATION . '/' . 'memory/' . $this->get_cgroup();
            if (!file_exists($path) || !is_readable($path . '/cgroup.procs')) {
                return $stats;
            }
            $stats['used'] = (int)file_get_contents($path . '/memory.usage_in_bytes');
            $stats['peak'] = (int)file_get_contents($path . '/memory.max_usage_in_bytes');
            $stats['free'] = (int)($stats['limit'] - $stats['used']);
            $stats['procs'] = array_map(function ($a) {
                return (int)$a;
            },
                file($path . '/cgroup.procs', FILE_IGNORE_NEW_LINES));
            return $stats;
        }

        private function _get_cpu_usage()
        {
            $stats = array(
                'used'     => null,
                'system'   => null,
                'free'     => null,
                'limit'    => $this->get_service_value('cgroup', 'cpu', self::DEFAULT_CPU),
                'user'     => null,
                'procs'    => array(),
                'maxprocs' => $this->get_service_value('cgroup', 'proclimit', self::MAX_PROCS)
            );
            $path = self::CGROUP_LOCATION . '/' . 'cpuacct/' . $this->get_cgroup();
            if (!file_exists($path) || !is_readable($path . '/cgroup.procs')) {
                return $stats;
            }

            $stats['used'] = intval(file_get_contents($path . '/cpuacct.usage'));
            $tmp = file($path . '/cpuacct.stat', FILE_IGNORE_NEW_LINES);
            $stats['user'] = (float)substr($tmp[0], strpos($tmp[0], " ") + 1) / CPU_CLK_TCK;
            $stats['system'] = (float)substr($tmp[1], strpos($tmp[1], " ") + 1) / CPU_CLK_TCK;
            $stats['free'] = (int)($stats['limit'] - $stats['used']);
            $stats['procs'] = array_map(function ($a) {
                return (int)$a;
            },
                file($path . '/cgroup.procs', FILE_IGNORE_NEW_LINES)
            );
            return $stats;
        }


    }
