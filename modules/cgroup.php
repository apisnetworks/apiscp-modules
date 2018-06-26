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
     *  Control group interfacing
     *
     * @package core
     */
    class Cgroup_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable
    {
        const CGROUP_LOCATION = \Opcenter\System\Cgroup::CGROUP_HOME;
	    const DEPENDENCY_MAP = [
		    'apache'
	    ];
        const MAX_MEMORY = 16384;
        const DEFAULT_MEMORY = 512;
        const DEFAULT_CPU = 10240;
        /** in MB */
        const MAX_PROCS = 25;

        public function __construct()
        {
            parent::__construct();
            $this->exportedFunctions = array(
                '*' => PRIVILEGE_SITE | PRIVILEGE_USER
            );
        }

        public function get_usage($controller)
        {
        	if (!IS_CLI) {
        		return $this->query('cgroup_get_usage', $controller);
	        }
            if (!in_array($controller, $this->get_controllers())) {
                return error("unknown controller `%s'");
            }
            return $this->{'_get_' . $controller . '_usage'}();
        }

        public function get_controllers()
        {
            return array('cpu', 'memory');
        }

        public function _create()
        {
	        if (platform_is('7.5')) {
		        return true;
	        }
	        $path = $this->web_site_config_dir();
	        // has no effect on cgroupv1 + threaded MPM
	        $file = $path . '/cgroup';
	        $config = '<IfModule cgroup_module>' .
                "\n\t" . "cgroup " . $this->site .
                "\n" . '</IfModule>';
	        if (!file_exists($file)) {
	            file_put_contents($file, $config);
            }
            foreach ($this->get_controllers() as $controller) {
                \Opcenter\System\Cgroup::create($controller, $this->site,
					[
						'tuid' => Web_Module::WEB_USERNAME,
						'tgid' => posix_getgrgid((int)$this->group_id)['name']
					]);
            }
        }

        public function _delete()
        {
	        if (platform_is('7.5')) {
		        return true;
	        }
            foreach ($this->get_controllers() as $controller) {
	            if (!\Opcenter\System\Cgroup::delete($controller, $this->site)) {
	            	warn("Failed to remove cgroup group `%s' from controller `%s'", $this->site, $controller);
	            }
            }

        }

        public function get_cgroup()
        {
            if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
                return $this->site;
            }
            return null;
        }

        /**
         * Get controller memory usage
         *
         * @return array
         */
        private function _get_memory_usage()
        {
			return $this->_fillUsage(
				\Opcenter\System\Cgroup::get_memory($this->site),
				[
					'limit' => $this->get_service_value('cgroup', 'memory', self::DEFAULT_MEMORY) * 1024 * 1024 * 1024,
				]
			);

        }

        private function _get_cpu_usage()
        {
	        return $this->_fillUsage(
		        \Opcenter\System\Cgroup::cpu_usage($this->site),
		        [
			        'limit'    => $this->get_service_value('cgroup', 'cpu', self::DEFAULT_CPU),
			        'maxprocs' => $this->get_service_value('cgroup', 'proclimit', self::MAX_PROCS)
		        ]
            );
        }

	    /**
	     * Populate cgroup defaults on controller error
	     *
	     * @param array $usage
	     * @param array $defaults
	     * @return array
	     */
        private function _fillUsage(array $usage, array $defaults): array {
	        foreach ($defaults as $k => $v) {
		        if (null === $usage[$k]) {
			        $usage[$k] = $this->get_service_value('cgroup', $v, $v);
		        }
	        }
	        return $usage;
        }

	    public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
	    {
	    	return true;
	    }

	    public function _edit()
	    {
		    // TODO: Implement _edit() method.
	    }

	    public function _create_user(string $user)
	    {
		    // TODO: Implement _create_user() method.
	    }

	    public function _delete_user(string $user)
	    {
		    // TODO: Implement _delete_user() method.
	    }

	    public function _edit_user(string $userold, string $usernew, array $oldpwd)
	    {
		    // TODO: Implement _edit_user() method.
	    }

	    public function _housekeeping() {
        	if (!$test = $this->get_controllers()[0] ?? null) {
        		return;
	        }
        	if (!\Opcenter\Filesystem\Mount::mounted(FILESYSTEM_SHARED . "/cgroup/${test}") && !\Opcenter\System\Cgroup::mountAll()) {
        		return false;
	        }
	        foreach (\Opcenter\Account\Enumerate::sites() as $site) {
        		foreach (\Opcenter\System\Cgroup::getControllers() as $c) {
        			$path = CGROUP_HOME . "/${c}/${site}";
        			if (file_exists($path)) {
        				continue;
			        }
			        \Opcenter\System\Cgroup::create($c, $site,
				        [
					        'tuid' => Web_Module::WEB_USERNAME,
					        'tgid' => \Auth::get_group_from_site($site)
				        ]);
		        }
	        }
	        return true;
	    }

    }
