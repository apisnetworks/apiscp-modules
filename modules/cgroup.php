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
		const DEFAULT_MEMORY = 512;
		const DEFAULT_CPU = 10240;
		/** in MB */
		const MAX_PROCS = 25;

		protected $exportedFunctions = [
			'*' => PRIVILEGE_SITE | PRIVILEGE_USER | PRIVILEGE_ADMIN
		];

		public function get_usage($controller)
		{
			if (!IS_CLI) {
				return $this->query('cgroup_get_usage', $controller);
			}
			if (!in_array($controller, $this->get_controllers(), true)) {
				return error("unknown controller `%s'");
			}

			return $this->{'_get_' . $controller . '_usage'}();
		}

		public function get_controllers()
		{
			return ['cpu', 'memory', 'pids', 'cpuacct'];
		}

		public function get_cgroup()
		{
			if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
				return $this->site;
			}

			return null;
		}

		/**
		 * Get configured limits
		 *
		 * @return array
		 */
		public function get_limits(): array
		{
			$limits = $this->getServiceValue('cgroup');
			if (!$limits['enabled']) {
				return [];
			}

			return array_except($limits, ['version', 'enabled']);
		}

		public function enabled(): bool
		{
			return (bool)$this->getServiceValue('cgroup', 'enabled');
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}

		public function _create()
		{
			if (platform_is('7.5')) {
				return true;
			}
			$svc = \Opcenter\SiteConfiguration::import($this->getAuthContext());
			$cgroup = new \Opcenter\Service\Validators\Cgroup\Enabled(new \Opcenter\Service\ConfigurationContext('cgroup',
				$svc), $svc->getSite());

			return $cgroup->populate($svc);
		}

		public function _delete()
		{
			if (platform_is('7.5')) {
				return true;
			}
			$svc = \Opcenter\SiteConfiguration::import($this->getAuthContext());
			$cgroup = new \Opcenter\Service\Validators\Cgroup\Enabled(new \Opcenter\Service\ConfigurationContext('cgroup',
				$svc), $svc->getSite());

			return $cgroup->depopulate($svc);
		}

		public function _edit()
		{
			if (platform_is('7.5') || !platform_is('7')) {
				// busted on Helios (v5)
				return true;
			}
			$svc = \Opcenter\SiteConfiguration::import($this->getAuthContext());
			$cgroup = new \Opcenter\Service\Validators\Cgroup\Enabled(new \Opcenter\Service\ConfigurationContext('cgroup',
				$svc), $svc->getSite());

			return $cgroup->reconfigure(array_get($this->getAuthContext()->conf('cgroup', 'old'), 'enabled', 0),
				array_get($this->getAuthContext()->conf('cgroup', 'new'), 'enabled', 1), $svc);
		}

		public function _create_user(string $user)
		{
			return true;
		}

		public function _delete_user(string $user)
		{
			return true;
		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			return true;
		}

		public function _housekeeping()
		{
			if (!($test = $this->get_controllers()[0] ?? null)) {
				return;
			}
			if (!\Opcenter\Filesystem\Mount::mounted(FILESYSTEM_SHARED . "/cgroup/${test}") && !\Opcenter\System\Cgroup::mountAll()) {
				return false;
			}
			foreach (\Opcenter\Account\Enumerate::sites() as $site) {
				if (!Auth::get_admin_from_site_id((int)substr($site, 4))) {
					continue;
				}
				$group = new \Opcenter\System\Cgroup\Group(
					$site,
					[
						'task' => [
							'uid' => Web_Module::WEB_USERNAME,
							'gid' => \Auth::get_group_from_site($site)
						]
					]
				);
				$ctx = $afi = null;
				foreach (\Opcenter\System\Cgroup::getControllers() as $c) {
					$controller = \Opcenter\System\Cgroup\Controller::make($group, $c, []);
					if (\Opcenter\System\Cgroup::exists($controller, $group)) {
						continue;
					}
					if (null === $ctx) {
						$ctx = \Auth::context(null, $site);
						$afi = \apnscpFunctionInterceptor::factory($ctx);
					}
					$controller->import($afi);
					$controller->create();
					$group->add($controller);
				}
				\Opcenter\System\Cgroup::create($group);
			}

			return true;
		}

		/**
		 * Get controller memory usage
		 *
		 * @return array
		 */
		private function _get_memory_usage()
		{
			$stats['limit'] = self::DEFAULT_MEMORY;
			$stats = \Opcenter\System\Cgroup::get_memory($this->site);
			if ($this->permission_level & PRIVILEGE_ADMIN || $stats['limit'] === null) {
				$stats['limit'] = \Opcenter\System\Memory::stats()['memtotal'] * 1024;
			}
			if ($stats['free'] === null) {
				$stats['free'] = \Opcenter\System\Memory::stats()['memfree'] * 1024;
			}

			return $this->_fillUsage(
				$stats,
				[
					'free' => $stats['limit'] - $stats['used']
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
		private function _fillUsage(array $usage, array $defaults): array
		{
			foreach ($defaults as $k => $v) {
				if (null === $usage[$k]) {
					$usage[$k] = $this->getServiceValue('cgroup', $v, $v);
				}
			}

			return $usage;
		}

		private function _get_cpuacct_usage()
		{
			return [];
		}

		private function _get_pids_usage()
		{
			// @todo replace CPU maxproc with pids subsystem
			$maxprocs = self::MAX_PROCS;
			if ($this->permission_level & PRIVILEGE_ADMIN) {
				$maxprocs = 999;
			}

			return $this->_fillUsage(
				\Opcenter\System\Cgroup::pid_usage($this->site),
				[
					'max' => $this->getServiceValue('cgroup', 'proclimit', $maxprocs)
				]
			);
		}

		private function _get_cpu_usage()
		{
			$maxcpu = self::DEFAULT_CPU;
			$maxprocs = self::MAX_PROCS;
			if ($this->permission_level & PRIVILEGE_ADMIN) {
				$maxcpu = 99999;
				$maxprocs = 999;
			}

			return $this->_fillUsage(
				\Opcenter\System\Cgroup::cpu_usage($this->site),
				[
					'limit'    => $this->getServiceValue('cgroup', 'cpu', $maxcpu),
					'maxprocs' => $this->getServiceValue('cgroup', 'proclimit', $maxprocs)
				]
			);
		}

	}
