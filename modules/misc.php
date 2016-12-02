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
	 * Miscellaneous functions that just don't have a place elsewhere
	 *
	 * @package core
	 */
	class Misc_Module extends Module_Skeleton
	{
		const MOUNTRC = '/etc/init.d/vmount';
		private $_mounts = array(
			'fcgi'   => '/var/tmp/fcgi',
			'procfs' => '/proc'
		);

		/**
		 * void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();
		}

		/**
		 * Current control panel version
		 *
		 * @return array
		 */
		public static function cp_version($field = '')
		{
			// @TODO convert to cache
			$cache = Cache_Super_Global::spawn();
			$key = 'g:cp_rev';
			if (false == ($cp = $cache->get($key))) {
				$xml = simplexml_load_string(shell_exec('svn info --xml ' . INCLUDE_PATH));

				if (!is_object($xml)) return warn("can't fetch svn rev info");
				$commit = $xml->entry->commit;
				$cp = array(
					'revision'  => (string)$commit->attributes()->revision,
					'timestamp' => strtotime($commit->date),
					'ver_min'   => APNSCP_VERSION,
					'ver_maj'   => 0
				);

				$ts = mktime(3, 30, 0);
				if (time() >= $ts) $ts += 86400;
				$cache->set($key, $cp, $ts - $_SERVER['REQUEST_TIME']);
			}
			return $field ? $cp[$field] : $cp;
		}

		public function platform_version() {
			return platform_version();
		}

		public function _init()
		{
			$this->exportedFunctions = array(
				'*'                      => PRIVILEGE_SITE,
				'cp_version'             => PRIVILEGE_ALL,
				'platform_version'       => PRIVILEGE_ALL,
				'dashboard_memory_usage' => PRIVILEGE_ALL,
				'lservice_memory_usage'  => PRIVILEGE_ALL,
				'changelog'              => PRIVILEGE_ALL,
				'run'                    => PRIVILEGE_SITE
			);
		}

		/**
		 * int dashboard_memory_usage()
		 *
		 * @return int memory usage, in bytes, that the dashboard is currently
		 * consuming
		 */
		public function dashboard_memory_usage()
		{
			return memory_get_usage();
		}

		/**
		 * int lservice_memory_usage()
		 *
		 * @return int memory usage in bytes
		 */
		public function apnscpd_memory_usage()
		{
			if (!IS_CLI)
				return $this->query('misc_apnscpd_memory_usage');
			return memory_get_usage();
		}

		public function toggle_procfs()
		{
			if (!$this->get_service_value('ssh', 'enabled'))
				return error("procfs requires ssh");
			if ($this->is_mounted('procfs'))
				return $this->unmount_service('procfs');
			return $this->mount_service('procfs');
		}

		public function is_mounted($svc)
		{
			// helios & apollo automatically mount fcgi
			if ($svc == 'fcgi' && version_compare(platform_version(), '4.5', '>=')) {
				return true;
			} else if (version_compare(platform_version(), '6', '>=')) {
				// sol automatically mounts procfs
				return true;
			}
			$proc = Util_Process::exec('%s mounted %s %s',
				self::MOUNTRC,
				$this->site,
				$svc,
				array(0, 1)
			);
			return $proc['errno'] == 0;
		}

		public function unmount_service($svc)
		{
			// helios & apollo automatically mount fcgi
			if ($svc == 'fcgi' && version_compare(platform_version(), '4.5', '>=')) {
				return true;
			} else if ($svc == 'procfs' && version_compare(platform_version(), '6', '>=')) {
				return true;
			}

			if (!IS_CLI)
				return $this->query('misc_unmount_service', $svc);
			$proc = Util_Process::exec(
				'%s unmount %s %s',
				self::MOUNTRC,
				$this->site,
				$svc
			);
			if ($proc['errno'] != 0)
				return false;
			return $this->_edit_mount_map($svc, 0);
		}

		private function _edit_mount_map($svc, $mount)
		{
			$sysconf = '/etc/sysconfig/vmount-' . $svc;
			touch($sysconf);
			$sites = explode("\n", trim(file_get_contents($sysconf)));
			$idx = array_search($this->site, $sites);
			if ($mount && $idx === false) {
				$sites[] = $this->site;
			} else if (!$mount && $idx !== false) {
				unset($sites[$idx]);
			} else {
				return -1;
			}
			file_put_contents($sysconf, join("\n", $sites));
			return 1;

		}

		public function mount_service($svc)
		{
			// helios & apollo automatically mount fcgi
			if ($svc == 'fcgi' && version_compare(platform_version(), '4.5', '>=')) {
				return true;
			} else if ($svc == 'procfs' && version_compare(platform_version(), '6', '>=')) {
				return true;
			}
			if (!IS_CLI)
				return $this->query('misc_mount_service', $svc);
			$proc = Util_Process::exec(
				'%s mount %s %s',
				self::MOUNTRC,
				$this->site,
				$svc
			);
			if ($proc['errno'] != 0)
				return false;

			return $this->_edit_mount_map($svc, 1);
		}

		public function procfs_enabled()
		{
			return $this->is_mounted('procfs');
		}

		public function changelog()
		{
			if (!IS_CLI)
				return $this->query('misc_changelog');
			$path = '/usr/local/apnscp_esprit';
			if (version_compare(platform_version(), 5, '>=')) {
				$path = '/usr/local/apnscp';
			}
			$proc = Util_Process::exec('/usr/bin/svn log '
				. $path . '/lib -v --limit 15');
			if (!$proc['success']) return false;
			return $proc['output'];
		}

		public function _edit()
		{
			$conf_cur = Auth::profile()->conf->cur;
			$conf_new = Auth::profile()->conf->new;
			if ($conf_new == $conf_cur) return;
			if (!$conf_new['ssh']['enabled']) $this->_delete();
			return;
		}

		public function _delete()
		{
			$services = array('procfs', 'fcgi');
			foreach ($services as $s) {
				if ($this->is_mounted($s))
					$this->unmount_service($s);
			}
		}

		public function test()
		{
			return $this->run("sleep 100");
		}

		public function _housekeeping() {
			// flush cp pagespeed cache
			if (extension_loaded('curl')) {
				$adapter = new HTTP_Request2_Adapter_Curl();
			} else {
				$adapter = new HTTP_Request2_Adapter_Socket();
			}
			dlog("Purging CP pagespeed cache");
			$url = 'http://' . Auth_Redirect::makeCPFromServer(SERVER_NAME_SHORT) .
				':' . Auth_Redirect::CP_PORT . '/*';
			
			$http = new HTTP_Request2(
				$url,
				'PURGE',
				array(
					'adapter' => $adapter,
					'store_body' => false
				)
			);
			try {
				$http->send();
			} catch (Exception $e) {
				dlog("WARN: failed to purge pagespeed cache, " . $e->getMessage());
			}
			return true;
		}
	}

?>
