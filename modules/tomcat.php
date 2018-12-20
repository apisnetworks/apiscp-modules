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
	 * Tomcat functions
	 *
	 * @package core
	 */
	class Tomcat_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable
	{
		const DEPENDENCY_MAP = ['apache'];
		const TOMCAT_PORT = 8080;

		public $exportedFunctions;

		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = array(
				'*'           => PRIVILEGE_SITE,
				'version'     => PRIVILEGE_ALL,
				'system_user' => PRIVILEGE_ALL,
				'enabled'     => PRIVILEGE_SITE | PRIVILEGE_USER,
				'permitted'   => PRIVILEGE_SITE | PRIVILEGE_USER

			);
		}

		/**
		 * Current user under which Tomcat operates
		 *
		 * @return null|string username or null if not present on system
		 */
		public function system_user(): ?string
		{
			$user = $this->_getKey();

			// same user as service name, Helios+ > tomcat
			return posix_getpwnam($user)['name'] ?? null;
		}

		/**
		 * Tomcat service key
		 *
		 * @return string
		 */
		private function _getKey()
		{
			$version = platform_version();
			if (version_compare($version, '5', '>=')) {
				// helios
				return 'tomcat';
			}

			return 'tomcat4';
		}

		/**
		 * Tomcat is enabled for an account
		 *
		 * @return bool
		 */
		public function enabled()
		{
			$key = $this->_getKey();

			return (bool)$this->getServiceValue($key, 'enabled');
		}

		/**
		 * Confirm Tomcat may be enabled for an account
		 *
		 * @return bool
		 */
		public function permitted()
		{
			$version = platform_version();
			if (version_compare($version, '4.5', '>=')) {
				// helios, apollo/aleph
				$key = $this->_getKey();

				return (bool)$this->getServiceValue($key, 'permit');
			}

			// older platforms with PostgreSQL enabled imply permit
			return (bool)$this->sql_enabled('pgsql');
		}

		/**
		 * Get Tomcat version number
		 *
		 * @return string
		 */
		public function version()
		{
			static $version;
			if (isset($version) && $version) {
				return $version;
			}
			$cache = Cache_Global::spawn();
			$key = 'tomcat.version';
			$version = $cache->get($key);
			if ($version) {
				return $version;
			}
			/**
			 * couple different strategies here:
			 * run version.sh or scrape localhost:8080
			 */
			$platformver = platform_version();
			$prefix = null;
			if (version_compare($platformver, '4.5', '>=')) {
				// aleph, helios+
				$prefix = $this->_getPrefix();
			}
			$path = $prefix . '/bin/version.sh';

			if (file_exists($path)) {
				$resp = Util_Process::exec($path);
				if (preg_match(Regex::TOMCAT_VERSION, $resp['output'], $m)) {
					$version = $m['version'];
				}
			}

			// bin/version.sh failed
			if (!$version) {
				$req = new HTTP_Request2('http://127.0.0.1:' . self::TOMCAT_PORT,
					HTTP_Request2::METHOD_GET, array('use_brackets' => true));
				$response = $req->send()->getBody();
				if (preg_match(Regex::TOMCAT_VERSION, $response, $m)) {
					$version = $m['version'];
				}
			}
			if (!$version) {
				$version = 'undefined';
			}
			$cache->set($key, $version);

			return $version;
		}

		/**
		 * Tomcat installation root
		 *
		 * @return string
		 */
		private function _getPrefix()
		{
			$version = platform_version();
			if (version_compare($version, '5', '>=')) {
				// aleph, helios+
				return '/opt/tomcat';
			} else {
				return '/opt/tomcat4';
			}
		}

		/**
		 * General EditVirtDomain hook
		 *
		 * @return bool
		 */
		public function _edit()
		{
			$key = $this->_getKey();

			$conf_old = $this->getAuthContext()->conf($key, 'old');
			$conf_new = $this->getAuthContext()->conf($key, 'new');

			if ($conf_new === $conf_old) {
				return;
			}
			$log = '/var/log/catalina.out';
			$path = $this->domain_fs_path() . $log;
			$origlog = $this->_getPrefix() . $log;
			if (file_exists($path)) {
				unlink($path);
			}
			if ($conf_new['enabled']) {
				link($origlog, $path);
			}

			return true;
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}

		public function _create()
		{
			// TODO: Implement _create() method.
		}

		public function _delete()
		{
			// TODO: Implement _delete() method.
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


	}
