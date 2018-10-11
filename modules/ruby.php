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
	 * Ruby, RoR features formerly under Web_Module
	 *
	 * @package core
	 */
	class Ruby_Module extends Module_Skeleton
	{
		const LTS = '2.4.4';
		public $exportedFunctions = array('*' => PRIVILEGE_SITE);

		public function __construct()
		{
			if (!platform_is('7.5')) {
				$this->exportedFunctions = [];
			}
			parent::__construct();
		}

		/**
		 * Execute Ruby within the scope of a version
		 *
		 * @param null|string $version
		 * @param string      $pwd
		 * @param string      $command
		 * @param array       $args optional command arguments
		 * @return array process output from pman_run
		 */
		public function do(?string $version, ?string $pwd = '~', string $command, ...$args): array
		{
			if ($version === 'lts') {
				$version = $this->get_lts();
			}
			$args[0]['_RUBY_PWD'] = $pwd ?? '~';

			if (!isset($args[1])) {
				$args[1] = [];
			}
			if ($version) {
				$args[1] += [
					'RBENV_VERSION' => $version
				];
			}

			$ret = $this->pman_run('/bin/bash -ic -- ' . escapeshellarg('cd %(_RUBY_PWD)s' .' && rbenv exec ' . $command), ...$args);
			if (!$ret['success']) {
				// no job control warning
				error(coalesce($ret['stdout'], $ret['stderr']));
			}
			return $ret;
		}

		/**
		 * Remove an installed Ruby
		 *
		 * @param string $version
		 * @return bool
		 */
		public function uninstall(string $version): bool
		{
			if ($version === 'lts') {
				$version = $this->get_lts();
			}
			$ret = $this->exec('uninstall -f', $version);
			if (!$ret['success']) {
				return error('failed to uninstall Ruby %s: %s',
					$version,
					coalesce($ret['stderr'], $ret['stdout'])
				);
			}

			return true;
		}

		/**
		 * Assign Ruby version to directory
		 *
		 * @param string $version
		 * @param string $path
		 * @return bool
		 */
		public function make_default(string $version, string $path = '~'): bool
		{
			if ($version === 'lts') {
				$version = $this->get_lts();
			}
			$path .= '/.ruby-version';

			return $this->file_put_file_contents($path, $version, true);
		}


		/**
		 * Install Ruby
		 *
		 * @param string $version
		 * @return bool
		 */
		public function install(string $version): bool
		{
			if ($version === 'lts') {
				$version = $this->get_lts();
			}
			$ret = $this->exec('install', $version);
			if (!$ret['success']) {
				return error('failed to install Ruby %s, error: %s',
					$version,
					coalesce($ret['stderr'], $ret['stdout'])
				);
			}

			return true;
		}

		/**
		 * Get configured Ruby LTS
		 *
		 * @return string
		 */
		protected function get_lts(): string {
			$prefs = \Preferences::factory($this->getAuthContext());
			return array_get($prefs, 'ruby.lts', static::LTS);
		}

		/**
		 * Set LTS for account
		 *
		 * @param string $version
		 */
		protected function set_lts(string $version): void {
			$prefs = \Preferences::factory($this->getAuthContext());
			$prefs->unlock($this->getApnscpFunctionInterceptor());
			array_set($prefs, 'ruby.lts', $version);
		}

		/**
		 * Ruby version is installed
		 *
		 * @param string $version
		 * @return bool
		 */
		public function installed(string $version): bool
		{
			if ($version === 'lts') {
				return $this->lts_installed();
			}
			$nodes = $this->list();

			return isset($nodes[$version]) || in_array($version, $nodes, true);
		}

		/**
		 * Get available Rubies
		 *
		 * @return array
		 */
		public function get_available(): array
		{
			$cache = \Cache_Super_Global::spawn();
			$key = 'ruby.rem';
			if (false !== ($res = $cache->get($key))) {
				return $res;
			}
			$ret = $this->exec('install --list');
			if (!$ret['success']) {
				error('failed to query Rubies - is rbenv installed?');

				return [];
			}
			$rubies = [];
			strtok($ret['output'], "\n ");
			while (false !== ($ruby = strtok("\n "))) {
				$rubies[] = $ruby;
			}

			$cache->set($key, $rubies);

			return $rubies;
		}

		/**
		 * List installed Rubys
		 *
		 * @return array
		 */
		public function list(): array
		{
			// 3 = no nodes installed
			$ret = $this->exec('versions');
			$rubies = [];
			if (preg_match_all('/^(?>(?<default>\S+)|\s+)\s*(?<version>\S+)(?>$|\s*)(?<misc>[^\r\n]*)$/m', $ret['output'], $versions, PREG_SET_ORDER)) {
				foreach ($versions as $v) {
					$rubies[] = $v['version'];
					if (isset($v['default'])) {
						$rubies['active'] = $v['version'];
					}
				}
				return $rubies;
			}

			return [];
		}

		/**
		 * Latest LTS is installed
		 *
		 * @return bool
		 */
		public function lts_installed(): bool
		{
			$versions = $this->list();
			return \in_array($this->get_lts(), $versions, true);
		}

		/**
		 * nvm wrapper
		 *
		 * @param null|string $name
		 * @param null|string $command
		 * @param array       $args optional args
		 * @return array
		 */
		private function exec(?string $name, string $command = null, ...$args): array
		{
			$ret = $this->pman_run('/bin/bash -ic -- ' . escapeshellarg("rbenv ${name} ${command}"),
				$args,
				[
					'BASH_ENV' => '/dev/null'
				]
			);

			return $ret;
		}

		public function _edit()
		{
			$conf_cur = $this->getAuthContext()->conf('ssh', 'cur');
			$conf_new = $this->getAuthContext()->conf('ssh', 'new');
			if (!version_compare(platform_version(), "6", ">=")) {
				return;
			}
			if ($conf_new['enabled'] && !$conf_cur['enabled']) {
				$this->initialize_gemset();
			}
		}

		public function initialize_gemset($user = null)
		{
			if (platform_is('7.5')) {
				return true;
			}
			if (!IS_CLI) {
				return $this->query('ruby_initialize_gemset', $user);
			}
			if (!is_dir(FILESYSTEM_SHARED . '/ruby')) {
				// Ruby not configured on platform
				return info("skipping rvm initialization - ruby not configured on platform");
			}
			if (!version_compare(platform_version(), "6", ">=")) {
				return info("gemset unsupported on platform v%d", platform_version());
			}
			if (!$user || !($this->permission_level & PRIVILEGE_SITE)) {
				$user = $this->username;
			}

			if (!$this->user_exists($user)) {
				return error("invalid user `%s'", $user);
			}
			if (!$this->misc_procfs_enabled()) {
				return -1;
			}

			$proc = new Util_Process_Sudo();
			$proc->setOption('user', $user);
			$ret = $proc->run("/bin/bash -i rvm user gemsets");
			if (!$ret['success']) {
				return error("error initializing gemset: `%s'", $ret['stderr']);
			}
			return $ret['success'];
		}

		public function _create()
		{
			$conf_new = $this->getAuthContext()->conf('ssh', 'new');
			if (!$conf_new['enabled']) {
				return true;
			}
			if (version_compare(platform_version(), "6", ">=")) {
				$this->initialize_gemset();
			}

		}
	}