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
	 * Manage and install Node versions
	 *
	 * @package core
	 */
	class Node_Module extends Module_Skeleton
	{
		const NVM_LOCATION = FILESYSTEM_SHARED . '/node/nvm/nvm-exec';

		protected $exportedFunctions = [
			'*' => PRIVILEGE_SITE
		];

		/**
		 * void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			if (!platform_is('6.5')) {
				$this->exportedFunctions = [];
			}
			parent::__construct();
		}

		/**
		 * Execute Node within the scope of a version
		 *
		 * @param null|string $version
		 * @param string $command
		 * @param array  $args optional command arguments
		 * @return array process output from pman_run
		 */
		public function do(?string $version, string $command, ...$args): array {
			if ($version === 'lts') {
				$version = '--lts';
			} else if ($version) {
				$version = escapeshellarg($version);
			}
			$ret = $this->exec('exec --silent ' . $version, $command, ...$args);
			return $ret;
		}


		/**
		 * Remove an installed Node
		 *
		 * @param string $version
		 * @return bool
		 */
		public function uninstall(string $version): bool {
			if ($version === 'lts') {
				$version = '--lts';
			}
			$ret = $this->exec('uninstall', $version);
			if (!$ret['success']) {
				return error('failed to uninstall Node %s: %s',
					$version,
					coalesce($ret['stderr'], $ret['stdout'])
				);
			}
			return true;
		}

		/**
		 * Assign Node version to directory
		 *
		 * @param string $version
		 * @param string $path
		 * @return bool
		 */
		public function make_default(string $version, string $path = '~'): bool {
			$path .= '/.nvmrc';
			return $this->file_put_file_contents($path , $version, true);
		}


		/**
		 * Install Node
		 *
		 * @param string $version
		 * @return bool
		 */
		public function install(string $version): bool {
			if ($version === 'lts') {
				$version = '--lts';
			}
			$ret = $this->exec('install', $version);
			if (!$ret['success']) {
				return error('failed to install Node %s, error: %s',
					$version,
					coalesce($ret['stderr'], $ret['stdout'])
				);
			}
			return true;
		}

		/**
		 * Node version is installed
		 *
		 * @param string $version
		 * @return bool
		 */
		public function installed(string $version): bool {
			if ($version === 'lts') {
				return $this->lts_installed();
			}
			$nodes = $this->list();
			return isset($nodes[$version]) || in_array($version, $nodes, true);
		}

		public function get_available(): array {
			$cache = \Cache_Super_Global::spawn();
			$key = 'node.rem';
			if (false !== ($res = $cache->get($key))) {
				return $res;
			}
			$ret = $this->exec('ls-remote');
			if (!$ret['success']) {
				error("failed to query remote Node versions: %s", coalesce($ret['stderr'], $ret['stdout']));
				return [];
			}

			if (!preg_match_all('/\s*v(?<version>\S*)\s*(?:\((?:Latest )?LTS: (\S*)\))?/', $ret['stdout'], $versions, PREG_SET_ORDER)) {
				warn("failed to discover any Nodes");
				return [];
			}
			$versions = array_column($versions, 'version');
			$cache->set($key, $versions);
			return $versions;
		}

		/**
		 * List installed Nodes
		 *
		 * @return array
		 */
		public function list(): array
		{
			// 3 = no nodes installed
			$ret = $this->exec('ls');
			if (!$ret['success']) {
				if ($ret['return'] !== 3) {
					error('failed to query nodes - is nvm installed?');
				}
				return [];
			}
			if (preg_match_all(\Regex::NVM_NODES, $ret['output'], $versions, PREG_SET_ORDER)) {
				$nodes = array_combine(array_column($versions, 'alias'), array_column($versions, 'version'));
				if (isset($nodes['->'])) {
					$nodes['active'] = $nodes['->'];
					unset($nodes['->']);
				}
				return $nodes;
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
			$lts = $versions['lts/*'] ?? null;
			return array_has($versions, $lts);
		}

		/**
		 * nvm wrapper
		 *
		 * @param null|string $name
		 * @param null|string $command
		 * @param array $args optional args
		 * @return array
		 */
		private function exec(?string $name, string $command = null, ...$args): array {
			$ret = $this->pman_run('/bin/bash -c -- ' . escapeshellarg("nvm ${name} ${command}"),
				$args,
				[
					'BASH_ENV' => '/etc/profile.d/nvm.sh',
					'NVM_DIR' => $this->user_get_home(),
					'PATH' => getenv('PATH') . PATH_SEPARATOR . '~/node_modules/.bin'
				]
			);
			return $ret;
		}
	}