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
			'*' => PRIVILEGE_SITE | PRIVILEGE_USER
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
		 * @param string      $command
		 * @param array       $args optional command arguments
		 * @return array process output from pman_run
		 */
		public function do(?string $version, string $command, ...$args): array
		{
			if ($version === 'lts') {
				$version = '--lts';
			} else if ($version) {
				$version = escapeshellarg($version);
			}
			$ret = $this->exec('exec --silent ' . $version, $command, ...$args);

			return $ret;
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
			$ret = $this->pman_run('/bin/bash -ic -- ' . escapeshellarg("nvm ${name} ${command}"),
				$args,
				[
					'PATH'     => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin' . PATH_SEPARATOR . '~/node_modules/.bin',
					'BASH_ENV' => '/dev/null'
				]
			);

			return $ret;
		}

		/**
		 * Remove an installed Node
		 *
		 * @param string $version
		 * @return bool
		 */
		public function uninstall(string $version): bool
		{
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
		 * Resolves symbolic names to version number
		 *
		 * @param string $version
		 * @param string $path
		 * @return bool
		 */
		public function make_default(string $version, string $path = '~'): bool
		{
			$path .= '/.nvmrc';
			if ($version === 'lts') {
				$version = 'lts/*';
			}

			return $this->file_put_file_contents($path, $this->resolveVersion($version), true);
		}

		/**
		 * Resolve Node alias to version number
		 *
		 * @param string $version
		 * @return null|string
		 */
		protected function resolveVersion(string $version): ?string
		{
			if ($version === 'lts') {
				$version = 'lts/*';
			}
			$ret = $this->exec('ls', '%s', $version);
			if ($ret['success']) {
				return rtrim(preg_replace('/^\S+\s+|\bv(?=\d)|\s+\*$/', '', $ret['output']));
			}

			return null;
		}

		/**
		 * Get installed LTS version for account
		 *
		 * @param string $alias Node release alias (argon, boron, carbon, dubnium, etc)
		 * @return null|string
		 */
		public function lts_version(string $alias = '*'): ?string
		{
			return $this->resolveVersion('lts/' . $alias);
		}

		/**
		 * Install Node
		 *
		 * @param string $version
		 * @return bool
		 */
		public function install(string $version): bool
		{
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
		public function installed(string $version): bool
		{
			if ($version === 'lts') {
				return $this->lts_installed();
			}
			$nodes = $this->list();

			return isset($nodes[$version]) || in_array($version, $nodes, true);
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
					error('failed to query nodes - is nvm installed? error: %s', $ret['error']);
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

		public function get_available(): array
		{
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

			if (!preg_match_all('/\s*v(?<version>\S*)\s*(?:\((?:Latest )?LTS: (\S*)\))?/', $ret['stdout'], $versions,
				PREG_SET_ORDER)) {
				warn("failed to discover any Nodes");

				return [];
			}
			$versions = array_column($versions, 'version');
			$cache->set($key, $versions);

			return $versions;
		}
	}