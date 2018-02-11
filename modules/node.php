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
			if (version_compare(platform_version(), '6.5', '<')) {
				$this->exportedFunctions = [];
			}
			parent::__construct();
		}

		/**
		 * Execute Node within the scope of a version
		 *
		 * @param string $version
		 * @param string $command
		 * @return bool
		 */
		public function use(string $version, string $command): bool {
			if ($version === 'lts') {
				$version = '--lts';
			}
			$ret = $this->exec('exec', $version . ' ' . $command);
			return $ret['success'];
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
			$nodes = $this->list_nodes();
			return isset($nodes[$version]) || in_array($version, $nodes, true);
		}

		/**
		 * List installed Nodes
		 *
		 * @return array
		 */
		public function list_nodes(): array
		{
			$ret = $this->exec('ls');
			if (!$ret['success']) {
				error('failed to query nodes - is nvm installed?');
				return [];
			}
			if (preg_match_all(\Regex::NVM_NODES, $ret['output'], $versions, PREG_SET_ORDER)) {
				return array_combine(array_column($versions, 'alias'), array_column($versions, 'version'));
			}
			return [];
		}

		/**
		 * nvm wrapper
		 *
		 * @param null|string $name
		 * @param string|null $args
		 * @return array
		 */
		private function exec(?string $name, string $args = null): array {
			$ret = $this->pman_run('/bin/bash -c "nvm %(name)s %(args)s"',
				['name' => $name, 'args' => $args],
				[
					'BASH_ENV' => '/etc/profile.d/nvm.sh',
					'NVM_DIR' => $this->user_get_home()
				]
			);

			return $ret;
		}


	}