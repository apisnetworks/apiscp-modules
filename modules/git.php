<?php declare(strict_types=1);
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
	 * Git management
	 *
	 * @package core
	 */
	class Git_Module extends Module_Skeleton
	{
		protected $exportedFunctions = ['*' => PRIVILEGE_SITE|PRIVILEGE_USER];

		/**
		 * Clone a repositroy
		 *
		 * @param string $repo
		 * @param string $target
		 * @param array  $opts
		 * @return bool
		 */
		public function clone(string $repo, string $target, array $opts): bool {
			$opts = array_key_map(function ($k, $v) {
				$rhand = '';
				if ($v !== null) {
					$rhand = '=' . escapeshellarg((string)$v);
				}
				return (isset($k[1]) ? '--' : '-') . escapeshellarg($k) . $rhand;
			}, $opts);
			$ret = $this->pman_run('git clone ' . implode(' ', $opts) . ' %(repo)s %(target)s',
				[
					'repo' => $repo,
					'target' => $target
				]
			);

			return $ret['success'] ?: error($ret['stderr']);
		}

		/**
		 * Path is valid git repository
		 *
		 * @param string $path
		 * @return bool
		 */
		public function valid(string $path): bool
		{
			if (!IS_CLI) {
				return $this->query('git_valid', $path);
			}
			return file_exists($this->domain_fs_path($path . '/.git/HEAD'));
		}

		/**
		 * List tags for repository
		 *
		 * @param string $path
		 * @return array|null
		 */
		public function tag(string $path): ?array
		{
			$ret = $this->pman_run('cd %(path)s && git tag', ['path' => $path]);
			if (!$ret['success']) {
				error("Failed to enumerate tags");
				return null;
			}
			return explode("\n", rtrim($ret['stdout']));
		}

		/**
		 * Initialize a git repository
		 *
		 * @param string $path
		 * @param bool   $bare
		 * @return bool
		 */
		public function init(string $path, bool $bare = true): bool {
			$ret = $this->pman_run('git init %(bare)s %(path)s',
			[
				'bare' => $bare ? '--bare' : null,
				'path' => $path
			]);
			return $ret['success'] ?: error($ret['stderr']);
		}

		/**
		 * Download objects and refs from another repository
		 *
		 * @param string $path
		 * @param array  $opts
		 * @return bool
		 */
		public function fetch(string $path, array $opts = []): bool {
			$opts = implode(' ', array_key_map(function ($k, $v) {
				$k = (isset($k[1]) ? '--' : '-') . escapeshellarg($k);
				if (null === $v) {
					return $k;
				}
				return $k . '=' . escapeshellarg($v);
			}, $opts));
			$ret = $this->pman_run("cd %(path)s && git fetch " . $opts, ['path' => $path]);
			return $ret['success'] ?: error("Failed to fetch: %s", $ret['stderr']);

		}

		/**
		 * Checkout ref/tag
		 *
		 * @param string $path
		 * @param string $ref
		 * @return bool
		 */
		public function checkout(string $path, string $ref): bool {
			$ret = $this->pman_run("cd %(path)s && git checkout %(ref)s", [
				'path' => $path,
				'ref' => $ref
			]);
			return $ret['success'] ?: error("Failed to checkout `%s': %s", $ref, $ret['stderr']);
		}
	}