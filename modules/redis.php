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
	 * Ghost management
	 *
	 * A blogging platform built on Node
	 *
	 * @package core
	 */
	class Redis_Module extends Module_Skeleton
	{
		const PREF_KEY = 'redis';
		protected $exportedFunctions = ['*' => PRIVILEGE_SITE|PRIVILEGE_USER];

		public function __construct()
		{
			parent::__construct();
			if ($this->permission_level && (!SSH_USER_DAEMONS || !$this->ssh_enabled())) {
				$this->exportedFunctions = ['*' => PRIVILEGE_NONE];
			}
		}

		/**
		 * Create a Redis service
		 *
		 * @param string $nickname
		 * @param array  $options
		 * @return bool
		 */
		public function create(string $nickname, array $options = []): bool
		{
			if (!IS_CLI) {
				return $this->query('redis_create', $nickname, $options);
			}
			if (!preg_match(Regex::REDIS_NICKNAME, $nickname)) {
				return error("Invalid connection nickname");
			}
			if ($this->exists($nickname)) {
				return error("Redis nickname already in use");
			}

			if (empty($options['unixsocket'])) {
				$port = \Opcenter\Net\Port::firstFree($this->getAuthContext());
				if (!$port) {
					return error("Unable to locate free port to run Redis service");
				}
				$options['port'] = $port;
				$options['bind'] = $options['bind'] ?? '127.0.0.1';
				if ($options['bind'] !== '127.0.0.1' && empty($options['requirepass'])) {
					return error("No password set for Redis connection and connection open to remote connections. A password must be set.");
				}
				if ($options['bind'] !== '127.0.0.1') {
					return error("External Redis support not supported yet");
				}
			}
			// always daemonize
			$options['daemonize'] = 'yes';

			$home = $this->user_get_home();
			$path = $home . '/.redis';

			if (!$this->file_exists($path)) {
				$this->file_create_directory($path, 0700);
			}

			if (!isset($options['dir'])) {
				$options['dir'] = $path . '/' . $nickname;
			}
			if (!$this->file_exists($options['dir'])) {
				$this->file_create_directory($options['dir'], 0700);
			}


			$fstpath = $this->domain_fs_path($this->getRedisConfiguration($nickname));
			copy(resource_path('templates/redis/redis.conf'), $fstpath);
			\Opcenter\Filesystem::chogp($fstpath, $this->user_id, $this->group_id, 0600);
			$map = \Opcenter\Map::load($fstpath, 'r+', 'textfile');
			if (empty($options['bind'])) {
				unset($map['bind'], $map['port']);
			}
			$options['daemonize'] = $options['daemonize'] ?? 'yes';
			$options['pidfile'] = $options['dir'] .'/redis.pid';

			foreach ($options as $k => $v) {
				$map[$k] = $v;
			}

			$map->save();

			$cfgfile = $this->getRedisConfiguration($nickname);
			$ret = $this->pman_run('redis-server %(cfg)s', ['cfg' => $cfgfile]);
			if (!$ret['success']) {
				return error("Failed to start redis: %s", $ret['stderr']);
			}
			$prefs = \Preferences::factory($this->getAuthContext());
			$data = array_get($prefs, self::PREF_KEY, []);
			$data[$nickname] = [
				'port' => $options['port'] ?? null,
				'bind' => $options['bind'] ?? null,
				'unixsocket' => $options['unixsocket'] ?? null,
				'type' => isset($options['unixsocket']) ? 'unix' : 'tcp',
			];
			$prefs->unlock($this->getApnscpFunctionInterceptor());
			$prefs[self::PREF_KEY] = $data;
			unset($prefs);
			if (!$this->crontab_add_job('@reboot', null, null, null, null, 'redis-server ' . $cfgfile)) {
				return warn("Failed to create redis-server job for reboot");
			}
			return true;
		}

		/**
		 * Redis nickname in use
		 *
		 * @param string $nickname
		 * @return bool
		 */
		public function exists(string $nickname): bool
		{
			$prefs = \Preferences::factory($this->getAuthContext());
			$pdata = array_get($prefs, self::PREF_KEY, []);
			return isset($pdata[$nickname]);
		}

		public function delete(string $nickname): bool
		{
			if (!IS_CLI) {
				return $this->query('redis_delete', $nickname);
			}

			if (!$this->exists($nickname)) {
				return error("Unknown Redis instance `%s'", $nickname);
			}
			if ($this->running($nickname) && !$this->stop($nickname)) {
				return error("Failed to stop Redis instance `%s'", $nickname);
			}
			$prefs = \Preferences::factory($this->getAuthContext());
			$key = static::PREF_KEY;
			$prefs->unlock($this->getApnscpFunctionInterceptor());
			$redispref = array_get($prefs, $key, []);
			unset($redispref[$nickname]);
			$prefs[$key] = $redispref;
			unset($prefs);
			$home = $this->user_get_home();

			$files = [
				$cfgfile = $this->getRedisConfiguration($nickname),
				"${home}/.redis/${nickname}"
			];

			foreach ($files as $f) {
				$this->file_delete($f, true);
			}
			$this->crontab_delete_job('@reboot', null, null, null, null, 'redis-server ' . $cfgfile);
			return true;
		}

		/**
		 * Get configuration from instance
		 *
		 * @param string $nickname
		 * @return array|null
		 */
		public function config(string $nickname): ?array {
			if (!IS_CLI) {
				return $this->query('redis_config', $nickname);
			}
			$fstcfg = $this->domain_fs_path($this->getRedisConfiguration($nickname));
			if (!file_exists($fstcfg)) {
				warn("Redis configuration for `%s' missing", $nickname);
				return null;
			}
			return \Opcenter\Map::load($fstcfg, 'r', 'textfile')->fetchAll();
		}

		/**
		 * Get all known instances
		 *
		 * @return array
		 */
		public function list(): array {
			if ($this->permission_level & PRIVILEGE_SITE) {
				$users = array_keys($this->user_get_users());
			} else {
				$users = [$this->username];

			}
			$instances = [];
			foreach ($users as $user) {
				$prefs = \Preferences::factory(Auth::context($user, $this->site));
				if (!$config = array_get($prefs, static::PREF_KEY, [])) {
					continue;
				}
				$instances += $config;
			}
			return $instances;
		}


		/**
		 * Start Redis instance
		 *
		 * @param string $name
		 * @return bool
		 */
		public function start(string $name): bool
		{
			if (!$this->exists($name)) {
				return error("Unknown redis instance `%s'", $name);
			} else if ($pid = $this->running($name)) {
				return warn("Redis instance `%s' already running with PID `%s'", $name, $pid);
			}
			$file = $this->getRedisConfiguration($name);
			return $this->pman_run('redis-server %s', $file)['success'] ?? false;
		}

		/**
		 * Instance is running
		 *
		 * @param string $name
		 * @return null|int
		 */
		public function running(string $name): ?int
		{
			if (!$this->exists($name)) {
				return null;
			}

			$config = $this->config($name);
			$pid = $config['pidfile'];
			if (!$pid || !$this->file_exists($pid)) {
				return null;
			}
			$pid = (int)$this->file_get_file_contents($pid);
			return \Opcenter\Process::pidMatches($pid, 'redis-server') ? $pid : null;
		}


		/**
		 * Stop Redis instance
		 *
		 * @param string $name
		 * @return bool
		 */
		public function stop(string $name): bool
		{
			if (!IS_CLI) {
				return $this->query('redis_stop', $name);
			}
			if (!$this->exists($name)) {
				return error("Unknown redis instance `%s'", $name);
			}
			if (!$pid = $this->running($name)) {
				return warn("Instance `%s' not running", $name);
			}

			return $this->pman_kill($pid);


		}

		/**
		 * Get configuration file from Redis file
		 *
		 * @param string $nickname
		 * @return array
		 */
		protected function getRedisConfiguration(string $nickname): string {
			return $this->user_get_home() . '/.redis/' . $nickname . '.conf';
		}
	}