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
	 * Discourse management
	 *
	 * Forum software
	 *
	 * @package core
	 */
	class Discourse_Module extends \Module\Support\Webapps
	{
		use \Module\Support\Webapps\Traits\PublicRelocatable {
			getAppRoot as getAppRootReal;
		}

		const DEFAULT_RUBY = '2.5.3';

		const MINIMUM_INTERPRETERS = [
			'0'           => '2.4.2',
			'2.2.0.beta5' => '2.5.2'
		];

		const APP_NAME = 'Discourse';
		const DEFAULT_VERSION_LOCK = 'major';
		const VERSION_CHECK_URL = 'https://api.github.com/repos/discourse/discourse/tags?per_page=1000';
		const DISCOURSE_REPO = 'https://github.com/discourse/discourse.git';

		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions['restart'] = PRIVILEGE_SITE | PRIVILEGE_USER;
		}

		public function plugin_status(string $hostname, string $path = '', string $plugin = null)
		{
			return error('not supported');
		}

		public function uninstall_plugin(string $hostname, string $path = '', string $plugin, bool $force = false): bool
		{
			return error('not supported');
		}

		public function disable_all_plugins(string $hostname, string $path = ''): bool
		{
			return error('not supported');
		}

		/**
		 * Get next Discourse version
		 *
		 * @param string $version
		 * @param string $maximalbranch
		 * @return null|string
		 */
		public function next_version(string $version, string $maximalbranch = '99999999.99999999.99999999'): ?string
		{
			return parent::next_version($version, $maximalbranch);
		}

		/**
		 * Reconfigure a Discourse instance
		 *
		 * @param            $field
		 * @param string     $attribute
		 * @param array      $new
		 * @param array|null $old
		 */
		public function reconfigure(string $field, string $attribute, array $new, array $old = null)
		{


		}

		/**
		 * @param string       $hostname
		 * @param string       $path
		 * @param string|array $fields
		 * @return mixed
		 */
		public function get_configuration(string $hostname, string $path, $fields): array
		{
			if (!IS_CLI) {
				return $this->query('discourse_get_configuration', $hostname, $path, $fields);
			}
			$config = $this->getAppRoot($hostname, $path) . '/config/discourse.conf';
			$map = \Opcenter\Map::read($this->domain_fs_path($config), 'inifile');
			$values = [];
			foreach ((array)$fields as $k) {
				$values[$k] = $map->fetch($k);
			}
			if (\count($values) === 1) {
				return array_pop($values);
			}

			return $values;
		}

		/**
		 * Get app root for Discourse
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return null|string
		 */
		protected function getAppRoot(string $hostname, string $path = ''): ?string
		{
			return $this->getAppRootReal($hostname, $path);
		}

		/**
		 * Install Discourse into a pre-existing location
		 *
		 * @TODO disable cgroup OOM killer on 1 GB sites?
		 *
		 * @param string $hostname domain or subdomain to install Laravel
		 * @param string $path     optional path under hostname
		 * @param array  $opts     additional install options
		 * @return bool
		 */
		public function install(string $hostname, string $path = '', array $opts = array()): bool
		{
			if (/*!is_debug() && */
			!IS_CLI) {
				return $this->query('discourse_install', $hostname, $path, $opts);
			}
			if (!$this->pgsql_enabled()) {
				return error("PostgreSQL must be enabled to install %s", ucwords($this->getInternalName()));
			}
			if (!SSH_USER_DAEMONS) {
				return error("[ssh] => user_daemons must be set to true in config.ini");
			}
			$available = null;
			if (!$this->hasMemoryAllowance(2048, $available)) {
				return error("Discourse requires at least 1024 MB memory, `%s' MB provided for account", $available);
			}
			if (!$this->hasStorageAllowance(2048, $available)) {
				return error("Discourse requires ~2 GB free. Only %.2f MB free.", $available);
			}

			if ($this->getServiceValue('cgroup', 'enabled') && ($limit = $this->getServiceValue('cgroup',
					'proclimit')) < 100) {
				return error("Resource limits enforced. proclimit `%d' is below minimum value 100. Change via cgroup,proclimit",
					$limit);
			}

			if (!platform_is('7.5')) {
				return error('Discourse requires at least a v7.5 platform. Current platform version %s',
					platform_version());
			}

			if (!$this->ssh_enabled()) {
				return error('Discourse requires ssh service to be enabled');
			}
			if (!$this->crontab_permitted()) {
				return error("Task scheduling not enabled for account - admin must enable crontab,permit");
			} else if (!$this->crontab_enabled() && !$this->crontab_toggle_status(1)) {
				return error("Failed to enable task scheudling");
			}

			if (!isset($opts['mode'])) {
				$opts['mode'] = 'apache';
			}

			if ($opts['mode'] !== 'standalone' && $opts['mode'] !== 'nginx' && $opts['mode'] !== 'apache') {
				return error("Unknown Discourse mode `%s'", $opts['mode']);
			}

			// assume all Discourse installs will be located in a parent directory
			// once installed, relink the domain/subdomain to $docroot + /public
			// also block installing under a path, because this would require either relocating
			// Discourse outside any document root, e.g. /var/www/<hostname>-<path>-discourse and making
			// a symlink, which fails once the parent document root moves (must use relative symlinks)
			// and clutters up wherever they get located... no sound solution
			if ($path) {
				return error('Discourse may only be installed directly on a subdomain or domain without a child path, e.g. https://discourse.domain.com but not https://domain.com/discourse');
			}


			if (!($docroot = $this->getDocumentRoot($hostname, $path))) {
				return error("failed to normalize path for `%s'", $hostname);
			}

			if (!parent::checkDocroot($docroot, $opts['user'] ?? null)) {
				return false;
			}

			$this->validateRuby(self::DEFAULT_RUBY, $opts['user'] ?? null);

			if (!empty($opts['ssl']) && !parent::configureSsl($hostname)) {
				return false;
			}

			if (!parent::checkVersion($opts)) {
				return false;
			}

			$args['version'] = $opts['version'];
			parent::prepareSquash($opts);

			if (!isset($opts['autoupdate'])) {
				$opts['autoupdate'] = true;
			}

			if (!parent::checkEmail($opts)) {
				return false;
			}

			$db = $this->_suggestDB($hostname, 'pgsql');
			if (!$db) {
				return false;
			}

			$dbuser = $this->_suggestUser($db, '127.0.0.1', 'pgsql');
			if (!$dbuser) {
				return false;
			}
			$dbpass = $this->suggestPassword();
			$dbconfig = [
				'db'              => $db,
				'user'            => $dbuser,
				'password'        => $dbpass,
				'max_connections' => 10
			];
			if (!$this->setupDatabase($dbconfig, 'pgsql')) {
				return error("Failed to create database");
			}

			$context = null;
			$wrapper = $this->getApnscpFunctionInterceptorFromDocroot($docroot, $context);
			$oldex = \Error_Reporter::exception_upgrade();
			try {
				$wrapper->git_clone(static::DISCOURSE_REPO, $docroot,
					[
						'recursive' => null,
						'depth'     => 0,
						'branch'    => 'v' . $opts['version']
					]);
				$wrapper->ruby_make_default(self::DEFAULT_RUBY, $docroot);
				$wrapper->ruby_do('', $docroot, 'gem install -E --no-document passenger bundler:"< 2"');
				$wrapper->ruby_do('', $docroot, 'bundle install -j' . max(4, (int)NPROC + 1));
				foreach (['pg_trgm', 'hstore'] as $extension) {
					$this->pgsql_add_extension($db, $extension);
				}
				if (!$wrapper->crontab_user_permitted($opts['user'] ?? $this->username)) {
					if (!$this->crontab_permit_user($opts['user'] ?? $this->username)) {
						return error("failed to enable task scheduling for `%s'", $opts['user'] ?? $this->username);
					}
					warn("Task scheduling enabled for user `%s'", $opts['user'] ?? $this->username);
				}
			} catch (\apnscpException $e) {
				info('removing temporary files');
				$this->remapPublic($hostname, $path, '');
				$this->file_delete($docroot, true);
				if ($this->pgsql_database_exists($db)) {
					$this->pgsql_delete_database($db);
				}
				if ($this->pgsql_user_exists($dbuser)) {
					$this->pgsql_delete_user($dbuser, '127.0.0.1');
				}

				return error("failed to install Discourse %s: %s", $args['version'], $e->getMessage());
			} finally {
				\Error_Reporter::exception_upgrade($oldex);
			}

			$params = array(
				'version'    => $this->get_version($hostname, $path),
				'hostname'   => $hostname,
				'path'       => $path,
				'autoupdate' => (bool)$opts['autoupdate'],
				'options'    => array_except($opts, 'version')
			);

			$opts['url'] = rtrim($hostname . '/' . $path, '/');

			if (null === ($docroot = $this->remapPublic($hostname, $path))) {
				// it's more reasonable to fail at this stage, but let's try to complete
				return error("Failed to remap Discourse to public/, manually remap from `%s' - Discourse setup is incomplete!",
					$docroot);
			}

			$docroot = $this->getDocumentRoot($hostname, $path);
			$approot = $this->getAppRoot($hostname, $path);
			$this->map('add', $docroot, $params);

			$passenger = \Module\Support\Webapps\Passenger::instantiateContexted($context, [$approot, 'ruby']);
			$passenger->createLayout();
			$passenger->setEngine('standalone');
			// avoid excessive mutex locking in Passenger
			$passenger->setProcessConcurrency(0);
			$passenger->setMaxPoolSize(3);
			$passenger->setMinInstances(3);
			$passenger->setEnvironment([
				'RUBY_GLOBAL_METHOD_CACHE_SIZE'       => 131072,
				'LD_PRELOAD'                          => '/usr/lib64/libjemalloc.so.1',
				'RUBY_GC_HEAP_GROWTH_MAX_SLOTS'       => 40000,
				'RUBY_GC_HEAP_INIT_SLOTS'             => 400000,
				'RUBY_GC_HEAP_OLDOBJECT_LIMIT_FACTOR' => 1.5
			]);
			$config = $approot . '/config/discourse.conf';
			$wrapper->file_copy($approot . '/config/discourse_defaults.conf', $config);

			if (!isset($opts['email'])) {
				$opts['email'] = $wrapper->common_get_email();
			}

			$configurables = [
				'db_name'          => $dbconfig['db'],
				'db_username'      => $dbconfig['user'],
				'db_password'      => $dbconfig['password'],
				'hostname'         => $hostname,
				'db_host'          => '127.0.0.1',
				'developer_emails' => $opts['email']
			];
			$this->set_configuration($hostname, $path, $configurables);

			$redispass = \Opcenter\Auth\Password::generate(32);
			if ($wrapper->redis_exists($this->domain)) {
				warn("Existing Redis profile named `%s' found - removing", $this->domain);
				$wrapper->redis_delete($this->domain);
			}
			$wrapper->redis_create($this->domain, ['requirepass' => $redispass]);
			$redisconfig = $wrapper->redis_config($this->domain);

			$config = \Opcenter\Map::write($this->domain_fs_path("${approot}/config/discourse.conf"),
				"inifile")->section(null);
			$vars = [
				'redis_port'     => $redisconfig['port'],
				'redis_host'     => '127.0.0.1',
				'redis_password' => $redisconfig['requirepass'],
				'db_pool'        => 7
			];
			foreach ($vars as $k => $v) {
				$config[$k] = $v;
			}
			unset($config);

			/**
			 * Sidekiq + DB migration + asset generation
			 */
			$exold = \Error_Reporter::exception_upgrade();
			try {
				$this->migrate($approot, 'production');
				$this->launchSidekiq($approot, 'production');
				$this->assetsCompile($approot, 'production');
				$this->file_put_file_contents($approot . '/Passengerfile.json',
					$passenger->getExecutableConfiguration());
				$passenger->start();
			} catch (\apnscpException $e) {
				dlog($e->getBacktrace());

				return error("Error encountered during housekeeping. Discourse may be incomplete: %s",
					$e->getMessage());
			} finally {
				\Error_Reporter::exception_upgrade($exold);
			}


			$autogenpw = false;
			if (!isset($opts['password'])) {
				$autogenpw = true;
				$opts['password'] = $this->suggestPassword(10);
				info("autogenerated password `%s'", $opts['password']);
			}

			$username = $this->user_getpwnam($opts['user'] ?? $this->username)['gecos'] ?: $this->username;
			info("setting displayed name to `%s'", $username);

			if ($passenger->getEngine() !== 'apache') {
				$command = $passenger->getExecutable();
				$args = [
					'@reboot',
					null,
					null,
					null,
					null,
					$command
				];
				if (!$wrapper->crontab_exists(...$args) && !$wrapper->crontab_add_job(...$args)) {
					warn("Failed to create job to start Passenger on boot. Command: %s", $command);
				}
				$this->pman_run($command);
			}

			if (!$this->file_put_file_contents($approot . '/public/.htaccess',
				'# Enable caching' . "\n" .
				'UnsetEnv no-cache' . "\n" .
				// prevents page not found on vanilla installs
				// defaults to index.html otherwise
				'DirectoryIndex disabled' . "\n" .
				$passenger->getDirectives()
			)) {
				return error('failed to create .htaccess control - Discourse is not properly setup');
			}

			$fqdn = $this->web_normalize_hostname($hostname);

			if (array_get($opts, 'notify', true)) {
				\Lararia\Bootstrapper::minstrap();
				\Illuminate\Support\Facades\Mail::to($opts['email'])->
				send((new \Module\Support\Webapps\Mailer('install.discourse', [
					'email'   => $opts['email'],
					'uri'     => rtrim($fqdn . '/' . $path, '/'),
					'proto'   => empty($opts['ssl']) ? 'http://' : 'https://',
					'appname' => static::APP_NAME
				]))->setAppName(static::APP_NAME));
			}

			if (!$opts['squash']) {
				parent::unsquash(dirname($docroot));
			}

			return info('Discourse installed - confirmation email with login info sent to %s', $opts['email']);
		}

		/**
		 * Verify Node LTS is installed
		 *
		 * @param string|null $version optional version to compare against
		 * @param string|null $user
		 * @return bool
		 */
		protected function validateRuby(string $version = 'lts', string $user = null): bool
		{
			if ($user) {
				$afi = \apnscpFunctionInterceptor::factory(Auth::context($user, $this->site));
			}
			$wrapper = $afi ?? $this;
			// @TODO accept newer Rubies if present
			if (!$wrapper->ruby_installed($version) && !$wrapper->ruby_install($version)) {
				return error('failed to install Ruby %s', $version);
			}
			$ret = $wrapper->ruby_do($version, null, 'gem install --no-document -E passenger rake');
			if (!$ret['success']) {
				return error('failed to install Passenger gem: %s', $ret['stderr'] ?? 'UNKNOWN ERROR');
			}
			$home = $this->user_get_home($user);
			$stat = $this->file_stat($home);
			if (!$stat || !$this->file_chmod($home, decoct($stat['permissions']) | 0001)) {
				return error("failed to query user home directory `%s' for user `%s'", $home, $user);
			}

			return true;
		}

		/**
		 * Get installed version
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return string version number
		 */
		public function get_version(string $hostname, string $path = ''): ?string
		{
			if (!$this->valid($hostname, $path)) {
				return null;
			}
			$approot = $this->getAppRoot($hostname, $path);
			$wrapper = $this->getApnscpFunctionInterceptorFromDocroot($approot);
			$ret = $wrapper->ruby_do(null, $approot,
				'ruby -e \'require "./%(path)s" ; puts Discourse::VERSION::STRING;\'',
				['path' => 'lib/version.rb']
			);

			return $ret['success'] ? trim($ret['output']) : null;
		}

		/**
		 * Location is a valid Discourse install
		 *
		 * @param string $hostname or $docroot
		 * @param string $path
		 * @return bool
		 */
		public function valid(string $hostname, string $path = ''): bool
		{
			if (0 === strpos($hostname, '/')) {
				if (!($path = realpath($this->domain_fs_path($hostname)))) {
					return false;
				}
				$approot = \dirname($path);
			} else {
				$approot = $this->getAppRoot($hostname, $path);
				if (!$approot) {
					return false;
				}
				$approot = $this->domain_fs_path($approot);
			}

			return file_exists($approot . '/lib/discourse.rb');
		}

		public function set_configuration(string $hostname, string $path, array $params = [])
		{
			if (!IS_CLI) {
				return $this->query('discourse_set_configuration', $hostname, $path, $params);
			}
			$config = $this->getAppRoot($hostname, $path) . '/config/discourse.conf';
			$ini = \Opcenter\Map::load($this->domain_fs_path($config), 'wd', 'inifile')->section(null);

			foreach ($params as $k => $v) {
				$ini[$k] = $v;
			}

			return true;

		}

		/**
		 * Migrate Discourse database
		 *
		 * @param string $approot
		 * @param string $appenv optional app environment to source DB config
		 * @return bool
		 */
		private function migrate(string $approot, string $appenv = 'production'): bool
		{
			return $this->rake($approot, 'db:migrate', $appenv);
		}

		private function rake(string $approot, string $task, string $appenv = 'production'): bool
		{
			$ret = $this->_exec($approot, 'bundle exec rake -j' . min(4, (int)NPROC + 1) . ' ' . $task, [
				'PATH'      => getenv('PATH') . PATH_SEPARATOR . '~/node_modules/.bin/',
				'RAILS_ENV' => $appenv
			]);

			return $ret['success'] ?: error("failed Rake task `%s': %s", $task,
				coalesce($ret['stderr'], $ret['stdout']));
		}

		private function _exec($path = null, $cmd, array $args = array())
		{
			// client may override tz, propagate to bin
			if (!is_array($args)) {
				$args = func_get_args();
				array_shift($args);
			}
			// PHP has no recursive union. array_merge() with numeric keys appends
			$baseArgs = [
				0 => [],
				1 => ['RAILS_ENV' => 'production'],
				2 => []
			];

			$args = array_key_map(function ($k, $v) use ($args) {
				return ($args[$k] ?? []) + $v;
			}, $baseArgs);

			$user = $this->username;
			if ($path) {
				$cmd = 'cd %(path)s && /bin/bash -ic -- ' . escapeshellarg($cmd);
				$args[0]['path'] = $path;
				$user = $this->file_stat($path)['owner'] ?? $this->username;
			}
			$args[2]['user'] = $user;

			$ret = $this->pman_run($cmd, ...$args);
			if (!strncmp(coalesce($ret['stderr'], $ret['stdout']), 'Error:', strlen('Error:'))) {
				// move stdout to stderr on error for consistency
				$ret['success'] = false;
				if (!$ret['stderr']) {
					$ret['stderr'] = $ret['stdout'];
				}

			}

			return $ret;
		}

		/**
		 * Launch Sidekiq process
		 *
		 * @param string $approot
		 * @param string $mode
		 * @return bool
		 */
		protected function launchSidekiq(string $approot, string $mode = 'production'): bool
		{
			if ($this->sidekiqRunning($approot)) {
				return true;
			}
			$job = [
				'@reboot',
				null,
				null,
				null,
				null,
				'/bin/bash -ic ' .
				escapeshellarg($this->getSidekiqJob($approot, 'production'))
			];
			if (!$this->crontab_exists(...$job)) {
				$this->crontab_add_job(...$job);
			}
			$ret = $this->_exec($approot, $this->getSidekiqCommand($approot),
				[
					'approot' => $approot
				],
				[
					'RAILS_ENV' => $mode
				]);

			return $ret['success'] ?: error("Failed to launch Sidekiq, check log/sidekiq.log");
		}

		protected function sidekiqRunning(string $approot): ?int
		{
			$pidfile = $this->domain_fs_path($approot . '/tmp/sidekiq.pid');
			if (!file_exists($pidfile)) {
				return null;
			}

			$pid = (int)file_get_contents($pidfile);

			return \Opcenter\Process::pidMatches($pid, 'ruby') ? $pid : null;
		}

		/**
		 * Get Sidekiq cronjob
		 *
		 * @param string $approot
		 * @param string $env
		 * @return string
		 */
		private function getSidekiqJob(string $approot, $env = 'production')
		{
			return 'cd ' . $approot . ' && env RAILS_ENV=production ' . $this->getSidekiqCommand($approot);
		}

		/**
		 * Get Sidekiq command
		 *
		 * @param string $approot
		 * @return string
		 */
		private function getSidekiqCommand(string $approot)
		{
			return 'bundle exec sidekiq -L log/sidekiq.log -P tmp/sidekiq.pid -q critical -q low -q default -d -c5';
		}

		/**
		 * Compile assets
		 *
		 * @param string $approot
		 * @param string $appenv
		 *
		 * @return bool
		 */
		private function assetsCompile(string $approot, string $appenv = 'production'): bool
		{
			$wrapper = $this->getApnscpFunctionInterceptorFromDocroot($approot);
			if (!$wrapper->node_installed('lts')) {
				$wrapper->node_install('lts');
				$wrapper->node_make_default('lts', $approot);
			}
			$ret = $wrapper->node_do('lts', 'npm install -g uglify-js@2');
			if (!$ret['success']) {
				return error('Failed to install uglifyjs: %s', $ret['error']);
			}

			return $this->rake($approot, 'assets:precompile');
		}

		public function build()
		{
			if (!is_debug()) {
				return true;
			}
			$approot = $this->getAppRoot($this->domain, '');
			$docroot = $this->getDocumentRoot($this->domain, '');
			$context = null;

			$wrapper = $this->getApnscpFunctionInterceptorFromDocroot($docroot, $context);
			$passenger = \Module\Support\Webapps\Passenger::instantiateContexted($context, [$approot, 'ruby']);
			$passenger->createLayout();
			$passenger->setEngine('standalone');
			$command = $passenger->getExecutableConfiguration();
			//
			echo $command, "\n";
			dd($passenger->getExecutable(), $passenger->getDirectives());


		}

		public function restart(string $hostname, string $path = ''): bool
		{
			if (!$approot = $this->getAppRoot($hostname, $path)) {
				return false;
			}
			$user = $this->getDocrootUser($approot);
			return \Module\Support\Webapps\Passenger::instantiateContexted(\Auth::context($user, $this->site),
				[$approot, 'ruby'])->restart();
		}

		/**
		 * Install and activate plugin
		 *
		 * @param string $hostname domain or subdomain of wp install
		 * @param string $path     optional path component of wp install
		 * @param string $plugin   plugin name
		 * @param string $version  optional plugin version
		 * @return bool
		 */
		public function install_plugin(
			string $hostname,
			string $path = '',
			string $plugin,
			string $version = 'stable'
		): bool {
			return error('not supported');
		}

		/**
		 * Get configuration from a webapp
		 *
		 * @param        $hostname
		 * @param string $path
		 * @param string $delete remove all files under docroot
		 * @return bool
		 */
		public function uninstall(string $hostname, string $path = '', string $delete = 'all'): bool
		{
			$approot = $this->getAppRoot($hostname, $path);
			// @xxx f'ugly
			$wrapper = $this->getApnscpFunctionInterceptorFromDocroot($approot);
			if ($wrapper !== $this->getApnscpFunctionInterceptor()) {
				$wrapper->discourse_uninstall($hostname, $path, 'proc');
			} else if ($delete !== 'proc') {
				$this->getApnscpFunctionInterceptor()->discourse_uninstall($hostname, $path, 'proc');
			}
			if ($delete === 'proc') {
				$this->kill($hostname, $path);
				// will fail if run as Apache, ignore
				$this->pman_run('cd %(approot)s && /bin/bash -ic %(cmd)s',
					['approot' => $approot, 'cmd' => 'passenger stop']);
				if ($this->redis_exists($hostname)) {
					$this->redis_delete($hostname);
				}
				$this->killSidekiq($approot);
				foreach ($this->crontab_filter_by_command($approot) as $job) {
					$this->crontab_delete_job(
						$job['minute'],
						$job['hour'],
						$job['day_of_month'],
						$job['month'],
						$job['day_of_week'],
						$job['cmd']
					);
				}

				return true;
			}

			return parent::uninstall($hostname, $path, $delete);
		}

		protected function killSidekiq(string $approot): bool
		{
			if (null === ($pid = $this->sidekiqRunning($approot))) {
				return false;
			}

			return $this->pman_kill($pid);
		}

		/**
		 * Check if version is latest or get latest version
		 *
		 * @param null|string $version
		 * @param string|null $branchcomp
		 * @return bool
		 */
		public function is_current(string $version = null, string $branchcomp = null)
		{
			return parent::is_current($version, $branchcomp);
		}

		/**
		 * Change Discourse admin credentials
		 *
		 * Common fields include: password, email, username, name
		 *
		 * @param string $hostname
		 * @param string $path
		 * @param array  $fields
		 * @return bool
		 */
		public function change_admin(string $hostname, string $path = '', array $fields): bool
		{
			if (/*!is_debug() && */
			!IS_CLI) {
				return $this->query('discourse_change_admin', $hostname, $path, $fields);
			}

			$docroot = $this->getAppRoot($hostname, $path);
			if (!$docroot) {
				return warn('failed to change administrator information');
			}

			$admin = $this->get_admin($hostname, $path);

			if (!$admin) {
				return error('cannot determine admin of Discourse install');
			}

			if (isset($fields['password'])) {
				if (!\Opcenter\Auth\Password::strong($fields['password'])) {
					return false;
				}
				$config = Opcenter\Map::read($this->domain_fs_path($docroot . '/config/application.rb'),
					'inifile')->section(null)->quoted(true);
				$itr = (int)($config['config.pbkdf2_iterations'] ?? 64000);
				$algo = $config['config.pbkdf2_algorithm'] ?? 'sha256';
				$fields['salt'] = bin2hex(openssl_random_pseudo_bytes(16));
				$fields['password_hash'] = hash_pbkdf2($algo, $fields['password'], $fields['salt'], $itr);
			}

			if (isset($fields['username'])) {
				$fields['username_lower'] = strtolower($fields['username']);
			}
			if (isset($fields['name'])) {
				$fields['name'] = $fields['name'];
			}
			$db = $this->connectDB($hostname, $path);
			if (!empty($fields['email'])) {
				if (!preg_match(Regex::EMAIL, $fields['email'])) {
					return error("Invalid email address `%s'", $fields['email']);
				}
				$db->query("UPDATE user_emails SET email = " . pg_escape_literal($fields['email']) . " WHERE user_id = 1 AND \"primary\" = 't'");
			}
			$q = "UPDATE users SET id = id";
			foreach (['password_hash', 'salt', 'username', 'username_lower', 'name'] as $field) {
				if (!isset($fields[$field])) {
					continue;
				}
				$q .= ", {$field} = '" . $db->escape_string($fields[$field]) . "'";
			}
			$q .= " WHERE id = 1";
			if (false === $db->query($q) || $db->affected_rows() < 1) {
				return error("Failed to change admin user `%s'", $admin);
			}
			if (isset($fields['email'])) {
				info('user login changed to %s', $fields['email']);
			}
			if (isset($fields['password'])) {
				info("user `%s' password changed", $fields['email'] ?? $admin);
			}

			return true;
		}

		/**
		 * Get the primary admin for a WP instance
		 *
		 * @param string      $hostname
		 * @param null|string $path
		 * @return string admin or false on failure
		 */
		public function get_admin(string $hostname, string $path = ''): ?string
		{
			if (!$pgsql = $this->connectDB($hostname, $path)) {
				return null;
			}

			$rs = $pgsql->query('SELECT username FROM users WHERE id = 1');
			if (!$rs || $rs->num_rows() < 1) {
				return null;
			}

			return $rs->fetch_object()->username;
		}

		/**
		 * Update core, plugins, and themes atomically
		 *
		 * @param string $hostname subdomain or domain
		 * @param string $path     optional path under hostname
		 * @param string $version
		 * @return bool
		 */
		public function update_all(string $hostname, string $path = '', string $version = null): bool
		{
			return $this->update($hostname, $path, $version) || error('failed to update all components');
		}

		/**
		 * Update Discourse to latest version
		 *
		 * @param string $hostname domain or subdomain under which WP is installed
		 * @param string $path     optional subdirectory
		 * @param string $version
		 * @return bool
		 */
		public function update(string $hostname, string $path = '', string $version = null): bool
		{
			$approot = $this->getAppRoot($hostname, $path);
			if (!$approot) {
				return error('update failed');
			}

			if (!$version) {
				$version = \Opcenter\Versioning::nextVersion($this->get_versions(),
					$this->get_version($hostname, $path));
			} else if (!\Opcenter\Versioning::valid($version)) {
				return error('invalid version number, %s', $version);
			}

			if (!$this->git_valid($approot)) {
				parent::setInfo($this->getDocumentRoot($hostname, $path), [
					'failed' => true
				]);

				return error("Cannot upgrade Discourse - not a valid git repository");
			}
			$wrapper = $this->getApnscpFunctionInterceptorFromDocroot($approot);
			$minimum = null;
			if (!$this->versionCheck($approot, $version, $minimum)) {
				parent::setInfo($this->getDocumentRoot($hostname, $path), [
					'failed' => true
				]);

				return error("Configured Ruby version `%s' does not meet minimum requirement `%s' for Discourse v%s",
					$wrapper->ruby_version_from_path($approot), $minimum, $version
				);
			}
			$wrapper->git_fetch($approot);
			$wrapper->git_fetch($approot, ['tags' => null]);
			$ret = $wrapper->git_checkout($approot, "v${version}");
			if ($ret) {
				// use default Ruby wrapper
				$wrapper->ruby_do('', $approot, 'bundle install -j' . min(4, (int)NPROC + 1));
				if (!$this->assetsCompile($approot)) {
					warn("Failed to compile assets");
				}
				$this->migrate($approot);
			}

			if ($version !== ($newver = $this->get_version($hostname, $path))) {
				report("Upgrade failed, reported version `%s' is not requested version `%s'", $newver, $version);
			}
			parent::setInfo($this->getDocumentRoot($hostname, $path), [
				'version' => $version,
				'failed'  => !$ret
			]);

			if (!$ret) {
				return error("failed to update Discourse");
			}

			return $this->restart($hostname, $path);
		}

		/**
		 * Get all available Discourse versions
		 *
		 * @return array
		 */
		public function get_versions(): array
		{
			$versions = $this->_getVersions();

			return array_column($versions, 'version');
		}

		/**
		 * Get all current major versions
		 *
		 * @return array
		 */
		private function _getVersions(): array
		{
			$key = $this->getInternalName() . '.versions';
			$cache = Cache_Super_Global::spawn();
			if (false !== ($ver = $cache->get($key))) {
				return (array)$ver;
			}
			$url = self::VERSION_CHECK_URL;
			$opts = [
				'http' => [
					'method' => 'GET',
					'header' => [
						'User-Agent: ' . PANEL_BRAND . ' ' . APNSCP_VERSION,
					]
				]
			];

			$context = stream_context_create($opts);
			$contents = file_get_contents($url, false, $context);
			if (!$contents) {
				return array();
			}
			$versions = json_decode($contents, true);
			array_walk($versions, function (&$a) {
				$a['version'] = ltrim($a['name'], 'v');
			});

			usort($versions, function ($a, $b) {
				if (version_compare($a['version'], $b['version'], '<')) {
					return -1;
				}
				if (version_compare($a['version'], $b['version'], '>')) {
					return 1;
				}

				return 0;
			});
			$cache->set($key, $versions, 43200);

			return $versions;
		}

		/**
		 * Ruby interpreter meets minimum version requirement
		 *
		 * @param string $approot          app root
		 * @param string $discourseVersion requested Discourse version
		 * @param null   $minVersion
		 * @return bool
		 */
		private function versionCheck(string $approot, string $discourseVersion, &$minVersion = null): bool
		{
			$wrapper = $this->getApnscpFunctionInterceptorFromDocroot($approot);
			$version = $wrapper->ruby_version_from_path($approot);
			$minVersion = '2.0';
			foreach (self::MINIMUM_INTERPRETERS as $a => $b) {
				if ($discourseVersion < $a) {
					break;
				}
				$minVersion = $b;
			}

			return version_compare($version, $minVersion, '>=');
		}

		/**
		 * Update plugins
		 *
		 * @param string $hostname domain or subdomain
		 * @param string $path     optional path within host
		 * @param array  $plugins
		 * @return bool
		 */
		public function update_plugins(string $hostname, string $path = '', array $plugins = array()): bool
		{
			return error('not implemented');
		}

		/**
		 * Update Laravel themes
		 *
		 * @param string $hostname subdomain or domain
		 * @param string $path     optional path under hostname
		 * @param array  $themes
		 * @return bool
		 */
		public function update_themes(string $hostname, string $path = '', array $themes = array()): bool
		{
			return error('not implemented');
		}

		/**
		 * Web application supports fortification
		 *
		 * @param string|null $mode optional mode (min, max)
		 * @return bool
		 */
		public function has_fortification(string $mode = null): bool
		{
			return false;
		}

		/**
		 * Restrict write-access by the app
		 *
		 * @param string $hostname
		 * @param string $path
		 * @param string $mode
		 * @return bool
		 */
		public function fortify(string $hostname, string $path = '', string $mode = 'max'): bool
		{
			return error('not implemented');
		}

		/**
		 * Relax permissions to allow write-access
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return bool
		 * @internal param string $mode
		 */
		public function unfortify(string $hostname, string $path = ''): bool
		{
			return error('not implemented');
		}

		/**
		 * Laravel housekeeping
		 *
		 * @return bool
		 */
		public function _housekeeping()
		{
			// nothing to do as Symfony is managed separately by
			// a the PHP module
			return true;
		}

		public function theme_status(string $hostname, string $path = '', string $theme = null)
		{
			return parent::theme_status($hostname, $path, $theme);
		}

		public function install_theme(string $hostname, string $path = '', string $theme, string $version = null): bool
		{
			return parent::install_theme($hostname, $path, $theme, $version);
		}

		/**
		 * Fake admin to change its credentials
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return bool
		 * @throws PostgreSQLError
		 */
		private function createAdmin(string $hostname, string $path): bool
		{
			if (!$approot = $this->getAppRoot($hostname, $path)) {
				return false;
			}
			if (!$db = $this->connectDB($hostname, $path)) {
				return error("Failed to connect to Discourse database");
			}
			if ($db->query("SELECT FROM users WHERE id = 1")->num_rows() > 0) {
				return warn("Admin user (id = 1) already present, not creating");
			}
			$hash = hash('sha256', (string)random_int(PHP_INT_MIN, PHP_INT_MAX));
			$q1 = 'INSERT INTO users (id, admin, created_at, updated_at, trust_level, username, username_lower, password_hash, salt, ip_address) VALUES(1, \'t\', NOW(), NOW(), 1, ' .
				pg_escape_literal($this->username) . ',' .
				strtolower(pg_escape_literal($this->username)) . ',' .
				pg_escape_literal(hash_hmac('sha256', (string)random_int(PHP_INT_MIN, PHP_INT_MAX), $hash)) . ',' .
				pg_escape_literal(substr($hash, 0, 32)) . ', ' . pg_escape_literal(\Auth::client_ip()) . ')';
			$q2 = 'INSERT INTO user_emails (id, user_id, created_at, updated_at, email, "primary") VALUES(1, 1, NOW(), NOW(), ' . pg_escape_literal($this->common_get_email()) . ', \'t\')';

			// @todo PDO
			return $db->query($q1)->affected_rows() && $db->query($q2)->affected_rows();


		}

		private function connectDB($hostname, $path): ?PostgreSQL
		{
			$dbconfig = $this->db_config($hostname, $path);
			$host = $dbconfig['host'] === 'localhost.localdomain' ? '127.0.0.1' : $dbconfig['host'];
			if (empty($dbconfig['user'])) {
				return null;
			}

			return \PostgreSQL::stub()->connect($host, $dbconfig['user'], $dbconfig['password'],
				$dbconfig['db']) ?: null;

		}

		/**
		 * Get database configuration for Discourse
		 *
		 * @param string $hostname domain or subdomain of wp blog
		 * @param string $path     optional path
		 * @return bool|array
		 */
		public function db_config(string $hostname, string $path = '')
		{
			if (!IS_CLI) {
				return $this->query("discourse_db_config", $hostname, $path);
			}

			$approot = $this->getAppRoot($hostname, $path);

			if (!$approot) {
				error('failed to determine Discourse app root - ' . $approot);

				return [];
			}
			$config = $approot . '/config/discourse.conf';

			if (!file_exists($this->domain_fs_path($config))) {
				error('failed to locate Discourse config in ' . $approot);

				return [];
			}
			$ini = \Opcenter\Map::load($this->domain_fs_path($config), 'r', 'inifile')->section(null);

			return [
				'db'       => $ini['db_name'],
				'host'     => $ini['db_host'],
				'user'     => $ini['db_username'],
				'password' => $ini['db_password'],
				'prefix'   => '',
				'type'     => 'pgsql'
			];
		}
	}


