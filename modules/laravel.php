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
	 * Laravel management
	 *
	 * An interface to wp-cli
	 *
	 * @package core
	 */
	class Laravel_Module extends \Module\Support\Webapps\Composer
	{
		use \Module\Support\Webapps\Traits\PublicRelocatable {
			getAppRoot as getAppRootReal;
		}
		const APP_NAME = 'Laravel';

		const VERSION_CHECK_URL = 'https://packagist.org/p/laravel/framework.json';

		// every Laravel app should contain artisan one level down...
		const LARAVEL_CLI = 'artisan';
		const DEFAULT_VERSION_LOCK = 'minor';

		protected $_aclList = array(
			'min' => array(
				'storage/framework/',
				'app/bootstrap/cache'
			),
			'max' => array(
				'storage/framework/cache',
				'storage/framework/views',
				'storage/framework/sessions',
				'storage/logs',
				'bootstrap/cache'
			)
		);

		/**
		 * Install Laravel into a pre-existing location
		 *
		 * @param string $hostname domain or subdomain to install Laravel
		 * @param string $path     optional path under hostname
		 * @param array  $opts     additional install options
		 * @return bool
		 */
		public function install(string $hostname, string $path = '', array $opts = array()): bool
		{
			if (!$this->mysql_enabled()) {
				return error("MySQL must be enabled to install %s", ucwords($this->getInternalName()));
			}
			if (!version_compare($this->php_version(), '7', '>=')) {
				return error('Laravel requires PHP7');
			}

			if (!$this->php_composer_exists()) {
				return error('composer missing! contact sysadmin');
			}

			// Same situation as with Ghost. We can't install under a path for fear of
			// leaking information
			if ($path) {
				return error("Composer projects may only be installed directly on a subdomain or domain without a child path, e.g. https://domain.com but not https://domain.com/laravel");
			}

			if (!($docroot = $this->getDocumentRoot($hostname, $path))) {
				return error("failed to normalize path for `%s'", $hostname);
			}

			if (!parent::checkDocroot($docroot, $opts['user'] ?? null)) {
				return false;
			}

			if (!$this->checkVersion($opts)) {
				return false;
			}

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
			if (!isset($opts['verlock'])) {
				$opts['verlock'] = static::DEFAULT_VERSION_LOCK;
			}

			$lock = $this->parseLock($opts['verlock'], $opts['version']);
			$ret = $this->_execComposer($docroot,
				'create-project --prefer-dist laravel/laravel %(docroot)s \'%(version)s\'',
				[
					'docroot' => $docroot,
					'version' => $lock
				]
			);
			if (!$ret['success']) {
				$this->file_delete($docroot, true);

				return error("failed to download laravel/laravel package: %s %s",
					$ret['stderr'], $ret['stdout']
				);
			}

			if (null === ($docroot = $this->remapPublic($hostname, $path))) {
				$this->file_delete($this->getDocumentRoot($hostname, $path), true);

				return error("Failed to remap Laravel to public/, manually remap from `%s' - Laravel setup is incomplete!",
					$docroot);
			}

			$oldex = \Error_Reporter::exception_upgrade();
			$approot = $this->getAppRoot($hostname, $path);
			try {
				$this->_execComposer($approot, 'composer config name %(hostname)s', ['hostname' => $hostname]);
				$docroot = $this->getDocumentRoot($hostname, $path);

				// ensure it's reachable
				$this->_fixCache($approot);

				$db = $this->_suggestDB($hostname);
				if (!$db) {
					return false;
				}

				$dbuser = $this->_suggestUser($db);
				if (!$dbuser) {
					return false;
				}
				$dbpass = $this->suggestPassword();
				$credentials = array(
					'db'       => $db,
					'user'     => $dbuser,
					'password' => $dbpass
				);

				if (!$this->setupDatabase($credentials, 'mysql')) {
					return error("Failed to create database");
				}

				$fqdn = $this->web_normalize_hostname($hostname);
				$args['uri'] = rtrim($fqdn . '/' . $path, '/');
				$args['proto'] = empty($opts['ssl']) ? 'http://' : 'https://';

				if (!$this->setConfiguration($approot, $docroot, array_merge([
					'dbname'     => $credentials['db'],
					'dbuser'     => $credentials['user'],
					'dbpassword' => $credentials['password'],
					'dbhost'     => 'localhost'
				], $args))) {
					return error("failed to set .env configuration");
				}
			} catch (\apnscpException $e) {
				$this->remapPublic($hostname, $path, '');
				$this->file_delete($approot, true);
				if (isset($credentials['db']) && $this->mysql_database_exists($credentials['db'])) {
					$this->mysql_delete_database($credentials['db']);
				}
				if (isset($credentials['user']) && $this->mysql_user_exists($credentials['user'], 'localhost')) {
					$this->mysql_delete_user($credentials['user'], 'localhost');
				}

				return error("Failed to install Laravel: %s", $e->getMessage());
			} finally {
				\Error_Reporter::exception_upgrade($oldex);
			}


			$commands = [
				'key:generate',
				'queue:seed',
				'migrate'
			];
			foreach ($commands as $cmd) {
				$this->_exec($approot, './artisan ' . $cmd);
			}

			// by default, let's only open up ACLs to the bare minimum
			$this->fortify($hostname, $path, 'max');

			$params = array(
				'version'    => $this->get_version($hostname, $path),
				'hostname'   => $hostname,
				'autoupdate' => (bool)$opts['autoupdate'],
				'options'    => array_except($opts, 'version'),
			);
			$this->map('add', $docroot, $params);
			$this->fixRewriteBase($docroot);
			$email = $opts['email'] ?? $this->common_get_email();
			$this->buildConfig($approot, $docroot);
			if (array_get($opts, 'notify', true)) {
				\Lararia\Bootstrapper::minstrap();
				\Illuminate\Support\Facades\Mail::to($email)->
				send((new \Module\Support\Webapps\Mailer('install.laravel', [
					'uri'     => $args['uri'],
					'proto'   => $args['proto'],
					'appname' => static::APP_NAME,
					'approot' => $approot
				]))->setAppName(static::APP_NAME));
			}

			if (!$opts['squash']) {
				parent::unsquash(dirname($docroot));
			}

			return info("Laravel installed on %s", $args['uri']);
		}

		protected function checkVersion(array &$options): bool
		{
			if (!parent::checkVersion($options)) {
				return false;
			}
			$phpversion = $this->php_version();

			$cap = null;
			if (version_compare($phpversion, '5.6.4', '<')) {
				$cap = '5.3';
			} else if (version_compare($phpversion, '7.0.0', '<')) {
				$cap = '5.4';
			} else if (version_compare($phpversion, '7.1.3', '<')) {
				$cap = '5.5';
			}

			if ($cap && version_compare($options['version'], $cap, '>=')) {
				info("PHP version `%s' detected, capping Laravel to %s", $phpversion, $cap);
				$options['version'] = $cap;
			}

			return true;
		}

		/**
		 * Restrict version semantically
		 *
		 * @param string $lockType
		 * @param string $version
		 * @return string
		 */
		private function parseLock(string $lockType, string $version): string
		{
			switch ($lockType) {
				case 'major':
					return '~' . \Opcenter\Versioning::asMinor($version);
				case 'minor':
					return \Opcenter\Versioning::asMinor($version) . '.*';
				case 'patch':
					return $version;
				case '':
					return '>' . $version;
				default:
					warn("unknown lock type `%s' - restricting to `%s'", $lockType, $version);

					return $version;
			}
		}

		private function _execComposer($path = null, $cmd, array $args = array())
		{
			$cmd = '/usr/bin/composer --no-interaction -q ' . $cmd;
			if (!is_array($args)) {
				$args = array_slice(func_get_args(), 2);
			}

			return $this->_exec($path, $cmd, $args);
		}

		private function _exec($path = null, $cmd, array $args = array())
		{
			// client may override tz, propagate to bin
			$cmd = $this->_getCommand() . $cmd;
			if (!is_array($args)) {
				$args = array_slice(func_get_args(), 2);
			}

			$user = $this->username;
			if ($path) {
				$cmd = 'cd %(path)s && /bin/bash -c -- ' . escapeshellarg($cmd);
				$args['path'] = $path;
				$user = $this->file_stat($path)['owner'] ?? $this->username;
			}

			if ($path) {
				$cmd = 'cd %(chdir)s && ' . $cmd;
				$args['chdir'] = $path;
			}
			$ret = $this->pman_run($cmd, $args, [], ['user' => $user]);

			return $ret;
		}

		private function _getCommand()
		{
			$tz = date_default_timezone_get();
			$cli = 'php -d mysqli.default_socket=' . escapeshellarg(ini_get('mysqli.default_socket')) .
				' -d date.timezone=' . $tz . ' -d memory_limit=128m ';

			return $cli;
		}

		protected function getAppRoot(string $hostname, string $path = ''): ?string
		{
			return $this->getAppRootReal($hostname, $path);
		}

		/**
		 * Inject custom bootstrapper
		 *
		 * @param $approot
		 * @return bool|int|void
		 */
		protected function _fixCache($approot)
		{
			$file = $this->domain_fs_path() . '/' . $approot . '/app/ApplicationWrapper.php';
			$tmpfile = tempnam($this->domain_fs_path() . '/tmp', 'appwrapper');
			if (!copy(resource_path('storehouse/laravel/ApplicationWrapper.php'), $tmpfile)) {
				return warn('failed to copy optimized cache bootstrap');
			}
			if (!posix_getuid()) {
				chown($tmpfile, File_Module::UPLOAD_UID);
			}

			$this->file_endow_upload(basename($tmpfile));
			$this->file_copy($this->file_unmake_path($tmpfile), $approot . '/app/ApplicationWrapper.php');
			unlink($tmpfile);
			$file = dirname(dirname($file)) . '/bootstrap/app.php';
			if (!file_exists($file)) {
				return error('unable to alter app.php - file is missing (Laravel corrupted?)');
			}
			$contents = file_get_contents($file);
			$contents = preg_replace('/new\sIlluminate\\\\Foundation\\\\Application/m', 'new App\\ApplicationWrapper',
				$contents);

			if (file_put_contents($file, $contents) < 1) {
				return false;
			}
			$ret = $this->_execComposer($approot, 'dumpautoload -o');

			return $ret['success'];
		}

		private function setConfiguration(string $approot, string $docroot, array $config)
		{
			$envcfg = (new \Opcenter\Provisioning\ConfigurationWriter("webapps.laravel.env",
				\Opcenter\SiteConfiguration::import($this->getAuthContext())))
				->compile($config);
			$this->file_put_file_contents("${approot}/.env", (string)$envcfg);

			return $this->buildConfig($approot, $docroot);
		}

		/**
		 * Rebuild config and force frontend cache
		 *
		 * @param string $approot
		 * @param string $docroot
		 * @return bool
		 */
		private function buildConfig(string $approot, string $docroot): bool
		{
			$ret = $this->_exec($approot, 'artisan config:cache');
			if (!$ret['success']) {
				return error("config rebuild failed: %s", coalesce($ret['stderr'], $ret['stdout']));
			}
			if (!($uri = $this->web_get_hostname_from_docroot($docroot))) {
				return error("no URI specified, cannot deduce URI from docroot `%s'", $docroot);
			}
			$uri = $this->web_normalize_hostname($uri);
			$ctx = stream_context_create(array(
				'http' =>
					array(
						'timeout'          => 5,
						'method'           => 'HEAD',
						'header'           => [
							"User-agent: apnscp Internal check",
							"Host: ${uri}"
						],
						'protocol_version' => '1.1'
					)
			));

			return (bool)get_headers('http://' . $this->site_ip_address(), 0, $ctx) ?:
				warn("failed to cache configuration directly, visit `%s' to cache configuration", $uri);
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
			return parent::fortify($hostname, $path, $mode);
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
			$path = $this->domain_fs_path($approot . '/vendor/composer/installed.json');

			if (!file_exists($path) || !($json = json_decode(file_get_contents($path), true))) {
				return null;
			}
			foreach ($json as $pkg) {
				if ($pkg['name'] === 'laravel/framework') {
					return \Opcenter\Versioning::asPatch($pkg['version_normalized']);
				}
			}

			return null;
		}

		/**
		 * Location is a valid Laravel install
		 *
		 * @param string $hostname or $docroot
		 * @param string $path
		 * @return bool
		 */
		public function valid(string $hostname, string $path = ''): bool
		{
			if ($hostname[0] === '/') {
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

			return file_exists($approot . '/artisan');
		}

		public function get_versions(): array
		{
			$key = 'laravel.verflat';
			$cache = \Cache_Global::spawn();
			if (false !== ($versions = $cache->get($key))) {
				return $versions;
			}
			$versions = array_column(array_filter($this->_getVersions(), function ($ver) {
				return false === strpos($ver['version_normalized'], '-') && $ver['version'][0] === 'v';
			}), 'version_normalized');
			natsort($versions);
			array_walk($versions, function (&$ver) {
				$ver = join('.', array_slice(explode('.', $ver), 0, 3));
			});

			$cache->set($key, $versions);

			return $versions;
		}

		/**
		 * Get all current major versions
		 *
		 * @return array
		 */
		private function _getVersions()
		{
			$key = 'laravel.versions';
			$cache = Cache_Super_Global::spawn();
			if (false !== ($ver = $cache->get($key))) {
				return $ver;
			}
			$url = self::VERSION_CHECK_URL;
			$contents = file_get_contents($url);
			if (!$contents) {
				return array();
			}
			$versions = json_decode($contents, true);
			if (!$versions || empty($versions['packages'])) {
				return array();
			}
			$versions = $versions['packages']['laravel/framework'];
			$cache->set($key, $versions, 43200);

			return $versions;
		}

		/**
		 * Uninstall Laravel from a location
		 *
		 * @param        $hostname
		 * @param string $path
		 * @param string $delete remove all files under docroot
		 * @return bool
		 */
		public function uninstall(string $hostname, string $path = '', string $delete = 'all'): bool
		{
			return parent::uninstall($hostname, $path, $delete);
		}

		/**
		 * Get database configuration for a blog
		 *
		 * @param string $hostname domain or subdomain of wp blog
		 * @param string $path     optional path
		 * @return array|bool
		 */
		public function db_config(string $hostname, string $path = '')
		{
			$this->web_purge();
			$docroot = $this->getAppRoot($hostname, $path);
			if (!$docroot) {
				return error('failed to determine Laravel');
			}
			$code = '$cfg = (include("./bootstrap/cache/config.php"))["database"]; $db=$cfg["connections"][$cfg["default"]]; ' .
				'print serialize(array("user" => $db["username"], "password" => $db["password"], "db" => $db["database"], ' .
				'"host" => $db["host"], "prefix" => $db["prefix"]));';
			$cmd = 'cd %(path)s && php -d mysqli.default_socket=' . escapeshellarg(ini_get('mysqli.default_socket')) . ' -r %(code)s';
			$ret = $this->pman_run($cmd, array('path' => $docroot, 'code' => $code));

			if (!$ret['success']) {
				return error("failed to obtain Laravel configuration for `%s'", $docroot);
			}
			$data = \Util_PHP::unserialize($ret['stdout']);

			return $data;
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

		public function update_all(string $hostname, string $path = '', string $version = null): bool
		{
			return $this->update($hostname, $path, $version) || error('failed to update all components');
		}

		/**
		 * Update Laravel to latest version
		 *
		 * @param string $hostname domain or subdomain under which WP is installed
		 * @param string $path     optional subdirectory
		 * @param string $version  version to upgrade
		 * @return bool
		 */
		public function update(string $hostname, string $path = '', string $version = null): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('update failed');
			}
			$approot = $this->getAppRoot($hostname, $path);
			$newversion = $this->get_version($hostname, $path) ?? $version;
			$cmd = 'update laravel/framework' . ($version ? ':' . $version : '');
			$ret = $this->_execComposer($approot, $cmd);
			$error = [$ret['stderr']];
			if ($newversion !== $version && $ret['success']) {
				$ret['success'] = false;
				$error = [
					"Failed to update Laravel from `%s' to `%s', check composer.json for version restrictions",
					$newversion, $version
				];
			}
			parent::setInfo($docroot, [
				'version' => $newversion,
				'failed'  => !$ret['success']
			]);

			return $ret['success'] ?: error(...$error);
		}

		/**
		 * Update Laravel plugins
		 *
		 * @param string $hostname domain or subdomain
		 * @param string $path     optional path within host
		 * @param array  $plugins
		 * @return bool
		 */
		public function update_plugins(string $hostname, string $path = '', array $plugins = array()): bool
		{
			return parent::update_plugins($hostname, $path, $plugins);
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
			return parent::update_themes($hostname, $path, $themes);
		}

		/**
		 * Web application supports fortification
		 *
		 * @param string|null $mode optional mode (min, max)
		 * @return bool
		 */
		public function has_fortification(string $mode = null): bool
		{
			return parent::has_fortification($mode);
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
			return parent::unfortify($hostname, $path);
		}

		public function plugin_status(string $hostname, string $path = '', string $plugin = null)
		{
			return false;
		}

		public function install_plugin(
			string $hostname,
			string $path = '',
			string $plugin,
			string $version = 'stable'
		): bool {
			return false;
		}

		public function uninstall_plugin(string $hostname, string $path = '', string $plugin, bool $force = false): bool
		{
			return false;
		}

		public function disable_all_plugins(string $hostname, string $path = ''): bool
		{
			return false;
		}

		public function theme_status(string $hostname, string $path = '', string $theme = null)
		{
			return parent::theme_status($hostname, $path, $theme); // TODO: Change the autogenerated stub
		}

		public function install_theme(string $hostname, string $path = '', string $theme, string $version = null): bool
		{
			return parent::install_theme($hostname, $path, $theme, $version);
		}

		public function change_admin(string $hostname, string $path = '', array $fields): bool
		{
			return false;
		}

		public function get_admin(string $hostname, string $path = ''): ?string
		{
			return null;
		}

		public function next_version(string $version, string $maximalbranch = '99999999.99999999.99999999'): ?string
		{
			return parent::next_version($version, $maximalbranch);
		}


	}