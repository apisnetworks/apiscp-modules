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
	class Laravel_Module extends Module_Support_Webapps
	{
		const APP_NAME = "Laravel";

		const VERSION_CHECK_URL = "https://packagist.org/p/laravel/framework.json";

		// every Laravel app should contain artisan one level down...
		const LARAVEL_CLI = '../artisan';

		protected $_aclList = array(
			'min' => array(
				'/storage/framework/',
				'/app/bootstrap/cache'
			),
			'max' => array(
				'/storage/framework/cache',
				'/storage/framework/views',
				'/storage/framework/sessions',
				'/storage/logs',
				'/bootstrap/cache'
			)
		);
		private $_versionCache = array();

		/**
		 * void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{

			parent::__construct();
			$this->exportedFunctions = array(
				'*' => PRIVILEGE_SITE | PRIVILEGE_USER
			);
		}

		/**
		 * Install Laravel into a pre-existing location
		 *
		 * @param string $hostname domain or subdomain to install Laravel
		 * @param string $path     optional path under hostname
		 * @param array  $opts     additional install options
		 */
		public function install($hostname, $path = '', array $opts = array())
		{
			if (!version_compare(platform_version(), '6.5', '>=')) {
				return error("Laravel requires PHP7 available on newer platforms");
			}
			if (!$this->php_composer_exists()) {
				return error("composer missing! contact sysadmin");
			}

			$docroot = $this->_normalizePath($hostname, $path);

			if (!parent::checkDocroot($docroot)) {
				return false;
			}

			// toss all projects in ~/laravel-projects
			if (!isset($opts['projectname'])) {
				$home = $this->user_get_home();
				$parent = $home . '/laravel-projects';
				$opts['projectname'] = $parent . '/' . $hostname . ($path ? '-' . $path : '');
				if (!$this->file_file_exists($parent) && !$this->file_create_directory($parent)) {
					return error("unable to create laravel project directory - home missing?");
				}
			} else if (!$this->file_file_exists(dirname($opts['projectname']))) {
				return error("parent directory `%s' does not exist", dirname($opts['projectname']));
			}

			if ($this->file_file_exists($opts['projectname'])) {
				$files = $this->file_get_directory_contents($opts['projectname']);
				if (count($files)) {
					return error("directory `%s' must be empty", $opts['projectname']);
				}
				$this->file_delete($opts['projectname'], true);
			}

			$approot = $opts['projectname'];
			/*$ret = $this->_execComposer(null, 'global require "laravel/installer"');

			if (!$ret['success']) {
				return error("failed to install laravel installer via composer: `%s'",
					coalesce($ret['stderr'], $ret['stdout'])
				);
			}
*/
			if (!isset($opts['autoupdate'])) {
				$opts['autoupdate'] = true;
				$opts['updatestrategy'] = 'patch';
			}

			$home = $this->user_get_home();

			$ret = $this->_exec(dirname($opts['projectname']), '%(home)s/.composer/vendor/bin/laravel --no-interaction -q %(dev)s new %(project)s',
				[
					'home' => $home,
					'dev' => !empty($opts['dev']) ? '--dev' : null,
					'projecthome' => dirname($opts['projectname']),
					'project' => basename($opts['projectname'])
				]
			);

			if (!$ret['success']) {
				return error("failed to install Laravel, error: %s",
					$ret['stderr']
				);
			}
			if ($this->file_file_exists($docroot)) {
				$this->file_delete($docroot, true);
			}
			$this->file_symlink($approot . '/public', $docroot);
			// ensure it's reachable
			$stat = $this->file_stat($home);
			$this->file_chmod($home, decoct($stat['permissions']) | 001);
			$this->_fixCache($approot);
			return;
			$db = $this->_suggestDB($hostname);
			if (!$db) {
				return false;
			}

			$dbuser = $this->_suggestUser($db);
			if (!$dbuser) {
				return false;
			}
			$dbpass = $this->_suggestPassword();
			$credentials = array(
				'db'       => $db,
				'user'     => $dbuser,
				'password' => $dbpass
			);

			if (!$this->sql_create_mysql_database($db)) {
				return error("failed to create suggested db `%s'", $db);
			} else if (!$this->sql_add_mysql_user($dbuser, 'localhost', $dbpass)) {
				$this->sql_delete_mysql_database($db);
				return error("failed to create suggested user `%s'", $dbuser);
			} else if (!$this->sql_set_mysql_privileges($dbuser, 'localhost', $db, array('read' => true, 'write' => true))) {
				$this->sql_delete_mysql_user($dbuser, 'localhost');
				$this->sql_delete_mysql_database($db);
				return error("failed to set privileges on db `%s' for user `%s'", $db, $dbuser);
			}
			if ($this->sql_add_mysql_backup($db, 'zip', 5, 2)) {
				info("added database backup task for `%s'", $db);
			}

			if (!$this->_generateNewConfig($hostname, $approot, $credentials)) {
				info("removing temporary files");
				$this->file_delete($approot, true);
				$this->sql_delete_mysql_database($db);
				$this->sql_delete_mysql_user($dbuser, 'localhost');
				return false;
			}


			$args = array(
				'email'    => $opts['email'],
				'mode'     => 'install',
				'url'      => $opts['url'],
				'title'    => $opts['title'],
				'user'     => $opts['user'],
				'password' => $opts['password']
			);

			$ret = $this->_exec($approot, 'core %(mode)s --admin_email=%(email)s --skip-email ' .
				'--url=%(url)s --title=%(title)s --admin_user=%(user)s ' .
				'--admin_password=%(password)s', $args);
			if (!$ret['success']) {
				return error("failed to create database structure: %s", $ret['stderr']);
			}
			// by default, let's only open up ACLs to the bare minimum
			$this->fortify($hostname, $path, 'max');

			if (!$version) {
				$version = $this->_getLastestVersion();
			}
			$params = array(
				'version'    => $version,
				'hostname'   => $hostname,
				'autoupdate' => (bool)$opts['autoupdate'],
				'fortify'    => 'min',
				'updatelimit' => 'patch'
			);
			$this->_map('add', $approot, $params);
			if (false === strpos($hostname, ".")) {
				$hostname = $hostname . '.' . $this->domain;
			}
			$url = 'http://' . $hostname . '/' . $path;
			$msg = "Hello!" . "\r\n" .
				"This is a confirmation that Laravel has been installed under " . $approot .
				". You may access Laravel via " . $url . "\r\n";
			$hdrs = "From: " . Crm_Module::FROM_NAME . " <" . Crm_Module::FROM_ADDRESS . ">\r\nReply-To: " . Crm_Module::REPLY_ADDRESS;
			Mail::send($opts['email'], "Laravel Installed", $msg, $hdrs);
			info("Laravel installed - confirmation email with login info sent to %s", $opts['email']);
			return true;
		}

		/**
		 * Inject custom bootstrapper
		 *
		 * @param $approot
		 * @return bool|int|void
		 */
		protected function _fixCache($approot) {
			$file = $this->domain_fs_path() . '/' . $approot . '/app/ApplicationWrapper.php';
			$tmpfile = tempnam($this->domain_fs_path() . '/tmp', 'appwrapper');
			if (!copy(__DIR__ . '/laravel/ApplicationWrapper.php', $tmpfile)) {
				return warn("failed to copy optimized cache bootstrap");
			}
			if (is_debug()) {
				chown ($tmpfile, File_Module::UPLOAD_UID);
			}

			$this->file_endow_upload(basename($tmpfile));
			$this->file_copy($this->file_unmake_path($tmpfile), $approot . '/app/ApplicationWrapper.php');
			unlink($tmpfile);
			$file = dirname(dirname($file)) . '/bootstrap/app.php';
			if (!file_exists($file)) {
				return error("unable to alter app.php - file is missing (Laravel corrupted?)");
			}
			$contents = file_get_contents($file);
			$contents = preg_replace('/new\sIlluminate\\\\Foundation\\\\Application/m', 'new App\\ApplicationWrapper', $contents);
			return file_put_contents($file, $contents);
		}

		private function _execComposer($path = null, $cmd, array $args = array()) {
			$cmd = '/usr/bin/composer --no-interaction -q --no-progress ' . $cmd;
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

			if ($path) {
				$cmd = 'cd %(chdir)s && ' . $cmd;
				$args['chdir'] = $path;
			}
			$ret = $this->pman_run($cmd, $args);
			return $ret;
		}

		private function _getCommand() {
			$tz = date_default_timezone_get();
			$cli = 'php -d mysqli.default_socket=' . escapeshellarg(ini_get("mysqli.default_socket")) .
				' -d date.timezone=' . $tz . ' -d memory_limit=128m ';
			return $cli;
		}

		private function _generateNewConfig($domain, $docroot, $dbcredentials, $ftpcredentials = array())
		{
			// generate db
			if (!isset($ftpcredentials['user'])) {
				$ftpcredentials['user'] = $this->username . '@' . $this->domain;
			}
			if (!isset($ftpcredentials['host'])) {
				$ftpcredentials['host'] = 'localhost';
			}
			if (!isset($ftpcredentials['password'])) {
				$ftpcredentials['password'] = '';
			}
			$xtraphp = '<<' . "\r\n" .
				"define('FTP_USER',%(ftpuser)s);" . "\n" .
				"define('FTP_HOST', %(ftphost)s);" . "\n" .
				($ftpcredentials['password'] ?
					"define('FTP_PASS', %(ftppass)s);" : '') . "\r\n";
			$args = array(
				'mode'     => 'config',
				'db'       => $dbcredentials['db'],
				'password' => $dbcredentials['password'],
				'user'     => $dbcredentials['user'],
				'ftpuser'  => $ftpcredentials['user'],
				'ftphost'  => 'localhost',
				'ftppass'  => $ftpcredentials['password']
			);


			$ret = $this->_exec($docroot, 'core %(mode)s --dbname=%(db)s --dbpass=%(password)s --dbuser=%(user)s --dbhost=localhost --extra-php ' . $xtraphp, $args);
			if (!$ret['success']) {
				return error("failed to generate configuration, error: %s", $ret['stderr']);
			}
			return true;
		}

		/**
		 * Get latest WP release
		 *
		 * @return string
		 */
		private function _getLastestVersion()
		{
			$versions = $this->_getVersions();
			if (!$versions) {
				return null;
			}
			$version = $max = null;
			foreach ($versions as $v => $data) {
				if ($v[0] !== "v") {
					continue;
				}
				if ($data['uid'] > $max) {
					$version = $v;
					$max = $data['uid'];
				}
			}
			$latest = $versions[$version];
			return $latest['version_normalized'];
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

		public function test() {
			return $this->_getLastestVersion();
		}

		/**
		 * Uninstall Laravel from a location
		 *
		 * @param        $hostname
		 * @param string $path
		 * @param bool   $deletefiles remove all files under docroot
		 * @return bool
		 */
		public function uninstall($hostname, $path = '', $deletefiles = true)
		{

			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("failed to determine Laravel");
			}
			if (!$this->valid($hostname, $path)) {
				return error("`%s' does not contain a valid Laravel install", $docroot);
			}

			$approot = $this->getAppRoot($docroot);

			$config = $this->db_config($hostname, $path);
			if (!$config) {
				warn("cannot remove database, conf/database.php missing?");
			}

			if ($this->sql_mysql_database_exists($config['db']) && !$this->sql_delete_mysql_database($config['db'])) {
				warn("failed to delete mysql database `%s'", $config['db']);
			}
			if ($config['user'] !== $this->get_service_value('mysql', 'dbaseadmin')) {
				if ($this->sql_mysql_user_exists($config['user'], 'localhost') && !$this->sql_delete_mysql_user($config['user'], 'localhost')) {
					warn("failed to delete mysql user `%s' on localhost", $config['user']);
				}
			}

			$this->_map('delete', $docroot);

			if (!$deletefiles) {
				return info("removed configuration, manually delete files under `%s'", $docroot);
			}

			$this->file_delete($docroot, true);
			$url = rtrim(join("/", array($hostname, $path)), "/");
			$this->file_purge();
			$this->file_create_directory($docroot);
			return info("deleted WP blog `%s' located under `%s'", $url, $docroot);
		}

		/**
		 * Location is a valid WP install
		 *
		 * @param string $hostname or $docroot
		 * @param string $path
		 * @return bool
		 */
		public function valid($hostname, $path = '')
		{
			if ($hostname[0] == '/') {
				$docroot = $hostname;
			} else {
				$docroot = $this->_normalizePath($hostname, $path);
				if (!$docroot) {
					return false;
				}
			}
			$approot = $this->getAppRoot($docroot);

			return $this->file_file_exists($approot . '/artisan');
		}

		/**
		 * Get database configuration for a blog
		 *
		 * @param string $hostname domain or subdomain of wp blog
		 * @param string $path     optional path
		 * @return array
		 */
		public function db_config($hostname, $path = '')
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("failed to determine WP");
			}
			$code = 'include("./wp-config.php"); print serialize(array("user" => DB_USER, "password" => DB_PASSWORD, "db" => DB_NAME, "host" => DB_HOST, "prefix" => $table_prefix));';
			$cmd = 'cd %(path)s && php -d mysqli.default_socket=' . escapeshellarg(ini_get('mysqli.default_socket')) . ' -r %(code)s';
			$ret = $this->pman_run($cmd, array('path' => $docroot, 'code' => $code));
			if (!$ret['success']) {
				return error("failed to obtain WP configuration for `%s'", $docroot);
			}
			$data = unserialize($ret['stdout']);
			return $data;
		}

		/**
		 * Check if version is latest or get latest version
		 *
		 * @param null $version
		 * @return int|string
		 */
		public function is_current($version = null)
		{
			$latest = $this->_getLastestVersion();;
			if (!$version) {
				return $version;
			}
			if (substr($latest, -2) === ".0") {
				$latest = substr($latest, 0, -2);
			}
			if (version_compare($version, $latest, '=')) {
				return 1;
			} else if (version_compare($version, $latest, '<')) {
				return 0;
			} else {
				return -1;
			}
		}


		/**
		 * Get Laravel application name
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return string|null declared name
		 */
		public function get_name($hostname, $path = '') {
			$docroot = $this->_normalizePath($hostname, $path);
			$path = $this->getAppRoot($docroot);
			$prefix = $this->domain_fs_path();
			$info = $prefix . '/' . $path . '/composer.json';
			if (!file_exists($info)) {
				return null;
			}
			$json = json_decode(file_get_contents($info));
			return !empty($json->name) ? $json->name : null;

		}

		/**
		 * Get installed version
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return null|string version number
		 */
		public function get_version($hostname, $path = '')
		{
			if (!$this->valid($hostname, $path)) {
				return null;
			}
			$docroot = $this->_normalizePath($hostname, $path);
			$path = $this->getAppRoot($docroot);
			$ret = $this->_exec($path, 'artisan -V');
			if (!$ret['success']) {
				return null;
			}
			$output = $ret['stdout'];
			return trim(substr($output, strrpos($output, " ")));
		}

		/**
		 * Update Laravel to latest version
		 *
		 * @param string $domain domain or subdomain under which WP is installed
		 * @param string $path   optional subdirectory
		 * @param string $version
		 * @return bool
		 */
		public function update($domain, $path = '')
		{
			$docroot = $this->_normalizePath($domain, $path);
			if (!$docroot) {
				return error("update failed");
			}
			$approot = $this->getAppRoot($docroot);
			$ret = $this->_execComposer($approot, 'update');
			return $ret['success'];
		}

		/**
		 * Update Laravel plugins
		 *
		 * @param string $hostname domain or subdomain
		 * @param string $path     optional path within host
		 * @param array  $plugins
		 * @return bool|void
		 */
		public function update_plugins($hostname, $path = '', $plugins = array())
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("update failed");
			}

			$cmd = 'plugin update';
			$args = array();
			if (!$plugins) {
				$cmd .= ' --all';
			} else {
				for ($i = 0, $n = sizeof($plugins); $i < $n; $i++) {
					$plugin = $plugins[$i];
					$version = null;
					if (isset($plugin['version'])) {
						$version = $plugin['version'];
					}
					if (isset($plugin['name'])) {
						$plugin = $plugin['name'];
					}

					$name = 'p' . $i;

					$cmd .= ' %(' . $name . ')s';
					$args[$name] = $plugin;
					if ($version) {
						$cmd .= ' --version=%(' . $name . 'v)s';
						$args[$name . 'v'] = $version;
					}
				}
			}

			$ret = $this->_exec($docroot, $cmd, $args);
			if (!$ret['success']) {
				return error("plugin update failed: `%s'", $ret['stderr']);
			}
			return $ret['success'];
		}

		/**
		 * Update Laravel themes
		 *
		 * @param string $hostname subdomain or domain
		 * @param string $path     optional path under hostname
		 * @param array  $themes
		 * @return bool|void
		 */
		public function update_themes($hostname, $path = '', $themes = array())
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("update failed");
			}

			$cmd = 'theme update';
			$args = array();
			if (!$themes) {
				$cmd .= ' --all';
			} else {
				for ($i = 0, $n = sizeof($themes); $i < $n; $i++) {
					$theme = $themes[$i];
					$version = null;
					if (isset($theme['version'])) {
						$version = $theme['version'];
					}
					if (isset($theme['name'])) {
						$plugin = $theme['name'];
					}

					$name = 'p' . $i;

					$cmd .= ' %(' . $name . ')s';
					$args[$name] = $theme;
					if ($version) {
						$cmd .= ' --version=%(' . $name . 'v)s';
						$args[$name . 'v'] = $version;
					}
				}
			}

			$ret = $this->_exec($docroot, $cmd, $args);
			if (!$ret['success']) {
				return error("theme update failed: `%s'", $ret['stderr']);
			}
			return $ret['success'];
		}

		/**
		 * Web application supports fortification
		 *
		 * @param string|null $mode optional mode (min, max)
		 * @return bool
		 */
		public function has_fortification($mode = null)
		{
			return parent::has_fortification($mode);
		}

		/**
		 * Restrict write-access by the app
		 *
		 * @param        $hostname
		 * @param string $path
		 */
		public function fortify($hostname, $path = '', $mode = 'max')
		{
			return parent::fortify($hostname, $path, $mode);
		}

		/**
		 * Relax permissions to allow write-access
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return bool
		 */
		public function unfortify($hostname, $path = '', $mode = 'max')
		{
			return parent::unfortify($hostname, $path, $mode);
		}

		protected function getAppRoot($docroot) {
			$stat = $this->file_stat($docroot);
			if ($stat['link']) {
				$docroot = $stat['referent'];
			}
			return dirname($docroot);
		}

		/**
		 * Override docroot map generation since the files to modify
		 * will be below 1 level
		 *
		 * @param array  $files
		 * @param string $docroot
		 * @return array
		 */
		protected function _mapFiles(array $files, $docroot) {
			return parent::_mapFiles($files, dirname($docroot));
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
	}

