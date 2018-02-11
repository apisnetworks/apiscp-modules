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
	 * Joomla! management
	 *
	 * @package core
	 */
	class Joomla_Module extends \Module\Support\Webapps
	{

		const APP_NAME = 'Joomla!';

		// primary domain document root
		const JOOMLA_CLI = '/usr/share/pear/joomlatools.phar';
		//const JOOMLA_CLI = '/.socket/php/pear/1.4.6/joomlatools-console-1.4.6/bin/joomla';
		const UPDATE_URI = 'https://github.com/joomla/joomla-cms/releases/download/%version%/Joomla_%version%-Stable-Update_Package.zip';

		// after installation apply the following fortification profile
		const DEFAULT_FORTIFY_MODE = 'max';

		const JOOMLA_CLI_VERSION = '1.4.11-2';
		const JOOMLA_MODULE_XML = 'http://update.joomla.org/core/extensions/%extension%.xml';

		const DEFAULT_VERSION_LOCK = 'major';

		const JOOMLA_MIRROR = 'http://mirror.apisnetworks.com/joomla';
		protected $_aclList = array(
			'min' => array(
				'/cache',
				'/tmp',
				'/administrator',
				'/logs',
				'/media',
				'/images',
				'/plugins',
				'/log'
			),
			'max' => array(
				'/cache',
				'/tmp',
				'/administrator/cache',
				'/logs',
				'/log'
			)
		);

		/**
		 * void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{

			parent::__construct();

		}

		public function get_versions(): array
		{
			return $this->_getVersions();
		}

		/**
		 * Get all current major versions
		 *
		 * @return array
		 */
		protected function _getVersions()
		{
			$key = 'joomla.versions';
			$cache = Cache_Super_Global::spawn();
			if (false !== ($ver = $cache->get($key))) {
				return $ver;
			}
			$proc = Util_Process::exec(
				'php ' . self::JOOMLA_CLI . ' --repo=%(repo)s --refresh versions',
				array(
					'repo' => self::JOOMLA_MIRROR
				)
			);
			if (!$proc['success'] || !preg_match_all(Regex::JOOMLA_VERSIONS, $proc['stdout'], $matches)) {
				error('failed to fetch Joomla versions: %s', $proc['stderr']);
				return [];
			}
			$versions = $matches[1];
			$cache->set($key, $versions, 43200);

			return $versions;
		}

		/**
		 * Install Joomla! into a pre-existing location
		 *
		 * @param string $hostname domain or subdomain to install Joomla!
		 * @param string $path     optional path under hostname
		 * @param array  $opts     additional install options
		 * @return bool
		 */
		public function install(string $hostname, string $path = '', array $opts = array()): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('failed to install Joomla');
			}

			if (!parent::checkDocroot($docroot)) {
				return false;
			}

			$version = null;
			if (isset($opts['version'])) {
				$version = $opts['version'];
			}

			if (!isset($opts['autoupdate'])) {
				$opts['autoupdate'] = true;
			}

			if (isset($opts['email']) && !preg_match(Regex::EMAIL, $opts['email'])) {
				return error("invalid email address `%s' specified", $opts['email']);
			}
			$opts['email'] = $this->get_config('siteinfo', 'email');

			if (!isset($opts['title'])) {
				$opts['title'] = '';
			}

			$squash = array_get($opts, 'squash', false);
			if ($squash && $this->permission_level & PRIVILEGE_USER) {
				warn('must squash privileges as secondary user');
				$squash = true;
			}
			$this->_exec(null, 'versions --refresh');
			$opts['squash'] = $squash;
			$fqdn = $this->web_normalize_hostname($hostname);

			if (!empty($opts['ssl']) && !parent::configureSsl($hostname)) {
				return false;
			}

			if ($version) {
				if (strcspn($version, '.0123456789')) {
					return error('invalid version number, %s', $version);
				}
			} else {
				$version = $this->getLatestVersion();
			}
			if (count(explode('.', $version)) < 3) {
				$version = \Opcenter\Versioning::asPatch($version);
			}
			$args = array(
				'mode'    => 'site:install',
				'docroot' => $docroot,
				'site'    => $fqdn,
				'repo'    => self::JOOMLA_MIRROR . '/archive/' . $version . '.tar.gz'
			);
			$args['version'] = $version;
			if (isset($opts['sampledata'])) {
				$data = $opts['sampledata'];
				if ($data !== 'blog' && $data !== 'default' && $data !== 'brochure' &&
					$data !== 'learn' && $data !== 'testing'
				) {
					return error("unknown sample data `%s'", $data);
				}
				$args['sampledata'] = '--sampledata=' . $data;
			} else {
				$args['sampledata'] = null;
			}

			$db = $this->_suggestDB($hostname);
			if (!$db) {
				return false;
			}

			$dbuser = $this->_suggestUser($db);
			if (!$dbuser) {
				return false;
			}
			$dbpass = $this->suggestPassword();
			$args['dbhost'] = 'localhost';
			$args['dbuser'] = $dbuser;
			$args['dbpass'] = $dbpass;
			$args['dbname'] = $db;
			$args['dbdriver'] = 'mysqli';
			if (!parent::setupDatabase(['db' => $db, 'user' => $dbuser, 'password' => $dbpass])) {
				return false;
			}
			// ensure the docroot is owned by the target uid to permit installation
			// correct it at the end
			if (!$squash) {
				$this->file_chown($docroot, $this->user_id);
			}

			$ret = $this->_exec($docroot,
				'site:download --www=%(docroot)s --release %(version)s --repo=%(repo)s -- ""', $args);
			$this->_fixMySQLSchema($docroot);
			if ($ret['success']) {
				$ret = $this->_exec($docroot,
					'database:install --skip-exists-check --mysql-host=%(dbhost)s --mysql-login=%(dbuser)s:%(dbpass)s ' .
					'--mysql-database=%(dbname)s --mysql-driver=%(dbdriver)s %(sampledata)s ' .
					'--www=%(docroot)s  -- ""', $args);
				if ($ret['success']) {
					$file = $this->_generateConfig($docroot, $opts);
					$args['tmpfile'] = $file;

					$ret = $this->_exec($docroot,
						'site:configure --options=%(tmpfile)s --mysql-host=%(dbhost)s --mysql-login=%(dbuser)s:%(dbpass)s ' .
						'--mysql-database=%(dbname)s --mysql-driver=%(dbdriver)s ' .
						'--www=%(docroot)s  -- ""', $args);
					unlink($this->domain_fs_path() . $file);
				}
			}
			if (!$ret['success']) {
				error('failed to install Joomla - removing temporary files: %s', $ret['stderr']);
				$this->file_delete($docroot, true);
				$this->sql_delete_mysql_database($db);
				$this->sql_delete_mysql_user($dbuser, 'localhost');

				return false;
			}

			parent::fixRewriteBase($docroot, $path);
			$autogenpw = false;
			if (!isset($opts['password'])) {
				$autogenpw = true;
				$opts['password'] = $this->suggestPassword(10);
				info("autogenerated password `%s'", $opts['password']);
			}

			if (!isset($opts['user'])) {
				$opts['user'] = $this->username;
				info("setting admin user to `%s'", $this->username);
			}

			$adminargs = array(
				'username' => $opts['user'],
				'password' => $opts['password'],
				'email'    => $opts['email']
			);

			if (!$this->change_admin($hostname, $path, $adminargs)) {
				warn('failed to set admin user, using default admin/admin combination');
			}

			$opts['url'] = rtrim($fqdn . '/' . $path, '/');

			// by default, let's only open up ACLs to the bare minimum
			$this->file_touch($docroot . '/.htaccess');


			if (!$version) {
				$version = $this->getLatestVersion();
			}
			$params = array(
				'version'    => $version,
				'hostname'   => $hostname,
				'path'       => $path,
				'autoupdate' => (bool)$opts['autoupdate'],
				'options'    => $opts
			);
			$this->_map('add', $docroot, $params);
			$fortifymode = self::DEFAULT_FORTIFY_MODE;
			$this->fortify($hostname, $path, $fortifymode);
			info('fortification mode set to %s', strtoupper($fortifymode));
			if (array_get($opts, 'notify', true)) {
				\Lararia\Bootstrapper::minstrap();
				\Illuminate\Support\Facades\Mail::to($opts['email'])->
				send((new \Module\Support\Webapps\Mailer('install.joomla', [
					'login'    => $opts['user'],
					'password' => $opts['password'],
					'uri'      => rtrim($fqdn . '/' . $path, '/'),
					'proto'    => empty($opts['ssl']) ? 'http://' : 'https://',
					'appname'  => static::APP_NAME
				]))->setAppName(static::APP_NAME));
			}

			if (!$opts['squash']) {
				parent::unsquash($docroot);
			}
			return info('Joomla! installed - confirmation email with login info sent to %s', $opts['email']);
		}

		private function _exec($path = null, $cmd, array $args = array())
		{
			// client may override tz, propagate to bin
			$tz = date_default_timezone_get();
			$cli = 'php -d mysqli.default_socket=' . escapeshellarg(ini_get('mysqli.default_socket')) .
				' -d date.timezone=' . $tz . ' -d memory_limit=128m ' . self::JOOMLA_CLI;
			if (!is_array($args)) {
				$args = func_get_args();
				array_shift($args);
			}
			$user = $this->username;
			if ($path) {
				$cmd = '--www=%(path)s ' . $cmd;
				$args['path'] = $path;
				$stat = $this->file_stat($path);
				$user = !empty($stat['owner']) && $stat['uid'] >= \a23r::get_class_from_module('user')::MIN_UID ?
					$stat['owner'] : $this->username;
			}
			$cmd = $cli . ' --no-interaction ' . $cmd;
			$ret = $this->pman_run($cmd, $args, null, ['user' => $user]);
			if (!strncmp($ret['stdout'], 'Error:', strlen('Error:'))) {
				// move stdout to stderr on error for consistency
				$ret['success'] = false;
				if (!$ret['stderr']) {
					$ret['stderr'] = $ret['stdout'];
				}
			} else {
				if (!$ret['success'] && !$ret['stderr']) {
					$ret['stderr'] = $ret['stdout'];
				}
			}
			return $ret;
		}

		private function _fixMySQLSchema($docroot)
		{
			if ($this->sql_mysql_version() >= 50503) {
				// utf8mb4 supported
				return true;
			}
			$prefix = $this->domain_shadow_path();
			$glob = $prefix . $docroot . '/{_,}installation/sql/mysql/*.sql';
			foreach (glob($glob, GLOB_BRACE) as $f) {
				$f = substr($f, strlen($prefix));
				$contents = $this->file_get_file_contents($f);
				$matches = 0;
				$contents = str_replace('utf8mb4', 'utf8', $contents, $matches);
				$this->file_put_file_contents($f, $contents, true);
			}

			return true;
		}

		private function _generateConfig($docroot, $opts)
		{
			$domainfsprefix = $this->domain_fs_path();
			$file = tempnam($domainfsprefix . '/' . sys_get_temp_dir(), 'joomla');
			chmod($file, 0644);
			$tz = date('T');
			$fullpath = $this->domain_fs_path() . $docroot;
			$opts = array(
				'debug'    => 0,
				'ftp_host' => 'localhost',
				'ftp_user' => $this->username . '@' . $this->domain,
				'ftp_root' => $docroot,
				'sitename' => $opts['title'],
				'offset'   => $tz,
				'tmp_path' => $fullpath . '/tmp',
				'log_path' => $fullpath . '/logs',
				'sendmail' => '/usr/sbin/sendmail',
				'mailer'   => 'mail',
				'smtpport' => 587,
				'force_ssl' => !empty($opts['ssl']) ? 2 : 0,
			);
			// pure PHP code
			file_put_contents($file, \Util_Yaml::YAMLDump($opts, false, 0));

			return substr($file, strlen($domainfsprefix));
		}

		/**
		 * Change Joomla admin credentials
		 *
		 * common fields include: username, password, name, email
		 *
		 * @param string $hostname
		 * @param string $path
		 * @param array  $fields
		 * @return bool
		 */
		public function change_admin(string $hostname, string $path = '', array $fields): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return warn('failed to change administrator information');
			}
			$admin = $this->get_admin($hostname, $path);

			if (!$admin) {
				return error('cannot determine admin of Joomla install');
			}
			$dbconfig = $this->db_config($hostname, $path);
			$conn = $this->_connectDB($dbconfig);
			if (!$conn) {
				return error("unable to connect to Joomla! database `%s'", $dbconfig['db']);
			}
			$fields = array_merge(array(
				'password' => null,
				'username' => null,
				'name'     => null,
				'email'    => null
			), $fields);
			if ($fields['password']) {
				$fields['password'] = $this->_saltedPassword($docroot, $fields['password']);
			}
			$filtered = array_filter($fields, function ($f) {
				return null !== $f;
			});

			$args = array();
			$builtQuery = array();
			foreach ($filtered as $k => $v) {
				$builtQuery[] = "$k = ?";
				$args[] = &$filtered[$k];
			}
			//$args = array_map(function($a) { return $a; }, $filtered);
			// plop admin user as part of WHERE username = ?
			$args[] = &$admin;
			$q = 'UPDATE ' . $dbconfig['prefix'] . 'users SET ' . implode(', ', $builtQuery) . ' WHERE username = ?';
			$stmt = $conn->prepare($q);
			$types = str_repeat('s', count($args));
			array_unshift($args, $types);
			call_user_func_array(array($stmt, 'bind_param'), $args);
			$rs = $stmt->execute();

			return $rs && $stmt->affected_rows > 0;
		}

		/**
		 * Get the primary admin for a Joomla instance
		 *
		 * @param string      $hostname
		 * @param null|string $path
		 * @return string|null admin or false on failure
		 */
		public function get_admin(string $hostname, string $path = ''): ?string
		{
			$dbconfig = $this->db_config($hostname, $path);
			$mysqli = $this->_connectDB($dbconfig);
			if (!$mysqli) {
				error('cannot get admin user - failed to connect to database');
				return null;
			}
			$q = 'select id, username FROM ' . $dbconfig['prefix'] . 'users ORDER BY registerDate ASC limit 1';
			$rs = $mysqli->query($q);
			if (!$rs || $rs->num_rows < 1) {
				warn('failed to enumerate Joomla administrative users');
				return null;
			}

			return $rs->fetch_object()->username;

		}

		/**
		 * Get database configuration for a blog
		 *
		 * @param string $hostname domain or subdomain of joomla
		 * @param string $path     optional path
		 * @return array|bool
		 */
		public function db_config(string $hostname, string $path = '')
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('failed to determine Joomla');
			}

			$j = $this->_getConfiguration($docroot);

			return array(
				'user'     => $j['user'],
				'password' => $j['password'],
				'db'       => $j['db'],
				'prefix'   => $j['dbprefix'],
				'host'     => $j['host']
			);
		}

		private function _getConfiguration($docroot)
		{

			$code = 'include("./configuration.php"); $j = new JConfig(); print serialize($j);';
			$cmd = 'cd %(path)s && php -d mysqli.default_socket=' . escapeshellarg(ini_get('mysqli.default_socket')) . ' -r %(code)s';
			$ret = $this->pman_run($cmd, array('path' => $docroot, 'code' => $code));
			if (!$ret['success']) {
				return error("failed to obtain Joomla configuration for `%s'", $docroot);
			}

			return get_object_vars(\Util_PHP::unserialize(trim($ret['stdout'])));
		}

		private function _connectDB($dbconfig)
		{
			static $conn;
			if ($conn) {
				return $conn;
			}
			$conn = new mysqli($dbconfig['host'], $dbconfig['user'], $dbconfig['password'], $dbconfig['db']);
			if ($conn->connect_error) {
				return false;
			}

			return $conn;
		}

		/**
		 * Generate a Joomla!-compatible salted password
		 *
		 * Supposedly compatible with 2.x and 3.x, only tested on 3.x
		 *
		 * @param string $docroot docroot path
		 * @param string $password
		 * @return string salted password
		 */
		private function _saltedPassword($docroot, $password): string
		{
			$salt = parent::suggestPassword(32);
			$hash = md5($password . $salt);

			return $hash . ':' . $salt;
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
		 * Install and activate plugin
		 *
		 * @param string $hostname domain or subdomain of joomla install
		 * @param string $path     optional path component of joomla install
		 * @param string $plugin   plugin name
		 * @param string $version  optional plugin version
		 * @return bool
		 */
		public function install_plugin(string $hostname, string $path = '', string $plugin, string $version = ''): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('invalid Joomla location');
			}

			$args = array($plugin);
			$ret = $this->_exec($docroot, 'plugin install %s --activate', $args);
			if (!$ret['success']) {
				return error("failed to install plugin `%s': %s", $plugin, $ret['stderr']);
			}
			info("installed plugin `%s'", $plugin);

			return true;
		}

		/**
		 * Uninstall a plugin
		 *
		 * @param string $hostname
		 * @param string $path
		 * @param string $plugin plugin name
		 * @param bool $force  delete even if plugin activated
		 * @return bool
		 */
		public function uninstall_plugin(string $hostname, string $path = '', string $plugin, bool $force = false): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('invalid Joomla location');
			}

			$args = array($plugin);
			$cmd = 'plugin uninstall %s';
			if ($force) {
				$cmd .= ' --deactivate';
			}
			$ret = $this->_exec($docroot, $cmd, $args);

			if (!$ret['stdout'] || !strncmp($ret['stdout'], 'Warning:', strlen('Warning:'))) {
				return error("failed to uninstall plugin `%s': %s", $plugin, $ret['stderr']);
			}
			info("uninstalled plugin `%s'", $plugin);

			return true;
		}

		public function plugin_status(string $hostname, string $path = '', string $plugin = null): array
		{
			return [];
		}

		/**
		 * Recovery mode to disable all plugins
		 *
		 * @param string $hostname subdomain or domain of Joomla
		 * @param string $path     optional path
		 * @return bool
		 */
		public function disable_all_plugins(string $hostname, string $path = ''): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('failed to determine path');
			}

			$ret = $this->_exec($docroot, 'plugin deactivate --all --skip-plugins');
			if (!$ret['success']) {
				return error('failed to deactivate all plugins: %s', $ret['stderr']);
			}

			return info('plugin deactivation successful: %s', $ret['stdout']);
		}

		/**
		 * Uninstall Joomla from a location
		 *
		 * @param        $hostname
		 * @param string $path
		 * @param string $delete "all", "db", or "files"
		 * @return bool
		 */
		public function uninstall(string $hostname, string $path = '', string $delete = 'all'): bool
		{
			return parent::uninstall($hostname, $path, $delete);
		}

		/**
		 * Check if version is latest or get latest version
		 *
		 * @param null|string $version
		 * @param string|null $branchcomp
		 * @return bool|int
		 */
		public function is_current(string $version = null, string $branchcomp = null)
		{
			return parent::is_current($version, $branchcomp);
		}

		/**
		 * Get installed version
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return string|null version number
		 */
		public function get_version(string $hostname, string $path = ''): ?string
		{
			if (!$this->valid($hostname, $path)) {
				return null;
			}
			$docroot = $this->getDocumentRoot($hostname, $path);
			$fsroot = $this->domain_fs_path();
			$path = $fsroot . $docroot;
			$versigs = array(
				'/libraries/cms/version/version.php', // 3.x, 2.5.x,
				'/libraries/joomla/version.php',      // 1.7.x allegedly
				'/includes/version.php'               // what I found in 1.7.5

			);
			$file = $path . '/language/en-GB/en-GB.xml';
			if (file_exists($file)) {
				$xml = simplexml_load_string(file_get_contents($file));
				$version = data_get($xml, 'version');
				if ($version) {
					return (string)$version[0];
				}
			}
			if (!defined('JPATH_PLATFORM')) {
				define('JPATH_PLATFORM', 'goddamn sanity checks');
			}
			if (!defined('_JEXEC')) {
				define('_JEXEC', 'this is also a PITA');
			}
			$version = null;
			foreach ($versigs as $sig) {
				$mypath = $path . $sig;
				if (!file_exists($mypath)) {
					continue;
				}
				$code = "define('JPATH_PLATFORM', 'foo'); define('_JEXEC', 'bar'); include_once './$sig'; class_exists('JVersion') or exit(1); " .
					'print (new JVersion)->getShortVersion();';
				$ret = $this->pman_run('cd %(docroot)s && php -r %(code)s', [
					'docroot' => $docroot,
					'path' => $sig,
					'code' => $code
				]);
				if ($ret['success']) {
					return trim($ret['output']);
				}
				break;
			}
			if (null === $version) {
				error('cannot determine Joomla! version - incomplete install?');
				return null;
			}

			return $version;
		}

		/**
		 * Location is a valid Joomla install
		 *
		 * @param string $hostname or $docroot
		 * @param string $path
		 * @return bool
		 */
		public function valid(string $hostname, string $path = ''): bool
		{
			if ($hostname[0] === '/') {
				$docroot = $hostname;
			} else {
				$docroot = $this->getDocumentRoot($hostname, $path);
				if (!$docroot) {
					return false;
				}
			}

			return $this->file_file_exists($docroot . '/libraries/joomla');
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
			$ret = ($this->update($hostname, $path, $version)/* && $this->update_plugins($hostname, $path)*/)
				|| error("failed to update all components");

			parent::setInfo($this->getDocumentRoot($hostname, $path), [
				'version' => $this->get_version($hostname, $path),
				'failed'  => !$ret
			]);

			return $ret;
		}

		/**
		 * Update Joomla! to latest version
		 *
		 * @param string $hostname domain or subdomain under which Joomla is installed
		 * @param string $path     optional subdirectory
		 * @param string $version
		 * @return bool
		 * @throws \HTTP_Request2_Exception
		 */
		public function update(string $hostname, string $path = '', string $version = null): bool
		{
			if (!IS_CLI) {
				return $this->query('joomla_update', $hostname, $path, $version);
			}

			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('update failed');
			}

			parent::setInfo($docroot, [
				'version' => $this->get_version($hostname, $path) ?? $version,
				'failed'  => !$this->update_real($docroot, $version)
			]);

			$mode = array_get(
				$this->getOptions($docroot),
				'fortify',
				self::DEFAULT_FORTIFY_MODE
			);
			$this->fortify($hostname, $path, $mode);
			info('Joomla updated, fortification set to %s', $mode);

			return info('Upgrade partially completed. Login to Joomla! admin portal to finish upgrade.');
		}

		protected function update_real(string $docroot, string $version = null): bool {

			if ($version) {
				if (!is_scalar($version) || strcspn($version, '.0123456789')) {
					return error('invalid version number, %s', $version);
				}
				if (!in_array($version, $this->get_versions())) {
					return error("unknown version `%s'", $version);
				}
			} else {
				$version = $this->getLatestVersion();
			}

			$replace = array(
				'version' => $version
			);
			$uri = preg_replace_callback(Regex::LAZY_SUB, function ($m) use ($replace) {
				return $replace[$m[1]];
			}, self::UPDATE_URI);

			$stat = $this->file_stat($docroot);
			if ($stat['uid'] < User_Module::MIN_UID) {
				$user = $this->username;
			} else {
				$user = $stat['owner'];
			}

			if (!parent::download($uri, $docroot)) {
				return error('failed to update Joomla! - download failed');
			}
			if ($user !== $this->username) {
				$this->file_chown($docroot, $user, true);
			}

			// as a prereq, joomlaupdate component must be updated as well
			// PHP runs jailed, may not have cache plugin installed, disable it
			$cfgfile = $docroot . '/configuration.php';
			$config = $this->file_get_file_contents($cfgfile);
			$newconfig = preg_replace('/public\s+\$cache_handler\s*=[^;]+;/', '', $config);
			$this->file_put_file_contents($cfgfile, $newconfig);
			if (!$this->_updateJoomlaUpdatePlugin($docroot, $user, $version)) {
				warn('Upgrade incomplete - failed to fetch Joomla! Update extension. Login to Joomla! admin portal to finish.');
			} else {
				warn('Login to Joomla! administrative panel to complete upgrade');
			}
			$this->file_put_file_contents($cfgfile, $config, true);

			return true;
		}

		private function _updateJoomlaUpdatePlugin($docroot, $user, $version)
		{
			$juext = $this->get_plugin_info('com_joomlaupdate');
			if (!$juext) {
				return false;
			}

			$updatever = (string)$juext['update']['targetplatform']['@attributes']['version'];
			if (version_compare((string)$version, $updatever, '<')) {
				return true;
			}

			$uri = $juext['update']['downloads']['downloadurl'];
			$path = $docroot . '/tmp/com_joomlaupdate';
			if ($this->file_file_exists($path)) {
				return false;
			}

			$this->file_create_directory($path);
			if (!parent::download($uri, $path)) {
				return false;
			}
			$this->file_chown($path, $user, true);

			$ret = $this->_exec($docroot, 'extension:installfile -- . %(plugin)s', array('plugin' => $path));
			$this->file_delete($path, true);
			return $ret['success'];
		}

		public function get_plugin_info($plugin, $ver = null)
		{
			$replace = array(
				'plugin' => $plugin,
				'ver'    => $ver
			);
			// @todo determine plugin versioning
			$uri = preg_replace_callback(Regex::LAZY_SUB, function ($m) use ($replace) {
				return $replace[$m[1]];
			}, 'http://update.joomla.org/core/extensions/%plugin%.xml?ver=%ver%');
			$content = silence(function () use ($uri) {
				return simplexml_load_string(file_get_contents($uri), 'SimpleXMLElement', LIBXML_NOCDATA);
			});
			if (!$content) {
				return false;
			}
			// @todo I don't like this, but SimpleXML is not an acceptable public
			// return type either
			return json_decode(json_encode((array)$content), true);
		}

		/**
		 * Update Joomla! plugins
		 *
		 * @param string $hostname domain or subdomain
		 * @param string $path     optional path within host
		 * @param array  $plugins
		 * @return bool
		 */
		public function update_plugins(string $hostname, string $path = '', array $plugins = array()): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('update failed');
			}

			$cmd = 'plugin update';
			$args = array();
			if (!$plugins) {
				$cmd .= ' --all';
			} else {
				for ($i = 0, $n = count($plugins); $i < $n; $i++) {
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
		 * Update Joomla! themes
		 *
		 * @param string $hostname subdomain or domain
		 * @param string $path     optional path under hostname
		 * @param array  $themes
		 * @return bool
		 */
		public function update_themes(string $hostname, string $path = '', array $themes = array()): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('update failed');
			}

			$cmd = 'theme update';
			$args = array();
			if (!$themes) {
				$cmd .= ' --all';
			} else {
				for ($i = 0, $n = count($themes); $i < $n; $i++) {
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

		/**
		 * Install joomlatools if necessary
		 *
		 * @return bool
		 */
		public function _housekeeping(): bool
		{
			$file = parent::_getWebappExtraStorageDirectory() . '/joomlatools-' .
				self::JOOMLA_CLI_VERSION . '.phar';

			if (!file_exists(self::JOOMLA_CLI) || sha1_file($file) !== sha1_file(self::JOOMLA_CLI)) {
				copy($file, self::JOOMLA_CLI);
				info('copied latest (v%s) JoomlaTools to PEAR', self::JOOMLA_CLI_VERSION);
			}

			$local = $this->service_template_path('siteinfo') . '/' . self::JOOMLA_CLI;
			if (!file_exists($local)) {
				copy(self::JOOMLA_CLI, $local);
			}

			return true;
		}

		/**
		 * Get referred name
		 *
		 * Referred to as Joomla!, but internally let's track as "joomla"
		 *
		 * @return string
		 */
		protected function getInternalName(): string
		{
			return 'joomla';
		}

		public function next_version(string $version, string $maximalbranch = '99999999.99999999.99999999'): ?string
		{
			return parent::next_version($version, $maximalbranch);
		}
	}
