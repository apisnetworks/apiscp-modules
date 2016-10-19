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
	 * Joomla! management
	 *
	 * @package core
	 */
	class Joomla_Module extends Module_Support_Webapps
	{

		const APP_NAME = "Joomla!";

		// primary domain document root
		const JOOMLA_CLI = '/usr/share/pear/joomlatools.phar';
		//const JOOMLA_CLI = '/.socket/php/pear/1.4.6/joomlatools-console-1.4.6/bin/joomla';
		const UPDATE_URI = 'https://github.com/joomla/joomla-cms/releases/download/%version%/Joomla_%version%-Stable-Update_Package.zip';

		// latest release
		const JOOMLA_CLI_URL = '';
		const JOOMLA_CLI_VERSION = '1.4.6';
		const JOOMLA_MODULE_XML = 'http://update.joomla.org/core/extensions/%extension%.xml';

		const JOOMLA_MIRROR = 'http://mirror.apisnetworks.com/joomla';
		protected $_aclList = array(
			'min' => array(
				'/cache',
				'/tmp',
				'/administrator',
				'/logs',
				'/media',
				'/images',
				'/plugins'
			),
			'max' => array(
				'/cache',
				'/tmp',
				'/administrator/cache',
				'/logs',

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
		 * Install Joomla! into a pre-existing location
		 *
		 * @param string $hostname domain or subdomain to install Joomla!
		 * @param string $path     optional path under hostname
		 * @param array  $opts     additional install options
		 */
		public function install($hostname, $path = '', array $opts = array())
		{
			$opts['version'] = '3.5.1';
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("failed to install Joomla");
			}

			if (!parent::checkDocroot($docroot)) {
				return false;
			}

			if (isset($opts['version'])) {
				$version = $opts['version'];
			} else {
				$version = null;
			}

			if (!isset($opts['autoupdate'])) {
				$opts['autoupdate'] = true;
			}

			if (isset($opts['email']) && !preg_match(Regex::EMAIL, $opts['email'])) {
				return error("invalid email address `%s' specified", $opts['email']);
			} else {
				$opts['email'] = $this->get_config('siteinfo', 'email');
			}

			if (!isset($opts['title'])) {
				$opts['title'] = '';
			}

			$args = array(
				'mode'    => 'site:install',
				'docroot' => $docroot,
				'site'    => $hostname,
				'repo'    => self::JOOMLA_MIRROR
			);

			if ($this->ssl_permitted() && $this->ssl_cert_exists()) {
				// @todo enable SSL
			}
			if (!is_null($version)) {
				if (strcspn($version, ".0123456789")) {
					return error("invalid version number, %s", $version);
				}

			} else {
				$version = $this->_getLatestVersion();
			}
			$args['version'] = '--release=' . $version;

			if (isset($opts['sampledata'])) {
				$data = $opts['sampledata'];
				if ($data !== "blog" && $data !== "default" && $data !== "brochure" &&
					$data !== "learn" && $data !== "testing"
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
			$dbpass = $this->_suggestPassword();
			$args['dbhost'] = 'localhost';
			$args['dbuser'] = $dbuser;
			$args['dbpass'] = $dbpass;
			$args['dbname'] = $db;
			$args['dbdriver'] = 'mysqli';
			//version_compare($version, '3.0', '>=') ? 'pdomysql' : 'mysqli';

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
			$ret = $this->_exec($docroot, 'site:download --www=%(docroot)s %(version)s --clone=false -- ""', $args);
			$this->_fixMySQLSchema($docroot);
			if ($ret['success']) {
				$ret = $this->_exec($docroot, 'database:install --skip-exists-check --mysql-host=%(dbhost)s --mysql-login=%(dbuser)s:%(dbpass)s ' .
					'--mysql-database=%(dbname)s --mysql-driver=%(dbdriver)s %(sampledata)s ' .
					'--www=%(docroot)s  -- ""', $args);
				if ($ret['success']) {
					$file = $this->_generateConfig($docroot, $opts);
					$args['tmpfile'] = $file;

					$ret = $this->_exec($docroot, 'site:configure --options=%(tmpfile)s --mysql-host=%(dbhost)s --mysql-login=%(dbuser)s:%(dbpass)s ' .
						'--mysql-database=%(dbname)s --mysql-driver=%(dbdriver)s ' .
						'--www=%(docroot)s  -- ""', $args);
					unlink($this->domain_fs_path() . $file);
				}
			}
			if (!$ret['success']) {
				error("failed to install Joomla - removing temporary files: %s", $ret['stderr']);
				$this->file_delete($docroot, true);
				$this->sql_delete_mysql_database($db);
				$this->sql_delete_mysql_user($dbuser, 'localhost');
				return false;
			}

			parent::fixRewriteBase($docroot, $path);
			$autogenpw = false;
			if (!isset($opts['password'])) {
				$autogenpw = true;
				$opts['password'] = $this->_suggestPassword(10);
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
				warn("failed to set admin user, using default admin/admin combination");
			}

			$opts['url'] = rtrim($hostname . '/' . $path, '/');

			// by default, let's only open up ACLs to the bare minimum
			$this->file_touch($docroot . '/.htaccess');
			$this->fortify($hostname, $path, 'max');
			//$this->file_set_acls(array($docroot . '/'), $users);
			if (!$version) {
				$version = $this->_getLatestVersion();
			}
			$params = array(
				'version'    => $version,
				'hostname'   => $hostname,
				'autoupdate' => (bool)$opts['autoupdate'],
				'fortify'    => 'max'
			);
			$this->_map('add', $docroot, $params);
			if (false === strpos($hostname, ".")) {
				$hostname = $hostname . '.' . $this->domain;
			}
			$url = 'http://' . $hostname . '/' . $path;
			$msg = "Hello!" . "\r\n" .
				"This is a confirmation that Joomla! has been installed under " . $docroot .
				". You may access Joomla! via " . $url . ". Access the administrative " .
				"panel at " . rtrim($url, "/") . '/administrator' . " using the following details:" . "\r\n\r\n" .
				"Username: " . $opts['user'] . "\r\n" .
				($autogenpw ? "Password: " . $opts['password'] . "\r\n" : '');
			$msg .= "\r\nWhen installing plugins or themes, be sure to place fortification mode " .
				"in \"Web App Write Mode\" in the control panel!" . "\r\n" .
				"See: http://kb.apisnetworks.com/control-panel/understanding-fortification/";
			$hdrs = "From: " . Crm_Module::FROM_NAME . " <" . Crm_Module::FROM_ADDRESS . ">\r\nReply-To: " . Crm_Module::REPLY_ADDRESS;
			Mail::send($opts['email'], "Joomla! Installed", $msg, $hdrs);
			info("Joomla! installed - confirmation email with login info sent to %s", $opts['email']);
			return true;
		}

		/**
		 * Get latest Joomla release
		 *
		 * @return string
		 */
		private function _getLatestVersion()
		{
			$versions = $this->_getVersions();
			if (!$versions) {
				return null;
			}
			return array_pop($versions);
		}

		/**
		 * Get all current major versions
		 *
		 * @return array
		 */
		private function _getVersions()
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
				return error("failed to fetch Joomla versions: %s", $proc['stderr']);
			}
			$versions = $matches[1];
			$cache->set($key, $versions, 43200);
			return $versions;
		}

		private function _exec($path = null, $cmd, array $args = array())
		{
			// client may override tz, propagate to bin
			$tz = date_default_timezone_get();
			$cli = 'php -d mysqli.default_socket=' . escapeshellarg(ini_get("mysqli.default_socket")) .
				' -d date.timezone=' . $tz . ' -d memory_limit=64m ' . self::JOOMLA_CLI;
			if (!is_array($args)) {
				$args = func_get_args();
				array_shift($args);
			}
			if ($path) {
				$cmd = '--www=%(path)s ' . $cmd;
				$args['path'] = $path;
			}
			$cmd = $cli . ' --no-interaction ' . $cmd;
			$ret = $this->pman_run($cmd, $args);
			if (!strncmp($ret['stdout'], "Error:", strlen("Error:"))) {
				// move stdout to stderr on error for consistency
				$ret['success'] = false;
				if (!$ret['stderr']) {
					$ret['stderr'] = $ret['stdout'];
				}
			} else if (!$ret['success'] && !$ret['stderr']) {
				$ret['stderr'] = $ret['stdout'];
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
			chmod($file, 644);
			$tz = 'UTC';
			//var_dump(date_default_timezone_get());
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
				/** @todo maybe authenticated SMTP? */
				'sendmail' => '/usr/sbin/sendmail'
			);
			// pure PHP code
			file_put_contents($file, serialize($opts));
			return substr($file, strlen($domainfsprefix));
		}

		/**
		 * Change Joomla admin credentials
		 *
		 * common fields include: username, password, name, email
		 *
		 * @param string $domain
		 * @param string $path
		 * @param array  $fields
		 * @return bool
		 */
		public function change_admin($domain, $path = null, array $fields)
		{
			$docroot = $this->_normalizePath($domain, $path);
			if (!$docroot) {
				return warn("failed to change administrator information");
			}
			$admin = $this->get_admin($domain, $path);

			if (!$admin) {
				return error("cannot determine admin of Joomla install");
			}
			$dbconfig = $this->db_config($domain, $path);
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
				return !is_null($f);
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
			$q = "UPDATE " . $dbconfig['prefix'] . "users SET " . join(", ", $builtQuery) . " WHERE username = ?";
			$stmt = $conn->prepare($q);
			$types = str_repeat("s", count($args));
			array_unshift($args, $types);
			call_user_func_array(array($stmt, 'bind_param'), $args);
			$rs = $stmt->execute();
			return $rs && $stmt->affected_rows > 0;
		}

		/**
		 * Get the primary admin for a Joomla instance
		 *
		 * @param      $domain
		 * @param null $path
		 * @return bool|string admin or false on failure
		 */
		public function get_admin($domain, $path = null)
		{
			$dbconfig = $this->db_config($domain, $path);
			$mysqli = $this->_connectDB($dbconfig);
			if (!$mysqli) {
				return error("cannot get admin user - failed to connect to database");
			}
			$q = "select id, username FROM " . $dbconfig['prefix'] . "users ORDER BY registerDate ASC limit 1";
			$rs = $mysqli->query($q);
			if (!$rs || $rs->num_rows < 1) {
				return warn("failed to enumerate Joomla administrative users");
			}
			return $rs->fetch_object()->username;

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
				return error("failed to determine Joomla");
			}

			$j = $this->_getConfiguration($docroot);
			return array(
				"user"     => $j['user'],
				"password" => $j['password'],
				"db"       => $j['db'],
				"prefix"   => $j['dbprefix'],
				"host"     => $j['host']
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
			$data = get_object_vars(unserialize($ret['stdout']));
			return $data;
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
		private function _saltedPassword($docroot, $password)
		{
			$salt = parent::_suggestPassword(32);
			$hash = md5($password . $salt);
			return $hash . ':' . $salt;
		}

		public function test()
		{
			$this->_setAdminUser('foobarbaz.com', '', 'debug', 'Panthers');
		}

		/**
		 * Install and activate plugin
		 *
		 * @param string $hostnaem domain or subdomain of wp install
		 * @param string $path     optional path component of wp install
		 * @param string $plugin   plugin name
		 * @param string $version  optional plugin version
		 * @return bool
		 */
		public function install_plugin($hostname, $path = '', $plugin, $version = 'stable')
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("invalid Joomla location");
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
		 * @param string $force  delete even if plugin activated
		 */
		public function uninstall_plugin($hostname, $path = '', $plugin, $force = false)
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("invalid Joomla location");
			}

			$args = array($plugin);
			$cmd = 'plugin uninstall %s';
			if ($force) {
				$cmd .= ' --deactivate';
			}
			$ret = $this->_exec($docroot, $cmd, $args);

			if (!$ret['stdout'] || !strncmp($ret['stdout'], "Warning:", strlen("Warning:"))) {
				return error("failed to uninstall plugin `%s': %s", $plugin, $ret['stderr']);
			}
			info("uninstalled plugin `%s'", $plugin);
			return true;
		}

		/**
		 * Recovery mode to disable all plugins
		 *
		 * @param string $hostname subdomain or domain of Joomla
		 * @param string $path     optional path
		 * @return bool
		 */
		public function disable_all_plugins($hostname, $path = '')
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("failed to determine path");
			}

			$ret = $this->_exec($docroot, 'plugin deactivate --all --skip-plugins');
			if (!$ret['success']) {
				return error("failed to deactivate all plugins: %s", $ret['stderr']);
			}
			return info("plugin deactivation successful: %s", $ret['stdout']);
		}

		/**
		 * Uninstall Joomla from a location
		 *
		 * @param        $hostname
		 * @param string $path
		 * @param bool   $delete "all", "db", or "files"
		 * @return bool
		 */
		public function uninstall($hostname, $path = '', $delete = 'all')
		{
			return parent::uninstall($hostname, $path, $delete);
		}

		/**
		 * Check if version is latest or get latest version
		 *
		 * @param null $version
		 * @return int|string
		 */
		public function is_current($version = null)
		{
			$latest = $this->_getLatestVersion();;
			if (!$version) {
				return $version;
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
		 * Get all available releases
		 *
		 * @return array
		 */
		public function versions()
		{
			return $this->_getVersions();
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
			$fsroot = $this->domain_fs_path();
			$path = $fsroot . $docroot;
			$versigs = array(
				'/libraries/cms/version/version.php', // 3.x, 2.5.x,
				'/libraries/joomla/version.php',      // 1.7.x allegedly
				'/includes/version.php'               // what I found in 1.7.5

			);
			$version = null;
			if (!defined('JPATH_PLATFORM')) {
				define('JPATH_PLATFORM', 'goddamn sanity checks');
			}
			if (!defined('_JEXEC')) {
				define('_JEXEC', 'this is also a PITA');
			}
			foreach ($versigs as $sig) {
				$mypath = $path . $sig;
				if (!file_exists($mypath)) {
					continue;
				}
				include_once($mypath);
				if (!class_exists('JVersion')) {
					break;
				}
				$jversion = new JVersion();
				if (!method_exists($jversion, 'getShortVersion')) {
					break;
				}
				$version = $jversion->getShortVersion();
				break;
			}
			if (is_null($version)) {
				return error("cannot determine Joomla! version - incomplete install?");
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

			return $this->file_file_exists($docroot . '/libraries/joomla');
		}

		/**
		 * Update core, plugins, and themes atomically
		 *
		 * @param string $hostname subdomain or domain
		 * @param string $path     optional path under hostname
		 * @return bool
		 */
		public function update_all($hostname, $path = '')
		{
			return $this->update($hostname, $path);
			/*&& $this->update_plugins($hostname, $path) &&
			$this->update_themes($hostname, $path) || error("failed to update all components");*/
		}

		/**
		 * Update Joomla! to latest version
		 *
		 * @param string $domain domain or subdomain under which Joomla is installed
		 * @param string $path   optional subdirectory
		 * @param string $version
		 * @return bool
		 */
		public function update($domain, $path = '', $version = null)
		{
			if (!IS_CLI) {
				return $this->query('joomla_update', $domain, $path, $version);
			}
			$docroot = $this->_normalizePath($domain, $path);
			if (!$docroot) {
				return error("update failed");
			}

			if ($version) {
				if (!is_scalar($version) || strcspn($version, ".0123456789")) {
					return error("invalid version number, %s", $version);
				} else if (!in_array($version, $this->versions())) {
					return error("unknown version `%s'", $version);
				}
			} else {
				$version = $this->_getLatestVersion();
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
				return error("failed to update Joomla! - download failed");
			}
			if ($user !== $this->username) {
				$this->file_chown($docroot, $user, true);
			}

			$this->fortify($domain, $path);
			info("Joomla updated, fortification set to MAX");

			// as a prereq, joomlaupdate component must be updated as well
			// PHP runs jailed, may not have cache plugin installed, disable it
			$cfgfile = $docroot . '/configuration.php';
			$config = $this->file_get_file_contents($cfgfile);
			$newconfig = preg_replace('/public\s+\$cache_handler\s*=[^;]+;/', '', $config);
			$this->file_put_file_contents($cfgfile, $newconfig);
			if (!$this->_updateJoomlaUpdatePlugin($docroot, $user, $version)) {
				warn("Upgrade incomplete - failed to fetch Joomla! Update extension. Login to admin portal to finish.");
			}
			$this->file_put_file_contents($cfgfile, $config, true);
			return info("Upgrade partially completed. Login to Joomla! admin portal to finish upgrade.");
		}

		private function _updateJoomlaUpdatePlugin($docroot, $user, $version) {
			$juext = $this->get_plugin_info('com_joomlaupdate');
			if (!$juext) {
				return false;
			}

			if (version_compare($version, $juext['update']['targetplatform']['@attributes']['version'], "<")) {
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

		public function get_plugin_info($plugin, $ver = null) {
			$replace = array(
				'plugin' => $plugin,
				'ver' => $ver
			);
			// @todo determine plugin versioning
			$uri = preg_replace_callback(Regex::LAZY_SUB, function ($m) use ($replace) {
				return $replace[$m[1]];
			}, 'http://update.joomla.org/core/extensions/%plugin%.xml?ver=%ver%');
			$content = silence(function() use ($uri) {
				return simplexml_load_file($uri, "SimpleXMLElement", LIBXML_NOCDATA);
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
		 * Update Joomla! themes
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
			parent::fortify($hostname, $path, $mode);
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

		/**
		 * Install wp-cli if necessary
		 *
		 * @return bool
		 */
		public function _housekeeping()
		{
			$file = parent::_getWebappExtraStorageDirectory() . '/joomlatools-' .
				self::JOOMLA_CLI_VERSION . '.phar';

			if (!file_exists(self::JOOMLA_CLI) || sha1_file($file) !== sha1_file(self::JOOMLA_CLI)) {
				copy($file, self::JOOMLA_CLI);
				info("copied latest (v%s) JoomlaTools to PEAR", self::JOOMLA_CLI_VERSION);
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
		protected function getInternalName()
		{
			return "joomla";
		}
	}