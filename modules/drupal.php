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
	 * Drupal drush interface
	 *
	 * @package core
	 */
	class Drupal_Module extends Module_Support_Webapps
	{
		const APP_NAME = "Drupal";

		// primary domain document root
		const DRUPAL_CLI = '/usr/share/pear/drupal.phar';

		// latest release
		const DRUPAL_CLI_URL = 'https://github.com/drush-ops/drush/releases/download/8.1.2/drush.phar';

		const VERSION_CHECK_URL = 'https://updates.drupal.org/release-history';

		protected $_aclList = array(
			'min' => array('/sites/*/files')
		);

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
		 * Install WordPress into a pre-existing location
		 *
		 * @param string $hostname domain or subdomain to install WordPress
		 * @param string $path     optional path under hostname
		 * @param array  $opts     additional install options
		 */
		public function install($hostname, $path = '', array $opts = array())
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("failed to install Drupal");
			}

			if (!parent::checkDocroot($docroot)) {
				return false;
			}

			// can't fetch translation file from ftp??
			// don't worry about it for now
			if (!isset($opts['locale'])) {
				$opts['locale'] = 'us';
			}
			if (!isset($opts['autoupdate'])) {
				$opts['autoupdate'] = true;
			}

			if (!isset($opts['dist'])) {
				$opts['profile'] = 'standard';
				$opts['dist'] = 'drupal';
				if (isset($opts['version'])) {
					if (strcspn($opts['version'], ".0123456789x")) {
						return error("invalid version number, %s", $opts['version']);
					}
					$opts['dist'] .= '-' . $opts['version'];
				} else if ($this->sql_mysql_version() < 50503) {
					info("older hosting platform, capping Drupal to 7.x, 8.x requires MySQL 5.5");
					$opts['dist'] = 'drupal-7';
				}

			} else if (!isset($opts['profile'])) {
				$opts['profile'] = $opts['dist'];
			}

			$cmd = 'dl %(dist)s';

			$tmpdir = '/tmp/drupal' . crc32(mt_rand(0, 8192));
			$args = array(
				'tempdir' => $tmpdir,
				'path'    => $docroot,
				'dist'    => $opts['dist']
			);
			/**
			 * drupal expects destination dir to exist
			 * move /tmp/<RANDOM NAME>/drupal to <DOCROOT> instead
			 * of downloading to <DOCROOT>/drupal and moving everything down 1
			 */
			$this->file_create_directory($tmpdir);
			$ret = $this->_exec('/tmp', $cmd . ' --drupal-project-rename --destination=%(tempdir)s -q', $args);

			if (!$ret['success']) {
				return error("failed to download Drupal - out of space?");
			}
			if ($this->file_file_exists($docroot)) {
				$this->file_delete($docroot, true);
			}
			$this->file_purge();
			$ret = $this->file_rename($tmpdir . '/drupal', $docroot);
			$this->file_delete($tmpdir, true);
			if (!$ret) {
				return error("failed to move Drupal install to `%s'", $docroot);
			}

			if (isset($opts['email']) && !preg_match(Regex::EMAIL, $opts['email'])) {
				return error("invalid email address `%s' specified", $opts['email']);
			} else {
				$opts['email'] = $this->get_config('siteinfo', 'email');
			}

			if (isset($opts['site-email']) && !preg_match(Regex::EMAIL, $opts['site-email'])) {
				return error("invalid site email `%s' provided", $opts['site-email']);
			} else if (!isset($opts['site-email'])) {
				// default to active domain, hope it's valid!
				if (false === strpos($hostname, ".")) {
					$hostname .= '.' . $this->domain;
				}
				$split = $this->web_split_host($hostname);
				if (!$this->email_address_exists('postmaster', $split['domain'])) {
					if (!$this->email_transport_exists($split['domain'])) {
						warn("email is not configured for domain `%s', messages sent from installation may " .
							"be unrespondable", $split['domain']);
					} else if ($this->email_add_alias('postmaster', $split['domain'], $opts['email'])) {
						info("created `postmaster@%s' address for Drupal mailings that " .
							"will forward to `%s'", $split['domain'], $opts['email']);
					} else {
						warn("failed to create Drupal postmaster address `postmaster@%s', messages " .
							"sent from installation may be unrespondable", $split['domain']);
					}
				}
				$opts['site-email'] = 'postmaster@' . $split['domain'];
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

			$dburi = 'mysqli://' . $credentials['user'] . ':' .
				$credentials['password'] . '@localhost/' . $credentials['db'];

			if (!isset($opts['title'])) {
				$opts['title'] = "A Random Drupal Install";
			}
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
			$xtra = array(
				"install_configure_form.update_status_module='array(FALSE,FALSE)'"
			);
			// drush reqs name if dist not drupal otherwise
			// getPath() on null error

			if ($opts['dist'] === 'drupal') {
				$fmtstr = '';
				$dist = '';
			} else {
				$fmtstr = '%(dist)s ';
				$dist = $opts['dist'];
			}
			$args = array(
				'dist'         => $dist,
				'profile'      => $opts['profile'],
				'dburi'        => $dburi,
				'account-name' => $opts['user'],
				'account-pass' => $opts['password'],
				'account-mail' => $opts['email'],
				'locale'       => $opts['locale'],
				'site-mail'    => $opts['site-email'],
				'title'        => $opts['title'],
				'xtraopts'     => join(" ", $xtra)
			);

			$ret = $this->_exec($docroot, 'site-install %(profile)s -q --db-url=%(dburi)s --account-name=%(account-name)s ' .
				'--account-pass=%(account-pass)s --account-mail=%(account-mail)s ' .
				'site-mail=%(site-mail)s --site-name=%(title)s %(xtraopts)s', $args);

			if (!$ret['success']) {
				info("removing temporary files");
				$this->file_delete($docroot, true);
				$this->sql_delete_mysql_database($db);
				$this->sql_delete_mysql_user($dbuser, 'localhost');
				return error("failed to install Drupal: %s", $ret['stderr']);
			}
			// by default, let's only open up ACLs to the bare minimum

			$files = array_map(function ($f) use ($docroot) {
				return $docroot . '/' . ltrim($f, "/");
			}, $this->_aclList['min']);
			$this->file_touch($docroot . '/.htaccess');
			$users = array(
				array(Web_Module::WEB_USERNAME => 7),
				array($this->username => 'drwx'),
				array(Web_Module::WEB_USERNAME => 'drwx'),
			);
			if (!$this->file_set_acls($files, $users, array(File_Module::ACL_MODE_RECURSIVE => true))) {
				warn("failed to set ACLs on `%s/sites/'", $docroot);
			}

			// confirm version
			$opts['version'] = $this->get_version($hostname, $path);
			$params = array(
				'version'    => $opts['version'],
				'hostname'   => $hostname,
				'autoupdate' => (bool)$opts['autoupdate'],
				'fortify'    => 'min'
			);
			$this->_map('add', $docroot, $params);
			if (false === strpos($hostname, ".")) {
				$hostname = $hostname . '.' . $this->domain;
			}
			/**
			 * Make sure RewriteBase is present, move to Module_Support_Webapps?
			 */
			parent::fixRewriteBase($docroot, $path);

			$this->_postInstallTrustedHost($dist, $hostname, $docroot);
			$url = 'http://' . $hostname . '/' . $path;
			$msg = "Hello!" . "\r\n" .
				"This is a confirmation that Drupal has been installed under " . $docroot .
				". You may access Drupal via " . $url . ". Access the administrative " .
				"panel at " . rtrim($url, "/") . '/user' . " using the following details:" . "\r\n\r\n" .
				"Username: " . $opts['user'] . "\r\n" .
				($autogenpw ? "Password: " . $opts['password'] . "\r\n" : '');
			$msg .= "\r\nWhen installing plugins or themes, you will need to use your " .
				"control panel password!";
			$hdrs = "From: " . Crm_Module::FROM_NAME . " <" . Crm_Module::FROM_ADDRESS . ">\r\nReply-To: " . Crm_Module::REPLY_ADDRESS;
			Mail::send($opts['email'], "Drupal Installed", $msg, $hdrs);
			info("Drupal installed - confirmation email with login info sent to %s", $opts['email']);
			return true;
		}

		private function _exec($path = null, $cmd, array $args = array())
		{
			// client may override tz, propagate to bin
			$tz = date_default_timezone_get();
			$cli = 'php -d pdo_mysql.default_socket=' . escapeshellarg(ini_get("mysqli.default_socket")) .
				' -d date.timezone=' . $tz . ' -d memory_limit=64m ' . self::DRUPAL_CLI . ' -y';
			if (!is_array($args)) {
				$args = func_get_args();
				array_shift($args);
			}
			if ($path) {
				$cli = 'cd %(path)s && ' . $cli;
				$args['path'] = $path;
			}
			$cmd = $cli . ' ' . $cmd;
			$ret = $this->pman_run($cmd, $args);
			if (!strncmp($ret['stdout'], "Error:", strlen("Error:"))) {
				// move stdout to stderr on error for consistency
				$ret['success'] = false;
				if (!$ret['stderr']) {
					$ret['stderr'] = $ret['stdout'];
				}

			}
			return $ret;
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
			return $this->_getVersion($docroot);
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

			return $this->file_file_exists($docroot . '/sites/default')
			|| $this->file_file_exists($docroot . '/sites/all');
		}

		/**
		 * Get version using exact docroot
		 *
		 * @param $docroot
		 * @return string
		 */
		private function _getVersion($docroot)
		{
			static $metaCache;
			if (!isset($metaCache)) {
				$metaCache = array();
			}
			$ret = $this->_exec($docroot, 'status --format=json');
			if (!$ret['success']) {
				return null;
			}

			$output = json_decode($ret['stdout'], true);
			return $output['drupal-version'];
		}

		/**
		 * Add trusted_host_patterns if necessary
		 *
		 * @param $version
		 * @param $hostname
		 * @param $docroot
		 * @return bool|void
		 */
		private function _postInstallTrustedHost($version, $hostname, $docroot)
		{
			if (version_compare($version, '8.0', '<')) {
				return true;
			}
			$file = $docroot . '/sites/default/settings.php';
			$content = $this->file_get_file_contents($file);
			if (!$content) {
				return error("unable to add trusted_host_patterns configuration - cannot get " .
					"Drupal configuration for `%s'", $hostname);
			}
			$content .= "\n\n" .
				'/** in the event the domain name changes, trust site configuration */' . "\n" .
				'$settings["trusted_host_patterns"] = array(' . "\n" .
				"\t" . "'^(www\.)?' . " . 'str_replace(".", "\\\\.", $_SERVER["DOMAIN"]) . ' . "'$'" . "\n" .
				");" . "\n";
			return $this->file_put_file_contents($file, $content, true, true);
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
		public function install_plugin($hostname, $path = '', $plugin, $version = '')
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("invalid Drupal location");
			}
			$dlplugin = $plugin;
			if ($version) {
				if (false === strpos($version, '-')) {
					// Drupal seems to like <major>-x naming conventions
					$version .= '-x';
				}
				$dlplugin .= '-' . $version;
			}
			$args = array($plugin);
			$ret = $this->_exec($docroot, 'pm-download -y %s', $args);
			if (!$ret['success']) {
				return error("failed to install plugin `%s': %s", $plugin, $ret['stderr']);
			}

			if (!$this->enable_plugin($hostname, $path, $plugin)) {
				return warn("downloaded plugin `%s' but failed to activate: %s", $plugin, $ret['stderr']);
			}
			info("installed plugin `%s'", $plugin);
			return true;
		}

		public function enable_plugin($hostname, $path = '', $plugin)
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("invalid Drupal location");
			}
			$ret = $this->_exec($docroot, 'pm-enable -y %s', array($plugin));
			if (!$ret) {
				return error("failed to enable plugin `%s': %s", $plugin, $ret['stderr']);
			}
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
				return error("invalid Drupal location");
			}

			$args = array($plugin);

			if ($this->plugin_active($hostname, $path, $plugin)) {
				if (!$force) {
					return error("plugin `%s' is active, disable first");
				}
				$this->disable_plugin($hostname, $path, $plugin);
			}

			$cmd = 'pm-uninstall %s';

			$ret = $this->_exec($docroot, $cmd, $args);

			if (!$ret['stdout'] || !strncmp($ret['stdout'], "Warning:", strlen("Warning:"))) {
				return error("failed to uninstall plugin `%s': %s", $plugin, $ret['stderr']);
			}
			info("uninstalled plugin `%s'", $plugin);
			return true;
		}

		public function plugin_active($hostname, $path = '', $plugin)
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("invalid Drupal location");
			}
			$plugin = $this->get_plugin_info($hostname, $path, $plugin);
			return $plugin['status'] === "enabled";
		}

		public function get_plugin_info($hostname, $path = '', $plugin)
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("invalid Drupal location");
			}
			$cmd = 'pm-info --format=json %s';
			$ret = $this->_exec($docroot, $cmd, array($plugin));
			if (!$ret['success']) {
				return null;
			}
			$tmp = json_decode($ret['stdout'], true);
			return array_pop($tmp);
		}

		public function disable_plugin($hostname, $path = '', $plugin)
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("invalid Drupal location");
			}
			$ret = $this->_exec($docroot, 'pm-disable -y %s', array($plugin));
			if (!$ret) {
				return error("failed to disable plugin `%s': %s", $plugin, $ret['stderr']);
			}
			info("disabled plugin `%s'", $plugin);
			return true;
		}

		/**
		 * Recovery mode to disable all plugins
		 *
		 * @param string $hostname subdomain or domain of WP
		 * @param string $path     optional path
		 * @return bool
		 */
		public function disable_all_plugins($hostname, $path = '')
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("failed to determine path");
			}
			$plugins = array();
			foreach ($this->list_all_plugins($hostname, $path) as $plugin => $info) {
				if (strtolower($info['status']) != "enabled") {
					continue;
				}
				$this->disable_plugin($hostname, $path, $plugin);
				$plugins[] = $info['name'];

			}
			if ($plugins) {
				return $plugins;
			}
			return true;
		}

		public function list_all_plugins($hostname, $path = '', $status = '')
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("invalid Drupal location");
			}
			if ($status) {
				$status = strtolower($status);
				$status = '--status=' . $status;
			}
			$ret = $this->_exec($docroot, 'pm-list --format=json --no-core %s', array($status));
			if (!$ret['success']) {
				return error("failed to enumerate plugins: %s", $ret['stderr']);
			}
			return json_decode($ret['stdout'], true);
		}

		/**
		 * Uninstall Drupal from a location
		 *
		 * @param        $hostname
		 * @param string $path
		 * @param bool   $deletefiles remove all files under docroot
		 * @return bool
		 */
		public function uninstall($hostname, $path = '', $delete = 'all')
		{
			return parent::uninstall($hostname, $path, $delete);
		}

		/**
		 * Get database configuration for a blog
		 *
		 * @param string $hostname domain or subdomain of Drupal
		 * @param string $path     optional path
		 * @return array
		 */
		public function db_config($hostname, $path = '')
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("failed to determine Drupal");
			}
			$code = 'include("./sites/default/settings.php"); $conf = $databases["default"]["default"]; print serialize(array("user" => $conf["username"], "password" => $conf["password"], "db" => $conf["database"], "prefix" => $conf["prefix"], "host" => $conf["host"]));';
			$cmd = 'cd %(path)s && php -r %(code)s';
			$ret = $this->pman_run($cmd, array('path' => $docroot, 'code' => $code));

			if (!$ret['success']) {
				return error("failed to obtain Drupal configuration for `%s'", $docroot);
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
			$vermask = substr($version, 0, strpos($version, '.'));
			$latest = $this->_getLastestVersion($vermask);
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
		 * Get latest Drupal release
		 *
		 * @return string
		 */
		private function _getLastestVersion($version = '7.x')
		{
			$version = $this->_extractBranch($version);
			$versions = $this->_getVersions('drupal', $version);
			if (!$versions) {
				return null;
			}
			$releases = $versions['releases']['release'];
			for ($i = 0, $n = count($releases); $i > $n; $i++) {
				// dev, alpha, etc
				if (!isset($releases[$i]['version_extra'])) {
					return $releases[$i]['version'];
				}
			}
			// can't find a suitable release, return the first one
			return $releases[0]['version'];
		}

		private function _extractBranch($version)
		{
			if (substr($version, -2) == ".x") {
				return $version;
			}
			$pos = strpos($version, ".");
			if (false === $pos) {
				// sent major alone
				return $version . '.x';
			}
			$newver = substr($version, 0, $pos);
			return $newver . '.x';
		}

		/**
		 * Get all current major versions
		 *
		 * @return array
		 */
		private function _getVersions($module = 'drupal', $version = '7.x')
		{
			$version = $this->_extractBranch($version);
			$key = 'drupal.versions:' . $module;

			$cache = Cache_Super_Global::spawn();
			if (false !== ($ver = $cache->get($key)) && isset($ver[$version])) {
				return $ver[$version];
			}
			$url = self::VERSION_CHECK_URL;
			$url .= '/' . $module . '/' . $version;
			$contents = file_get_contents($url);

			if (!$contents) {
				return array();
			}
			if (!is_array($ver)) {
				$ver = array();
			}

			$versions = json_decode(json_encode(simplexml_load_string($contents)), true);
			$ver[$version] = $versions;
			$cache->set($key, $versions, 43200);
			return $versions;
		}

		public function test()
		{
			return $this->_getLastestVersion('8.x');
		}

		/**
		 * Change WP admin credentials
		 *
		 * $fields is a hash whose indices match password
		 *
		 * @param string $hostname
		 * @param string $path
		 * @param array  $fields password only field supported for now
		 * @return bool
		 */
		public function change_admin($hostname, $path = null, array $fields)
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return warn("failed to change administrator information");
			}
			$admin = $this->get_admin($hostname, $path);

			if (!$admin) {
				return error("cannot determine admin of Drupal install");
			}

			$args = array(
				'user' => $admin
			);

			if (isset($fields['password'])) {
				$args['password'] = $fields['password'];
				$ret = $this->_exec($docroot, 'user-password --password=%(password)s %(user)s', $args);
				if (!$ret['success']) {
					return error("failed to update password for user `%s': %s", $admin, $ret['stderr']);
				}
			}
			return true;
		}

		/**
		 * Get the primary admin for a Drupal instance
		 *
		 * @param      $domain
		 * @param null $path
		 * @return bool|string admin or false on failure
		 */
		public function get_admin($domain, $path = null)
		{
			$docroot = $this->_normalizePath($domain, $path);
			$ret = $this->_exec($docroot, 'user-information 1 --format=json');
			if (!$ret['success']) {
				return warn("failed to enumerate Drupal administrative users");
			}
			$tmp = json_decode($ret['stdout'], true);
			if (!$tmp) {
				return false;
			}
			$tmp = array_pop($tmp);
			return $tmp['name'];
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
			return $this->update($hostname, $path) && $this->update_plugins($hostname, $path)
			|| error("failed to update all components");
		}

		/**
		 * Update Drupal to latest version
		 *
		 * @param string $hostname domain or subdomain under which WP is installed
		 * @param string $path     optional subdirectory
		 * @param string $version
		 * @return bool
		 */
		public function update($hostname, $path = '', $version = null)
		{
			$docroot = $this->_normalizePath($hostname, $path);
			if (!$docroot) {
				return error("update failed");
			}

			if ($version) {
				if (!is_scalar($version) || strcspn($version, ".0123456789x-")) {
					return error("invalid version number, %s", $version);
				}
			} else {
				$current = $this->_extractBranch($this->get_version($hostname, $path));
				$version = $this->_getLastestVersion($current);
			}

			// save .htaccess
			$htaccess = $docroot . DIRECTORY_SEPARATOR . '.htaccess';
			if ($this->file_file_exists($htaccess) && !$this->file_move($htaccess, $htaccess . '.bak', true)) {
				return error("upgrade failure: failed to save copy of original .htaccess");
			}
			$this->file_purge();
			$cmd = 'pm-update drupal-%(version)s';
			$args = array('version' => $version);

			$this->_setMaintenance($docroot, true, $current);
			$ret = $this->_exec($docroot, $cmd, $args);
			$this->file_purge();
			$this->_setMaintenance($docroot, false, $current);

			if ($this->file_file_exists($htaccess . '.bak') && !$this->file_move($htaccess . '.bak', $htaccess, true)
				&& ( $this->file_purge() || true ) )
			{
				warn("failed to rename backup `%s/.htaccess.bak' to .htaccess", $docroot);
			}

			if (!$ret['success']) {
				return warn("failed to update Drupal - " .
					"login to Drupal admin panel to manually perform operation");
			}

			return $ret['success'];
		}

		/**
		 * Set Drupal maintenance mode before/after update
		 *
		 * @param $docroot
		 * @param $mode
		 */
		private function _setMaintenance($docroot, $mode, $version = null)
		{
			if (is_null($version)) {
				$version = $this->_getVersion($docroot);
			}
			if ($version[0] >= 8) {
				$maintenancecmd = 'sset system.maintenance_mode %(mode)d';
				$cachecmd = 'cr';
			} else {
				$maintenancecmd = 'vset --exact maintenance_mode %(mode)d';
				$cachecmd = 'cache-clear all';
			}

			$ret = $this->_exec($docroot, $maintenancecmd, array('mode' => intval($mode)));
			if (!$ret['success']) {
				warn("failed to set maintenance mode");
			}
			$ret = $this->_exec($docroot, $cachecmd);
			if (!$ret['success']) {
				warn("failed to rebuild cache");
			}

			return true;
		}

		/**
		 * Update Drupal plugins and themes
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
			$cmd = 'pm-update --check-disabled --no-core';

			$args = array();
			if ($plugins) {
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
					$args[$name] = $plugin . ($version ? '-' . $version : '');
				}
			}

			$ret = $this->_exec($docroot, $cmd, $args);
			if (!$ret['success']) {
				return error("plugin update failed: `%s'", $ret['stderr']);
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

		public function _housekeeping()
		{
			if (!file_exists(self::DRUPAL_CLI)) {
				$url = self::DRUPAL_CLI_URL;
				$res = Util_HTTP::download($url, self::DRUPAL_CLI);
				if (!$res) {
					return error("failed to install Drupal CLI");
				}
				info("downloaded Drupal CLI");
				chmod(self::DRUPAL_CLI, 0755);
			}

			$local = $this->service_template_path('siteinfo') . '/' . self::DRUPAL_CLI;
			if (!file_exists($local)) {
				copy(self::DRUPAL_CLI, $local);
				chmod($local, 755);
			}
			return true;
		}

		private function _getCommand()
		{
			return 'php ' . self::DRUPAL_CLI;
		}
	}