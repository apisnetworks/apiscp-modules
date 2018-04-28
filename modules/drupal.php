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
	 * Drupal drush interface
	 *
	 * @package core
	 */
	class Drupal_Module extends \Module\Support\Webapps
	{
		const APP_NAME = 'Drupal';

		// primary domain document root
		const DRUPAL_CLI = '/usr/share/pear/drupal.phar';
		const DEFAULT_BRANCH = '8.x';
		const DRUPAL_MAJORS = ['6.x', '7.x', '8.x'];
		// latest release
		const DRUPAL_CLI_URL = 'https://github.com/drush-ops/drush/releases/download/8.1.16/drush.phar';
		const VERSION_CHECK_URL = 'https://updates.drupal.org/release-history';
		const DEFAULT_VERSION_LOCK = 'major';

		protected $_aclList = array(
			'max' => array('/sites/*/files')
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

		/**
		 * Install WordPress into a pre-existing location
		 *
		 * @param string $hostname domain or subdomain to install WordPress
		 * @param string $path     optional path under hostname
		 * @param array  $opts     additional install options
		 * @return bool
		 */
		public function install(string $hostname, string $path = '', array $opts = array()): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('failed to install Drupal');
			}

			if (!parent::checkDocroot($docroot)) {
				return false;
			}

			if (!empty($opts['ssl']) && !parent::configureSsl($hostname)) {
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

			$squash = array_get($opts, 'squash', false);
			if ($squash && $this->permission_level & PRIVILEGE_USER) {
				warn('must squash privileges as secondary user');
				$squash = true;
			}
			$opts['squash'] = $squash;

			if (!isset($opts['dist'])) {
				$opts['profile'] = 'standard';
				$opts['dist'] = 'drupal';
				if (isset($opts['version'])) {
					if (strcspn($opts['version'], '.0123456789x')) {
						return error('invalid version number, %s', $opts['version']);
					}
					$opts['dist'] .= '-' . $opts['version'];
				} else {
					if ($this->sql_mysql_version() < 50503) {
						info('older hosting platform, capping Drupal to 7.x, 8.x requires MySQL 5.5');
						$opts['dist'] = 'drupal-7';
					}
				}

			} else {
				if (!isset($opts['profile'])) {
					$opts['profile'] = $opts['dist'];
				}
			}

			$cmd = 'dl %(dist)s';

			$tmpdir = '/tmp/drupal' . crc32((string)\Util_PHP::random_int());
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
				return error('failed to download Drupal - out of space? Error: `%s\'',
					coalesce($ret['stderr'], $ret['stdout'])
				);
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
			// ensure the docroot is owned by the target uid to permit installation
			// correct it at the end
			if (!$squash) {
				$this->file_chown($docroot, $this->user_id);
			}

			if (isset($opts['email']) && !preg_match(Regex::EMAIL, $opts['email'])) {
				return error("invalid email address `%s' specified", $opts['email']);
			}
			$opts['email'] = $this->get_config('siteinfo', 'email');


			if (isset($opts['site-email']) && !preg_match(Regex::EMAIL, $opts['site-email'])) {
				return error("invalid site email `%s' provided", $opts['site-email']);
			}

			if (!isset($opts['site-email'])) {
				// default to active domain, hope it's valid!
				if (false === strpos($hostname, '.')) {
					$hostname .= '.' . $this->domain;
				}
				$split = $this->web_split_host($hostname);
				if (!$this->email_address_exists('postmaster', $split['domain'])) {
					if (!$this->email_transport_exists($split['domain'])) {
						warn("email is not configured for domain `%s', messages sent from installation may " .
							'be unrespondable', $split['domain']);
					} else {
						if ($this->email_add_alias('postmaster', $split['domain'], $opts['email'])) {
							info("created `postmaster@%s' address for Drupal mailings that " .
								"will forward to `%s'", $split['domain'], $opts['email']);
						} else {
							warn("failed to create Drupal postmaster address `postmaster@%s', messages " .
								'sent from installation may be unrespondable', $split['domain']);
						}
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
			$dbpass = $this->suggestPassword();
			$credentials = array(
				'db'       => $db,
				'user'     => $dbuser,
				'password' => $dbpass,
			);

			if (!parent::setupDatabase($credentials)) {
				return false;
			}

			$dburi = 'mysqli://' . $credentials['user'] . ':' .
				$credentials['password'] . '@localhost/' . $credentials['db'];

			if (!isset($opts['title'])) {
				$opts['title'] = 'A Random Drupal Install';
			}
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
				'xtraopts'     => implode(' ', $xtra)
			);

			$ret = $this->_exec($docroot,
				'site-install %(profile)s -q --db-url=%(dburi)s --account-name=%(account-name)s ' .
				'--account-pass=%(account-pass)s --account-mail=%(account-mail)s ' .
				'site-mail=%(site-mail)s --site-name=%(title)s %(xtraopts)s', $args);

			if (!$ret['success']) {
				info('removing temporary files');
				$this->file_delete($docroot, true);
				$this->sql_delete_mysql_database($db);
				$this->sql_delete_mysql_user($dbuser, 'localhost');
				return error('failed to install Drupal: %s', $ret['stderr']);
			}
			// by default, let's only open up ACLs to the bare minimum

			$files = array_map(function ($f) use ($docroot) {
				return $docroot . '/' . ltrim($f, '/');
			}, $this->_aclList['max']);
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
				'path'       => $path,
				'autoupdate' => (bool)$opts['autoupdate'],
				'options'    => $opts
			);
			$this->_map('add', $docroot, $params);
			parent::fortify($hostname, $path, 'max');
			$fqdn = $this->web_normalize_hostname($hostname);
			/**
			 * Make sure RewriteBase is present, move to Webapps?
			 */
			parent::fixRewriteBase($docroot, $path);

			$this->_postInstallTrustedHost($dist, $hostname, $docroot);
			if (!empty($opts['ssl'])) {
				// @todo force redirect to HTTPS
			}
			if (array_get($opts, 'notify', true)) {
				\Lararia\Bootstrapper::minstrap();
				\Illuminate\Support\Facades\Mail::to($opts['email'])->
				send((new \Module\Support\Webapps\Mailer('install.drupal', [
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
			return info('Drupal installed - confirmation email with login info sent to %s', $opts['email']);
		}

		/**
		 * Get installed version
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return null|string version number
		 */
		public function get_version(string $hostname, string $path = ''): ?string
		{

			if (!$this->valid($hostname, $path)) {
				return null;
			}
			$docroot = $this->getDocumentRoot($hostname, $path);
			return $this->_getVersion($docroot);
		}

		/**
		 * Location is a valid WP install
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

			return $this->file_file_exists($docroot . '/sites/default')
				|| $this->file_file_exists($docroot . '/sites/all');
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
		public function install_plugin(string $hostname, string $path = '', string $plugin, string $version = ''): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('invalid Drupal location');
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
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('invalid Drupal location');
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
		 * @param string      $hostname
		 * @param string      $path
		 * @param string      $plugin plugin name
		 * @param bool|string $force  delete even if plugin activated
		 * @return bool
		 */
		public function uninstall_plugin(string $hostname, string $path = '', string $plugin, bool $force = false): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('invalid Drupal location');
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

			if (!$ret['stdout'] || !strncmp($ret['stdout'], 'Warning:', strlen('Warning:'))) {
				return error("failed to uninstall plugin `%s': %s", $plugin, $ret['stderr']);
			}
			info("uninstalled plugin `%s'", $plugin);
			return true;
		}

		public function plugin_active($hostname, $path = '', $plugin)
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('invalid Drupal location');
			}
			$plugin = $this->plugin_status($hostname, $path, $plugin);
			return $plugin['status'] === 'enabled';
		}

		public function plugin_status(string $hostname, string $path = '', string $plugin = null): ?array
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('invalid Drupal location');
			}
			$cmd = 'pm-info --format=json %(plugin)s';
			$ret = $this->_exec($docroot, $cmd, ['plugin' => $plugin]);
			if (!$ret['success']) {
				return null;
			}
			$plugins = [];
			foreach(json_decode($ret['stdout'], true) as $name => $meta) {
				$plugins[$name] = [
					'version' => $meta['version'],
					'next' => null,
					'current' => true,
					'max' => $meta['version']
				];
			}

			return $plugin ? $array_pop($plugins) : $plugins;
		}

		public function disable_plugin($hostname, $path = '', $plugin)
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('invalid Drupal location');
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
		public function disable_all_plugins(string $hostname, string $path = ''): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('failed to determine path');
			}
			$plugins = array();
			$installed = $this->list_all_plugins($hostname, $path);
			if (!$installed) {
				return true;
			}
			foreach ($installed as $plugin => $info) {
				if (strtolower($info['status']) !== 'enabled') {
					continue;
				}
				$this->disable_plugin($hostname, $path, $plugin);
				$plugins[] = $info['name'];

			}
			if ($plugins) {
				info("disabled plugins: `%s'", implode(',', $plugins));
			}
			return true;
		}

		public function list_all_plugins($hostname, $path = '', $status = '')
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('invalid Drupal location');
			}
			if ($status) {
				$status = strtolower($status);
				$status = '--status=' . $status;
			}
			$ret = $this->_exec($docroot, 'pm-list --format=json --no-core %s', array($status));
			if (!$ret['success']) {
				return error('failed to enumerate plugins: %s', $ret['stderr']);
			}
			return json_decode($ret['stdout'], true);
		}

		/**
		 * Uninstall Drupal from a location
		 *
		 * @param string $hostname
		 * @param string $path
		 * @param string $delete
		 * @return bool
		 * @internal param string $deletefiles remove all files under docroot
		 */
		public function uninstall(string $hostname, string $path = '', string $delete = 'all'): bool
		{
			return parent::uninstall($hostname, $path, $delete);
		}

		/**
		 * Get database configuration for a blog
		 *
		 * @param string $hostname domain or subdomain of Drupal
		 * @param string $path     optional path
		 * @return array|bool
		 */
		public function db_config(string $hostname, string $path = '')
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('failed to determine Drupal');
			}
			$code = 'include("./sites/default/settings.php"); $conf = $databases["default"]["default"]; print serialize(array("user" => $conf["username"], "password" => $conf["password"], "db" => $conf["database"], "prefix" => $conf["prefix"], "host" => $conf["host"]));';
			$cmd = 'cd %(path)s && php -r %(code)s';
			$ret = $this->pman_run($cmd, array('path' => $docroot, 'code' => $code));

			if (!$ret['success']) {
				return error("failed to obtain Drupal configuration for `%s'", $docroot);
			}

			return \Util_PHP::unserialize(trim($ret['stdout']));
		}

		/**
		 * Check if version is latest or get latest version
		 *
		 * @param null|string $version
		 * @param string|null $branchcomp
		 * @return int|string
		 */
		public function is_current(string $version = null, string $branchcomp = null)
		{
			$vermask = $version ? substr($version, 0, strpos($version, '.')) : null;
			$latest = $this->_getLastestVersion($vermask);
			if (!$version) {
				return $latest;
			}
			if (version_compare((string)$version, (string)$latest, '=')) {
				return 1;
			}
			if (version_compare((string)$version, (string)$latest, '<')) {
				return 0;
			}
			return -1;
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
		public function change_admin(string $hostname, string $path = '', array $fields): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return warn('failed to change administrator information');
			}
			$admin = $this->get_admin($hostname, $path);

			if (!$admin) {
				return error('cannot determine admin of Drupal install');
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
		 * @param string $hostname
		 * @param string $path
		 * @return null|string admin or false on failure
		 */
		public function get_admin(string $hostname, string $path = ''): ?string
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			$ret = $this->_exec($docroot, 'user-information 1 --format=json');
			if (!$ret['success']) {
				warn('failed to enumerate Drupal administrative users');
				return null;
			}
			$tmp = json_decode($ret['stdout'], true);
			if (!$tmp) {
				return null;
			}
			$tmp = array_pop($tmp);
			return $tmp['name'];
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
			$ret = ($this->update($hostname, $path, $version) && $this->update_plugins($hostname, $path))
				|| error('failed to update all components');

			parent::setInfo($this->getDocumentRoot($hostname, $path), [
				'version' => $this->get_version($hostname, $path),
				'failed'  => !$ret
			]);
			return $ret;
		}

		/**
		 * Update Drupal to latest version
		 *
		 * @param string $hostname domain or subdomain under which WP is installed
		 * @param string $path     optional subdirectory
		 * @param string $version
		 * @return bool
		 */
		public function update(string $hostname, string $path = '', string $version = null): bool
		{
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error('update failed');
			}
			if ($this->isLocked($docroot)) {
				return error('Drupal is locked - remove lock file from `%s\' and try again', $docroot);
			}
			if ($version) {
				if (!is_scalar($version) || strcspn($version, '.0123456789x-')) {
					return error('invalid version number, %s', $version);
				}
				$current = $this->_extractBranch($version);
			} else {
				$current = $this->_extractBranch($this->get_version($hostname, $path));
				$version = $this->_getLastestVersion($current);
			}

			// save .htaccess
			$htaccess = $docroot . DIRECTORY_SEPARATOR . '.htaccess';
			if ($this->file_file_exists($htaccess) && !$this->file_move($htaccess, $htaccess . '.bak', true)) {
				return error('upgrade failure: failed to save copy of original .htaccess');
			}
			$this->file_purge();
			$cmd = 'pm-update drupal-%(version)s';
			$args = array('version' => $version);

			$this->_setMaintenance($docroot, true, $current);
			$ret = $this->_exec($docroot, $cmd, $args);
			$this->file_purge();
			$this->_setMaintenance($docroot, false, $current);

			if ($this->file_file_exists($htaccess . '.bak') && !$this->file_move($htaccess . '.bak', $htaccess, true)
				&& ($this->file_purge() || true)
			) {
				warn("failed to rename backup `%s/.htaccess.bak' to .htaccess", $docroot);
			}

			parent::setInfo($docroot, [
				'version' => $this->get_version($hostname, $path) ?? $version,
				'failed' => !$ret['success']
			]);

			$this->fortify($hostname, $path, array_get($this->getOptions($docroot), 'fortify', 'max'));

			if (!$ret['success']) {
				return warn('failed to update Drupal - ' .
					'login to Drupal admin panel to manually perform operation');
			}


			return $ret['success'];
		}

		public function isLocked(string $docroot): bool {
			return file_exists($this->domain_fs_path() . $docroot . DIRECTORY_SEPARATOR .
				'.drush-lock-update');
		}

		/**
		 * Update Drupal plugins and themes
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
			$cmd = 'pm-update --check-disabled --no-core';

			$args = array();
			if ($plugins) {
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
					$args[$name] = $plugin . ($version ? '-' . $version : '');
				}
			}

			$ret = $this->_exec($docroot, $cmd, $args);
			if (!$ret['success']) {
				/**
				 * NB: "Command pm-update needs a higher bootstrap level"...
				 * Use an older version of Drush to bring the version up
				 * to use the latest drush
				 */
				return error("plugin update failed: `%s'", coalesce($ret['stderr'], $ret['stdout']));
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
		 * Relax permissions to allow write-access
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return bool
		 */
		public function unfortify(string $hostname, string $path = ''): bool
		{
			return parent::unfortify($hostname, $path);
		}

		public function _housekeeping()
		{
			if (!file_exists(self::DRUPAL_CLI)) {
				$url = self::DRUPAL_CLI_URL;
				$res = Util_HTTP::download($url, self::DRUPAL_CLI);
				if (!$res) {
					return error('failed to install Drupal CLI');
				}
				info('downloaded Drupal CLI');
				chmod(self::DRUPAL_CLI, 0755);
			}

			$local = $this->service_template_path('siteinfo') . '/' . self::DRUPAL_CLI;
			if (!file_exists($local)) {
				copy(self::DRUPAL_CLI, $local);
				chmod($local, 755);
			}
			return true;
		}

		private function _exec($path = null, $cmd, array $args = array())
		{
			// client may override tz, propagate to bin
			$tz = date_default_timezone_get();
			$cli = 'php -d pdo_mysql.default_socket=' . escapeshellarg(ini_get('mysqli.default_socket')) .
				' -d date.timezone=' . $tz . ' -d memory_limit=192m ' . self::DRUPAL_CLI . ' -y';
			if (!is_array($args)) {
				$args = func_get_args();
				array_shift($args);
			}
			$user = $this->username;
			if ($path) {
				$user = parent::getDocrootUser($path);
				$cli = 'cd %(path)s && ' . $cli;
				$args['path'] = $path;
			}
			$cmd = $cli . ' ' . $cmd;
			$ret = $this->pman_run($cmd, $args, null, ['user' => $user]);
			if (0 === strpos((string)coalesce($ret['stderr'], $ret['stdout']), 'Error:')) {
				// move stdout to stderr on error for consistency
				$ret['success'] = false;
				if (!$ret['stderr']) {
					$ret['stderr'] = $ret['stdout'];
				}

			}
			return $ret;
		}

		/**
		 * Get version using exact docroot
		 *
		 * @param $docroot
		 * @return string
		 */
		protected function _getVersion($docroot): ?string
		{
			static $metaCache;
			if (null === $metaCache) {
				$metaCache = array();
			}
			$ret = $this->_exec($docroot, 'status --format=json');
			if (!$ret['success']) {
				return null;
			}

			$output = json_decode($ret['stdout'], true);

			return $output['drupal-version'] ?? null;
		}

		/**
		 * Add trusted_host_patterns if necessary
		 *
		 * @param $version
		 * @param $hostname
		 * @param $docroot
		 * @return bool
		 */
		private function _postInstallTrustedHost($version, $hostname, $docroot): bool
		{
			if (version_compare((string)$version, '8.0', '<')) {
				return true;
			}
			$file = $docroot . '/sites/default/settings.php';
			$content = $this->file_get_file_contents($file);
			if (!$content) {
				return error('unable to add trusted_host_patterns configuration - cannot get ' .
					"Drupal configuration for `%s'", $hostname);
			}
			$content .= "\n\n" .
				'/** in the event the domain name changes, trust site configuration */' . "\n" .
				'$settings["trusted_host_patterns"] = array(' . "\n" .
				"\t" . "'^(www\.)?' . " . 'str_replace(".", "\\\\.", $_SERVER["DOMAIN"]) . ' . "'$'" . "\n" .
				');' . "\n";
			return $this->file_put_file_contents($file, $content, true, true);
		}

		/**
		 * Get latest Drupal release
		 *
		 * @param null $version
		 * @return null|string
		 */
		private function _getLastestVersion($version = null): ?string
		{
			if (!$version) {
				$version = self::DEFAULT_BRANCH;
			}
			$version = $this->_extractBranch($version);
			$versions = $this->_getVersions('drupal', $version);

			if (!$versions) {
				return null;
			}
			$releases = $versions['releases']['release'];
			for ($i = 0, $n = count($releases); $i < $n; $i++) {
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
			if (substr($version, -2) === '.x') {
				return $version;
			}
			$pos = strpos($version, '.');
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
		 * @param string $module
		 * @param string $version
		 * @return array
		 */
		private function _getVersions($module = 'drupal', $version = self::DEFAULT_BRANCH): array
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

		/**
		 * Set Drupal maintenance mode before/after update
		 *
		 * @param      $docroot
		 * @param      $mode
		 * @param null $version
		 * @return bool
		 */
		private function _setMaintenance($docroot, $mode, $version = null)
		{
			if (null === $version) {
				$version = $this->_getVersion($docroot);
			}
			if ($version[0] >= 8) {
				$maintenancecmd = 'sset system.maintenance_mode %(mode)d';
				$cachecmd = 'cr';
			} else {
				$maintenancecmd = 'vset --exact maintenance_mode %(mode)d';
				$cachecmd = 'cache-clear all';
			}

			$ret = $this->_exec($docroot, $maintenancecmd, array('mode' => (int)$mode));
			if (!$ret['success']) {
				warn('failed to set maintenance mode');
			}
			$ret = $this->_exec($docroot, $cachecmd);
			if (!$ret['success']) {
				warn('failed to rebuild cache');
			}

			return true;
		}

		private function _getCommand()
		{
			return 'php ' . self::DRUPAL_CLI;
		}


		/**
		 * Get all available stable versions
		 *
		 * @return array
		 */
		public function get_versions(): array
		{
			$key = 'drupal.verflat';
			$cache = \Cache_Global::spawn();
			if (false !== ($versions = $cache->get($key))) {
				return $versions;
			}
			$tmp = [];
			foreach (array_reverse(self::DRUPAL_MAJORS) as $branch) {
				$branchversions = $this->_getVersions('drupal', $branch);
				$tmp = array_merge_recursive($tmp, $branchversions);
			}

			$versions = array_column(array_filter(array_reverse(array_get($tmp, 'releases.release')), function ($v) {
				return empty($v['version_extra']) && $v['status'] === 'published';
			}), 'version');
			$cache->set($key, $versions, 86400);
			return $versions;
		}

		/**
		 * Update WordPress themes
		 *
		 * @param string $hostname subdomain or domain
		 * @param string $path     optional path under hostname
		 * @param array  $themes
		 * @return bool
		 */
		public function update_themes(string $hostname, string $path = '', array $themes = array()): bool
		{
			return false;
		}

		public function next_version(string $version, string $maximalbranch = '99999999.99999999.99999999'): ?string
		{
			return parent::next_version($version, $maximalbranch);
		}

		public function theme_status(string $hostname, string $path = '', string $theme = null)
		{
			return parent::theme_status($hostname, $path, $theme); // TODO: Change the autogenerated stub
		}

		public function install_theme(string $hostname, string $path = '', string $theme, string $version = null): bool
		{
			return parent::install_theme($hostname, $path, $theme, $version);
		}
	}
