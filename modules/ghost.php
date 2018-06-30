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
	class Ghost_Module extends \Module\Support\Webapps
	{
		const APP_NAME = 'Ghost';
		const GHOST_CLI = 'ghost';
		const DEFAULT_VERSION_LOCK = 'major';
		const VERSION_CHECK_URL = 'https://api.github.com/repos/TryGhost/Ghost/releases?per_page=1000';

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
		 * Get all available Ghost versions
		 *
		 * @return array
		 */
		public function get_versions(): array
		{
			$versions = $this->_getVersions();
			return array_column($versions, 'version');
		}

		/**
		 * Get next Ghost version
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
		 * Reconfigure a Ghost instance
		 *
		 * @param            $field
		 * @param string     $attribute
		 * @param array      $new
		 * @param array|null $old
		 */
		public function reconfigure(string $field, string $attribute, array $new, array $old = null)
		{

			// ghost config url <newurl>
		}

		public function get_configuration($field)
		{

		}

		/**
		 * Install Ghost into a pre-existing location
		 *
		 * @param string $hostname domain or subdomain to install Laravel
		 * @param string $path     optional path under hostname
		 * @param array  $opts     additional install options
		 * @return bool
		 */
		public function install(string $hostname, string $path = '', array $opts = array()): bool
		{
			if (!platform_is('6.5')) {
				return error('Ghost requires at least a v6.5 platform');
			}
			if (!$this->ssh_enabled()) {
				return error('Ghost requires ssh service to be enabled');
			}
			// assume all Ghost installs will be located in a parent directory
			// once installed, relink the domain/subdomain to $docroot + /public
			// also block installing under a path, because this would require either relocating
			// Ghost outside any document root, e.g. /var/www/<hostname>-<path>-ghost and making
			// a symlink, which fails once the parent document root moves (must use relative symlinks)
			// and clutters up wherever they get located... no sound solution
			if ($path) {
				return error('Ghost may only be installed directly on a subdomain or domain without a child path, e.g. https://domain.com but not https://domain.com/ghost');
			}

			$this->validateNode();
			$docroot = $this->getDocumentRoot($hostname, $path);
			if (!$docroot) {
				return error("failed to normalize path for `%s'", $hostname);
			}

			if (!parent::checkDocroot($docroot)) {
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

			if (!parent::checkEmail($opts)) {
				return false;
			}

			$db = $this->_suggestDB($hostname);
			if (!$db) {
				return false;
			}

			$dbuser = $this->_suggestUser($db, '127.0.0.1');
			if (!$dbuser) {
				return false;
			}
			$dbpass = $this->suggestPassword();
			$args['dbname'] =  $db;
			$args['dbuser'] = $dbuser;
			$args['dbpassword'] = $dbpass;

			if (!$this->sql_create_mysql_database($db)) {
				return error("failed to create suggested db `%s'", $db);
			}
			// ??? wtf Ghost!
			if (!$this->sql_add_mysql_user($dbuser, '127.0.0.1', $dbpass, 10)) {
				$this->sql_delete_mysql_database($db);
				return error("failed to create suggested user `%s'", $dbuser);
			}
			if (!$this->sql_set_mysql_privileges($dbuser, '127.0.0.1', $db,
					array('read' => true, 'write' => true)))
			{
				$this->sql_delete_mysql_user($dbuser, '127.0.0.1');
				$this->sql_delete_mysql_database($db);
				return error("failed to set privileges on db `%s' for user `%s'", $db, $dbuser);
			}

			if ($this->sql_add_mysql_backup($db, 'zip', 5, 2)) {
				info("added database backup task for `%s'", $db);
			}

			$fqdn = $this->web_normalize_hostname($hostname);
			$args['uri'] = rtrim($fqdn . '/' . $path, '/');
			$args['proto'] = empty($opts['ssl']) ? 'http://' : 'https://';
			// use localhost.localdomain, which is an alias to 127.0.0.1;
			// ghost looks for "mysqld" if dbhost is localhost or 127.0.0.1;
			// this isn't present in a synthetic root
			$ret = $this->_exec($docroot,
				'nvm exec --silent --lts ghost install --process=local --no-prompt --no-stack --no-start --no-color --db=mysql --dbhost=localhost.localdomain --dbuser=%(dbuser)s --dbpass=%(dbpassword)s ' .
				'--dbname=%(dbname)s --no-setup-linux-user --no-setup-nginx --version=%(version)s --url=%(proto)s%(uri)s --mail=sendmail',
				$args);

			if (!$ret['success']) {
				info('removing temporary files');
				$this->file_delete($docroot, true);
				$this->sql_delete_mysql_database($db);
				$this->sql_delete_mysql_user($dbuser, '127.0.0.1');
				return error('failed to download Ghost v%s: %s', $args['version'], $ret['stderr']);
			}

			$this->node_make_default('lts/*', $docroot);

			$autogenpw = false;
			if (!isset($opts['password'])) {
				$autogenpw = true;
				$opts['password'] = $this->suggestPassword(10);
				info("autogenerated password `%s'", $opts['password']);
			}

			$username = $this->user_getpwnam($opts['user']  ?? $this->username)['gecos'] ?: $this->username;
			info("setting displayed name to `%s'", $username);
			$opts['url'] = rtrim($hostname . '/' . $path, '/');

			foreach (['tmp', 'public', 'logs'] as $dir) {
				$this->file_create_directory("${docroot}/${dir}") || warn("failed to create application directory `%s/%s'", $docroot, $dir);
			}

			if (!$this->file_put_file_contents($docroot . '/public/.htaccess',
				'PassengerEnabled on' . "\n" .
				'PassengerStartupFile current/index.js' . "\n" .
				'PassengerAppType node' . "\n" .
				'PassengerNodejs ' . $this->getNodeCommand() . "\n" .
				'PassengerAppRoot ' . $this->domain_fs_path($docroot) . "\n"
			)) {
				return error('failed to create .htaccess control - Ghost is not properly setup');
			}

			$params = array(
				'version'    => $this->get_version($hostname, $path),
				'hostname'   => $hostname,
				'path'       => $path,
				'autoupdate' => (bool)$opts['autoupdate'],
				'options'    => array_except($opts, 'version')
			);
			$approot = $docroot;
			if (!$this->fixSymlink($docroot)) {
				return error('Failed to correct current/ symlink');
			}
			if (null === ($docroot = $this->remapPublic($hostname, $path))) {
				$docroot = $this->getDocumentRoot($hostname, $path);
				// it's more reasonable to fail at this stage, but let's try to complete
				$approot = $docroot;
				warn("Failed to remap Ghost to public/, manually remap from `%s'", $docroot);
			}
			$this->map('add', $docroot, $params);
			$this->linkConfiguration($approot, 'production');
			
			// @todo migrate cache management to reconfigure method
			$config = [
				'useMinFiles' => 'true',
				'caching.frontend.maxAge' => 120,
				'logging.rotation.enabled' => 'true',
				// frontend caches + leave 5 for update/admin
				'database.pool.max' => 5,
				'paths.contentPath' => "${approot}/content"
			];
			foreach ($config as $c => $v) {
				$ret = $this->_exec($approot, 'ghost config set %(c)s %(v)s', ['c' => $c, 'v' => $v]);
				if (!$ret['success']) {
					return error("Failed to set configuration `%s': %s", $c, coalesce($ret['stderr'], $ret['stdout']));
				}
			}

			$this->_exec($approot, 'npm install -g knex-migrator');
			$ret = $this->_exec("${approot}/current", 'knex-migrator init');
			if (!$ret['success']) {
				return error('Failed to create initial database configuration - knex-migrator failed: %s',
					coalesce($ret['stderr'], $ret['stdout']));
			}
			if (!$this->migrate($approot)) {
				return error('Failed to migrate database configuration - Ghost installation incomplete');
			}
			$this->change_admin($hostname, $path, [
				'email' => $opts['email'],
				'password' => $opts['password'],
				'name' => $username
			]);
			if (array_get($opts, 'notify', true)) {
				\Lararia\Bootstrapper::minstrap();
				\Illuminate\Support\Facades\Mail::to($opts['email'])->
				send((new \Module\Support\Webapps\Mailer('install.ghost', [
					'login'    => $opts['email'],
					'password' => $opts['password'],
					'uri'      => $args['uri'],
					'proto'    => $args['proto'],
					'appname'  => static::APP_NAME
				]))->setAppName(static::APP_NAME));
			}

			if (!$opts['squash']) {
				parent::unsquash(dirname($docroot));
			}
			return info('Ghost installed - confirmation email with login info sent to %s', $opts['email']);
		}

		/**
		 * Get app root for Ghost
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return null|string
		 */
		protected function getAppRoot(string $hostname, string $path = ''): ?string
		{
			// Ghost/Laravel app root resides 1 level down
			$path = $this->web_normalize_path($hostname, $path);
			return $path ? dirname($path) : null;
		}

		/**
		 * Migrate database configuration to current/
		 *
		 * @param string $approot
		 * @param string $appenv
		 * @return bool
		 */
		private function linkConfiguration(string $approot, string $appenv = 'production'): bool
		{
			if ($this->file_file_exists($approot . "/current/config.${appenv}.json")) {
				return true;
			}
			return $this->file_symlink($approot . "/config.${appenv}.json", $approot . "/current/config.${appenv}.json") ||
				warn("failed to link configuration ${approot}/config.${appenv}.json to current/");
		}

		/**
		 * Migrate Ghost database
		 *
		 * @param string $approot
		 * @param string $appenv optional app environment to source DB config
		 * @return bool
		 */
		private function migrate(string $approot, string $appenv = 'production'): bool
		{
			$this->linkConfiguration($approot, $appenv);
			$ret = $this->_exec("${approot}/current", 'knex-migrator migrate');
			return $ret['success'] ?: error("failed to migrate database in `%s': %s", $approot, coalesce($ret['stderr'], $ret['stdout']));
		}

		private function _exec($path = null, $cmd, array $args = array())
		{
			// client may override tz, propagate to bin
			if (!is_array($args)) {
				$args = func_get_args();
				array_shift($args);
			}
			$user = $this->username;
			if ($path) {
				$cmd = 'cd %(path)s && /bin/bash -ic -- ' . escapeshellarg($cmd);
				$args['path'] = $path;
				$user = $this->file_stat($path)['owner'] ?? $this->username;
			}

			$ret = $this->pman_run($cmd, $args,
				[
					'BASH_ENV' => '/etc/profile.d/nvm.sh',
					'NVM_DIR'  => $this->user_get_home($user),
					'PATH' => getenv('PATH') . PATH_SEPARATOR . '~/node_modules/.bin',
					'NODE_ENV' => 'production'
				], ['user' => $user]);

			if (!strncmp($ret['stdout'], 'Error:', strlen('Error:'))) {
				// move stdout to stderr on error for consistency
				$ret['success'] = false;
				if (!$ret['stderr']) {
					$ret['stderr'] = $ret['stdout'];
				}

			}
			return $ret;
		}

		/**
		 * Get all current major versions
		 *
		 * @return array
		 */
		private function _getVersions(): array
		{
			$key = 'ghost.versions';
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
			$versions = array_reverse(json_decode($contents, true));
			array_walk($versions, function (&$a) {
				$a['version'] = $a['tag_name'];
			});
			$cache->set($key, $versions, 43200);
			return $versions;
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
		public function install_plugin(string $hostname, string $path = '', string $plugin, string $version = 'stable'): bool
		{
			return error('not supported');
		}

		/**
		 * Uninstall WP from a location
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
		 * Location is a valid WP install
		 *
		 * @param string $hostname or $docroot
		 * @param string $path
		 * @return bool
		 */
		public function valid(string $hostname, string $path = ''): bool
		{
			if ($hostname[0] === '/') {
				$approot = \dirname($hostname);
			} else {
				$approot = $this->getAppRoot($hostname, $path);
				if (!$approot) {
					return false;
				}
			}
			return file_exists($this->domain_fs_path() . $approot . '/current/core/server/lib/ghost-version.js');
		}

		/**
		 * Get database configuration for a blog
		 *
		 * @param string $hostname domain or subdomain of wp blog
		 * @param string $path     optional path
		 * @return bool|array
		 */
		public function db_config(string $hostname, string $path = '')
		{
			$approot = $this->getAppRoot($hostname, $path);
			if (!$approot) {
				error('failed to determine Ghost config');
				return [];
			}

			foreach (['development','production'] as $env) {
				$path = "${approot}/config.${env}.json";
				if ($this->file_file_exists($path)) {
					// @todo unify config into a consistent object
					$json = json_decode($this->file_get_file_contents($path), true)['database']['connection'];
					if (!$json) {
						continue;
					}
					$json['db'] = $json['database'];
					$json['prefix'] = '';
					return $json;
				}
			}
			return [];
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
		 * Change Ghost admin credentials
		 *
		 * Common fields include: password, email, name; email doubles as login
		 *
		 * @param string $hostname
		 * @param string $path
		 * @param array  $fields
		 * @return bool
		 */
		public function change_admin(string $hostname, string $path = '', array $fields): bool
		{
			$docroot = $this->getAppRoot($hostname, $path);
			if (!$docroot) {
				return warn('failed to change administrator information');
			}
			$admin = $this->get_admin($hostname, $path);

			if (!$admin) {
				return error('cannot determine admin of Ghost install');
			}

			if (isset($fields['password'])) {
				if (!\Opcenter\Auth\Password::strong($fields['password'])) {
					return false;
				}
				$fields['password'] = password_hash($fields['password'], PASSWORD_BCRYPT, ['cost' => 10]);
			}
			if (isset($fields['name'])) {
				$fields['slug'] = str_slug($fields['name']);
			}

			$db = $this->connectDB($hostname, $path);
			$q = "UPDATE users SET status = 'active'";
			foreach (['password', 'email', 'name', 'slug'] as $field) {
				if (!isset($fields[$field])) {
					continue;
				}
				$q .= ", {$field} = '" . $db->escape_string($fields[$field]) . "'";
			}
			$q .= " WHERE email = '" . $admin . "'";
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
			$mysql = $this->connectDB($hostname, $path);
			$rs = $mysql->query('SELECT email FROM users WHERE id = 1');
			if (!$rs || $rs->num_rows < 1) {
				return null;
			}
			return $rs->fetch_object()->email;
		}

		private function connectDB($hostname, $path): \MySQL
		{
			$dbconfig = $this->db_config($hostname, $path);
			$host = $dbconfig['host'] === 'localhost.localdomain' ? '127.0.0.1' : $dbconfig['host'];
			return \MySQL::stub()->connect($host, $dbconfig['user'], $dbconfig['password'], $dbconfig['db']);
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
			$path = $this->domain_fs_path() . $approot . '/current/package.json';
			if (!file_exists($path)) {
				warn('missing package.json from Ghost root - cannot detect version');
				return null;
			}
			return json_decode(file_get_contents($path))->version;
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
		 * Update Ghost to latest version
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
			//$this->validateNode();
			if (!$version) {
				$version = \Opcenter\Versioning::nextVersion($this->get_versions(), $this->get_version($hostname, $path));
			} else if (!\Opcenter\Versioning::valid($version)) {
				return error('invalid version number, %s', $version);
			}
			// -D bypasses permission checks
			$cmd = 'ghost update -D --no-restart --no-color %(version)s';
			$args['version'] = $version;
			$ret = $this->_exec($approot, $cmd, $args);
			$this->fixSymlink($approot);
			$this->file_touch("${approot}/tmp/restart.txt");
			parent::setInfo($approot, [
				'version' => $this->get_version($hostname, $path),
				'failed'  => !$ret['success']
			]);
			return $ret['success'] && $this->migrate($approot);
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
			return parent::theme_status($hostname, $path, $theme); // TODO: Change the autogenerated stub
		}

		public function install_theme(string $hostname, string $path = '', string $theme, string $version = null): bool
		{
			return parent::install_theme($hostname, $path, $theme, $version);
		}

		/**
		 * Verify Node LTS is installed
		 *
		 * @param string|null $version optional version to compare against
		 * @return bool
		 */
		protected function validateNode(string $version = null): bool
		{
			if (!$this->node_installed('lts') && !$this->node_install('lts')) {
				return error('failed to install Node LTS');
			}
			$ret = $this->node_do('lts', 'npm install -g ghost-cli');
			$this->_exec('~', 'nvm use --delete-prefix --lts');
			if (!$ret['success']) {
				return error('failed to install ghost-cli: %s', $ret['stderr'] ?? 'UNKNOWN ERROR');
			}
			return true;
		}

		/**
		 * Get path to active Node
		 *
		 * @param string|null $version
		 * @return null|string
		 */
		protected function getNodeCommand(string $version = null): ?string
		{
			$ret = $this->node_do('lts', 'which node');
			return $ret['success'] ? trim($ret['output']) : null;
		}

		/**
		 * Relink current/ from absolute to relative symlink
		 *
		 * @param string $approot
		 * @return bool
		 */
		private function fixSymlink(string $approot): bool
		{
			$path = $this->domain_fs_path("${approot}/current");
			if (!is_link($path)) {
				return error("${approot}/current missing - can't relink");
			}
			$link = readlink($path);
			if ($link[0] !== '/') {
				// relative link
				$stat = $this->file_stat("${approot}/current");
				return !empty($stat['referent']) ? true : error("${approot}/current does not point to an active Ghost install");
			}
			if (0 !== strpos($link, $approot)) {
				return false;
			}
			return $this->file_delete($approot .'/current') && $this->file_symlink($link, $approot . '/current');
		}
	}


