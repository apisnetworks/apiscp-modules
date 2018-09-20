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
	 *  Provides administrative functions
	 *
	 * @package core
	 */
	class Admin_Module extends Module_Skeleton
	{
		use ImpersonableTrait;

		const ADMIN_HOME = '/etc/opcenter/webhost';
		// @var string under ADMIN_HOME
		const ADMIN_CONFIG = '.config/';
		const ADMIN_CONFIG_LEGACY = '/etc/appliance/appliance.ini';

		protected $exportedFunctions = [
			'*' => PRIVILEGE_ADMIN
		];

		public function __construct()
		{
			parent::__construct();
			if (!AUTH_ADMIN_API) {
				$this->exportedFunctions = array_merge($this->exportedFunctions,
					array_fill_keys([
						'activate_site',
						'deactivate_site',
						'add_site',
						'edit_site',
						'delete_site',
						'hijack',
					], PRIVILEGE_NONE)
				);
			}
		}


		/**
		 * List all domains on the server
		 *
		 * @return array
		 * @throws PostgreSQLError
		 */
		public function get_domains(): array
		{

			$q = \PostgreSQL::initialize()->query("SELECT domain,site_id FROM siteinfo ORDER BY domain");
			$domains = array();
			while (null !== ($row = $q->fetch_object())) {
				$domains[$row->site_id] = $row->domain;
			}
			return $domains;
		}

		/**
		 * Get e-mail from domain
		 *
		 * @param  string $domain
		 * @return bool|string address or false on error
		 * @throws PostgreSQLError
		 */
		public function get_address_from_domain(string $domain)
		{
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error("invalid domain `%s'", $domain);
			}
			$siteid = $this->get_site_id_from_domain($domain);
			if (!$siteid) {
				return false;
			}
			$pgdb = \PostgreSQL::initialize();
			$q = $pgdb->query("SELECT email FROM siteinfo WHERE site_id = " . intval($siteid));
			if ($pgdb->num_rows() > 0) {
				return $q->fetch_object()->email;
			}
			return false;
		}

		/**
		 * Translate domain to id
		 *
		 * @param  string $domain domain
		 * @return null|int
		 * @throws PostgreSQLError
		 */
		public function get_site_id_from_domain($domain): ?int
		{
			if (!preg_match(Regex::DOMAIN, $domain)) {
				error("invalid domain `%s'", $domain);
				return null;
			}
			$pgdb = \PostgreSQL::initialize();
			$q = $pgdb->query("SELECT site_id FROM siteinfo WHERE domain = '" . $domain . "'");
			if ($pgdb->num_rows() > 0) {
				return (int)$q->fetch_object()->site_id;
			}
			$id = Auth::get_site_id_from_domain($domain);
			return $id;

		}

		/**
		 * Get account metadata
		 *
		 * @param string $domain
		 * @param string $service
		 * @param string $class
		 * @return array|bool|mixed|void
		 */
		public function get_meta_from_domain(string $domain, string $service, string $class = null)
		{

			if (!IS_CLI) {
				return $this->query('admin_get_meta_from_domain', $domain, $service, $class);
			}
			$site = $domain;

			// $domain passed as site
			if (strpos($domain, 'site') !== 0 || (int)$domain !== substr($domain, 4)) {
				$tmp = Auth::get_site_id_from_domain($domain);
				if (!$tmp) {
					return error("unknown domain `$domain'");
				}
				$site = 'site' . $tmp;
			} else if (!Auth::site_exists($site)) {
				return error("site `%s' out of bounds", $site);
			}
			$file = '/home/virtual/' . $site . '/info/current/' . $service;
			$new = '/home/virtual/' . $site . '/info/new/' . $service . (!platform_is('7.5') ? '.new' : '');
			if (file_exists($new)) {
				$file = $new;
			} else if (!file_exists($file)) {
				return error("service `$service' not installed for `$domain'");
			}

			$meta = Util_Conf::parse_ini($file);
			if (!$class) {
				return $meta;
			}
			if (!isset($meta[$class])) {
				// @XXX DEBUG from CRM
				Error_Reporter::report(join(" ",
						array($domain, $service, $class)) . " " . Error_Reporter::get_debug_bt());
				return error("meta `%s' does not exist for `%s'",
					$class, $service);
			}
			return $meta[$class];
		}

		/**
		 * Get appliance admin email
		 *
		 * @return string|null
		 */
		public function get_email(): ?string
		{
			if (!IS_CLI) {
				return $this->query('admin_get_email');
			}
			$ini = $this->_get_admin_config();
			return $ini['adminemail'] ?? $ini['email'] ?? null;
		}

		/**
		 * Set appliance admin email
		 *
		 * @param string $email
		 * @return bool
		 */
		public function set_email($email)
		{
			if (!IS_CLI) {
				return $this->query('admin_set_email', $email);
			}
			if (!preg_match(Regex::EMAIL, $email)) {
				return error("invalid email `%s'", $email);
			}
			$ini = $this->_get_admin_config();
			$ini['adminemail'] = $email;
			$data = '[DEFAULT]' . "\n" . implode("\n", array_key_map(function ($k, $v) {
					return $k . ' = ' . $v;
				}, $ini)) . "\n";
			$prefs = \Preferences::factory($this->getAuthContext())->unlock($this->getApnscpFunctionInterceptor());
			$prefs['email'] = $email;
			return (bool)file_put_contents($this->getAdminConfigFile(), $data);
		}

		public function _housekeeping()
		{
			$configHome = static::ADMIN_HOME . '/' . self::ADMIN_CONFIG;
			if (!is_dir($configHome)) {
				mkdir($configHome) && chmod($configHome, 0700);
			}

			$defplan = \Opcenter\Service\Plans::path(\Opcenter\Service\Plans::default());
			if (!is_dir($defplan)) {
				$base = \Opcenter\Service\Plans::path('');
				// plan name change
				$dh = opendir($base);
				if (!$dh) {
					return error("Plan path `%s' missing, account creation will fail until fixed",
						$base
					);
				}
				while (false !== ($f = readdir($dh))) {
					if ($f === '..' || $f === '.') {
						continue;
					}
					$path = $base . DIRECTORY_SEPARATOR . $f;
					if (is_link($path)) {
						unlink($path);
						break;
					}
				}
				if ($f !== false) {
					info("old default plan `%s' renamed to `%s'",
						$f, \Opcenter\Service\Plans::default()
					);
				}
				symlink(dirname($defplan) . '/.skeleton', $defplan);
			}


			$themepath = public_path('images/themes/current');
			if (is_link($themepath) && basename(readlink($themepath)) === STYLE_THEME) {
				return;
			}
			is_link($themepath) && unlink($themepath);
			symlink(STYLE_THEME, dirname($themepath) . '/current');
		}

		protected function _get_admin_config()
		{
			$file = $this->getAdminConfigFile();
			if (!file_exists($file)) {
				return [];
			}
			if (!platform_is('7.5')) {
				return parse_ini_file($file);
			}
			return Util_PHP::unserialize(file_get_contents($file));
		}

		private function getAdminConfigFile(): string {
			if (version_compare(platform_version(), '7.5', '<')) {
				return self::ADMIN_CONFIG_LEGACY;
			}
			return self::ADMIN_HOME . DIRECTORY_SEPARATOR . self::ADMIN_CONFIG .
				DIRECTORY_SEPARATOR . $this->username;
		}

		/**
		 * Force bulk update of webapps
		 *
		 * @param array $options
		 * @return bool
		 */
		public function update_webapps(array $options = []): bool {
			$launcher = \Module\Support\Webapps\Updater::launch();
			foreach ($options as $k => $v) {
				switch ($k) {
					case 'limit':
						$launcher->batch((int)$v);
						break;
					case 'type':
						$launcher->limitType($v);
						break;
					case 'assets':
						$launcher->enableAssetUpdates((bool)$v);
						break;
					case 'core':
						$launcher->enableCoreUpdates((bool)$v);
						break;
					case 'site':
						$launcher->limitSite($v);
						break;
					default:
						fatal("unknown option `%s'", $k);
				}
			}
			return (bool)$launcher->run();
		}

		/**
		 * Reset failed apps
		 *
		 * @param array $constraints [site: <anything>, version: <operator> <version>, type: <type>]
		 * @return int
		 */
		public function reset_webapp_failure(array $constraints = []): int {
			$known = ['site', 'version', 'type'];
			if ($bad = array_diff(array_keys($constraints), $known)) {
				error("unknown constraints: `%s'", implode(', ', $bad));
				return 0;
			}
			if (isset($constraints['site'])) {
				$siteid = Auth::get_site_id_from_anything($constraints['site']);
				if (!$siteid) {
					error("unknown site `%s'", $constraints['site']);
					return 0;
				}
				$sites = ['site' . $siteid];
			} else {
				$sites = \Opcenter\Account\Enumerate::active();
			}
			$versionFilter = function(array $appmeta) use ($constraints) {
				if (!isset($constraints['version'])) {
					return true;
				}
				if (!isset($appmeta['version'])) {
					return false;
				}

				$vercon = explode(' ', $constraints['version']);
				if (count($vercon) === 1) {
					$vercon = ['=', $vercon[0]];
				}
				return version_compare($appmeta['version'], ...array_reverse($vercon));
			};
			$typeFilter = function(array $appmeta) use ($constraints) {
				if (!isset($constraints['type'])) {
					return true;
				}
				return $appmeta['type'] === $constraints['type'];
			};
			$count = 0;
			foreach ($sites as $site) {
				$auth = Auth::context(null, $site);
				$finder = new \Module\Support\Webapps\Finder($auth);
				$apps = $finder->getApplications(function ($appmeta) {
					return !empty($appmeta['failed']);
				});
				foreach ($apps as $path => $app) {
					if (!$typeFilter($app)) {
						continue;
					}
					if (!$versionFilter($app)) {
						continue;
					}
					/**
					 * @var \Module\Support\Webapps\App\Type\Unknown $instance
					 */
					$instance =  \Module\Support\Webapps\App\Loader::factory(null, $path, $auth);
					$instance->clearFailed();
					info("Reset failed status on `%s/%s'", $instance->getHostname(), $instance->getPath());
					$count++;
				}
			}
			return $count;
		}

		/**
		 * Locate webapps under site
		 *
		 * @param string|array $site
		 * @return array
		 */
		public function locate_webapps($site = null): array {
			return \Module\Support\Webapps\Finder::find($site);
		}

		/**
		 * Delete site
		 *
		 * @param string $site
		 * @return bool
		 */
		public function delete_site(string $site): bool {
			if (!IS_CLI) {
				return $this->query('admin_delete_site', $site);
			}

			$ret = \Util_Process_Safe::exec(INCLUDE_PATH . '/bin/DeleteDomain --output=json %s', $site);
			\Error_Reporter::merge_buffer((array)json_decode($ret['stdout'], true));

			return $ret['success'];
		}

		/**
		 * Add site
		 *
		 * @param string $domain
		 * @param string $admin
		 * @param array  $opts
		 * @return bool
		 */
		public function add_site(string $domain, string $admin, array $opts = []): bool
		{
			if (!IS_CLI) {
				return $this->query('admin_add_site', $domain, $admin, $opts);
			}
			array_set($opts, 'siteinfo.admin_user', $admin);
			array_set($opts, 'siteinfo.domain', $domain);
			$cmd = implode(' ', array_key_map(function ($key, $val) {
				return '-c ' . escapeshellarg(str_replace_first('.', ',',
						$key)) . '=' . escapeshellarg((string)\Util_Conf::build_ini($val));
			}, array_dot($opts)));
			$cmd = INCLUDE_PATH . "/bin/AddDomain --output=json ${cmd}";
			info("AddDomain command: $cmd");
			$ret = \Util_Process_Safe::exec($cmd);
			\Error_Reporter::merge_buffer((array)json_decode($ret['stdout'], true));

			return $ret['success'];
		}

		/**
		 * Edit site
		 *
		 * @param string $site
		 * @param array  $opts
		 * @return bool
		 */
		public function edit_site(string $site, array $opts = []): bool
		{
			if (!IS_CLI) {
				return $this->query('admin_edit_site', $site, $opts);
			}

			$args = implode(' ', array_key_map(function($key, $val) {
				return '-c ' . escapeshellarg(str_replace_first('.', ',', $key)) . '=' . escapeshellarg((string)\Util_Conf::build_ini($val));
			}, array_dot($opts)));
			$cmd = INCLUDE_PATH . "/bin/EditDomain --output=json ${args} %s";
			info("Edit command: $cmd", $site);
			$ret = \Util_Process_Safe::exec($cmd, $site);
			\Error_Reporter::merge_buffer((array)json_decode($ret['stdout'], true));

			return $ret['success'] ;
		}

		/**
		 * Activate site
		 *
		 * @param string $site
		 * @return bool
		 */
		public function activate_site(string $site): bool
		{
			if (!IS_CLI) {
				return $this->query('admin_activate_site', $site);
			}

			$ret = \Util_Process_Safe::exec(INCLUDE_PATH . '/bin/ActivateDomain --output=json %s', $site);
			\Error_Reporter::merge_buffer((array)json_decode($ret['stdout'], true));

			return $ret['success'];
		}

		/**
		 * Deactivate site
		 *
		 * @param string $site
		 * @return bool
		 */
		public function deactivate_site(string $site): bool
		{
			if (!IS_CLI) {
				return $this->query('admin_deactivate_site', $site);
			}

			$ret = \Util_Process_Safe::exec(INCLUDE_PATH . '/bin/SuspendDomain --output=json %s', $site);
			\Error_Reporter::merge_buffer((array)json_decode($ret['stdout'], true));

			return $ret['success'];
		}

		/**
		 * Hijack a user account
		 *
		 * Replaces current session with new account session
		 *
		 * @param string      $site
		 * @param string|null $user
		 * @return null|string
		 */
		public function hijack(string $site, string $user = null): ?string
		{
			return $this->impersonateRole($site, $user);
		}

		/**
		 * Get server storage usage
		 *
		 * @return array
		 */
		public function get_storage(): array {
			$mounts = $this->stats_get_partition_information();
			for ($i = 0, $n = count($mounts); $i < $n; $i++) {
				$mount = $mounts[$i];
				if ($mount['mount'] != '/') {
					continue;
				}
				return [
					'qused' => $mount['used'],
					'qhard' => $mount['size'],
					'qsoft' => $mount['size'],
					'fused' => 0,
					'fsoft' => PHP_INT_MAX,
					'fhard' => PHP_INT_MAX
				];

			}
			warn("Failed to locate root partition / - storage information incomplete");
			return [];
		}
	}