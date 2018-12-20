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

	use Opcenter\Http\Apache\Map;

	/**
	 * Web server and package management
	 *
	 * @package core
	 */
	class Web_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable
	{
		const DEPENDENCY_MAP = [
			'ipinfo',
			'ipinfo6',
			'siteinfo',
			'dns'
		];

		// primary domain document root
		const MAIN_DOC_ROOT = '/var/www/html';
		const WEB_USERNAME = APACHE_USER;
		const WEB_GROUPID = APACHE_GID;
		const PROTOCOL_MAP = '/etc/httpd/conf/http10';

		protected $pathCache = [];
		protected $service_cache;

		/**
		 * void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = array(
				'*'                 => PRIVILEGE_SITE,
				'add_subdomain_raw' => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'host_html_dir'     => PRIVILEGE_SITE | PRIVILEGE_USER,
				'reload'            => PRIVILEGE_SITE | PRIVILEGE_ADMIN
			);

		}


		public function ruby_on_rails_enabled()
		{
			return $this->ruby_rails_installed();
		}

		public function enable_ruby_on_rails($ver = null)
		{
			return $this->ruby_install_rails($ver);
		}

		public function disable_ruby_on_rails()
		{
			return $this->ruby_uninstall_rails();
		}

		public function get_ruby_version($full = false)
		{
			return $this->ruby_version($full);
		}

		public function ruby_exists()
		{
			return parent::__call('ruby_exists');
		}

		public function gem_exists()
		{
			return $this->ruby_gem_exists();
		}

		public function list_installed_gems($rubyver = null)
		{
			return $this->ruby_list_installed_gems();
		}

		public function list_remote_gems()
		{
			return $this->ruby_list_remote_gems();
		}

		public function get_gem($gem, $local = false)
		{
			return $this->ruby_get_gem($gem, $local);
		}

		public function get_gem_version($gem, $local = false)
		{
			return $this->ruby_gem_version($gem, $local);
		}

		public function install_gem($gem, $ver = null)
		{
			return $this->ruby_install_gem($gem, $ver);
		}

		public function uninstall_gem($gem, $ver = null)
		{
			return $this->ruby_uninstall_gem($gem, $ver);
		}

		public function get_rubygems_version()
		{
			return $this->ruby_rubygems_version();
		}

		public function get_gem_description($gem)
		{
			return $this->ruby_gem_description($gem);
		}

		public function install_pear_package($module)
		{
			return $this->php_install_package($module);
		}

		public function list_installed_pear_packages()
		{
			return $this->php_list_installed_packages();
		}

		public function list_remote_pear_packages()
		{
			return $this->php_list_remote_packages();
		}

		public function get_pear_description($mModule)
		{
			return $this->php_package_description($mModule);
		}

		public function add_pear_channel($xml)
		{
			return $this->php_add_channel($xml);
		}

		public function remove_pear_channel($channel)
		{
			return $this->remove_channel($channel);
		}

		public function list_pear_channels()
		{
			return $this->php_list_channels();
		}

		public function get_pear_channel_info($channel)
		{
			return $this->php_get_channel_info($channel);
		}

		public function get_frontpage_status($domain = null)
		{
			return $this->frontpage_enabled($domain);

		}

		public function toggle_frontpage($domain = null)
		{
			$status = $this->frontpage_enabled($domain);
			if ($status) {
				return $this->frontpage_disable($domain);
			} else {
				return $this->frontpage_enable($domain);
			}
		}

		public function get_frontpage_sites()
		{
			return $this->frontpage_get_active_domains();
		}

		/**
		 * User capability is enabled for web service
		 *
		 * Possible values subdomain, cgi
		 *
		 * @param  string $user user
		 * @param  string $svc  service name possible values subdomain, cgi
		 * @return bool
		 */
		public function user_service_enabled($user, $svc)
		{
			if (!IS_CLI) {
				return $this->query('web_user_service_enabled',
					array($user, $svc));
			}
			if ($svc != "cgi" && $svc != "subdomain") {
				return new ArgumentError("Invalid service name " . $svc . " passed");
			}

			return true;
			/** Ensim's broken */

			$dbm_file = '/etc/virtualhosting/subdomain/' . $this->site . '.ownermap';
			if (!file_exists($dbm_file) && $svc == 'cgi') {
				return true;
			} else {
				if (!file_exists($dbm_file) && $svc == 'subdomain') {
					return false;
				}
			}
			if (isset($this->service_cache[$this->domain]) &&
				(filemtime($dbm_file) <= $this->service_cache[$this->domain]['time'])
			) {
				return isset($this->service_cache[$this->domain]['cgi'][$svc]);
			}

			$srvcInfo = array('subdomain' => array(), 'cgi' => array());

			/** find subdomain and CGI information */
			$dbm = dba_open("/etc/virtualhosting/subdomain/" . $this->site . ".ownermap", "r", "db4");
			if ($key = dba_firstkey($dbm)) {
				do {
					$value = dba_fetch($key, $dbm);
					$srvcInfo['subdomain'][$value] = 1;
					/**
					 *  realistically, so long as CGI is enabled for the domain, subusers
					 *  will have access to CGI scripts, so default to true
					 */
					$srvcInfo['cgi'][$value] = 1;
				} while ($key = dba_nextkey($dbm));
			}
			dba_close($dbm);

			$srvcInfo['time'] = time();
			$this->service_cache[$this->domain] = $srvcInfo;

			return isset($this->service_cache[$this->domain][$svc][$user]);
		}

		/**
		 * Sweep all subdomains to confirm accessibility
		 *
		 * @return array list of subdomains invalid
		 */
		public function validate_subdomains()
		{
			$prefix = $this->domain_fs_path();
			$invalid = array();
			foreach (glob($prefix . '/var/subdomain/*/') as $entry) {
				$subdomain = basename($entry);
				if ((is_link($entry . '/html') || is_dir($entry . '/html')) && file_exists($entry . '/html')) {
					continue;
				}
				warn("inaccessible subdomain `%s' detected", $subdomain);
				$file = File_Module::convert_relative_absolute($entry . '/html',
					readlink($entry . '/html'));
				$invalid[$subdomain] = substr($file, strlen($prefix));
			}

			return $invalid;
		}

		/**
		 * Check if hostname is a subdomain
		 *
		 * @param string $hostname
		 * @return bool
		 */
		public function is_subdomain(string $hostname): bool
		{
			if (false !== strpos($hostname, '.') && !preg_match(Regex::SUBDOMAIN, $hostname)) {
				return false;
			}

			return is_dir($this->domain_fs_path('/var/subdomain/' . $hostname));
		}

		public function subdomain_accessible($subdomain)
		{
			if ($subdomain[0] == '*') {
				$subdomain = substr($subdomain, 2);
			}

			return file_exists($this->domain_fs_path('/var/subdomain/' . $subdomain . '/html')) &&
				is_executable($this->domain_fs_path('/var/subdomain/' . $subdomain . '/html'));
		}

		/**
		 * Retrieve document root for given host
		 *
		 * Doubly useful to evaluate where documents
		 * will be served given a particular domain
		 *
		 * @param string $hostname HTTP host
		 * @param string $path     optional path component
		 * @return string document root path
		 */
		public function normalize_path(string $hostname, string $path = ''): ?string
		{
			if (!IS_CLI && isset($this->pathCache[$hostname][$path])) {
				return $this->pathCache[$hostname][$path];
			}
			$prefix = $this->domain_fs_path();
			if (false === ($docroot = $this->get_docroot($hostname))) {
				return null;
			}

			if ($path) {
				$docroot .= DIRECTORY_SEPARATOR . ltrim($path, '/');
			}

			$checkpath = $prefix . DIRECTORY_SEPARATOR . $docroot;
			clearstatcache(true, $checkpath);
			if (\Util_PHP::is_link($checkpath)) {
				// take the referent unless the path doesn't exist
				// let the API figure out what to do with it
				if (false === ($checkpath = realpath($checkpath))) {
					return $docroot;
				}
				if (0 !== strpos($checkpath, $prefix)) {
					error("docroot for `%s/%s' exceeds site root", $hostname, $path);

					return null;
				}
				$docroot = substr($checkpath, strlen($prefix));
			}
			if (!file_exists($checkpath)) {
				$subpath = dirname($checkpath);
				if (!file_exists($subpath)) {
					error("invalid domain `%s', docroot `%s' does not exist", $hostname, $docroot);

					return null;
				}
			}
			if (!isset($this->pathCache[$hostname])) {
				$this->pathCache[$hostname] = [];
			}
			$this->pathCache[$hostname][$path] = $docroot;

			return $docroot ?: null;
		}

		/**
		 * Get document root from hostname
		 *
		 * @param        $hostname
		 * @param string $path
		 * @return bool|string
		 */
		public function get_docroot($hostname, $path = '')
		{
			$domains = $this->list_domains();
			$path = ltrim($path, '/');
			if (isset($domains[$hostname])) {
				return rtrim($domains[$hostname] . '/' . $path, '/');
			}

			$domains = $this->list_subdomains();
			if (array_key_exists($hostname, $domains)) {
				// missing symlink will report as NULL
				if (null !== $domains[$hostname]) {
					return $domains[$hostname];
				}
				$info = $this->subdomain_info($hostname);

				return rtrim($info['path'] . '/' . $path, '/');
			}

			if (0 === strpos($hostname, "www.")) {
				$tmp = substr($hostname, 4);

				return $this->get_docroot($tmp);
			}
			if (false !== strpos($hostname, '.')) {
				$host = $this->split_host($hostname);
				if ($host['subdomain'] && $this->subdomain_exists($host['subdomain'])) {
					return $this->get_docroot($host['subdomain']);
				}

			}

			return error("unknown domain `$hostname'");
		}

		/**
		 * List subdomains on the account
		 *
		 * Array format- subdomain => path
		 *
		 * @param string       $filter  filter by "global", "local", "path"
		 * @param string|array $domains only show subdomains bound to domain or re for path
		 * @return array matching subdomains
		 */
		public function list_subdomains($filter = '', $domains = array())
		{
			if ($filter && $filter != 'local' && $filter != 'global' && $filter != 'path') {
				return error("invalid filter mode `%s'", $filter);
			}
			$subdomains = array();
			if ($filter == 'path') {
				$re = $domains;
				if ($re[0] !== $re[-1]) {
					$re = '!' . preg_quote($re, '!') . '!';
				}
			} else {
				$re = null;
			}
			if ($domains && !is_array($domains)) {
				$domains = array($domains);
			}
			foreach (glob($this->domain_fs_path() . '/var/subdomain/*/') as $entry) {
				$subdomain = basename($entry);
				$path = '';
				if (is_link($entry . '/html') || is_dir($entry . '/html') /* smh... */) {
					if (!is_link($entry . '/html')) {
						warn("subdomain `%s' doc root is directory", $subdomain);
						$path = Opcenter\Http\Apache::makeSubdomainPath($entry);
					} else {
						$path = (string)substr(File_Module::convert_relative_absolute($entry . '/html',
							readlink($entry . '/html')),
							strlen($this->domain_fs_path()));
					}
				}
				if ($filter && ($filter == 'local' && !strpos($subdomain, '.') ||
						$filter == 'global' && strpos($subdomain, '.'))
				) {
					continue;
				}
				if ($filter == 'path' && !preg_match($re, $path)) {
					continue;
				}

				if ($filter !== 'path' && strpos($subdomain, '.') && $domains) {
					$skip = 0;
					foreach ($domains as $domain) {
						$lendomain = strlen($domain);
						if (substr($subdomain, -$lendomain) != $domain) {
							$skip = 1;
							break;
						}
					}
					if ($skip) {
						continue;
					}
				}

				$subdomains[$subdomain] = $path;
			}

			asort($subdomains, SORT_LOCALE_STRING);

			return $subdomains;
		}

		/**
		 * Get detailed information on a subdomain
		 *
		 * Response:
		 *  path (string): filesystem location
		 *  active (bool): subdomain references accessible directory
		 *  user (string): owner of subdomain
		 *  type (string): local, global, or fallthrough
		 *
		 * @param  string $subdomain
		 * @return array
		 */
		public function subdomain_info($subdomain)
		{
			if ($subdomain[0] == '*') {
				$subdomain = substr($subdomain, 2);
			}

			if (!$subdomain) {
				return error("no subdomain provided");
			}
			if (!$this->subdomain_exists($subdomain)) {
				return error($subdomain . ": subdomain does not exist");
			}

			$info = array(
				'path'   => null,
				'active' => false,
				'user'   => null,
				'type'   => null
			);

			$fs_location = $this->domain_fs_path() . '/var/subdomain/' . $subdomain;

			if (!strpos($subdomain, ".")) {
				$type = 'global';
			} else if (!array_key_exists($subdomain, $this->list_domains())) {
				$type = 'local';
			} else {
				$type = 'fallthrough';
			}

			$info['type'] = $type;
			$link = $fs_location . '/html';
			/**
			 * link does not exist
			 * test first if no symlink referent is present,
			 * then verify (is_link()) that the $link is not present
			 * file_exists() checks the referent
			 */
			if (!file_exists($link) && !is_link($link)) {
				return $info;
			}
			// case when <subdomain>/html is directory instead of symlink
			if (!is_link($link)) {
				$path = $link;
			} else {
				clearstatcache(true, $link);
				$path = File_Module::convert_relative_absolute($link, readlink($link));
			}
			$info['path'] = $this->file_canonicalize_site($path);

			$info['active'] = file_exists($link) && is_readable($link);
			$stat = $this->file_stat($info['path']);
			if (!$stat || $stat instanceof Exception) {
				return $info;
			}
			$info['user'] = $stat['owner'];

			return $info;
		}

		/**
		 * Check if named subdomain exists
		 *
		 * Fallthrough, local, and global subdomain patterns
		 * are valid
		 *
		 * @see add_subdomain()
		 *
		 * @param  string $subdomain
		 * @return bool
		 */
		public function subdomain_exists($subdomain)
		{
			if ($subdomain[0] == '*') {
				$subdomain = substr($subdomain, 2);
			}
			$path = $this->domain_fs_path('/var/subdomain/' . $subdomain);

			return file_exists($path);
		}

		public function list_domains()
		{
			return array_merge(
				array($this->getConfig('siteinfo', 'domain') => self::MAIN_DOC_ROOT),
				$this->aliases_list_shared_domains());
		}

		/**
		 * Split hostname into subdomain + domain components
		 *
		 * @param string $hostname
		 * @return array|bool components or false on error
		 */
		public function split_host($host)
		{
			if (!preg_match(Regex::HTTP_HOST, $host)) {
				return error("can't split, invalid host `%s'", $host);
			}
			$split = array(
				'subdomain' => '',
				'domain'    => $host
			);
			$domain_lookup = $this->list_domains();
			if (!$host || isset($domain_lookup[$host])) {
				return $split;
			}

			$offset = 0;
			$level_sep = strpos($host, '.');
			do {
				$subdomain = substr($host, $offset, $level_sep - $offset);
				$domain = substr($host, $level_sep + 1);
				if (isset($domain_lookup[$domain])) {
					break;
				}

				$offset = $level_sep + 1;
				$level_sep = strpos($host, '.', $offset + 1);
			} while ($level_sep !== false);
			if (!isset($domain_lookup[$domain])) {
				return $split;
			}
			$split['subdomain'] = (string)substr($host, 0, $offset) . $subdomain;
			$split['domain'] = $domain;

			return $split;
		}

		/**
		 * Get the normalized hostname from a global subdomain
		 *
		 * @param string $host
		 * @return string
		 */
		public function normalize_hostname(string $host): string
		{
			if (false !== strpos($host, ".")) {
				return $host;
			}

			// @todo track domain/entry_domain better in contexted roles
			return $host . '.' .
				($this->inContext() ? $this->domain : \Session::get('entry_domain', $this->domain));
		}

		// {{{ remove_user_subdomain()

		/**
		 * Get information on a domain
		 *
		 * Info elements
		 *    path (string): filesystem path
		 *  active (bool): domain is active and readable
		 *  user (string): owner of directory
		 *
		 * @param  string $domain
		 * @return array domain information
		 */
		public function domain_info($domain)
		{
			if (!$this->domain_exists($domain)) {
				return error($domain . ": domain does not exist");
			}

			$info = array(
				'path'   => null,
				'active' => false,
				'user'   => null
			);

			if ($domain === $this->getConfig('siteinfo', 'domain')) {
				$path = self::MAIN_DOC_ROOT;
			} else {
				$domains = $this->aliases_list_shared_domains();
				$path = $domains[$domain];
			}
			$info['path'] = $path;
			$info['active'] = is_readable($this->domain_fs_path() . $path);

			$stat = $this->file_stat($path);
			if (!$stat || $stat instanceof Exception) {
				return $stat;
			}
			$info['user'] = $stat['owner'];

			return $info;
		}

		/**
		 * Test if domain is attached to account
		 *
		 * @param  string $domain
		 * @return bool
		 */
		public function domain_exists($domain)
		{
			return $domain == $this->getConfig('siteinfo', 'domain') ||
				array_key_exists($domain, $this->aliases_list_shared_domains());

		}

		// }}}

		public function get_hostname_from_docroot(string $docroot): ?string
		{
			$docroot = rtrim($docroot, '/');
			if ($docroot === static::MAIN_DOC_ROOT) {
				return $this->getServiceValue('siteinfo', 'domain');
			}
			$aliases = $this->aliases_list_shared_domains();
			if (false !== ($domain = array_search($docroot, $aliases, true))) {
				return $domain;
			}

			if ($subdomain = $this->list_subdomains('path', $docroot)) {
				return key($subdomain);
			}

			return null;
		}

		/**
		 * Assign a path as a DAV-aware location
		 *
		 * @param string $location filesystem location
		 * @param string $provider DAV provider
		 * @return \Exception|boolean
		 */
		public function bind_dav($location, $provider)
		{
			if (!IS_CLI) {
				return $this->query('web_bind_dav', $location, $provider);
			}

			if (!$this->verco_svn_enabled() && (strtolower($provider) == 'svn')) {
				return error("Cannot use Subversion provider when not enabled");
			} else {
				if ($location[0] != '/') {
					return error("DAV location `%s' is not absolute", $location);
				} else {
					if (!file_exists($this->domain_fs_path() . $location)) {
						return error('DAV location `%s\' does not exist', $location);
					}
				}
			}

			$stat = $this->file_stat($location);
			if ($stat instanceof Exception) {
				return $stat;
			}

			if ($stat['file_type'] != 'dir') {
				return error("bind_dav: `$location' is not directory");
			} else {
				if (!$stat['can_write']) {
					return error("`%s': cannot write to directory", $location);
				}
			}

			$this->query('file_fix_apache_perms_backend', $location);
			$file = $this->site_config_dir() . '/dav';
			if (file_exists($file) &&
				preg_match('}' . $this->domain_fs_path() . $location . '"?[/\s]*>}', file_get_contents($file))
			) {
				return warn("DAV path `%s' already set", $location);
			}
			$dav_config = '';
			if (file_exists($file)) {
				$dav_config = trim(file_get_contents($file)) . "\n";
			}
			$dav_config .= '<Directory "' . $this->domain_fs_path() . rtrim($location, '/') . '">' . "\n" .
				"\t" . 'Dav ' . ($provider == 'svn' ? 'svn' : 'On') . "\n" .
				'</Directory>' . "\n";
			$needs_define = stristr($dav_config, 'IfDefine !SLAVE');
			if ($needs_define) {
				$dav_config = '<IfDefine !SLAVE>' . "\n" .
					$dav_config . '</IfDefine>' . "\n";
			}
			file_put_contents($file, $dav_config);

			return true;
		}

		public function site_config_dir()
		{
			return \Opcenter\Http\Apache::siteStoragePath($this->site);
		}

		/**
		 * Permit a disallowed protocol access to hostname
		 *
		 * @param string $hostname
		 * @param string $proto only http10 is valid
		 * @return bool
		 */
		public function allow_protocol(string $hostname, string $proto = 'http10'): bool
		{
			if (!IS_CLI) {
				return $this->query('web_allow_protocol', $hostname, $proto);
			}
			if ($proto !== 'http10') {
				return error("protocol `%s' not known, only http10 accepted", $proto);
			}
			if (!$this->protocol_disallowed($hostname, $proto)) {
				return true;
			}
			$map = Map::open(self::PROTOCOL_MAP, Map::MODE_WRITE);
			$map[$hostname] = $this->site_id;

			return $map->sync();
		}

		public function protocol_disallowed(string $hostname, string $proto = 'http10'): bool
		{
			if ($proto !== 'http10') {
				return error("protocol `%s' not known, only http10 accepted", $proto);
			}
			$map = Map::open(self::PROTOCOL_MAP);

			return !isset($map[$hostname]);
		}

		public function disallow_protocol(string $hostname, string $proto = 'http10'): bool
		{
			if (!IS_CLI) {
				return $this->query('web_disallow_protocol', $hostname, $proto);
			}
			if ($proto !== 'http10') {
				return error("protocol `%s' not known, only http10 accepted", $proto);
			}
			if ($this->protocol_disallowed($hostname, $proto)) {
				return true;
			}
			$map = Map::open(self::PROTOCOL_MAP, Map::MODE_WRITE);
			unset($map[$hostname]);

			return $map->sync();

		}

		public function unbind_dav($location)
		{
			if (!IS_CLI) {
				return $this->query('web_unbind_dav', $location);
			}
			$file = $this->site_config_dir() . '/dav';
			$dav_config = file_get_contents($file);
			$lines = explode("\n", $dav_config);
			$i = 0;
			$found = false;
			while ($i < count($lines)) {
				$line = $lines[$i];
				if (preg_match('!' . $this->domain_fs_path() . $location . '"?/?(?:>|\s)!', $line)) {
					$found = true;
					do {
						unset($lines[$i]);
						$i++;
					} while (false === stripos($lines[$i], '</Directory>') && ($i < count($lines)));
					unset($lines[$i]);
					break;
				}
				$i++;
			}
			file_put_contents($file, implode("\n", $lines));

			return $found;

		}

		public function list_dav_locations()
		{
			$dav_locations = array();
			$file = $this->site_config_dir() . '/dav';
			if (!file_exists($file)) {
				return $dav_locations;
			}
			$fp = fopen($file, 'r');
			$idx = 0;
			$inside = 0;
			while (false !== ($line = fgets($fp))) {
				if (preg_match('}' . $this->domain_fs_path() . '(/[^>]+(?!["/>]).)}', $line, $match)) {
					$inside = 1;
					$dav_locations[$idx] = array('path' => $match[1], 'provider' => 'dav');

				} else if ($inside && preg_match('/Dav\s+([\S]+)/i', $line, $match)) {
					$match[1] = strtolower($match[1]);
					$dav_locations[$idx]['provider'] = ($match[1] == 'on' ? 'dav' : $match[1]);

				} else if (false !== stripos($line, '</Directory>')) {
					$inside = 0;
					$idx++;
				}
			}
			fclose($fp);

			return $dav_locations;
		}

		public function _edit()
		{
			$conf_new = $this->getAuthContext()->getAccount()->new;
			$conf_old = $this->getAuthContext()->getAccount()->old;
			// change to web config or ipconfig
			$ssl = \Opcenter\SiteConfiguration::getModuleRemap('openssl');
			if ($conf_new['apache'] != $conf_old['apache'] ||
				$conf_new['ipinfo'] != $conf_old['ipinfo'] ||
				$conf_new[$ssl] != $conf_old[$ssl] ||
				$conf_new['aliases'] != $conf_old['aliases']
			) {
				\Opcenter\Http\Apache::activate();
			}

		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			if ($userold === $usernew) {
				return;
			}
			/**
			 * @TODO
			 * Assert that all users are stored under /home/username
			 * edit_user hook is called after user is changed, so
			 * this is lost without passing user pwd along
			 */
			$userhome = $this->user_get_user_home($usernew);
			$re = '!^' . $oldpwd['home'] . '!';
			mute_warn();
			$subdomains = $this->list_subdomains('path', $re);
			unmute_warn();
			foreach ($subdomains as $subdomain => $path) {
				$newpath = preg_replace('!' . DIRECTORY_SEPARATOR . $userold . '!',
					DIRECTORY_SEPARATOR . $usernew, $path, 1);
				if ($subdomain === $userold) {
					$newsubdomain = $usernew;
				} else {
					$newsubdomain = $subdomain;
				}
				if ($this->rename_subdomain($subdomain, $newsubdomain, $newpath)) {
					info("moved subdomain `%s' from `%s' to `%s'", $subdomain, $path, $newpath);
				}
			}

			return true;
		}

		/**
		 * Rename a subdomain and/or change its path
		 *
		 * @param string $subdomain    source subdomain
		 * @param string $newsubdomain new subdomain
		 * @param string $newpath
		 * @return bool
		 */
		public function rename_subdomain(string $subdomain, string $newsubdomain = null, string $newpath = null): bool
		{
			if (!$this->subdomain_exists($subdomain)) {
				return error($subdomain . ": subdomain does not exist");
			}
			if ($newsubdomain && $subdomain !== $newsubdomain && $this->subdomain_exists($newsubdomain)) {
				return error("destination subdomain `%s' already exists", $newsubdomain);
			}
			if (!$newsubdomain && !$newpath) {
				return error("no rename operation specified");
			}
			if ($newpath && ($newpath[0] != '/' && $newpath[0] != '.')) {
				return error("invalid path `%s', subdomain path must " .
					"be relative or absolute", $newpath);
			}

			if (!$newsubdomain) {
				$newsubdomain = $subdomain;
			} else {
				$newsubdomain = strtolower($newsubdomain);
			}
			$sdpath = Opcenter\Http\Apache::makeSubdomainPath($subdomain);
			$link = null;
			$old_stat = $this->file_make_path($sdpath, $link);
			// case when html is missing due to erroneous deletion of symlink

			$old_path = $sdpath;
			if ($link) {
				$old_path = $this->file_convert_relative_absolute(dirname($sdpath), $old_stat['referent']);
			}

			// rename subdomain, keep path

			if (!$newpath) {
				$newpath = $old_path;
			}
			if (!$newsubdomain) {
				$newsubdomain = $subdomain;
			}
			if ($subdomain !== $newsubdomain) {
				if (!$this->remove_subdomain($subdomain) || !$this->add_subdomain($newsubdomain, $newpath)) {
					error("changing subdomain `%s' to `%s' failed", $subdomain, $newsubdomain);
					if (!$this->add_subdomain($subdomain, $old_path)) {
						error("critical: could not reassign subdomain `%s' to `%s' after failed rename", $subdomain,
							$old_path);
					}

					return false;
				}
			} else if (!$this->remove_subdomain($subdomain) || !$this->add_subdomain($subdomain, $newpath)) {
				error("failed to change path for `%s' from `%s' to `%s'",
					$subdomain,
					$old_path,
					$newpath);
				if (!$this->add_subdomain($subdomain, $old_path)) {
					error("failed to restore subdomain `%s' to old path `%s'",
						$subdomain,
						$old_path);
				}

				return false;
			}

			return true;
		}

		/**
		 * Remove a subdomain
		 *
		 * @param string $subdomain fully or non-qualified subdomain
		 * @return bool
		 */
		public function remove_subdomain(string $subdomain): bool
		{
			// clear both ends
			$this->purge();

			if (!IS_CLI) {
				return $this->query('web_remove_subdomain', $subdomain);
			}

			$subdomain = strtolower($subdomain);
			if (!preg_match(Regex::SUBDOMAIN, $subdomain)) {
				return error($subdomain . ": invalid subdomain");
			} else if (!$this->subdomain_exists($subdomain)) {
				return warn($subdomain . ": subdomain does not exist");
			}
			$this->map_subdomain('delete', $subdomain);
			$path = $this->domain_fs_path() . '/var/subdomain/' . $subdomain;
			if (is_link($path)) {
				return unlink($path) && warn("subdomain `%s' path `%s' corrupted, removing reference",
						$subdomain,
						$this->file_unmake_path($path)
					);
			}
			$dh = opendir($path);
			while (false !== ($entry = readdir($dh))) {
				if ($entry === '..' || $entry === '.') {
					continue;
				}
				if (!is_link($path . '/' . $entry) && is_dir($path . '/' . $entry)) {
					warn("directory found in subdomain `%s'", $entry);
					continue;
				} else {
					unlink($path . '/' . $entry);
				}
			}
			closedir($dh);
			rmdir($path);

			return true;
		}

		/**
		 * Clear path cache
		 *
		 * @return void
		 */
		public function purge(): void
		{
			$this->pathCache = [];
			if (!IS_CLI) {
				$this->query('web_purge');
			}
		}

		/**
		 * Manage subdomain symlink mapping
		 *
		 * @todo   merge from Web_Module::map_domain()
		 * @param  string $mode      add/delete
		 * @param  string $subdomain subdomain to add/remove
		 * @param  string $path      domain path
		 * @param  string $user      user to assign mapping
		 * @return bool
		 */
		public function map_subdomain(string $mode, string $subdomain, string $path = null, string $user = null): bool
		{
			if (!IS_CLI) {
				return $this->query('web_map_subdomain',
					$mode,
					$subdomain,
					$path,
					$user);
			}

			$mode = substr($mode, 0, 3);
			if (!preg_match(Regex::SUBDOMAIN, $subdomain)) {
				return error($subdomain . ": invalid subdomain");
			}
			if ($mode != 'add' && $mode != 'del') {
				return error($mode . ": invalid mapping operation");
			}
			if ($mode == 'del') {
				$docroot = $this->get_docroot($subdomain);
				if ($docroot) {
					$prefs = \Module\Support\Webapps\MetaManager::instantiateContexted($this->getAuthContext());
					$prefs->forget($docroot);
				}

				return $this->file_delete('/home/*/all_subdomains/' . $subdomain);
			}
			if ($mode == 'add') {
				if (!$user) {
					$stat = $this->file_stat($path);
					if ($stat instanceof Exception) {
						return error("Cannot map subdomain - failed to determine user from `%s'", $path);
					}
					$user = $this->user_get_username_from_uid($stat['uid']);
				}
				$user_home = '/home/' . $user;
				$user_home_abs = $this->domain_fs_path() . $user_home;

				if (!file_exists($this->domain_fs_path() . $path)) {
					warn($path . ": path does not exist, creating link");
				}
				if (!file_exists($user_home_abs . '/all_subdomains')) {
					$this->file_create_directory($user_home . '/all_subdomains');
					$this->file_chown($user_home . '/all_subdomains', $user);
				}
				$this->file_symlink($path, $user_home . '/all_subdomains/' . $subdomain);
			}

			return true;
		}

		/**
		 * Add subdomain to account
		 *
		 * There are 3 types of subdomains:
		 * Local- subdomain includes subdomain + domain - foo.bar.com
		 * Fallthrough- subdomain is named after domain - bar.com
		 * Global- subdomain excludes domain - foo
		 *
		 * @param  string $subdomain
		 * @param  string $docroot document root of the subdomain
		 * @return bool
		 */
		public function add_subdomain($subdomain, $docroot)
		{
			if (!IS_CLI) {
				return $this->query('web_add_subdomain', $subdomain, $docroot);
			}
			$subdomain = strtolower(trim($subdomain));
			if ($subdomain === 'www') {
				return error("illegal subdomain name");
			}
			$subdomain = preg_replace('/^www\./', '', strtolower($subdomain));
			if (!preg_match(Regex::SUBDOMAIN, $subdomain) &&
				0 !== strpos($subdomain, '*.') &&
				!preg_match(Regex::DOMAIN, $subdomain)
			) {
				return error($subdomain . ": invalid subdomain");
			}
			if ($this->subdomain_exists($subdomain)) {
				return error($subdomain . ": subdomain exists");
			}
			if ($docroot[0] != '/' && $docroot[0] != '.') {
				return error("invalid path `%s', subdomain path must " .
					"be relative or absolute", $docroot);
			}
			/**
			 * This is particularly nasty because add_subdomain can provide
			 * either the subdomain or the subdomain + domain as the $subdomain
			 * argument.  We need to (1) loop through each domain to determine if
			 * a FQDN or subdomain, (2) query each DNS record to ensure
			 * it is provisioned correctly, (3) add missing records.
			 *
			 * A FQDN for a hostname on the other hand is  a bit easier; just
			 * add the record.  First we check to see if it's FQDN or not.  If
			 * FQDN, check DNS and add.
			 */
			$domains = array_keys($this->list_domains());
			if ($subdomain[0] == '*') {
				$domain = substr($subdomain, 2);
				$subdomain = '';
				if (!in_array($domain, $domains, true)) {
					return error("domain `%s' not attached to account (DNS > Addon Domains)", $domain);
				}
			}

			// is it a fully-qualified domain name? i.e. www.apisnetworks.com or
			// a subdomain? e.g. "www"
			$FQDN = false;

			// hostnames to query and setup DNS records for
			$recs_to_add = array();
			foreach ($domains as $domain) {
				if (preg_match('/\.' . $domain . '$/', $subdomain)) {
					// local subdomain
					$FQDN = true;
					$recs_to_add = array(
						array(
							'subdomain' => substr($subdomain, 0, -strlen($domain) - 1),
							'domain'    => $domain
						)
					);
					break;
				} else if ($subdomain === $domain) {
					// subdomain is fallthrough
					$recs_to_add[] = array(
						'subdomain' => '*',
						'domain'    => $domain
					);

				}
			}
			if (!$recs_to_add) {
				// domain is global subdomain
				foreach ($domains as $domain) {
					$recs_to_add[] = array(
						'subdomain' => $subdomain,
						'domain'    => $domain
					);
				}
			}

			foreach ($recs_to_add as $record) {
				if (!$this->dns_zone_exists($record['domain'])) {
					warn("DNS zone `%s' does not exist, skipping", $record['domain']);
					continue;
				}
				if (!$this->dns_record_exists($record['domain'], $record['subdomain'], 'A')) {
					$ret = $this->dns_add_record($record['domain'],
						$record['subdomain'],
						'A',
						$this->common_get_ip_address());
					if (!$ret) {
						error($record['subdomain'] . '.' . $record['domain'] . ": DNS master returned bad value");
					}
				}

				if ($record['subdomain'] != '*' &&
					!$this->dns_record_exists($record['domain'], 'www.' . $record['subdomain'], 'A')
				) {
					$ret = $this->dns_add_record($record['domain'],
						'www.' . $record['subdomain'],
						'A',
						$this->common_get_ip_address());
					if (!$ret) {
						error("%s.%s: DNS master returned bad value",
							$record['subdomain'], $record['domain']);
					}
				}

			}
			/**
			 * Home directories without subdomains explicitly enabled
			 * are created with 700.  This bears the side-effect of Apache
			 * being unable to descend past /home/<user>/.  Fix by giving
			 * the execute bit
			 */
			if (preg_match('!^/home/([^/]+)!', $docroot, $user_home)) {
				$user = $user_home[1];
				$stat = $this->file_stat('/home/' . $user);
				if ($stat instanceof Exception || !$stat) {
					return error("user `$user' does not exist");
				}
				$ret = $this->file_chmod('/home/' . $user, decoct($stat['permissions']) | 001);

				if (!$ret) {
					return $ret;
				}
			} else {
				$user = $this->common_get_service_value('siteinfo', 'admin_user');
			}

			$prefix = $this->domain_fs_path();
			if (!file_exists($prefix . $docroot)) {
				if (\Util_PHP::is_link($prefix . $docroot)) {
					// fix cases where a client links the doc root to an absolute symlink outside the scope
					// of apache, e.g. /var/www/html -> /foo, apache would see <fst>/foo, not /foo
					$newlink = $this->file_convert_absolute_relative($docroot, readlink($prefix . $docroot));
					warn("converted unfollowable absolute symlink to relative (document root): %s -> %s", $docroot,
						$newlink);
					unlink($prefix . $docroot);
					$ret = $this->file_symlink($newlink, $docroot);
				} else {
					$ret = $this->file_create_directory($docroot, 0755, true);
				}

				if (!$ret) {
					return $ret;
				}
				$this->file_chown($docroot, $user);
				$index = $prefix . $docroot . '/index.html';
				copy('/etc/virtualhosting/templates/apache/var/www/html/index.html',
					$index);
				chown($index, (int)$this->user_get_uid_from_username($user));
				chgrp($index, $this->group_id);
			}
			$subdomainpath = Opcenter\Http\Apache::makeSubdomainPath($subdomain);

			return $this->add_subdomain_raw($subdomain,
					$this->file_convert_absolute_relative($subdomainpath, $docroot)) &&
				$this->map_subdomain('add', $subdomain, $docroot, $user);
		}

		public function add_subdomain_raw($subdomain, $docroot)
		{

			$prefix = $this->domain_fs_path();
			$subdomain_path = Opcenter\Http\Apache::makeSubdomainPath($subdomain);
			$subdomain_parent = dirname($prefix . $subdomain_path);
			if (!file_exists($subdomain_parent)) {
				\Opcenter\Filesystem::mkdir($subdomain_parent, $this->user_id, $this->group_id);
			}
			$tmp = $docroot;
			if ($docroot[0] === '.' && $docroot[1] == '.') {
				$tmp = $subdomain_parent . DIRECTORY_SEPARATOR . $docroot;
			}

			$user = fileowner($tmp);
			if (!file_exists($tmp)) {
				Error_Reporter::print_debug_bt();
			}

			return symlink($docroot, $prefix . $subdomain_path) &&
				Util_PHP::lchown($prefix . $subdomain_path, $user) &&
				Util_PHP::lchgrp($prefix . $subdomain_path, $this->group_id);
		}

		/**
		 * Account created
		 */
		public function _create()
		{
			\Opcenter\Http\Apache::activate();
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}

		public function _reload($why = null)
		{
			if (in_array($why, [null, "php", "aliases", "letsencrypt"])) {
				return \Opcenter\Http\Apache::activate();
			}
		}

		public function _delete()
		{
			$map = Map::open(self::PROTOCOL_MAP, Map::MODE_WRITE);
			$map->removeValues($this->site_id);
			$map->sync();
			if (!platform_is('7.5')) {
				// part of DeleteDomain on Delta platform
				\Opcenter\Provisioning\Apache::removeConfiguration($this->site);
			}
			\Opcenter\Http\Apache::activate();

		}

		public function http_config_dir()
		{
			deprecated_func('use site_config_dir');

			return $this->site_config_dir();
		}

		public function config_dir()
		{
			return \Opcenter\Http\Apache::CONFIG_PATH;
		}

		public function _delete_user(string $user)
		{
			$this->remove_user_subdomain($user);
		}

		/**
		 * Removes all subdomains associated with a named user
		 *
		 * @param string $user
		 * @return bool
		 */
		public function remove_user_subdomain(string $user): bool
		{
			$ret = true;
			foreach ($this->list_subdomains() as $subdomain => $dir) {
				if (!preg_match('!^/home/' . preg_quote($user, '!') . '(/|$)!', (string)$dir)) {
					continue;
				}
				$ret &= $this->web_remove_subdomain($subdomain);
			}

			return (bool)$ret;
		}

		public function _create_user(string $user)
		{
			// TODO: Implement _create_user() method.
		}
	}
