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
	 * Aliases and shared domains
	 *
	 * @package core
	 */
	class Aliases_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable
	{
		const DEPENDENCY_MAP = [
			'siteinfo',
			'users', // addon domain ownership
		];
		const CONFIG_DB_DIR = '/etc/httpd/conf/domains/';
		/** addon domain dns verification record */
		const DNS_VERIFICATION_RECORD = 'newacct';
		const BYPASS_FILE = '/etc/virtualhosting/dnsbypass';

		/**
		 * void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			$this->exportedFunctions = array(
				'*'                         => PRIVILEGE_SITE,
				'add_shared_domain_backend' => PRIVILEGE_SERVER_EXEC | PRIVILEGE_SITE,
				'map_domain'                => PRIVILEGE_SERVER_EXEC,
			);
			parent::__construct();
		}

		/**
		 * Post-verification add_shared_domain()
		 *
		 * @param string $domain
		 * @param string $path
		 * @return bool
		 */
		public function add_shared_domain_backend($domain, $path)
		{
			$parent = dirname($path);

			if (!file_exists($this->domain_fs_path() . $parent)) {
				warn("%s: parent directory does not exist", $parent);
				if (!$this->file_create_directory($parent, 0755, true)) {
					return error("failed to create parent directory");
				}
			}
			if (!$this->_create_doc_root($path)) {
				return error("failed to create document root `%s'", $path);
			}
			$stat = $this->file_stat($path);
			$user = null;
			if (isset($stat['owner'])) {
				$user = $stat['owner'];
				if (ctype_digit($user)) {
					warn("no such user found for domain `%s' uid `%d'", $domain, $user);
					$user = null;
				}
			} else {
				Error_Reporter::report("Bad stat response: " . var_export($stat, true));
			}

			if (!$user && $stat['uid'] < \User_Module::MIN_UID) {
				return error("unable to determine ownership of docroot `%s' for `%s'",
					$path, $domain);
			} else if (!$user) {
				warn("invalid uid `%d' detected on `%s', squashed to account uid `%d'",
					$stat['uid'],
					$domain,
					$this->user_id
				);
				$this->file_chown($path, $this->user_id, true);
				$user = $this->user_id;
			}

			$ret = $this->add_alias($domain);
			if (!$ret) {
				file_exists($path) && unlink($path);
				return error("failed to add domain alias configuration `%s'", $domain);
			}

			$this->notify_admin($domain, $path);

			if (!$this->map_domain('add', $domain, $path, $user)) {
				return error("failed to map domain `%s' in http configuration", $domain);
			}
			$ip = $this->common_get_ip_address();
			$this->_remove_bypass($domain);
			return $this->dns_add_zone_backend($domain, $ip);
		}

		/**
		 * Notify appliance admin domain has been added
		 *
		 * @param string $domain
		 * @param string $path
		 * @return bool
		 */
		protected function notify_admin(string $domain, string $path): bool {
			if (!DOMAINS_NOTIFY) {
				return false;
			}

			$template = \BladeLite::factory('views/email');
			$html = $template->make('aliases.domain-add',
				[
					'domain' => $domain,
					'path' => $path,
					'authdomain' => $this->domain,
					'authuser' => $this->username,
					'siteid' => $this->site_id,
				]
			)->render();

			$opts = array(
				'html_charset' => 'utf-8',
				'text_charset' => 'utf-8'
			);
			$from = \Crm_Module::FROM_NAME . ' <' . \Crm_Module::FROM_ADDRESS . '>';
			$headers = array(
				'Sender' => $from,
				'From'   => $from
			);
			$mime = new Mail_Mime($opts);

			$mime->setHTMLBody($html);
			$mime->setTXTBody(strip_tags($html));
			$headers = $mime->txtHeaders($headers);
			$msg = $mime->get();

			return Mail::send(
				\Crm_Module::COPY_ADMIN,
				"Domain Added",
				$msg,
				$headers
			);

		}
		/**
		 * Manage domain symlink mapping
		 *
		 * @todo   merge into web module
		 *
		 * @param  string $mode   add/delete
		 * @param  string $domain domain to add/remove
		 * @param  string $path   domain path
		 * @param  string $user   user to assign mapping
		 * @return bool
		 */
		public function map_domain($mode, $domain, $path = null, $user = null)
		{
			if (!IS_CLI) {
				return $this->query('aliases_map_domain',
					$mode,
					$domain,
					$path,
					$user);
			}

			$mode = substr($mode, 0, 3);
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error($domain . ": invalid domain");
			}
			if ($mode != 'add' && $mode != 'del') {
				return error($mode . ": invalid map operation");
			}
			if ($mode == 'del') {
				return $this->_remove_apache_map($domain, $path) &&
					$this->file_delete('/home/*/all_domains/' . $domain);
			} else {
				if ($mode == 'add') {
					if (!$user) {
						$stat = $this->file_stat($path);
						if ($stat instanceof Exception) {
							return $stat;
						}

						$user = $this->user_get_username_from_uid($stat['uid']);
					}
					if ($user) {
						if ($user == $this->tomcat_system_user()) {
							$user = $this->username;
							$uid = $this->user_get_uid_from_username($user);
						} else {
							$uid = $this->user_get_uid_from_username($user);
							if ($uid < User_Module::MIN_UID) {
								$user = $this->username;
							}
						}

						$user_home = '/home/' . $user;
						$user_home_abs = $this->domain_fs_path() . $user_home;

						if (!file_exists($this->domain_fs_path() . $path)) {
							warn($path . ": path does not exist, creating link");
						}
						if (!file_exists($user_home_abs . '/all_domains')) {
							$this->file_create_directory($user_home . '/all_domains');
							$this->file_chown($user_home . '/all_domains', $user);
						}
						// remove symlink if domain previously added
						$fullpath = $this->domain_fs_path() . $user_home . '/all_domains/' . $domain;
						// sometimes clients do dumb things, like remove the symlink and recreate
						// as an empty directory
						clearstatcache(true, $fullpath);
						if (is_link($fullpath)) {
							unlink($fullpath);
						} else {
							if (is_dir($fullpath)) {
								Error_Reporter::mute_warning(true);
								if (!rmdir($fullpath)) {
									warn("not creating symlink all_domains/%s; a directory was found within " .
										"that contains files", $domain);
								}
								Error_Reporter::unmute_warning();
							}
						}
						// and sometimes clients can do really dumb things like
						// assign a doc root under all_domains/
						$localpath = $user_home . '/all_domains/' . $domain;
						if (!file_exists($fullpath)) {
							$this->file_create_symlink($path, $localpath);
						} else {
							warn("cannot make symlink %s - file exists, possibly misplaced docroot?",
								$localpath
							);
						}
					} else {
						warn($domain . ": cannot determine user for domain mapping");
					}
				}
			}
			if ($mode == 'add') {
				return $this->_add_apache_map($domain, $path);
			}
			return $this->_remove_apache_map($domain, $path);
		}

		/**
		 * Domain is exempt from DNS verification requirements
		 *
		 * @param $domain
		 * @return bool
		 */
		public function bypass_exists($domain)
		{
			return $this->_is_bypass($domain);
		}

		/**
		 * Modify shared domain settings
		 *
		 * @param  string $domain
		 * @param  array  $newparams
		 * @return bool
		 */
		public function modify_domain(string $domain, array $newparams): bool
		{
			if (!IS_CLI) {
				return $this->query('aliases_modify_domain', $domain, $newparams);
			}
			if (!$this->shared_domain_exists($domain)) {
				return error("domain `$domain' is not attached to account");
			}
			if ($this->shared_domain_hosted($domain)) {
				return error("domain `$domain' is hosted by another account");
			}
			if ($domain === $this->get_config('siteinfo', 'domain')) {
				return error("cannot modify primary domain");
			}

			$params = array('type', 'domain', 'location', 'owner');
			if (isset($newparams['owner'])) {
				$newowner = $newparams['owner'];
				if (!$this->_change_owner($domain, $newowner)) {
					return false;
				}
			}

			if (isset($newparams['path'])) {
				$path = $newparams['path'];
				if (!$this->_change_path($domain, $path)) {
					return false;
				}
			}

			if (isset($newparams['domain'])) {
				$newdomain = $newparams['domain'];
				if (!$this->_change_domain($domain, $newdomain)) {
					return false;
				}
			}
			return true;
		}

		/**
		 * bool remove_shared_domain(string)
		 *
		 * @param string $domain domain name to remove
		 */
		public function remove_shared_domain($domain)
		{
			if (!IS_CLI) {
				$docroot = $this->web_get_docroot($domain);
				$status = $this->query('aliases_remove_shared_domain', $domain);
				if ($status && $docroot) {
					$meta = \Module\Support\Webapps\MetaManager::instantiateContexted($this->getAuthContext());
					$meta->forget($docroot);
				}
				return $status;
			}
			$domain = strtolower($domain);
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error("Invalid domain `$domain'");
			}
			$this->map_domain('delete', $domain);
			if (!$this->remove_alias($domain)) {
				return false;
			}
			/**
			 * NB: don't call dns_remove_zone, the domain may be added back at a later date,
			 * in which case the DNS will get clobbered
			 */
			return true;
		}

		public function remove_alias($alias)
		{
			if (!IS_CLI) {
				$status = $this->query('aliases_remove_alias', $alias);
				return $status;
			}
			$alias = trim(strtolower($alias));
			if (!preg_match(Regex::DOMAIN, $alias)) {
				return error("Invalid domain");
			}

			$aliases = (array)$this->get_service_value('aliases', 'aliases');

			$key = array_search($alias, $aliases);
			if ($key === false) {
				return error("domain `$alias' not found");
			}

			unset($aliases[$key]);
			if (!$aliases) {
				$this->set_config_journal('aliases', 'enabled', 0);
			}

			return $this->set_config_journal('aliases', 'aliases', $aliases);
		}

		public function add_shared_domain($domain, $path)
		{
			$domain = preg_replace('/^www./', '', strtolower($domain));
			$path = rtrim(str_replace('..', '.', $path), '/') . '/';

			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error($domain . ": invalid domain");
			} else if (!preg_match(Regex::ADDON_DOMAIN_PATH, $path)) {
				return error($path . ": invalid path");
			} else if ($domain == $this->get_service_value('siteinfo', 'domain')) {
				return error("Primary domain may not be replicated as a shared domain");
			}

			if (!$this->_verify($domain)) {
				return false;
			}
			return $this->query('aliases_add_shared_domain_backend', $domain, $path);
		}

		/**
		 * Verify domain hosted on account
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function shared_domain_exists($domain)
		{
			return $domain == $this->get_config('siteinfo', 'domain') ||
				array_key_exists($domain, $this->list_shared_domains());
		}

		/**
		 * array list_shared_domains()
		 *
		 * @return array
		 */
		public function list_shared_domains()
		{
			if (!IS_CLI) {
				return $this->query('aliases_list_shared_domains');
			}
			$map = $this->_load_map();
			if (isset($map[$this->domain])) {
				unset($map[$this->domain]);
			}
			return $map;
		}

		/**
		 * Shared domain is hosted by another account
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function shared_domain_hosted($domain)
		{
			$domain = strtolower($domain);
			if ($this->dns_domain_hosted($domain, true)) {
				return true;
			}
			$id = Auth::get_site_id_from_domain($domain);
			if ($id && $id != $this->site_id) {
				return true;
			}
			return false;
		}

		/**
		 * Get challenge token to verify ownership of domain
		 *
		 * @param string $domain
		 * @return string
		 */
		public function challenge_token()
		{
			$str = (string)fileinode($this->domain_info_path());
			return sha1($str);
		}

		/**
		 * Compare domain configuration journal
		 *
		 * @return bool
		 */
		public function list_unsynchronized_domains()
		{
			$active = parent::get_active_services('aliases');
			$active = $active['aliases'];
			$pending = (array)parent::get_new_services('aliases');
			if ($pending) {
				$pending = $pending['aliases'];
			}
			$domains = array_keys($this->list_shared_domains());
			$changes = array(
				'add'    => array_diff($pending, $active),
				'remove' => array_diff($active, $domains)
			);
			return $changes;
		}

		public function synchronize_changes()
		{
			if (!IS_CLI) {
				return $this->query('aliases_synchronize_changes');
			}

			$cache = Cache_Account::spawn($this->getAuthContext());
			$time = $cache->get('aliases.sync');
			$aliases = array_keys($this->list_shared_domains());
			$this->set_config_journal('aliases', 'enabled', intval(count($aliases) > 0));
			$this->set_config_journal('aliases', 'aliases', $aliases);
			return $this->_synchronize_changes() && ($cache->set('aliases.sync', $time) || true);
		}

		/**
		 * array list_aliases()
		 *
		 * @return array aliases associated to the domain
		 */
		public function list_aliases()
		{
			$values = $this->get_service_value('aliases', 'aliases');
			return (array)$values;
		}

		public function _reset(Util_Account_Editor &$editor = null)
		{
			$module = 'aliases';
			$params = array('aliases' => array(), 'enabled' => 0);
			if ($editor) {
				foreach ($params as $k => $v) {
					$editor->setConfig($module, $k, $v);
				}
			}
			return array($module => $params);
		}

		public function _edit()
		{
			$conf_cur = Auth::profile()->conf->cur['siteinfo'];
			$conf_new = Auth::profile()->conf->new['siteinfo'];
			$domainold = $conf_cur['domain'];
			$domainnew = $conf_new['domain'];

			// domain name change via auth_change_domain()
			if ($domainold !== $domainnew) {
				// domain changed via Account > Settings
				if ($this->_is_bypass($domainnew)) {
					$this->_remove_bypass($domainnew);
				}
			}
			$aliasesnew = array_get(Auth::conf('aliases', 'new'), 'aliases', []);
			$aliasescur = array_get(Auth::conf('aliases', 'cur'), 'aliases', []);
			$add = array_diff($aliasesnew, $aliasescur);
			$rem = array_diff($aliasescur, $aliasesnew);
			$db = \Opcenter\Map::load(\Opcenter\Map::DOMAIN_MAP, 'wd');
			foreach ($add as $a) {
				$db->insert($a, $this->site);
			}
			foreach ($rem as $r) {
				$db->delete($r);
			}
			$db->close();
			return;
		}

		public function _create() {
			$db = \Opcenter\Map::write(\Opcenter\Map::DOMAIN_MAP);
			$conf = array_get(Auth::conf('aliases'), 'aliases', []);
			foreach ($conf as $domain) {
				$db->insert($domain, $this->site);
			}
			$db->close();
		}

		public function _delete() {
			$db = \Opcenter\Map::write(\Opcenter\Map::DOMAIN_MAP);
			$conf = array_get(Auth::conf('aliases'), 'aliases', []);
			foreach ($conf as $domain) {
				$db->delete($domain);
			}
			$db->close();
		}

		public function _edit_user(string $user, string $usernew, array $oldpwd)
		{
			if ($user === $usernew) {
				return;
			}

			$domains = $this->list_shared_domains();
			$home = $oldpwd['home'];
			$newhome = preg_replace('!' . DIRECTORY_SEPARATOR . $user . '!', DIRECTORY_SEPARATOR . $usernew, $home, 1);
			foreach ($domains as $domain => $info) {
				if (strncmp($home, $newhome, strlen($home))) {
					continue;
				}
				$newpath = preg_replace('!^' . $home . '!', $newhome, $info['path']);
				if (!$this->_change_path($domain, $newpath)) {
					warn("failed to update domain `%s'", $domain);
				}
			}
			return true;
		}

		/**
		 * Add hostname to account configuration
		 *
		 * add_alias() implies that prereq checks have been made,
		 * including duplication checks
		 *
		 * @param string $alias
		 * @return bool
		 */
		protected function add_alias($alias)
		{
			if (!IS_CLI) {
				return error(__METHOD__ . ' should be called from backend');
			}

			$alias = strtolower($alias);
			if (!preg_match(Regex::DOMAIN, $alias)) {
				return error($alias . ": invalid domain");
			}

			$aliases = (array)$this->get_service_value('aliases', 'aliases');
			$aliases[] = $alias;

			return $this->set_config_journal('aliases', 'enabled', 1) &&
				$this->set_config_journal('aliases', 'aliases', $aliases);
		}

		protected function _verify($domain)
		{
			if ($this->shared_domain_exists($domain)) {
				return error("domain `$domain' exists");
			}

			if ($this->shared_domain_hosted($domain)) {
				return error("`%s': domain is already hosted by another account", $domain);
			}

			if (!DOMAINS_DNS_CHECK) {
				return true;
			}

			if (!$this->dns_domain_on_account($domain) /** domain under same invoice */ &&
				!$this->_verify_dns($domain) && !$this->_verify_url($domain)
			) {
				$nameservers = $this->dns_get_authns_from_host($domain);
				$cpnameservers = $this->dns_get_hosting_nameservers();
				$hash = $this->challenge_token($domain);
				$script = $hash . '.html';
				return error("`%s': domain has DNS records delegated to nameservers %s. " .
					"Domain cannot be added to this account for security. Complete one of the following options to " .
					"verify ownership:" . "\r\n\r\n" .
					"(1) Change nameservers to %s within the domain registrar" . "\r\n" .
					"(2) Upload a html file to your old hosting provider accessible via http://%s/%s with the content:\r\n\t%s" . "\r\n" .
					"(3) Create a temporary DNS record named %s.%s with an `A' resource record that points to %s" . "\r\n\r\n" .
					"Please contact your previous hosting provider for assistance with performing any of " .
					"these verification options.",
					$domain,
					join(", ", $nameservers),
					join(", ", $cpnameservers),
					$domain,
					$script,
					$hash,
					self::DNS_VERIFICATION_RECORD,
					$domain,
					$this->common_get_ip_address()
				);
			}
			return true;
		}

		/**
		 * Ensure a domain is not already hosted through Apis
		 *
		 * @param $domain
		 * @return bool domain can be hosted
		 */
		protected function _verify_dns($domain)
		{
			/*
			 * workaround for account migrations which
			 * duplicate domains across multiple servers
			 * that no longer have DNS properly delegated
			 *
			 * @XXX DNS checks can be bypassed via API: BAD
			 */
			if ($this->_is_bypass($domain)) {
				return true;
			}
			// domain not hosted, 5 second timeout
			$ip = silence(function() use ($domain) {
				return parent::__call('dns_gethostbyname_t', [$domain, 5000]);
			});
			if (!$ip) {
				return true;
			}
			$myip = $this->common_get_ip_address();

			if ($ip === $myip) {
				// domain is on this server and would appear in db lookup check
				return true;
			}
			if ($this->domain_is_delegated($domain)) {
				return true;
			}
			$record = self::DNS_VERIFICATION_RECORD . '.' . $domain;
			$tmp = $this->dns_gethostbyname_t($record, 1500);
			if ($tmp && $tmp == $myip) {
				return true;
			}
			return false;
		}

		/**
		 * Verify that a domain is delegated to hosting nameservers
		 *
		 * @param $domain
		 * @return int
		 */
		protected function domain_is_delegated($domain)
		{
			if ($this->dns_domain_uses_nameservers($domain)) {
				return true;
			}
			$ns = $this->dns_get_authns_from_host($domain);
			// no nameservers set, treat this as addable
			// some nameservers return records, some fail if the
			// target domain is not registered... may need workaround in future
			// query WHOIS?
			if (is_null($ns)) {
				return -1;
			}
			$hostingns = $this->dns_get_hosting_nameservers();
			// uses at least 1 of the required nameservers, we're good

			foreach ($ns as $n) {
				if (in_array($n, $hostingns)) {
					return 1;
				}
			}
			return 0;
		}

		/**
		 * Check to bypass addon domain DNS validation test
		 *
		 * @param string $domain
		 * @return bool domain is bypassed
		 */
		protected function _is_bypass($domain)
		{
			if (defined('DOMAINS_DNS_CHECK') && !constant('DOMAINS_DNS_CHECK')) {
				return true;
			}
			if (!file_exists(self::BYPASS_FILE)) {
				return false;
			}

			$recs = file(self::BYPASS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

			return (false !== ($line = array_search($domain, $recs)));
		}

		protected function _verify_url($domain)
		{
			$hash = $this->challenge_token($domain);
			$url = 'http://' . $domain . '/' . $hash . '.html';
			if (extension_loaded('curl')) {
				$adapter = new HTTP_Request2_Adapter_Curl();
			} else {
				$adapter = new HTTP_Request2_Adapter_Socket();
			}

			$http = new HTTP_Request2(
				$url,
				HTTP_Request2::METHOD_GET,
				array(
					'adapter' => $adapter,
				)
			);

			try {
				$response = $http->send();
				$code = $response->getStatus();
				switch ($code) {
					case 200:
						break;
					case 403:
						return error("Verification URL request forbidden by server");
					case 404:
						return false;
					case 302:
						return error("Verification URL request moved to different location, ",
							$response->getDefaultReasonPhrase());
					default:
						return error("Verification URL request failed, code `%d': %s",
							$code, $response->getReasonPhrase());
				}
				$content = $response->getBody();
			} catch (HTTP_Request2_Exception $e) {
				return error("Fatal error retrieving verification URL: `%s'", $e->getMessage());
			}
			return trim(strip_tags($content)) == $hash;
		}

		private function _create_doc_root($path)
		{
			// sync up file cache
			$this->file_purge();
			if (!file_exists($this->domain_fs_path() . '/' . $path)) {
				$gid = $this->group_id;
				if (preg_match('!^/home/([^/]+)/!', $path, $user)) {
					$user = $user[1];
					$users = $this->user_get_users();
					$uid = $users[$user]['uid'];
					if ($uid < 500) {
						return error($user . ": user unknown in system");
					}
				} else {
					$uid = $this->user_id;
				}
				$fullpath = $this->domain_fs_path() . '/' . $path;
				if (!mkdir($fullpath)) {
					return error("z'huh!? failed to create doc root?");
				}
				chown($fullpath, (int)$uid);
				chgrp($fullpath, (int)$gid);
				$index = $fullpath . '/index.html';
				$template = '/etc/virtualhosting/templates/apache/var/www/html/index.html';
				if (file_exists($template)) {
					copy($template, $index);
					chown($index, (int)$uid);
					chgrp($index, (int)$gid);
				}


			}
			return file_exists($this->domain_fs_path() . '/' . $path);
		}

		/**
		 * Remove domain from apache map
		 *
		 * @param  string $domain
		 * @param  string $path
		 * @return bool
		 */
		private function _remove_apache_map($domain)
		{
			$domain = strtolower($domain);
			$map_file = $this->_map_path();
			if (file_exists($map_file)) {
				$map = file_get_contents($map_file);
			} else {
				$map = '';
			}

			file_put_contents($map_file,
				preg_replace('/^' . preg_quote($domain, '/') . '\b.+$[\r\n]*/m', '', $map)
			);
			$db = \Opcenter\Map::load(\Opcenter\Map::DOMAIN_MAP, 'wd');
			$db->delete($domain);
			$db->close();
			return $this->_generate_map();
		}

		/**
		 * Rebuild domain map
		 *
		 * @return bool
		 */
		private function _generate_map()
		{

			$map_file = $this->_map_path();
			$output_file = self::CONFIG_DB_DIR . '/' . $this->site;
			file_exists($output_file) && unlink($output_file);
			$proc = Util_Process::exec('httxt2dbm -f DB -i %s -o %s',
				$map_file,
				$output_file
			);
			return $proc['success'];
		}

		/**
		 * Add domain to apache map
		 *
		 * @param  string $domain
		 * @param  string $path
		 * @return bool
		 */
		private function _add_apache_map($domain, $path)
		{
			$domain = strtolower($domain);
			$map_file = $this->_map_path();
			if (!file_exists($this->domain_fs_path() . $path)) {
				warn($path . ': directory does not exist');
			}
			$map = '';
			if (file_exists($map_file)) {
				$map = file_get_contents($map_file);
			}
			$path = rtrim($path, '/');
			if (!preg_match('/^' . preg_quote($domain) . '\b.+$[\r\n]*/m', $map)) {
				$map .= $domain . ' ' . $this->domain_fs_path() . $path . "\n";
			}
			file_put_contents($map_file, $map);
			return $this->_generate_map();
		}

		/**
		 * Remove a domain from DNS bypass check
		 *
		 * @param  string $domain
		 * @return bool
		 */
		private function _remove_bypass($domain)
		{
			if (!file_exists(self::BYPASS_FILE)) {
				return true;
			}

			$recs = file(self::BYPASS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

			if (false === ($line = array_search($domain, $recs))) {
				return -1;
			}

			unset($recs[$line]);
			if (count($recs) < 1) {
				// save a few cpu cycles
				unlink(self::BYPASS_FILE);
			} else {
				file_put_contents(self::BYPASS_FILE, join($recs, "\n"));
			}
			return true;
		}

		private function _change_owner($domain, $user)
		{
			$users = $this->user_get_users();
			if (!isset($users[$user])) {
				return error("user `$user' not found");
			}
			$map = $this->_load_map();
			if (!array_key_exists($domain, $map)) {
				return error("domain `$domain' not found in domain map");
			}

			$path = $map[$domain];
			return $this->file_chown($path, $user, true);
		}

		private function _change_path($domain, $newpath)
		{
			$map = $this->_load_map();
			if (!array_key_exists($domain, $map)) {
				return error("domain `$domain' not found in domain map");
			} else if (!preg_match(Regex::ADDON_DOMAIN_PATH, $newpath)) {
				return error($newpath . ": invalid path");
			}
			$oldpath = $map[$domain];
			if (!$this->_remove_apache_map($domain)) {
				return false;
			}
			if (!file_exists($this->domain_fs_path() . $newpath)) {
				$this->_create_doc_root($newpath);
			}
			if (!$this->_add_apache_map($domain, $newpath)) {
				// domain addition failed - revert
				$this->_add_apache_map($domain, $oldpath);
				return error("domain `$domain' path change failure - reverting");
			}
			$meta = \Module\Support\Webapps\MetaManager::instantiateContexted($this->getAuthContext());
			$meta->rename($oldpath, $newpath);
			return true;

		}

		private function _change_domain($domain, $newdomain)
		{
			$map = $this->_load_map();
			if (!array_key_exists($domain, $map)) {
				return error("domain `$domain' not found in domain map");
			}
			$map = $this->_load_map();
			$path = $map[$domain];
			$ret = $this->remove_shared_domain($domain)
				&& $this->_synchronize_changes() &&
				$this->add_shared_domain($newdomain, $path);
			if ($ret) {
				warn("activate configuration changes for new domain to take effect");
			}
			return $ret;
		}

		private function _synchronize_changes()
		{
			if (file_exists($this->domain_info_path() . '/suspended')) {
				return error('account is suspended, will not resync');
			}
			$cmd = new Util_Account_Editor($this->getAuthContext()->getAccount());
			// pull in latest, unsynchronized config from new/
			$cmd->importConfig();
			$status = $cmd->edit();
			if (!$status) {
				return error("failed to activate domain changes");
			}
			info("Hang tight! Domain changes will be active within a few minutes, but may take up to 24 hours to work properly.");
			$this->getAuthContext()->importAccount()->reset();
			return true;
		}

		private function _load_map()
		{
			$domains = array();
			$file = $this->_map_path();
			if (!file_exists($file)) {
				return $domains;
			}
			$map = file_get_contents($file);
			$regex = '!(?<domain>' . Regex::recompose(Regex::DOMAIN, '!') . ')' .
				'\b\s+(?::(?<type>.):(?<url>.+)|' . $this->domain_fs_path() . '(?<path>/.+))$!m';
			if (!preg_match_all($regex, $map, $matches, PREG_SET_ORDER)) {
				return $domains;
			}

			foreach ($matches as $match) {
				$domain = $match['domain'];
				$site = isset($match['path']) ? $match['path'] : $match['url'];
				$domains[$domain] = rtrim($site, '/');
			}
			return $domains;
		}

		private function _map_path()
		{
			return $this->domain_info_path() . '/domain_map';
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}

		public function _create_user(string $user)
		{
			// TODO: Implement _create_user() method.
		}

		public function _delete_user(string $user)
		{
			// TODO: Implement _delete_user() method.
		}


	}