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
	 * Provides authorization mechanisms and management
	 *
	 * @package core
	 */
	class Auth_Module extends Module_Support_Auth implements \Opcenter\Contracts\Hookable
	{
		const DEPENDENCY_MAP = [
			'siteinfo', 'users'
		];
		const RESET_WRAPPER = INCLUDE_PATH . '/bin/scripts/reset_password';
		const API_KEY_LIMIT = 10;
		const API_USER_SYNC_COMMENT = "apnscp user sync";
		// override in effect, don't report
		const PWOVERRIDE_KEY = 'pwoverride';
		// recognized browser storage key, cookies don't like "."
		const LOGIN_KEY = 'sectoken';
		// tunable minimum acceptable password length
		const MIN_PW_LENGTH = AUTH_MIN_PW_LENGTH;
		const ADMIN_AUTH = '/etc/opcenter/webhost/passwd';

		private static $domain_db;

		/**
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = array(
				'*'                 => PRIVILEGE_ALL,
				'verify_password'   => PRIVILEGE_SERVER_EXEC | PRIVILEGE_ALL,
				'change_domain'     => PRIVILEGE_SITE,
				'change_username'   => PRIVILEGE_SITE|PRIVILEGE_ADMIN,
				'set_temp_password' => PRIVILEGE_ADMIN
			);
		}

		private static function _connect_db()
		{
			if (!is_null(self::$domain_db) && self::$domain_db->ping()) {
				return self::$domain_db;
			}
			$db = new mysqli();
			$db->init();
			if (!$db->real_connect(AUTH_USERNAME_HOST, AUTH_USERNAME_USER, AUTH_USERNAME_PASSWORD)
				|| !$db->select_db(AUTH_USERNAME_DB)
			) {
				return error("Cannot connect to domain server at this time");
			}

			self::$domain_db = &$db;
			return $db;
		}

		/**
		 * Active session information
		 *
		 * @return array
		 */
		public function session_info()
		{
			$auth = Auth::autoload()->authInfo();
			return (array)$auth;
		}

		/**
		 * Change an account password
		 *
		 * user parameter may only be supplied by account admin
		 * domain parameter may only be supplied by server admin
		 *
		 * @param string $password
		 * @param string $user
		 * @param string $domain
		 *
		 * @return bool
		 */
		public function change_password($password, $user = null, $domain = null)
		{
			if (!$this->password_permitted($password, $user)) {
				return error("weak password disallowed");
			} else if ($this->is_demo()) {
				return error("cannot change password in demo mode");
			}
			$crypted = $this->crypt($password);
			return $this->change_cpassword($crypted, $user, $domain);
		}

		public function password_permitted($password, $user = null)
		{
			return \Opcenter\Auth\Password::strong($password, $user);
		}

		/**
		 * Encrypt a password using the strongest hash
		 *
		 * @param string $password
		 * @param string|null $salt
		 * @return string
		 */
		public function crypt($password, $salt = null)
		{
			return \Opcenter\Auth\Shadow::crypt($password, $salt);
		}

		public function change_cpassword($cpassword, $user = null, $domain = null)
		{
			if ($this->is_demo()) {
				return error("demo account password changes disabled");
			}

			$user = $user ?: $this->username;
			$domain = $domain ?: $this->domain;

			if (!IS_CLI) {
				$ret = $this->query('auth_change_cpassword', $cpassword, $user, $domain);
				if (!$ret) {
					return $ret;
				}
				if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
					if ($this->get_service_value(self::getAuthService(), self::PWOVERRIDE_KEY)) {
						return true;
					}
					// admin password changed
					$email = $this->common_get_email() ?? $this->get_config('siteinfo', 'email');
				} else if ($this->permission_level & PRIVILEGE_ADMIN) {
					$email = $this->common_get_email();
				}
				parent::sendNotice(
					'password',
					[
						'email' => $email,
						'ip' => \Auth::client_ip(),
						'username' => $user
					]
				);
				\apnscpSession::invalidate_by_user($this->site_id, $user, true);
				return $ret;
			}

			if (!\Opcenter\Auth\Shadow::valid_crypted($cpassword)) {
				return error("provided password for user `%s' is not crypted", $user);
			}
			if ($user !== $this->username && $this->permission_level & PRIVILEGE_USER) {
				return error("insufficient privileges to specify user");
			}
			if ($this->permission_level & PRIVILEGE_ADMIN) {
				if (!($fp = fopen(self::ADMIN_AUTH, 'r+')) || !flock($fp, LOCK_EX | LOCK_NB)) {
					fclose($fp);
					return error("unable to gain exclusive lock on `%s'", self::ADMIN_AUTH);
				}
				$lines = [];
				while (false !== ($line = fgets($fp))) {
					$lines[] = explode(':', rtrim($line));
				}
				if (false === ($pos = array_search($user, array_column($lines, 0)))) {
					flock($fp, LOCK_UN);
					fclose($fp);
					return error("user `%s' does not exist", $user);
				}
				$lines[$pos][1] = $cpassword;
				if (!ftruncate($fp, 0)) {
					flock($fp, LOCK_UN);
					fclose($fp);
					return error("failed to truncate `%s'", self::ADMIN_AUTH);
				}
				rewind($fp);
				fwrite($fp, implode("\n", array_map(function ($a) {
					return join(':', $a);
				}, $lines)));

				return flock($fp, LOCK_UN) && fclose($fp);
			}
			if ($this->permission_level & PRIVILEGE_SITE) {
				$users = $this->user_get_users();
				if (!isset($users[$user])) {
					return error('%s: user not found', $user);
				}
			}

			$ret = $this->_change_cpassword_raw($cpassword, $user, $domain);
			return $ret;
		}

		public function is_demo()
		{
			/**
			 * No demo for admin since it just consists of the ticket interface
			 */
			if ($this->permission_level & PRIVILEGE_ADMIN) {
				return false;
			}

			return $this->billing_get_invoice() == 'APNS-HOSTING-1111111111111111';
		}

		public function is_inactive()
		{
			if (!IS_CLI) {
				return $this->query('auth_is_inactive');
			}
			if ($this->permission_level & (PRIVILEGE_USER | PRIVILEGE_SITE)) {
				return file_exists(\Opcenter\Account\State::disableMarker($this->site));
			}
			return false;
		}

		/**
		 * Generate an API key
		 *
		 * Generates a 256-bit SOAP key for use with invoking the Web Services
		 * in apnscp esprit.  The key is a hexadecimal-encoded value traditionally
		 * split into groups of 8, or 96 bits per bunch, delimited by a '-'.  When
		 * authenticating, this is the format preferred, but this function will
		 * instead return the 512-bit key gumped into one big string.  At this time
		 * you are limited to just 10 keys.
		 *
		 * @param string $comment optional comment
		 * @param string $user optional user for site admin
		 *
		 * @return string 256-bit SOAP key
		 */
		public function create_api_key($comment = '', $user = null)
		{
			if (!$user || !($this->permission_level & PRIVILEGE_SITE)) {
				$user = $this->username;
			} else if (!$this->user_exists($user)) {
				return error("cannot set comment for key, user `%s' does not exist", $user);
			}

			if (strlen($comment) > 255) {
				warn("api key comment truncated beyond 255 characters");
			}
			$key = hash("sha256", uniqid((string)random_int(PHP_INT_MIN, PHP_INT_MAX), true));
			$invoice = null;
			if (!($this->permission_level & PRIVILEGE_ADMIN)) {
				$invoice = $this->billing_get_invoice();
				if (!$invoice) {
					return error('unable to find invoice for account');
				}
			}
			$db = Auth_SOAP::get_api_db();
			$qfrag = $this->_getAPIQueryFragment();
			$rs = $db->query("SELECT
				`api_key`
				FROM `api_keys` " .
				$qfrag['join'] .
				"WHERE
				`username` = '" . $user . "'
				AND " . $qfrag['where'] . " GROUP BY (api_key)");

			if ($rs->num_rows >= self::API_KEY_LIMIT) {
				return error("%d key limit reached", self::API_KEY_LIMIT);
			}
			$q = "INSERT INTO `api_keys` " .
				"(`api_key`, `server_name`, `username`, `site_id`, `invoice`)" .
				"VALUES (?,'" . SERVER_NAME_SHORT . "',?,?,?)";
			$stmt = $db->prepare($q);
			if ($this->permission_level & PRIVILEGE_ADMIN) {
				$site_id = null;
				$invoice = null;
			} else if ($this->permission_level & PRIVILEGE_RESELLER) {
				$site_id = null;
				$invoice = $this->billing_get_invoice();
			} else {
				$site_id = $this->site_id;
				$invoice = $this->billing_get_invoice();
			}
			$stmt->bind_param("ssds", $key, $this->username, $site_id, $invoice);
			if (!$stmt->execute()) {
				return error("unable to add key - %s", $stmt->error);
			}
			if ($comment) {
				$this->set_api_key_comment($key, $comment, $user);
			}
			return $key;
		}

		/**
		 * Alter a comment attached to an API key
		 *
		 * @param string $key
		 * @param string $comment
		 * @param string $user optional username for site admin
		 * @return bool
		 */
		public function set_api_key_comment($key, $comment = null, $user = null)
		{
			$key = str_replace('-', '', strtolower($key));
			if (!ctype_xdigit($key)) {
				return error($key . ": invalid key");
			}


			if (strlen($comment) > 255) {
				warn("comment truncated to max length 255 characters");
			}
			if (!$user || !($this->permission_level & PRIVILEGE_SITE)) {
				$user = $this->username;
			} else if (!$this->user_exists($user)) {
				return error("cannot set comment for key, user `%s' does not exist", $user);
			}
			$db = Auth_SOAP::get_api_db();
			$qfrag = $this->_getAPIQueryFragment();
			$rs = $db->query("UPDATE `api_keys` " . $qfrag['join'] .
				"SET comment = '" . $db->escape_string($comment) . "'
				WHERE `api_key` = '" . strtolower($key) . "'
				AND " . $qfrag['where'] . "
				AND `username` = '" . $user . "';");
			return $rs && $db->affected_rows > 0;
		}
		/* }}} */

		/**
		 * Verify account password
		 *
		 * @param string $password user password
		 *
		 * May not be called via SOAP.  Exclusively internal method.
		 *
		 * @return bool
		 */
		public function verify_password($password)
		{
			$file = self::ADMIN_AUTH;
			if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
				if (!$this->site) {
					return false;
				}
				$file = $this->domain_fs_path() . '/etc/shadow';
			}
			$fp = fopen($file, 'r');
			if (!$fp) {
				return false;
			}
			$data = array();
			while (false !== ($line = fgets($fp))) {
				if (0 === strpos($line, $this->username . ':')) {
					$data = explode(':', rtrim($line));
					break;
				}
			}
			fclose($fp);
			if (!$data) {
				return false;
			}

			if (!isset($data[1])) {
				$str = "Corrupted shadow: " . $file . "\r\n" .
					$this->username . "\r\n";
				Error_Reporter::report($str . "\r\n" . var_export($data, true));
				return false;
			}
			$salt = join('$', explode('$', $data[1]));
			return password_verify($password, $salt);
		}

		/* }}} */

		/**
		 * Queries the last login data for the current user.
		 *
		 * Response will be false on first login, otherwise an associative array
		 * of indexes date and IP are returned containing the date as an
		 * integer (unix timestamp) and IP address in in conventional IPv4 fashion
		 *
		 * @return mixed
		 *
		 */
		public function get_last_login()
		{
			$login = $this->get_login_history(1);
			if (!$login) {
				return array();
			}
			return $login[0];
		}

		/**
		 * Retrieves all login requests for a user
		 *
		 * Return is NULL if this is the first time logging in,
		 * otherwise an associative array of indexes date and IP are returned
		 * containing the date as an integer (unix timestamp) and IP address in
		 * in conventional IPv4 fashion
		 *
		 * @param integer $limit limit results retrieved to N resultsm
		 *
		 * @return mixed
		 *
		 */
		public function get_login_history($limit = null)
		{
			$logins = array();
			// don't display all IP addresses for security
			if ($this->is_demo()) {
				$logins[] = array(
					'ip' => Auth::client_ip(),
					'ts' => Auth::login_time()
				);
				return $logins;
			}
			if (!is_null($limit) && $limit < 100) {
				$limit = intval($limit);
			} else {
				$limit = 10;
			}
			$limitStr = 'LIMIT ' . ($limit + 1);
			$handler = \MySQL::initialize();
			$q = $handler->query("SELECT
				UNIX_TIMESTAMP(`login_date`) AS login_date,
				INET_NTOA(`ip`) AS ip FROM `login_log`
				WHERE
				`domain` = '" . $this->domain . "'
				AND `username` = '" . $this->username . "'
				ORDER BY id DESC " . $limitStr);
			$q->fetch_object();

			while (($data = $q->fetch_object()) !== null) {
				$logins[] = array(
					'ip' => $data->ip,
					'ts' => $data->login_date
				);
			}
			/** dummy request to get rid of the current session */
			//if (sizeof($logins) == 0 || !isset($logins[0]['ip']))
			//    return array();
			return $logins;

		}

		public function user_enabled($user, $svc = 'cp')
		{
			if (!in_array($svc, $this->_pam_services())) {
				return error("unknown service `$svc'");
			}
			// admin is always permitted to CP
			if ($svc == "cp" && ($this->permission_level & PRIVILEGE_SITE) &&
				$user == $this->username
			) {
				return true;
			} else {
				if ($this->permission_level & (PRIVILEGE_ADMIN | PRIVILEGE_RESELLER)) {
					return true;
				}
			}
			return (new Util_Pam($this->getAuthContext()))->check($user, $svc);
		}

		public function user_permitted($user, $svc = 'cp')
		{
			return $this->user_enabled($user, $svc);
		}

		/**
		 * Change primary account domain
		 *
		 * @param string $domain
		 */
		public function change_domain($domain)
		{
			if (!IS_CLI) {
				$olddomain = $this->domain;
				$ret = $this->query('auth_change_domain', $domain);
				if ($ret) {
					parent::sendNotice(
						'domain',
						[
							'email' => $this->get_config('siteinfo', 'email'),
							'ip' => Auth::client_ip()
						]
					);
					$this->_purgeLoginKey($this->username, $olddomain);
				}
				return $ret;
			}

			if ($this->is_demo()) {
				return error("domain change disabled for demo");
			}

			$domain = strtolower($domain);
			if (0 === strpos($domain, "www.")) {
				$domain = substr($domain, 4);
			}
			if ($domain === $this->domain) {
				return error("new domain is equivalent to old domain");
			}
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error("`%s': invalid domain", $domain);
			}
			if (!is_debug() && $this->dns_domain_hosted($domain, true)) {
				// permit user to rehost a previously hosted domain if it is on the same account
				return error("`%s': cannot add domain - hosted on another " .
					"account elsewhere", $domain);
			}
			if ($this->aliases_shared_domain_exists($domain)) {
				return error("`%s': domain already hosted on account - " .
					"remove before adding", $domain);
			}
			if ($this->web_subdomain_exists($domain)) {
				return error("cannot promote subdomain `%s' to domain", $domain);
			}
			if (!$this->aliases_bypass_exists($domain) &&
				$this->dns_gethostbyname_t($domain) != $this->common_get_ip_address() &&
				$this->dns_get_records_external('', 'any', $domain) &&
				!$this->dns_domain_uses_nameservers($domain) // whois check in the future
			) {
				$currentns = join(",", (array)$this->dns_get_authns_from_host($domain));
				$hostingns = join(",", $this->dns_get_hosting_nameservers($domain));
				return error("domain uses third-party nameservers - %s, change nameservers to %s before promoting " .
					"this domain to primary domain status", $currentns, $hostingns);
			}
			// alternatively use $this->set_config_journal() and require a sync
			$proc = new Util_Account_Editor($this->getAuthContext()->getAccount());
			$proc->setConfig('siteinfo', 'domain', $domain)->
			setConfig('proftpd', 'ftpserver', 'ftp' . $domain)->
			setConfig('apache', 'webserver', 'www.' . $domain)->
			setConfig('sendmail', 'mailserver', 'mail.' . $domain);
			return $proc->edit();
		}

		/**
		 * Change primary account username
		 *
		 * @param string $user
		 * @return bool
		 */
		public function change_username($user): bool
		{
			if (!IS_CLI) {
				$olduser = $this->username;
				$ret = $this->query('auth_change_username', $user);
				if ($ret && ($email = $this->common_get_email())) {
					// admin password changed
					parent::sendNotice(
						'username',
						[
							'email' => $email,
							'ip' => Auth::client_ip()
						]
					);
					$this->_purgeLoginKey($olduser, $this->domain);
				}
				return $ret;
			}

			if ($this->is_demo()) {
				return error("username change disabled for demo");
			}
			$user = strtolower($user);
			if (!preg_match(Regex::USERNAME, $user)) {
				return error("invalid new username `%s'", $user);
			}
			if ($this->permission_level & PRIVILEGE_ADMIN) {
				// @todo convert to Opcenter

				if (!($fp = fopen(self::ADMIN_AUTH, 'r+')) || !flock($fp, LOCK_EX|LOCK_NB)) {
					fclose($fp);
					return error("unable to gain exclusive lock on `%s'", self::ADMIN_AUTH);
				}
				$lines = [];
				while (false !== ($line = fgets($fp))) {
					$lines[] = explode(':', rtrim($line));
				}
				if (false !== ($pos = array_search($user, array_column($lines, 0)))) {
					flock($fp, LOCK_UN);
					fclose($fp);
					return error("user `%s' already exists", $user);
				}
				if (false === ($pos = array_search($this->username, array_column($lines, 0)))) {
					flock($fp, LOCK_UN);
					fclose($fp);

					return error("original user `%s' does not exist", $this->username);
				}
				$lines[$pos][0] = $user;
				if (!ftruncate($fp, 0)) {
					flock($fp, LOCK_UN);
					fclose($fp);
					return error("failed to truncate `%s'", self::ADMIN_AUTH);
				}
				rewind($fp);
				fwrite($fp, implode("\n", array_map(function ($a) { return join(':', $a); }, $lines)));
				return flock($fp, LOCK_UN) && fclose($fp);
			}
			// make sure user list is not cached
			$this->user_flush();
			if (!$this->_username_unique($user)) {
				return error("requested username `%s' in use on another account", $user);
			}
			if ($this->user_exists($user)) {
				return error("requested username `%s' already exists on this account", $user);
			}
			if (version_compare(platform_version(), '7.5', '<')) {
				// handled by Opcenter\Service\Validators\Siteinfo\AdminUser::reconfigure
				$procs = \Opcenter\Process::matchUser(
					$this->get_service_value('siteinfo', 'admin')
				);
				foreach ($procs as $proc) {
					\Opcenter\Process::kill($proc, SIGTERM);
				}
			}
			$proc = new Util_Account_Editor($this->getAuthContext()->getAccount());
			$proc->setConfig('siteinfo', 'admin_user', $user)
				->setConfig('mysql', 'dbaseadmin', $user);
			$ret = $proc->edit();

			if (!$ret) {
				return error("failed to change admin user");
			}
			return true;
		}

		/**
		 * Set a temporary password for an account
		 *
		 * @param string $site
		 * @param int    $limit
		 * @param string|null $password
		 * @return bool
		 */
		public function set_temp_password($site, $limit = 120/** time in seconds */, $password = null)
		{
			if (!IS_CLI) {
				return $this->query('auth_set_temp_password', $site, $limit, $password);
			}

			if (!$password) {
				$password = $this->_generate_password();
			}
			if (intval($limit) != $limit) {
				return error("invalid time limit `%s'", $limit);
			}

			if (substr($site, 0, 4) !== "site") {
				$tmp = Auth::get_site_id_from_domain($site);
				if (!$tmp) {
					return error("domain `%s' not found on server", $site);
				}
				$site = 'site' . $tmp;
			} else {
				$tmp = Auth::get_domain_from_site_id(substr($site, 4));
				if (!$tmp) {
					return error("site `%s' not found on server", $site);
				}
			}

			$site_id = substr($site, 4);
			$domain = Auth::get_domain_from_site_id($site_id);
			$user = Auth::get_admin_from_site_id($site_id);
			$crypted = $this->crypt($password);
			$oldcrypted = $this->_get_site_admin_shadow($site_id);
			$args = array(
				'path'   => '/home/virtual/' . $site . '/fst',
				'passwd' => $crypted,
				'user'   => $user
			);
			$accountMeta = \Auth_Info_User::initializeUser($user, \Auth::get_domain_from_site_id($site_id))->getAccount();
			$editor = new Util_Account_Editor($accountMeta);
			$ret = $editor->setMode('edit')->setConfig(self::getAuthService(), self::PWOVERRIDE_KEY, true)
				->setConfig(self::getAuthService(), 'cpasswd', $crypted)->edit();
			//if (!$ret) {
			// once Image/Augend go, we can use the above
			//$editor = Util_Process_Safe::exec('chroot %(path)s usermod -p %(passwd)s %(user)s', $args);
			if (!$ret) {
				return error("failed to set temp password: `%s'", Error_Reporter::get_last_msg());
			}
			$siteconf = str_replace("/fst", "/info/current/" . self::getAuthService(), $args['path']);
			$fp = fopen($siteconf, "a");
			if (!$fp || !flock($fp, LOCK_EX | LOCK_NB)) {
				if (is_resource($fp)) {
					fclose($fp);
				}
				return error("failed to lock siteinfo conf");
			}
			fwrite($fp, self::PWOVERRIDE_KEY . " = 1\n\n");
			flock($fp, LOCK_UN);
			fclose($fp);

			// touch siteXX/info to purge stale conf
			touch(dirname(dirname($siteconf)));

			$dt = new DateTime("now + " . intval($limit) . " seconds");
			$proc = new Util_Process_Schedule($dt);
			$key = 'RESET-' . $site_id;
			if (!$proc->idPending($key)) {
				$proc->setID($key);
				$editor = new Util_Account_Editor($accountMeta);
				$editor->setMode('edit')->setConfig(self::getAuthService(), 'cpasswd', $oldcrypted)->
				setConfig(self::getAuthService(), self::PWOVERRIDE_KEY, false);
				// runs as root, which leaves $site null, populate
				$cmd = $editor->getCommand();
				$status = $proc->run($cmd);
			} else {
				// shim a response if run multiple times
				$status = array(
					'success' => true
				);
			}

			if ($status['success']) {
				info("Password set on `%s'@`%s' to `%s' for %d seconds",
					$user,
					$domain,
					$password,
					$limit
				);
			}
			return $password;
		}

		/**
		 * array get_api_keys (void)
		 *
		 * listing all keys associated to an account:
		 *  - key: the generated key
		 *  - last_used: an integer representation of the last date the key was used.
		 *               If the key was never used, null is set for that value.
		 * Returns the list of SOAP keys associated to an account
		 *
		 * @return array
		 */
		public function get_api_keys($user = null)
		{
			if (!$user || !($this->permission_level & PRIVILEGE_SITE)) {
				$user = $this->username;
			} else if ($user && !$this->user_exists($user)) {
				return error("user `%s' does not exist", $user);
			}
			return $this->_get_api_keys_real($user);
		}

		/**
		 * Delete SOAP key
		 *
		 * The key should be in hexadecimal strictly without dashes,
		 * case does not matter.
		 *
		 * @param string $key key to delete from keyring
		 * @return bool
		 */
		public function delete_api_key($key, $user = null)
		{
			$key = str_replace('-', '', strtolower($key));
			if (!ctype_xdigit($key)) {
				return error($key . ": invalid key");
			}
			// verify key via get_api_keys() since _getAPIQueryFragment()
			// won't work in a DELETE clause
			$keys = $this->get_api_keys($user);
			if (!$keys) {
				return false;
			}
			$found = false;
			foreach ($keys as $k) {
				if ($k['key'] === $key) {
					$found = true;
					break;
				}
			}
			if (!$found) {
				return error("unknown key `%s'", $key);
			}
			$db = Auth_SOAP::get_api_db();
			$rs = $db->query("DELETE FROM `api_keys`
				WHERE `api_key` = '" . strtolower($key) . "'");
			return (bool)$rs;
		}

		public function _create()
		{
			$this->rebuildMap();
		}

		public function _edit()
		{
			$conf_new = $this->getAuthContext()->getAccount()->new;
			$conf_old = $this->getAuthContext()->getAccount()->old;
			$user = array(
				'old' => $conf_old['siteinfo']['admin_user'],
				'new' => $conf_new['siteinfo']['admin_user']
			);
			$this->rebuildMap();
			if ($user['old'] === $user['new']) {
				return;
			}
			return $this->_edit_wrapper($user['old'], $user['new']);
		}

		public function deny_user($user, $svc = 'cp')
		{
			return (new Util_Pam($this->getAuthContext()))->remove($user, $svc);
		}

		/**
		 * Permit user access to apnscp
		 *
		 * @param string $user username
		 */
		public function permit_user($user, $svc = 'cp')
		{
			if (!in_array($svc, $this->_pam_services())) {
				return error("unknown service `$svc'");
			}
			return (new Util_Pam($this->getAuthContext()))->add($user, $svc);
		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			return $this->_edit_wrapper($userold, $usernew);
		}

		public function _reset(\Util_Account_Editor &$editor = null)
		{
			$module = self::getAuthService();
			$crypted = $this->_get_site_admin_shadow($this->site_id);
			if (!$crypted) {
				fatal("call _reset() in auth from backend");
			}
			$params = array(
				'cpasswd' => $crypted
			);
			if ($editor) {
				foreach ($params as $k => $v) {
					$editor->setConfig($module, $k, $v);
				}
			}

			return array($module => $params);

		}

		protected function _get_api_keys_real($user)
		{
			$db = Auth_SOAP::get_api_db();
			$qfrag = $this->_getAPIQueryFragment();
			/**
			 * make sure only 1 key is pulled if account resides elsewhere
			 * e.g. during migration
			 */
			$q = "SELECT `api_key`,
				UNIX_TIMESTAMP(`last_used`) as last_used,
				comment
				FROM `api_keys`
				" . $qfrag['join'] . "
				WHERE
					`username` = '" . $db->escape_string($user) . "' AND " .
				$qfrag['where'] . " GROUP BY (api_key)";
			$rs = $db->query($q);
			if (!$rs) {
				return error("failed to get keys");
			}
			$keys = array();
			while ($row = $rs->fetch_object()) {
				$keys[] = array(
					'key'       => $row->api_key,
					'last_used' => $row->last_used,
					'comment'   => $row->comment
				);
			}
			return $keys;
		}

		/**
		 * Create salt used by crypt()
		 *
		 * @link _crypt_password()
		 * @return string
		 */
		private function _generate_salt()
		{
			return \Opcenter\Auth\Shadow::mksalt();
		}

		/**
		 * Check if requested hash is supported
		 *
		 * @param int|string $version @link crypt(5)
		 * @return bool
		 */
		private function _hash_supported($version)
		{
			return \Opcenter\Auth\Shadow::hash_supported((string)$version);
		}

		private function _change_cpassword_raw(string $cpassword, string $user = null, string $domain = null)
		{
			if (null === $user) {
				$user = $this->username;
			}
			$ret = \Opcenter\Auth\Shadow::bindTo($this->make_domain_fs_path($domain))->set_cpasswd($cpassword, $user);
			if ($ret) {
				$pwd = (array)$this->user_getpwnam($user);
				Util_Account_Hooks::run('edit_user', [$user, $user, $pwd]);
			}
			return $ret;
		}

		/**
		 * Assemble additional API key query restrictions
		 *
		 * @return array
		 */
		private function _getAPIQueryFragment()
		{
			$qfrag = array('where' => '1 = 1', 'join' => '');
			if ($this->permission_level & PRIVILEGE_ADMIN) {
				$qfrag['where'] = 'api_keys.invoice IS NULL AND site_id IS NULL';
			} else {
				$invoice = $this->billing_get_invoice();
				if (!$invoice) {
					error("cannot get billing invoice for API key");
					$qfrag['where'] = '1 = 0';
					return $qfrag;
				}
				$qfrag['where'] = "api_keys.invoice = '" . Auth_SOAP::get_api_db()->real_escape_string($invoice) . "'";
			}
			return $qfrag;
		}

		/**
		 * Purge browser security key
		 *
		 * @param string $user
		 * @param string $domain
		 * @return bool
		 */
		private function _purgeLoginKey($user = "", $domain = "")
		{
			// needs to be broken out into separate support function...
			$userkey = md5($user . $domain);
			$arrkey = self::LOGIN_KEY . '.' . $userkey;
			if (\Preferences::exists($arrkey)) {
				\Preferences::forget($arrkey);
			}

			return true;
		}

		/**
		 * Username is unique to a server or across all servers
		 *
		 * @param string $user
		 * @return int -1 if not globally unique
		 *  0 if not unique on server
		 *  1 if globally unique and unique on server
		 */
		private function _username_unique($user)
		{
			$user = strtolower($user);
			if (Auth::get_admin_from_site_id($user)) {
				return 0;
			}

			$db = $this->_connect_db();
			if (!$db) {
				return error("cannot connect to db");
			}
			$q = "SELECT 1 FROM account_cache where admin = '" .
				$db->real_escape_string($user) . "'";
			$rs = $db->query($q);
			return $rs->num_rows > 0 ? -1 : 1;
		}

		private function _generate_password()
		{
			return \Opcenter\Auth\Password::generate();
		}

		/**
		 * Get shadow entry for site admin
		 *
		 * A nasty kludge
		 *
		 * @todo remove once user role switching is implemented
		 * @param int $site_id
		 */
		private function _get_site_admin_shadow($site_id)
		{
			$site = 'site' . (int)$site_id;
			$base = FILESYSTEM_VIRTBASE . "/${site}/fst";
			$file = '/etc/shadow';
			$admin = Auth::get_admin_from_site_id($site_id);
			if (!file_exists($base . $file)) {
				fatal("shadow not found for `%s'", $site);
			}
			$shadow = null;
			$fp = fopen($base . $file, 'r');
			while (false !== ($line = fgets($fp))) {
				$tok = strtok($line, ":");
				if ($tok != $admin) {
					continue;
				}
				$shadow = strtok(":");
				break;
			}
			fclose($fp);
			if (!$shadow) {
				fatal("admin `%s' not found for `%s'", $admin, $site);
			}
			return $shadow;
		}

		public function _delete()
		{
			/*
			 * @todo check if account listed elsewhere, don't delete keys if
			 */
			$server = \Auth_Redirect::lookup($this->domain);
			if (!$server || $server === SERVER_NAME_SHORT) {
				foreach ($this->get_api_keys() as $key) {
					$this->delete_api_key($key['key']);
				}
			}
		}

		/**
		 * General user edit for admin and users
		 *
		 * @param $userold old username
		 * @param $usernew new username
		 * @return bool
		 */
		private function _edit_wrapper($userold, $usernew)
		{
			if ($userold === $usernew) {
				return;
			}
			$db = \MySQL::initialize();
			foreach ($this->_get_api_keys_real($userold) as $key) {
				if (!$db->query("UPDATE api_keys SET `username` = '" . $db->escape_string($usernew) . "' " .
					"WHERE api_key = '" . $key['key'] . "' AND `username` = '" . $db->escape_string($userold) . "'"
				)) {
					warn("failed to rename API keys for user `%s' to `%s'", $userold, $usernew);
				}
			}
			// @XXX centralize logins
			$invoice = $this->billing_get_invoice();
			if (!$db->query("UPDATE login_log SET `username` = '" . $db->escape_string($usernew) . "' " .
				"WHERE `username` = '" . $db->escape_string($userold) . "' AND invoice = '" . $db->escape_string($invoice)) . "'") {
				warn("failed to rename login history for user `%s' to `%s'", $userold, $usernew);
			}


			/**
			 * _edit() is called before Ensim processes any config changes
			 * including renaming the user. Pam::add_user() will elicit a
			 * warning if the user does not exist (which it doesn't yet)
			 *
			 */
			mute_warn();
			foreach ($this->_pam_services() as $svc) {
				if ($this->user_permitted($userold, $svc)) {
					$this->deny_user($userold, $svc);
					$this->permit_user($usernew, $svc);
				}
			}
			unmute_warn();
			// flush getpwnam() cache
			$this->user_flush();
			return true;
		}

		private function _pam_services()
		{
			return array('cp', 'dav');
		}

		public function _housekeeping() {
			// ensure reset wrapper is always up to date, should be a
			// git hook, but to-do
			\Opcenter\Filesystem::chogp(static::RESET_WRAPPER, 'root', WS_GID, 04750);
			// convert domain map over to TokyoCabinet
			$this->rebuildMap();
		}

		public function _create_user(string $user)
		{
			// TODO: Implement _create_user() method.
		}

		public function _delete_user(string $user)
		{
			// TODO: Implement _delete_user() method.
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}
	}