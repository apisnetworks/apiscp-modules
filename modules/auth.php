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
     * Provides authorization mechanisms and management
     *
     * @package core
     */
    class Auth_Module extends Module_Support_Auth
    {
        const API_KEY_LIMIT = 10;
        const API_USER_SYNC_COMMENT = "apnscp user sync";
        // override in effect, don't report
        const PWOVERRIDE_KEY = 'pwoverride';
        // recognized browser storage key, cookies don't like "."
        const LOGIN_KEY = 'sectoken';

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
                'change_username'   => PRIVILEGE_SITE,
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
            } else {
                if ($this->is_demo()) {
                    return error("cannot change password in demo mode");
                }
            }
            $crypted = $this->crypt($password);
            return $this->change_cpassword($crypted, $user, $domain);
        }

        public function password_permitted($password, $user = null)
        {
            if (is_debug()) {
                return true;
            }
            if (!$user) {
                $user = $this->username;
            }
            $disallowed = array(
                'test',
                'password',
                'letmein',
                'qwerty',
                '1234',
                '12345',
                '123456',
                $user
            );
            if (false !== array_search($password, $disallowed) || strlen($password) < 7) {
                return error("password is weak");
            } else {
                if (preg_match('/.{0,4}' . $user . '.{0,4}/i', $password)) {
                    return error("password cannot be same as username");
                }
            }
            /**
             * At least 7 characters long + require 2 of 3 classes:
             * - at least 1 uppercase
             * - at least 1 lowercase
             * - at least 1 numeric
             */
            return true;
        }

        /**
         * Encrypt a password using the strongest hash
         *
         * @param type $password
         * @param type $salt
         */
        public function crypt($password, $salt = null)
        {
            if (!$salt) {
                $salt = $this->_generate_salt();
            } else {
                if ($salt[0] != '$') {
                    return error("malformed salt `%s'", $salt);
                } else {
                    if (!$this->_hash_support($salt[1])) {
                        return error("unknown hash requested `%s'", $salt[1]);
                    } else {
                        return crypt($password, $salt);
                    }
                }
            }
            // let the API autoselect the best possible hash
            $platform_hashes = array(
                'CRYPT_SHA512'   => '6',
                'CRYPT_SHA256'   => '5',
                'CRYPT_BLOWFISH' => '2a',
                'CRYPT_MD5'      => '1'
            );
            $hash = $marker = null;
            foreach ($platform_hashes as $h => $m) {
                if ($this->_hash_supported($m)) {
                    $hash = $h;
                    $marker = $m;
                    break;
                }
            }
            if (!$hash) {
                return error("no suitable hashes supported on platform");
            }
            $salt = '$' . $marker . '$' . $salt;
            return crypt($password, $salt);
        }

        public function change_cpassword($cpassword, $user = null, $domain = null)
        {
            if ($this->is_demo()) {
                return error("demo account password changes disabled");
            }

            if (!IS_CLI) {
                $ret = $this->query('auth_change_cpassword', $cpassword, $user, $domain);
                if (!$ret || $this->get_service_value('siteinfo', self::PWOVERRIDE_KEY)) {
                    return $ret;
                } else {
                    if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
                        // admin password changed
                        parent::sendNotice(
                            'password',
                            $this->get_config('siteinfo', 'email'),
                            Auth::client_ip()
                        );
                    }
                }
                \apnscpSession::invalidate_by_user($this->site_id, $this->username, true);
                return $ret;
            }

            if ($user && $this->permission_level & PRIVILEGE_USER) {
                return error("insufficient privileges to specify user");
            }

            if (!$user) {
                $user = $this->username;
            }
            if (!$domain) {
                $domain = $this->domain;
            }

            if ($this->permission_level & PRIVILEGE_SITE) {
                $users = $this->user_get_users();
                if (!isset($users[$user])) {
                    return error($user . ": user not found");
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
                return file_exists($this->domain_info_path() . '/disabled');
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
         * @return string 256-bit SOAP key
         */
        public function create_api_key($comment = null)
        {
            for ($i = 0, $rand = ""; $i < 16; $i++) {
                $rand .= mt_rand(0, 256);
            }
            if (strlen($comment) > 255) {
                warn("api key comment truncated beyond 255 characters");
            }
            $key = hash("sha256", uniqid($rand, true));
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
				`username` = '" . $this->username . "'
				AND " . $qfrag['where'] . " GROUP BY (api_key)");

            if ($rs->num_rows > self::API_KEY_LIMIT) {
                return error("%d key limit reached", self::API_KEY_LIMIT);
            }
            $q = "INSERT INTO `api_keys` " .
                "(`api_key`, `server_name`, `username`, `site_id`, `invoice`)" .
                "VALUES (?,'" . SERVER_NAME_SHORT . "',?,?,?)";
            $stmt = $db->prepare($q);
            if ($this->permission_level & PRIVILEGE_ADMIN) {
                $site_id = null;
                $invoice = null;
            } else {
                if ($this->permission_level & PRIVILEGE_RESELLER) {
                    $site_id = null;
                    $invoice = $this->billing_get_invoice();
                } else {
                    $site_id = $this->site_id;
                    $invoice = $this->billing_get_invoice();
                }
            }
            $stmt->bind_param("ssds", $key, $this->username, $site_id, $invoice);
            if (!$stmt->execute()) {
                return error("unable to add key");
            }
            if ($comment) {
                $this->set_api_key_comment($key, $comment);
            }
            return $key;
        }

        /**
         * Alter a comment attached to an API key
         *
         * @param string $key
         * @param string $comment
         * @return bool
         */
        public function set_api_key_comment($key, $comment = null)
        {
            $key = str_replace('-', '', strtolower($key));
            if (!ctype_xdigit($key)) {
                return error($key . ": invalid key");
            }


            if (strlen($comment) > 255) {
                warn("comment truncated to max length 255 characters");
            }
            $db = Auth_SOAP::get_api_db();
            $qfrag = $this->_getAPIQueryFragment();
            $rs = $db->query("UPDATE `api_keys` " . $qfrag['join'] .
                "SET comment = '" . $db->escape_string($comment) . "'
				WHERE `api_key` = '" . strtolower($key) . "'
				AND " . $qfrag['where'] . "
				AND `username` = '" . $this->username . "';");
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
            $data = array();
            if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
                if (!$this->site) {
                    return false;
                }
                $fp = fopen($this->domain_fs_path() . '/etc/shadow', 'r');
                if (!$fp) {
                    return false;
                }
                while (!feof($fp)) {
                    $data = explode(':', trim(fgets($fp)));
                    if ($data[0] == $this->username) {
                        break;
                    }
                }
            } else {
                $fp = fopen('/etc/opcenter/webhost/passwd', 'r');
                $data = explode(':', trim(fread($fp, 1024)));
                if ($data[0] != $this->username) {
                    return false;
                }
            }
            fclose($fp);
            if (!$data) {
                return false;
            }
            if (!isset($data[1])) {
                $str = $this->domain_fs_path() . '/etc/shadow' . "\r\n" .
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
            $limitStr = '';
            if (!is_null($limit) && $limit < 100) {
                $limit = intval($limit);
            } else {
                $limit = 10;
            }
            $limitStr = 'LIMIT ' . ($limit + 1);

            $q = $this->mysql->query("SELECT
				UNIX_TIMESTAMP(`login_date`) AS login_date,
				INET_NTOA(`ip`) AS ip FROM `login_log`
				WHERE
				`domain` = '" . $this->domain . "'
				AND `username` = '" . $this->username . "'
				ORDER BY id DESC " . $limitStr);
            $q->fetch_object();

            while (($data = $q->fetch_object()) != false) {
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
            return $this->user_permitted($user, $svc);
        }

        public function user_permitted($user, $svc = 'cp')
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
            return Util_Pam::check_entry($user, $svc);
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
                        $this->get_config('siteinfo', 'email'),
                        Auth::client_ip()
                    );
                    $this->_purgeLoginKey($this->username, $olddomain);
                }
                return $ret;
            }

            if ($this->is_demo()) {
                return error("domain change disabled for demo");
            }

            $domain = strtolower($domain);
            if (substr($domain, 0, 4) == "www.") {
                $domain = substr($domain, 4);
            }
            if ($domain == $this->domain) {
                return error("new domain is equivalent to old domain");
            } else {
                if (!preg_match(Regex::DOMAIN, $domain)) {
                    return error("`%s': invalid domain", $domain);
                } else {
                    if (!is_debug() && $this->dns_domain_hosted($domain, true)) {
                        // permit user to rehost a previously hosted domain if it is on the same account
                        return error("`%s': cannot add domain - hosted on another " .
                            "account elsewhere", $domain);
                    } else {
                        if ($this->aliases_shared_domain_exists($domain)) {
                            return error("`%s': domain already hosted on account - " .
                                "remove before adding", $domain);
                        } else {
                            if ($this->web_subdomain_exists($domain)) {
                                return error("cannot promote subdomain `%s' to domain", $domain);
                            } else {
                                if (!$this->aliases_bypass_exists($domain) &&
                                    $this->dns_gethostbyname_t($domain) != $this->common_get_ip_address() &&
                                    $this->dns_get_records_external('', 'any', $domain) &&
                                    !$this->dns_domain_uses_nameservers($domain) // whois check in the future
                                ) {
                                    $currentns = join(",", $this->dns_get_authns_from_host($domain));
                                    $hostingns = join(",", $this->dns_get_hosting_nameservers());
                                    return error("domain uses third-party nameservers - %s, change nameservers to %s before promoting " .
                                        "this domain to primary domain status", $currentns, $hostingns);
                                }
                            }
                        }
                    }
                }
            }
            // alternatively use $this->set_config_journal() and require a sync
            $proc = new Util_Account_Editor();
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
         */
        public function change_username($user)
        {
            if (!IS_CLI) {
                $olduser = $this->username;
                $ret = $this->query('auth_change_username', $user);
                if ($ret && $this->permission_level & PRIVILEGE_SITE && $olduser == $this->username) {
                    // admin password changed
                    parent::sendNotice(
                        'username',
                        $this->get_config('siteinfo', 'email'),
                        Auth::client_ip()
                    );
                    $this->_purgeLoginKey($olduser, $this->domain);
                }
                return $ret;
            }

            if ($this->is_demo()) {
                return error("username change disabled for demo");
            }
            $user = strtolower($user);

            // make sure user list is not cached
            $this->user_flush();
            if (!preg_match(Regex::USERNAME, $user)) {
                return error("invalid new username `%s'", $user);
            } else {
                if (!$this->_username_unique($user)) {
                    return error("requested username `%s' in use on another account", $user);
                } else {
                    if ($this->user_exists($user)) {
                        return error("requested username `%s' already exists on this account", $user);
                    }
                }
            }
            $proc = new Util_Account_Editor();
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
         * @param type   $limit
         * @param type   $password
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

            if (substr($site, 0, 4) != "site") {
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
            $editor = new Util_Account_Editor($site);
            $ret = $editor->setMode('edit')->setConfig('siteinfo', self::PWOVERRIDE_KEY, true)
                ->setConfig('siteinfo', 'cpasswd', $crypted)->edit();
            //if (!$ret) {
            // once Image/Augend go, we can use the above
            //$editor = Util_Process_Safe::exec('chroot %(path)s usermod -p %(passwd)s %(user)s', $args);
            if (!$ret) {
                return error("failed to set temp password: `%s'", Error_Reporter::get_last_msg());
            }
            $siteconf = str_replace("/fst", "/info/current/siteinfo", $args['path']);
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
                $editor = new Util_Account_Editor($site);
                $editor->setMode('edit')->setConfig('siteinfo', 'cpasswd', $oldcrypted)->
                setConfig('siteinfo', self::PWOVERRIDE_KEY, false);
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

        public function _delete()
        {
            foreach ($this->get_api_keys() as $key) {
                $this->delete_api_key($key['key']);
            }
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
            } else {
                if ($user) {
                    if (!$this->user_exists($user)) {
                        return error("user `%s' does not exist", $user);
                    }
                }
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

        public function _edit()
        {
            $conf_new = Auth::profile()->conf->new;
            $conf_cur = Auth::profile()->conf->cur;
            $user = array(
                'old' => $conf_cur['siteinfo']['admin_user'],
                'new' => $conf_new['siteinfo']['admin_user']
            );
            if ($user['old'] == $user['new']) {
                return;
            }
            return $this->_edit_wrapper($user['old'], $user['new']);
        }

        public function deny_user($user, $svc = 'cp')
        {
            return Util_Pam::remove_entry($user, 'cp');
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
            return Util_Pam::add_entry($user, $svc);
        }

        public function _edit_user($user, $newuser)
        {
            return $this->_edit_wrapper($user, $newuser);
        }

        public function _reset(Util_Account_Editor &$editor = null)
        {
            $module = 'siteinfo';
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
            $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            $salt = '';
            // 16 is max length for sha512. crypt() will truncate to acceptable
            // length, with 8 being the smallest
            for ($i = 0, $len = strlen($chars) - 1; $i < CRYPT_SALT_LENGTH; $i++) {
                $r = random_int(0, $len);
                $salt .= $chars[$r];
            }
            return $salt;
        }

        /**
         * Check if requested hash is supported
         *
         * @param int $version @link crypt(5)
         * @return bool
         */
        private function _hash_supported($version)
        {
            switch ($version) {
                case 6:
                    $hash = 'CRYPT_SHA512';
                    break;
                case 5:
                    $hash = 'CRYPT_SHA256';
                    break;
                case 2:
                    $hash = 'CRYPT_BLOWFISH';
                    break;
                case 1:
                    $hash = 'CRYPT_MD5';
                    break;
                default:
                    return false;

            }
            return defined($hash) && constant($hash);
        }

        private function _change_cpassword_raw($cpassword, $user = null, $domain = null)
        {

            if ($cpassword[0] != '$' || ($cpassword[2] != '$' && $cpassword[3] != '$')) {
                // blowfish uses 2x notation
                return error("password must be encrypted via crypt()");
            } else {
                if (!in_array($cpassword[1], array("1", "2", "5", "6"))) {
                    /**
                     * Supported crypt types from crypt(3)
                     */
                    return error("invalid crypt type `%s'", $cpassword[1]);
                }
            }


            $cmd = '';
            $user = strtolower($user);

            if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
                // end-users are requesting a pw change
                // we still need to chroot to the proper filesystem path
                $cmd .= '/usr/sbin/chroot ' . $this->domain_fs_path() . ' ';
            } else {
                // otherwise we're changing the admin or reseller password...
            }

            $cmd .= "/usr/sbin/usermod -p %(passwd)s %(user)s";
            $args = array(
                'passwd' => $cpassword,
                'user'   => $user
            );
            $status = Util_Process_Safe::exec($cmd, $args);
            return $status['success'];
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
                $qfrag['join'] = "JOIN domain_information ON (domain_information.di_invoice = api_keys.invoice AND domain_information.parent_domain IS NULL)";
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
            $chars = "abcdefABCDEF123456789";
            $password = '';
            for ($i = 0, $char_len = strlen($chars) - 1; $i < 8; $i++) {
                $r = mt_rand(0, $char_len);
                $password .= $chars[$r];
            }
            return $password;
        }

        /**
         * Get shadow entry for site admin
         *
         * A nasty kludge
         *
         * @todo remove once user role switching is implemented
         * @param int $site
         */
        private function _get_site_admin_shadow($site_id)
        {
            $site = 'site' . intval($site_id);
            $base = '/home/virtual/' . $site . '/fst';
            $file = '/etc/shadow';
            $admin = Auth::get_admin_from_site_id($site_id);
            if (!file_exists($base . $file)) {
                fatal("shadow not found for `%s'", $site);
            }
            $shadow = null;
            $fp = fopen($base . $file, 'r');
            do {
                $line = fgets($fp);
                $tok = strtok($line, ":");
                if ($tok != $admin) {
                    continue;
                }
                $shadow = strtok(":");
                break;
            } while (!feof($fp));
            fclose($fp);
            if (!$shadow) {
                fatal("admin `%s' not found for `%s'", $admin, $site);
            }
            return $shadow;
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
            $db = $this->mysql;
            foreach ($this->_get_api_keys_real($userold) as $key) {
                $q = $db->query("UPDATE api_keys SET `username` = '" . $db->escape_string($usernew) . "' " .
                    "WHERE api_key = '" . $key['key'] . "' AND `username` = '" . $db->escape_string($userold) . "'"
                );
            }
            // @XXX centralize logins
            /*$q = $db->query("UPDATE login_log SET `username` = '" . $db->escape_string($usernew) . "' " .
                "WHERE `username` = '" . $db->escape_string($userold) . "' AND domain IS NULL");*/


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
            return array('cp');
        }

        public function _housekeeping() {
            // ensure reset wrapper is always up to date, should be a
            // git hook, but to-do
            $rstwrapper = INCLUDE_PATH . '/bin/scripts/reset_password';
            chown($rstwrapper, 'root');
            chgrp($rstwrapper, 'nobody');
            chmod($rstwrapper, 04750);
        }
    }

?>
