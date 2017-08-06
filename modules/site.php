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
     * Provides site administrator-specific functionality
     *
     * @package core
     *
     */
    class Site_Module extends Module_Support_Auth
    {
        const MIN_STORAGE_AMNESTY = QUOTA_STORAGE_WAIT;

        // time in seconds between amnesty requests
        const AMNESTY_DURATION = QUOTA_STORAGE_DURATION;
        // 24 hours
        const AMNESTY_MULTIPLIER = QUOTA_STORAGE_BOOST;

        // increase storage by 100% max
        private $user_srvc_cache = array();

        /**
         * {{{ void __construct(void)
         *
         * @ignore
         */
        public function __construct()
        {
            parent::__construct();
            $this->exportedFunctions = array(
                '*'               => PRIVILEGE_SITE,
                'get_admin_email' => PRIVILEGE_SITE | PRIVILEGE_USER,
                'ip_address'      => PRIVILEGE_SITE | PRIVILEGE_USER,
                'split_hostname'  => PRIVILEGE_SITE | PRIVILEGE_USER
            );
        }

        /**
         * bool user_service_enabled(string, string)
         *
         * @param string $mUser username
         * @param string $mSrvc service name, possible values are ssh proftpd and imap
         * @return bool
         */
        public function user_service_enabled($user, $service)
        {
            $svc_cache = $this->user_svc_cache;
            $svc_file = $this->domain_fs_path() . '/etc/' . $service . '.pamlist';
            $site = $this->site_id;

            if (!file_exists($svc_file)) {
                return new ArgumentError("Invalid service name " . $service);
            }

            /** check local cache */
            if (!isset($svc_cache[$site]) ||
                filemtime($svc_file) > $svc_cache[$site]['mtime']
            ) {
                $fp = fopen($svc_file, 'r');
                $contents = fread($fp, filesize($svc_file));
                foreach (explode("\n", $contents) as $line) {
                    $svc_cache[$site]['users'][trim($line)][$service] = 1;
                }

                fclose($fp);
                $svc_cache[$site]['mtime'] = filemtime($svc_file);
            }

            return isset($svc_cache[$site]['users'][$user][$service]);

        }


        /**
         * array get_user_count ()
         * Finds the number of users currently on an account and the maximum
         * number permitted.
         *
         * @deprecated     1.0 Use User::get_user_count()
         * @return array users: users present on the account
         *                 total:total number permitted
         */
        public function get_user_count()
        {
            deprecated(__FUNCTION__ . " will be removed.  Use User::get_user_count()");
            return $this->user_get_user_count();
        }


        /**
         *  array get_bandwidth_usage(string)
         *
         * @privilege PRIVILEGE_SITE
         * @param int $type type of bandwidth usage to retrieve
         * @return array indexes begin, rollover, and threshold
         */
        public function get_bandwidth_usage($type = null)
        {
            $site_id = $this->site_id;
            if (!$site_id) {
                Error_Reporter::report(var_export($this, true));
            }
            switch ($type) {
                case null:
                    $bw_rs = $this->pgsql->query("SELECT
						begindate,
						rollover,
						threshold as threshold
						FROM bandwidth_spans
						JOIN bandwidth USING (site_id)
						WHERE
						bandwidth_spans.site_id = " . $site_id . "
						AND
						bandwidth_spans.enddate IS NULL
						AND
						bandwidth.site_id = " . $site_id);
                    if (!$bw_rs) {
                        return array('used' => 0, 'total' => -1);
                    }
                    $bw_rs = $bw_rs->fetch_object();
                    // @BUG account has no bandwidth enddate
                    if (!$bw_rs || !$bw_rs->begindate) {
                        $ret = $this->_autofix_bandwidth($site_id, $this->get_service_value('bandwidth', 'rollover'));
                        if (!$ret) {
                        	warn("failed to autofix bandwidth for site `%d'", $this->site_id);
                            return false;
                        }
                        return $this->get_bandwidth_usage($type);
                    }

                    $used_rs = $this->pgsql->query("SELECT
						SUM(in_bytes)+SUM(out_bytes) AS sum
						FROM
						bandwidth_log
						WHERE
						site_id = " . $this->site_id . "
						AND
						ts >= '" . $bw_rs->begindate . "'");
                    return array(
                        'used'  => (float)$used_rs->fetch_object()->sum,
                        'total' => (float)($bw_rs ? $bw_rs->threshold : -1)
                    );
                    break;
                default:
                    return error("Unknown bandwidth type " . $type);
            }
        }

        /* }}} */


        private function _autofix_bandwidth($site, $rollover)
        {
            $db = $this->pgsql;
            $site = intval($site);
            $ts = mktime(0, 0, 0, date("m"), $rollover);
            $ts2 = strtotime('last month', $ts);
            if ($ts > time()) {
                $ts = $ts2;
            }
            $res = $db->query("INSERT INTO bandwidth_spans (site_id, begindate, enddate) VALUES($site, TO_TIMESTAMP($ts), NULL);");
            return !(bool)pg_last_error();
        }

        // {{{ get_bandwidth_rollover()

        /**
         * Retrieve day on which banwidth rolls over to 0
         *
         * @return int
         */
        public function get_bandwidth_rollover()
        {
            $rollover = $this->get_service_value('bandwidth', 'rollover');
            $localtime = localtime(time(), true);
            $today = date('j');
            $month = ($rollover < $today ? ($localtime['tm_mon'] + 1) : $localtime['tm_mon']);
            return mktime(0, 0, 0, ++$month, $rollover);

        }

        // }}}

        /**
         * bool set_admin_email(string email)
         *
         * @privilege PRIVILEGE_SITE
         * @return bool true on success, false on failure
         * @param string $email e-mail address to update the record to
         *                      Backend PostgreSQL operation to update it in the db
         */
        public function set_admin_email($email)
        {
            if (!preg_match(Regex::EMAIL, $email)) {
                return error("Invalid e-mail address, " . $email);
            }
            $oldemail = $this->get_config('siteinfo', 'email');
            $this->pgsql->query("UPDATE siteinfo SET email = '" . $email . "' WHERE site_id = '" . $this->site_id . "';");
            // no need to trigger a costly account config rebuild
            $this->set_config('siteinfo', 'email', $email);

            $ret = $this->pgsql->affected_rows() > 0;
            if (!$ret) {
                return false;
            }
            parent::sendNotice('email', $oldemail, Auth::client_ip());
            return true;
        }

        public function get_admin_email()
        {
            return $this->get_config('siteinfo', 'email');
        }


        /* }}} */

        /**
         * array get_users()
         *
         * @deprecated 1.0 {@see User_Module::get_users()}
         */
        public function get_users()
        {
            deprecated(__FUNCTION__ . " will be removed.  Use User::get_users()");
            return $this->user_get_users();

        }
        /* }}} */

        // {{{ ip_address()

        /**
         * Get IP address attached to account
         *
         * @return string
         */
        public function ip_address()
        {
            $addr = $this->get_service_value('ipinfo', 'namebased') ?
                $this->get_service_value('ipinfo', 'nbaddrs') :
                $this->get_service_value('ipinfo', 'ipaddrs');

            return is_array($addr) ? array_pop($addr) : $addr;
        }

        // }}}

        // {{{ split_hostname()

        /**
         * Split hostname into subdomain + domain components
         *
         * @deprecated @see Web_Module::split_host()
         *
         * @param string $hostname
         * @return array
         */
        public function split_hostname($hostname)
        {
            deprecated_func("use web_split_host()");
            return $this->web_split_host($hostname);
        }

        // }}}

        /**
         * Get quota for an account
         *
         * qused: disk quota used
         * qsoft: disk quota soft limit
         * qhard: disk quota hard limit
         * fused: files used
         * fsoft: files soft limit
         * fhard: files hard limit
         *
         * @see User_Module::get_quota()
         * @return array
         */
        public function get_account_quota()
        {
            if (!IS_CLI) {
                return $this->query('site_get_account_quota');
            }
            // occasionally a stale .socket mountpoint is reflected in quota
            // and emits stderr, squelch this
            $quota_rep = Util_Process::exec('quota -w -g ' . $this->group_id,
                array('mute_stderr' => true)
            );
            if (!preg_match(Regex::QUOTA_USRGRP, $quota_rep['output'], $quota)) {
                warn("quota output error");
                return array();
            }

            return array(
                'qused' => (int)$quota['qused'],
                'qsoft' => (int)$quota['qsoft'],
                'qhard' => (int)$quota['qhard'],
                'fused' => (int)$quota['fileused'],
                'fsoft' => (int)$quota['filesoft'],
                'fhard' => (int)$quota['filehard']
            );
        }

        /**
         * Get port range allocated to account
         *
         * @return array
         */
        public function get_port_range()
        {
            if (!$this->get_service_value('ssh', 'enabled')) {
                return array();
            }
            $fmt = array('4%03u0', '4%03u9');
            $prettify = function ($p) use ($fmt) {
                return array(
                    sprintf($fmt[0], $p),
                    sprintf($fmt[1], $p)
                );
            };
            if (platform_version() < 5) {
                $site = $this->site_id;
                return $prettify($site);
            }

            $ports = $this->get_service_value('ssh', 'port_index');

            if (is_array($ports)) {
                return array_map($prettify, $ports);
            }
            return $prettify($ports);
        }

        /**
         * Wipe an account, reinitializing it to its pristine state
         *
         * @param string $token confirmation token
         * @return bool
         */
        public function wipe($token = null)
        {
            $token = strtolower($token);
            $calctoken = $this->_calculateToken($this->site);
            if (!$token) {
                // allow wiping via AJAX, Account > Settings
                if (defined('AJAX') && AJAX) {
                    return $calctoken;
                }
                $msg = "This is the most nuclear of options. " .
                    "Respond with the following token `%s' to confirm";
                return warn($msg, $calctoken);
            }

            if ($token !== $calctoken) {
                $msg = "provided token `%s' does not match confirmation token `%s'";
                return error($msg, $token, $calctoken);
            }

            if (!IS_CLI) {
                return $this->query('site_wipe', $token);
            }

            $editor = new Util_Account_Editor();
            // assemble domain creation cmd from current config
            $editor->importConfig();
            $afi = apnscpFunctionInterceptor::init();
            $modules = $afi->list_all_modules();
            $auth = Auth::get_driver()->profile();
            foreach ($modules as $m) {
                $c = $afi->get_class_from_module($m);
                $class = new $c;
                // CLI doesn't populate session id, user params automatically
                $class->set_session_id($this->session_id);
                $class->set_user_parameters($auth);
                $class->_reset($editor);
            }
            $addcmd = $editor->setMode('add')->getCommand();
            // send a copy of the command in case the account gets wiped and
            // never comes back from the dead
            Mail::send(Crm_Module::COPY_ADMIN, "Account Wipe", $addcmd);
            $delproc = new Util_Account_Editor();
            $site_id = $this->site_id;
            if (!$delproc->delete()) {
                return false;
            }
            apnscpSession::invalidate_by_site_id($site_id);
            $proc = new Util_Process_Schedule('now');
            $ret = $proc->run($addcmd);
            return $ret['success'];
        }

        /**
         * Token confirmation to delete site
         *
         * @param string $site
         * @return string
         */
        private function _calculateToken($site)
        {

            $inode = fileinode($this->domain_info_path());
            $hash = hash('crc32', $inode);
            return $hash;
        }

        /**
         * Request a temporary bump to account storage
         *
         * @see MIN_STORAGE_AMNESTY
         * @return bool
         */
        public function storage_amnesty()
        {
            if (!IS_CLI) {
                return $this->query('site_storage_amnesty');
            }

            $last = $this->common_get_service_value('diskquota', 'amnesty');
            $now = coalesce($_SERVER['REQUEST_TIME'], time());
            if (self::MIN_STORAGE_AMNESTY > ($now - $last)) {
                $aday = self::MIN_STORAGE_AMNESTY / 86400;
                return error("storage amnesty may be requested once every %d days, %d days remaining",
                    $aday,
                    $aday - ceil(($now - $last) / 86400)
                );
            }

            $storage = $this->common_get_service_value('diskquota', 'quota');
            $newstorage = $storage * self::AMNESTY_MULTIPLIER;
            $acct = new Util_Account_Editor();
            $acct->setConfig('diskquota', 'quota', $newstorage)->
            setConfig('diskquota', 'amnesty', $now);
            $ret = $acct->edit();
            if ($ret !== true) {
                Error_Reporter::report(var_export($ret, true));
                return error("failed to set amnesty on account");
            }
            $acct->setConfig('diskquota', 'quota', $storage);
            $cmd = $acct->getCommand();
            $proc = new Util_Process_Schedule('+' . self::AMNESTY_DURATION . ' seconds');
            $ret = $proc->run($cmd);
            $msg = sprintf("Domain: %s\r\nSite: %d\r\nServer: %s", $this->domain, $this->site_id, SERVER_NAME_SHORT);
            Mail::send(Crm_Module::COPY_ADMIN, "Amnesty Request", $msg);
            return $ret['success'];
        }

        /**
         * Account is under amnesty
         *
         * @return bool
         */
        public function amnesty_active()
        {
            $time = isset($_SERVER['REQUEST_TIME']) ? $_SERVER['REQUEST_TIME'] : time();
            $amnesty = $this->get_service_value('diskquota', 'amnesty');
            return ($time - $amnesty) <= self::AMNESTY_DURATION;
        }

        public function find_and_store($base = '/{home,usr/local,var/www,var/lib,var/log}')
        {
            $cache = Cache_Account::spawn();
            $key = 'fas';

            Util_Filesystem_Collector::collect();

        }

	    public function _create()
	    {
		    $conf = Auth::conf('siteinfo');
		    $db = \Opcenter\Map::load(\Opcenter\Map::DOMAIN_MAP, 'wd');
		    if (!$db->exists($conf['domain'])) {
			    // @TODO remove once Opcenter is done
			    $db->set($conf['domain'], $this->site);
		    }
		    $db->close();
	    }

	    public function _delete()
	    {
		    $db = \Opcenter\Map::load(\Opcenter\Map::DOMAIN_MAP, 'wd');
		    $domain = array_get(Auth::conf('siteinfo'), 'domain', []);
		    $db->delete($domain);
		    $db->close();
	    }

	    public function _edit() {
            $new = Auth::conf('siteinfo', 'new');
            $cur = Auth::conf('siteinfo', 'cur');
            if ($new['domain'] === $cur['domain']) {
            	return;
            }
            // domain rename
            $db = \Opcenter\Map::load(\Opcenter\Map::DOMAIN_MAP, 'wd');
            $db->delete($cur['domain']);
            $db->insert($new['domain'], $this->site);
            $db->close();
	    }
    }