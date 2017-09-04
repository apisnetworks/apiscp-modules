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
     * Provides common functionality associated with the crontab interface
     *
     * @package core
     */
    class Crontab_Module extends Module_Skeleton
    {
        const CRON_SPOOL = '/var/spool/cron';

        /**
         * {{{ void __construct(void)
         *
         * @ignore
         */
        public function __construct()
        {
            parent::__construct();
            $this->exportedFunctions = array(
                'permit_user'    => PRIVILEGE_SITE,
                'deny_user'      => PRIVILEGE_SITE,
                'user_permitted' => PRIVILEGE_SITE | PRIVILEGE_USER,
                'toggle_status'  => PRIVILEGE_SITE,
                'reload'         => PRIVILEGE_SITE,
                'list_users'     => PRIVILEGE_SITE,
                '*'              => PRIVILEGE_SITE | PRIVILEGE_USER,
            );
        }

        /** }}} */


        public function list_cronjobs($user = null)
        {
            deprecated_func("use list_jobs()");
            return $this->list_jobs($user);
        }

        /**
         * List scheduled tasks
         *
         * Invokes crontab -l from the shell and returns the output as an associative
         *
         * @return array
         */
        public function list_jobs($user = null)
        {
            if (!IS_CLI) {
                return $this->query('crontab_list_jobs', $user);
            }

            if (!$this->get_service_value("ssh", "enabled")) {
                return error("cronjob requires ssh");
            } else {
                if (!$this->enabled()) {
                    return error("cron daemon is not running");
                }
            }

            if ($this->permission_level & PRIVILEGE_USER) {
                $user = $this->username;
            } else {
                if (!$user) {
                    $user = $this->username;
                } else {
                    if (!$this->_valid_user($user)) {
                        return error("`%s': unknown or system user", $user);
                    }
                }
            }

            if (!$this->user_permitted($user)) {
                return error("user `%s' not permitted to schedule tasks", $user);
            }

            $spool = $this->get_spool_file($user);
            if (!file_exists($spool)) {
                return array();
            }
            $fp = fopen($spool, 'r');
            $cronjobs = array();
            while (false !== ($line = fgets($fp))) {
                if (!preg_match(Regex::CRON_TASK, $line, $matches)) {
	                continue;
                }
                if (!empty($matches['token'])) {
                    list($min, $hour, $dom, $month, $dow) = $this->_parseCronToken($matches['token']);
                } else {
                    $min = $matches['min'];
                    $hour = $matches['hour'];
                    $dom = $matches['dom'];
                    $month = $matches['month'];
                    $dow = $matches['dow'];
                }
                $cmd = $matches['cmd'];
                $cronjobs[] = array(
                    "minute"       => $min,
                    "hour"         => $hour,
                    "day_of_month" => $dom,
                    "month"        => $month,
                    "day_of_week"  => $dow,
                    "cmd"          => $cmd,
                    "disabled"     => (bool)$matches['disabled']
                );
            }
            return $cronjobs;
        }

        /**
         * Check if scheduled task service is enabled
         *
         * Returns true if the cron daemon is running within the environment,
         * false if not.  Note well that it will return false IF the cron daemon
         * is installed within the account, but is not running on the system.
         *
         * @privilege PRIVILEGE_SITE
         * @return bool
         */
        public function enabled()
        {
            // mounting procfs with hidepid=1 will mask crond, call as root to avoid this
            if (!IS_CLI) {
                return $this->query('crontab_enabled');
            }

            if (!$this->get_service_value("ssh", "enabled")) {
                return false;
            }
            $pid = $this->domain_fs_path() . '/var/run/crond.pid';
            if (!file_exists($pid)) {
                return false;
            }
            $proc = '/proc/' . trim(file_get_contents($pid)) . '/cmdline';
            return file_exists($proc) && basename(trim(file_get_contents($proc))) === 'crond';
        }

        public function user_permitted($user = null)
        {
            if (!$user || ($this->permission_level & PRIVILEGE_USER)) {
                $user = $this->username;
            }
            if (!$this->enabled()) {
                return false;
            }

            $file = $this->domain_fs_path() . '/etc/cron.deny';
            if (!file_exists($file)) {
                return true;
            }
            $fp = fopen($file, 'r');
            $found = true;
            while (false !== ($line = fgets($fp))) {
                $line = trim($line);
                if ($line == $user) {
                    $found = false;
                    break;
                }
            }
            fclose($fp);

            return $found;
        }

        /**
         * @deprecated
         * @see enabled()
         */
        public function crontab_enabled()
        {
            deprecated_func("use enabled()");
            return $this->enabled();
        }

        public function disable_job(
            $min,
            $hour,
            $dom,
            $month,
            $dow,
            $cmd,
            $user = null
        ) {
            if (!IS_CLI) {
                return $this->query('crontab_disable_job', $min, $hour, $dom,
                    $month, $dow, $cmd, $user);
            }

            if ($this->permission_level & PRIVILEGE_USER) {
                $user = $this->username;
            } else {
                if (!$user) {
                    $user = $this->username;
                } else {
                    if (!$this->_valid_user($user)) {
                        return error("`%s': unknown or system user", $user);
                    }
                }
            }
            $contents = explode("\n", $this->_getCronContents($user));
            $found = false;
            $timespec = $min . " " . $hour . " " . $dom . " " . $month . " " . $dow;
            $match = rtrim($timespec) . " " . $cmd;
            $new = array();
            foreach ($contents as $line) {
                if (!$found && $line === $match) {
                    $found = true;
                    $line = '#' . $line;
                }
                $new[] = $line;
            }
            if (!$found) {
                warn("requested cron `%s' not matched", $match);
            }
            return $this->_setCronContents(join("\n", $new), $user);
        }

        public function add_raw($line, $user = null)
        {

        }

        public function enable_job(
            $min,
            $hour,
            $dom,
            $month,
            $dow,
            $cmd,
            $user = null
        ) {
            if (!IS_CLI) {
                return $this->query('crontab_enable_job', $min, $hour, $dom,
                    $month, $dow, $cmd, $user);
            }

            if ($this->permission_level & PRIVILEGE_USER) {
                $user = $this->username;
            } else {
                if (!$user) {
                    $user = $this->username;
                } else {
                    if (!$this->_valid_user($user)) {
                        return error("`%s': unknown or system user", $user);
                    }
                }
            }
            $contents = explode("\n", $this->_getCronContents($user));
            $found = false;
            $timespec = $min . " " . $hour . " " . $dom . " " . $month . " " . $dow;
            $match = rtrim($timespec) . " " . $cmd;
            $new = array();
            foreach ($contents as $line) {
                if (!$line) {
                    continue;
                }
                if (!$found && $match === ($tmp = ltrim($line, "#"))) {
                    // assignment evaluated first before boolean, use $tmp
                    $found = true;
                    $new[] = $tmp;
                } else {
                    $new[] = $line;
                }
            }
            return $this->_setCronContents(join("\n", $new), $user);
        }

        public function add_cronjob(
            $min,
            $hour,
            $dom,
            $month,
            $dow,
            $cmd,
            $user = null
        ) {
            deprecated_func("use add_job()");
            return $this->add_job($min, $hour, $dom, $month, $dow, $cmd, $user);
        }

        /**
         * Schedule a periodic task
         *
         * @param mixed  $min   minute (0-59)
         * @param mixed  $hour  hour (0-23)
         * @param mixed  $dom   day of month (1-31)
         * @param mixed  $month month (1-12)
         * @param mixed  $dow   0-7 day of week
         * @param string $cmd   command
         *
         * @return bool
         */
        public function add_job(
            $min,
            $hour,
            $dom,
            $month,
            $dow,
            $cmd,
            $user = null
        ) {
            if (!IS_CLI) {
                if ($this->auth_is_demo()) {
                    return error("cronjob forbidden in demo");
                }
                return $this->query(
                    "crontab_add_job",
                    $min,
                    $hour,
                    $dom,
                    $month,
                    $dow,
                    $cmd,
                    $user
                );
            }

            if (!$this->enabled()) {
                return error("cron is not running");
            }

            if ($this->permission_level & PRIVILEGE_USER) {
                $user = $this->username;
            } else {
                if (!$user) {
                    $user = $this->username;
                } else {
                    if (!$this->_valid_user($user)) {
                        return error("`%s': unknown or system user", $user);
                    }
                }
            }

            if (!$this->user_permitted($user)) {
                return error("user `%s' not permitted to schedule tasks", $user);
            }
            if ($min[0] === '@') {
                list($min, $hour, $dom, $month, $dow) = $this->_parseCronToken($min);
            } /*else {
				if ($min < 0 || $min > 59) {
					return error("bad time spec, min out of boundary [0,59], got %d", $min);
				} else if ($hour < 0 || $hour > 23) {
					return error("bad time spec, hour out of bounddary [0,23], got %d", $min);
				}
			}*/

            if (!$cmd) {
                return error("no command specified");
            }

            // Make sure this isn't a duplicate
            $jobs = $this->list_jobs($user);
            foreach ($jobs as $j) {
                if ($j['minute'] == $min &&
                    $j['hour'] == $hour &&
                    $j['day_of_month'] == $dom &&
                    $j['month'] == $month &&
                    $j['day_of_week'] == $dow &&
                    $j['cmd'] == $cmd
                ) {
                    return error("duplicate job already scheduled: `%s'", $cmd);
                } else {
                    if ($j['cmd'] == $cmd) {
                        warn("similar job scheduled: `%s'", $cmd);
                    }
                }
            }
            // list_jobs() won't include
            $contents = rtrim($this->_getCronContents($user));
            $contents .= "\n" . $min . " " . $hour . " " . $dom . " " . $month . " " . $dow . " " . $cmd . "\n";
            return $this->_setCronContents($contents, $user);
        }

        /**
         * Set the recipient for cronjob-generated output
         *
         * @param  string $address e-mail address
         * @return bool
         */
        public function set_mailto($address)
        {

        }

        /**
         * Get the recipient e-mail for cronjob-generated output
         *
         * @return string
         */
        public function get_mailto()
        {

        }

        public function delete_cronjob(
            $min,
            $hour,
            $dom,
            $month,
            $dow,
            $cmd,
            $user = null
        ) {
            deprecated_func("use delete_job()");
            return $this->delete_job($min, $hour, $dom, $month, $dow, $cmd, $user);

        }

        /**
         * Remove a periodic task
         *
         * @param mixed  $min
         * @param mixed  $hour
         * @param mixed  $dom
         * @param mixed  $month
         * @param mixed  $dow
         * @param string $cmd
         *
         * @return bool
         *
         */
        public function delete_job(
            $min,
            $hour,
            $dom,
            $month,
            $dow,
            $cmd,
            $user = null
        ) {
            if (!IS_CLI) {
                return $this->query("crontab_delete_job", $min, $hour,
                    $dom, $month, $dow, $cmd, $user);
            }

            if (!$this->enabled()) {
                return error("crond is not enabled");
            }

            if ($this->permission_level & PRIVILEGE_USER) {
                $user = $this->username;
            } else {
                if (!$user) {
                    $user = $this->username;
                } else {
                    if (!$this->_valid_user($user)) {
                        return error("`%s': unknown or system user", $user);
                    }
                }
            }

            if (!$this->user_permitted($user)) {
                return error("user `%s' not permitted to schedule tasks", $user);
            }
            $contents = $this->_getCronContents($user);

            $spool = $this->get_spool_file($user);

            if (!file_exists($spool)) {
                return error($this->username . ": crond not active for user");
            }
            $pwd = $this->user_getpwnam($user);
            if (!$pwd) {
                return error("getpwnam() failed for user `%s'", $user);
            }
            $fp = fopen($spool, 'r');
            $tempFile = tempnam($this->domain_fs_path() . "/tmp", "apnscp");
            $tmpfp = fopen($tempFile, "w");
            $done = false;
            while (false !== ($line = fgets($fp))) {
                if (preg_match(Regex::CRON_TASK, $line, $matches)) {
                    if (!$done &&
                        $matches['cmd'] === $cmd &&
                        (isset($matches['token']) && $matches['token'] == $min ||
                            $matches['min'] == $min &&
                            $matches['hour'] == $hour &&
                            $matches['dom'] == $dom &&
                            $matches['month'] == $month &&
                            $matches['dow'] == $dow)
                    ) {
                        $done = true;
                        continue;
                    }
                }
                fwrite($tmpfp, $line);
            }
            /** and cleanup */
            fclose($tmpfp);
            fclose($fp);
            return unlink($spool) && copy($tempFile, $spool) &&
                unlink($tempFile) && chgrp($spool, (int)$pwd['uid']) &&
                chown($spool, (int)$pwd['gid']) && chmod($spool, 0600);
        }

        /**
         * Reload crond
         *
         * @see toggle_status()
         * @return bool
         */
        public function reload()
        {
            return $this->toggle_status(-1);
        }

        /**
         * List all users with an active crontab spool
         *
         * @return array
         */
        public function list_users()
        {
            $users = array();
            $dir = $this->domain_fs_path() . self::CRON_SPOOL;
            if (!file_exists($dir)) {
                return $users;
            }
            $dh = opendir($dir);
            while (false !== ($file = readdir($dh))) {
                if ($file == "." || $file == "..") {
                    continue;
                } else {
                    if (substr($file, 0, 4) == "tmp.") {
                        continue;
                    }
                }
                $users[] = $file;
            }
            closedir($dh);
            return $users;
        }

        public function _delete()
        {
            if ($this->enabled()) {
                $this->toggle_status(0);
            }
        }

        public function _create()
        {
            $conf = Auth::profile()->conf->new;
            if ($conf['ssh']['enabled']) {
                $this->_edit();
            }
        }

        public function _edit()
        {
            $conf_new = Auth::profile()->conf->new;
            $conf_old = Auth::profile()->conf->cur;
            $userold = $conf_old['siteinfo']['admin_user'];
            $usernew = $conf_new['siteinfo']['admin_user'];
            if (version_compare(platform_version(), '6.5', '>=')) {
                $spoolpath = $this->domain_shadow_path() . self::CRON_SPOOL;
                if (!file_exists($spoolpath)) {
                    mkdir($spoolpath, 0755, true);
                    chmod($spoolpath, 0700);
                    chown($spoolpath, 'root');
                }
            }

            if ($userold === $usernew) {
                return true;
            }
            return $this->_edit_user($userold, $usernew);
        }

        public function _edit_user(string $userold, string $usernew, array $oldpwd)
        {
        	if ($userold === $usernew) {
        		return;
	        }
            $oldspool = $this->get_spool_file($userold);
            $newspool = $this->get_spool_file($usernew);
            if (file_exists($oldspool)) {
                rename($oldspool, $newspool);
            }
            if (!$this->get_service_value('ssh', 'enabled')) {
                return true;
            } else {
                if (!$this->user_permitted($userold)) {
                    return true;
                }
            }

            $this->_deny_user_real($userold);
            $this->_permit_user_real($usernew);

            $this->restart();
            return true;
        }

        /**
         * Deny a user from using crontab facility
         *
         * @param string $user username
         * @return boolean
         */
        public function deny_user($user)
        {
            if (!IS_CLI) {
                return $this->query('crontab_deny_user', $user);
            }

            if (!$this->enabled()) {
                return true;
            }
            $uid = $this->user_get_uid_from_username($user);
            if (!$uid || $uid < User_Module::MIN_UID) {
                return error("user `%s' is system user or does not exist", $user);
            }
            return $this->_deny_user_real($user);
        }

        /**
         * Permit a user access to crontab
         *
         * @param string $user
         * @return boolean
         */
        public function permit_user($user)
        {
            if (!IS_CLI) {
                return $this->query('crontab_permit_user', $user);
            }

            if (!$this->enabled()) {
                return false;
            }
            $uid = $this->user_get_uid_from_username($user);
            if (is_int($uid) && $uid < User_Module::MIN_UID) {
                return error("user `%s' is system user", $user);
            } else {
                if (!$uid) {
                    warn("user `%s' does not exist", $user);
                }
            }
            return $this->_permit_user_real($user);
        }

        public function restart()
        {
            if (!$this->get_service_value('ssh', 'enabled')) {
                return error("crond not enabled for account");
            }
            if ($this->enabled()) {
                $this->toggle_status(0);
            } else {
                warn("crond was not running");
            }
            return $this->toggle_status(1);
        }

        /**
         * Toggle cronjob status
         *
         * Possible modes:
         *    -1: reload
         *     0: kill and remove
         *     1: enable
         *
         * @param int $status status flag [-1,0,1]
         * @return bool
         */
        public function toggle_status($status)
        {
            if (!IS_CLI) {
                return $this->query("crontab_toggle_status", (int)$status);
            }
            if (!$this->get_service_value("ssh", "enabled")) {
                return error("prerequisite ssh not satisfied");
            } else {
                if ($status != -1 && $status != 0 && $status != 1) {
                    return error("%s: invalid args passed to %s", $status, __FUNCTION__);
                }
            }
            $pid_file = $this->domain_fs_path() . '/var/run/crond.pid';
            $kill_cmd = '/bin/kill -%s `cat ' . $pid_file . '`';
            switch ($status) {
                case 1:
                    if (!file_exists($this->domain_fs_path() . '/usr/sbin/crond')) {
                        Util_Process::exec('/root/replicatedomain.sh vixie-cron ' . $this->domain);
                    }
                    if (platform_version() < 5) {
                        $cmd = '/sbin/initlog -q -c \'nice -20 /usr/sbin/crond\'';
                    } else {
                        $cmd = '/bin/sh -c \'nice -20 /usr/sbin/crond\'';
                    }
                    $status = Util_Process::exec('/usr/sbin/chroot %s %s',
                        $this->domain_fs_path(),
                        $cmd,
                        array(
                            'mute_stderr' => true
                        )
                    );
                    return $status['success'];
                case 0:
                    if (!file_exists($pid_file)) {
                        return error("/var/run/crond.pid: file not found");
                    }
                    $status = Util_Process::exec($kill_cmd,
                        9);
                    if (version_compare(platform_version(), '4.5') < 0) {
                        unlink($this->domain_fs_path() . '/usr/sbin/crond');
                        unlink($this->domain_fs_path() . '/usr/bin/crontab');
                    }
                    return $status['success'];
                case -1:
                    if (!file_exists($pid_file)) {
                        return error("/var/run/crond.pid: file not found");
                    }
                    $status = Util_Process::exec($kill_cmd, 'HUP');
                    return $status['success'];
                default:
                    return error($status . ": invalid parameter passed");
            }
        }

        protected function _deny_user_real($user)
        {
            $file = $this->domain_fs_path() . '/etc/cron.deny';
            if (!file_exists($file)) {
                touch($file);
            }
            $fp = fopen($file, 'a+');
            $users = array();
            while (false !== ($line = fgets($fp))) {
                $line = trim($line);
                if ($line == $user) {
                    continue;
                }
                $users[] = $line;
            }
            $users[] = $user;
            ftruncate($fp, 0);
            fwrite($fp, join($users, "\n"));
            fclose($fp);
            return true;
        }

        protected function _permit_user_real($user)
        {
            $file = $this->domain_fs_path() . '/etc/cron.deny';
            if (!file_exists($file)) {
                return true;
            }
            $fp = fopen($file, 'a+');
            $users = array();
            while (false !== ($line = fgets($fp))) {
                $line = trim($line);
                if ($line == $user) {
                    continue;
                }
                $users[] = $line;
            }
            ftruncate($fp, 0);
            fwrite($fp, join($users, "\n"));
            fclose($fp);
            return true;
        }

        private function _valid_user($user)
        {
            $uid = $this->user_get_uid_from_username($user);
            return $uid && $uid > User_Module::MIN_UID;
        }

        /**
         * Get absolute path to crontab spool file
         *
         * @return string
         */
        private function get_spool_file($user = null)
        {
            if (!$user || ($this->permission_level & PRIVILEGE_USER)) {
                $user = $this->username;
            }
            return $this->domain_fs_path() . self::CRON_SPOOL . '/' . $user;
        }

        /**
         * Parse crontab @token into corresponding time
         *
         * @param $token @token [@reboot, @yearly, @weekly, @monthly, @daily, @hourly]
         * @return array
         */
        private function _parseCronToken($token)
        {
            $min = $hour = $dom = $month = $dow = '';
            $hash = $this->site_id % 60;
            $hash2 = $this->site_id % 24;
            $expand = array(0 => $hash, 1 => $hash2, 2 => '*', 3 => '*', 4 => '*');
            switch ($token) {
                case '@reboot':
                    return array($token, '', '', '', '');
                case '@yearly':
                case '@annually':
                    $expand[3] = date('M');
                    return $expand;
                case '@weekly':
                    $expand[4] = '0';
                    return $expand;
                case '@monthly':
                    $expand[2] = '1';
                    return $expand;
                case '@daily':
                    return $expand;
                case '@hourly':
                    $expand[1] = '*';
                    return $expand;
                default:
                    warn("unknown crond token `$token'");
                    return $expand;

            }
        }

        private function _getCronContents($user)
        {
            $spool = $this->get_spool_file($user);

            if (!file_exists($spool)) {
                return "";
            }
            return file_get_contents($spool);
        }

        private function _setCronContents($contents, $user)
        {
            $tmpFile = tempnam($this->domain_fs_path() . "/tmp", "apnscp");
            $pwd = $this->user_getpwnam($user);
            if (!$pwd) {
                return error("getpwnam() failed for user `%s'", $user);
            }

            $fp = fopen($tmpFile, "a");
            if (!flock($fp, LOCK_EX | LOCK_NB)) {
                fclose($fp);
                return error("failed to lock cron resource for `%s'", $user);
            }
            ftruncate($fp, 0);
            fwrite($fp, $contents . "\n");
            fclose($fp);
            chmod($tmpFile, 0644);
            $sudo = new Util_Process_Sudo();
            $sudo->setUser($user . '@' . $this->domain);
            $retData = $sudo->run("crontab %s ",
                '/tmp/' . basename($tmpFile));
            unlink($tmpFile);
            return $retData['success'] ? true :
                error("failed to set cron contents for `%s': %s", $user, $retData['error']);
        }
    }