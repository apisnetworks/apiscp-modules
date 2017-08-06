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
     * Logfile manipulation and management
     *
     * @package core
     */
    class Logs_Module extends Module_Skeleton
    {
        /**
         * {{{ void __construct(void)
         *
         * @ignore
         */
        public function __construct()
        {
            parent::__construct();
            $this->exportedFunctions = array(
                '*' => PRIVILEGE_SITE
            );
        }

        /* }}} */

        public function get_webserver_log_usage()
        {
            if (!file_exists($this->domain_fs_path() . '/var/log/httpd/')) {
                return 0;
            }

            $dh = opendir($this->domain_fs_path() . '/var/log/httpd/');
            $size = 0;
            while (($file = readdir($dh)) !== false) {
                if ($file == '.' || $file == '..') {
                    continue;
                }
                $size += (filesize($this->domain_fs_path() . '/var/log/httpd/' . $file) / 1024);
            }
            closedir($dh);
            return $size;
        }

        /**
         * array list_logfiles()
         *
         * @return array
         */
        public function list_logfiles()
        {
            $logs = array();
            $path = $this->web_site_config_dir() . '/custom_logs';
            if (!file_exists($path)) {
                $logs['*']['*'] = 'access_log';
                return $logs;
            }
            $logdata = file_get_contents($path);
            $logs = $this->render_log_data_as_array($logdata);

            return $logs;
        }

        /**
         * bool add_logfile(string, string, string)
         *
         * @param string $domain
         * @param string $subdomain
         * @param string $file
         * @return bool
         */
        public function add_logfile($domain, $subdomain, $file)
        {
            if (!IS_CLI) {
                return $this->query('logs_add_logfile', $domain, $subdomain, $file);
            }
            if ($domain != "*" && !preg_match(Regex::HTTP_HOST, $domain)) {
                return error($domain . ": invalid domain");
            } else {
                if ($subdomain && $subdomain != "*" && !preg_match(Regex::SUBDOMAIN, $subdomain)) {
                    return error($subdomain . ": invalid subdomain");
                } else {
                    if (!preg_match(Regex::HTTP_LOG_FILE, $file)) {
                        return error($file . ": Invalid logfile");
                    }
                }
            }

            $data = array();
            $path = $this->web_site_config_dir() . '/custom_logs';
            if (!file_exists($path)) {
                $data['*']['*'] = 'access_log';
            } else {
                $logdata = file_get_contents($path);
                $data = $this->render_log_data_as_array($logdata);
            }
            if (isset($data[$domain]) && isset($data[$domain][$subdomain])) {
                // @BUG warn generates error on pb when going from backend to gui
                return warn("profile for " . $subdomain . ($subdomain ? "." : '') . $domain . " exists");
            }
            $data[$domain][$subdomain] = $file;

            return file_put_contents($logdata, $this->render_array_as_log_data($data), LOCK_EX) &&
                touch($this->domain_fs_path() . '/var/log/httpd/' . $file) &&
                chown($this->domain_fs_path() . '/var/log/httpd/' . $file, $this->user_id) &&
                chgrp($this->domain_fs_path() . '/var/log/httpd/' . $file, $this->group_id) &&
                chown($this->domain_fs_path() . '/etc/logrotate.d/apache', 'root') &&
                chgrp($this->domain_fs_path() . '/etc/logrotate.d/apache', $this->group_id) &&
                $this->add_log_rotation_profile('/var/log/httpd/' . $file, 'apache');
        }

        /**
         * bool add_log_rotation_profile(string)
         *
         * @param string $mLog log name, relative to /var/log/httpd/
         * @return bool
         */
        public function add_log_rotation_profile($log, $profile = 'apache')
        {
            if (!IS_CLI) {
                return $this->query('logs_add_log_rotation_profile', $log, $profile);
            }
            $log = str_replace('..', '', $log);
            if (!preg_match(Regex::HTTP_LOG_FILE, $log)) {
                return error("Invalid logfile `$log'");
            } else {
                if (!preg_match('/^[A-Z0-9_]+$/i', $profile) ||
                    !file_exists($this->domain_fs_path() . '/etc/logrotate.d/' . $profile)
                ) {
                    return error("Invalid service `$profile'");
                }
            }

            $data = file_get_contents($this->domain_fs_path() . '/etc/logrotate.d/' . $profile);
            if (preg_match('!\s*' . $log . '\s*(?:\s|{)!', $data)) {
                return true;
            }

            // TODO: Raise a warning instead if duplicate log rotation profile exists
            // return new FileError("Rotation profile for ".$log." already exists");
            $data = rtrim($data) . "\n" . $log . " {\n\tmissingok\n}";
            file_put_contents($this->domain_fs_path() . '/etc/logrotate.d/' . $profile, $data, LOCK_EX);
            return true;

        }

        /**
         * bool remove_logfile(string, string)
         *
         * @param string $domain
         * @param string $subdomain
         * @return bool
         */
        public function remove_logfile($domain, $subdomain)
        {
            if (!IS_CLI) {
                return $this->query('logs_remove_logfile', $domain, $subdomain);
            }
            $path = $this->web_site_config_dir() . '/custom_logs';
            $data = file_get_contents($path);
            $data = $this->render_log_data_as_array($data);

            if (!isset($data[$domain]) && !isset($data[$domain][$subdomain])) {
                return warn("Log profile not found for " . $subdomain . "." . $domain);
            }
            $log_file = '/var/log/httpd/' . $data[$domain][$subdomain];

            unset($data[$domain][$subdomain]);
            // no more logs left on the domain
            if (sizeof($data[$domain]) == 0) {
                unset($data[$domain]);
            }
            file_put_contents($path, $this->render_array_as_log_data($data), LOCK_EX);

            $this->remove_log_rotation_profile($log_file, 'apache');

            foreach (glob($this->domain_fs_path() . $log_file . '{,.gz,.[1-4],.[1-4].gz}', GLOB_BRACE) as $log) {
                unlink($log);
            }

            return true;
        }

        /**
         * bool remove_log_rotation_profile(string)
         *
         * @param string $mLog log name, relative to /var/log/httpd/
         * @return bool
         */
        public function remove_log_rotation_profile($log, $profile = 'apache')
        {
            if (!IS_CLI) {
                return $this->query('logs_remove_log_rotation_profile', $log, $profile);
            }
            $log = str_replace('..', '', $log);
            if (!preg_match(Regex::HTTP_LOG_FILE, $log)) {
                return error("Invalid logfile");
            } else {
                if (!preg_match('/^[A-Z0-9_]+$/i', $profile) ||
                    !file_exists($this->domain_fs_path() . '/etc/logrotate.d/' . $profile)
                ) {
                    return error("Invalid service type");
                }
            }

            $data = file_get_contents($this->domain_fs_path() . '/etc/logrotate.d/' . $profile);
            $data_new = preg_replace('!^\s*' . $log . '\s*{[^}]+[\r\n]+}$!m', '', $data);
            if ($data == $data_new) {
                return warn("no such log `" . basename($log) . "' found for service " . $profile);
            }
            file_put_contents($this->domain_fs_path() . '/etc/logrotate.d/' . $profile,
                $data_new,
                LOCK_EX);

            return true;

        }

        /**
         * Validate logrotate configuration
         *
         * @return int 0 on err, 1 on clean syntax, -1 on clean but invalid syntax
         */
        public function validate_config()
        {
            if (!IS_CLI) {
                return $this->query('logs_validate_config');
            }
            $proc = new Util_Process_Chroot($this->domain_fs_path());
            $ret = $proc->run('/usr/sbin/logrotate %s %s', ['-d', '/etc/logrotate.conf']);
            // additional non-fatal markup can appear in logrotate config, logrotate -d
			// returns 0 irrespective on v6 platforms, 1 on error on v6.5+ platforms...
	        // including case below; manually parse debug output
            $errs = array();
            foreach (explode("\n", $ret['stderr']) as $line) {
                if (0 !== strpos($line, "error:")) {
	                continue;
                } else if (0 === strpos($line, "error: error opening /")) {
	                /**
	                 * even if missingok is set, logrotate will complain
	                 * if a file to be removed is missing in dry-run mode
	                 */
                    continue;
                }
                $errs[] = $line;
                warn($line);
            }
            return count($errs) === 0;
        }

        public function set_logrotate($data)
        {
            if (!IS_CLI) {
                return $this->query('logs_set_logrotate', $data);
            }

            $file = $this->domain_fs_path() . '/etc/logrotate.conf';
            $old = file_get_contents($file);
            file_put_contents($file, $data);
            if (!$this->validate_config()) {
                file_put_contents($file, $old);
                return false;
            }
            return true;
        }

        private function render_log_data_as_array($data)
        {
            $logs = $envmap = array();
            $lines = explode("\n", $data);
            $domains = $this->web_list_domains();
            for ($i = 0, $n = sizeof($lines); $i < $n; $i++) {
                $line = $lines[$i];
                $directive = strtolower(strtok($line, " "));

                if ($directive == 'setenvifnocase') {
                    preg_match('/^\s*SetEnvIfNoCase\s+Host\s+\(?(\.?[^\.]+)\.\)?\??([\S]+)\s+(.+)$/i', $line,
                        $lineCapture);
                    $subdomain = str_replace(array('.*', '\\'), array('*', ''), $lineCapture[1]);
                    $domain = str_replace(array('.*', '\\'), array('*', ''), $lineCapture[2]);
                    $env = $lineCapture[3];
                    $envmap[$env] = array('subdomain' => $subdomain, 'domain' => $domain);
                } else {
                    if ($directive == 'customlog') {
                        $logpath = strtok(" ");
                        $logfile = substr($logpath, strrpos($logpath, '/') + 1);
                        $logtype = strtok(" ");
                        $env = strtok(" ");
                        if (!$env) {
                            $logs['*'] = array('*' => $logfile);
                            continue;
                        }
                        $pos = strpos($env, '=');
                        if ($pos !== false) {
                            $env = substr($env, $pos + 1);
                        }
                        if (isset($envmap[$env])) {
                            $subdomain = $envmap[$env]['subdomain'];
                            $domain = $envmap[$env]['domain'];
                        } else {
                            if (substr($env, 0, 2) == 'L-') {

                                $subdomain = str_replace('_', '.', substr($env, 2));
                                if ($subdomain[0] == '.' || strpos($subdomain, '.') !== false) {
                                    // domain fall-through or local subdomain

                                    $components = $this->web_split_host(ltrim($subdomain, '.'));
                                    $domain = $components['domain'];
                                    if ($subdomain[0] == '.') {
                                        // domain fall-through
                                        $subdomain = '*';
                                    } else {
                                        // local subdomain
                                        if ($components) {
                                            $subdomain = $components['subdomain'];
                                        } else {
                                            $domain = substr($subdomain, strpos($subdomain, '.') + 1);
                                            $subdomain = substr($subdomain, 0, strpos($subdomain, '.'));
                                        }
                                    }
                                } else {
                                    // global subdomain
                                    $domain = '*';
                                }
                            } else {
                                error("Unknown log identifier `$env'");
                                continue;
                            }
                        }
                        if (!isset($logs[$domain])) {
                            $logs[$domain] = array();
                        }
                        $logs[$domain][$subdomain] = $logfile;
                    }
                }
            }
            return $logs;
        }

        /**
         * The expected format is as follows:
         * Numerically indexed array, which gives log position, each
         * element is an array itself with the indexes subdomain, domain, and file
         */
        private function render_array_as_log_data(array $data)
        {
            /**
             * logfile is just created, once we do this we lose the wildcard
             * piped logging feature, so make a case to catch the rest
             */
            $txt = '<IfDefine !SLAVE>' . "\n";

            foreach ($data as $domain => $logs) {
                foreach ($logs as $subdomain => $file) {
                    /**
                     * SetEnvIfNoCase Host <subdomain>.<domain> <subdomain>_<domain>
                     * Substitute [*.] with _ so the env variable name doesn't puke
                     */
                    $env = 'env=L-';
                    list($subdomain, $domain) = str_replace('.', '_', array($subdomain, $domain));
                    if ($subdomain == '*') {
                        if ($domain == '*') {
                            $env = '';
                        } else {
                            $env .= '_' . $domain;
                        }
                    } else {
                        if ($subdomain) {
                            $env .= $subdomain . '.';
                        }
                        if ($domain != '*') {
                            $env .= $domain;
                        }
                    }

                    $env = str_replace(
                        array('*', '.'),
                        '_',
                        $env
                    );
                    $txt .= 'CustomLog ' . $this->domain_fs_path() . '/var/log/httpd/' . $file . ' combined ' . $env . "\n";
                }
            }
            return $txt . "ErrorLog " . $this->domain_fs_path() . '/var/log/httpd/error_log' . "\n</IfDefine>";
        }
    }

?>
