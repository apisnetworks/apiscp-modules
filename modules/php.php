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
     * Class Php_Module
     *
     * @package core
     */
    class Php_Module extends Module_Support_Php
    {
        const COMPOSER_LOCATION = '/usr/bin/composer.phar';

        public $exportedFunctions = array(
            '*'       => PRIVILEGE_SITE,
            'version' => PRIVILEGE_ALL
        );

        /**
         * Install PEAR package
         *
         * @param  string $module
         * @return bool
         */
        public function install_package($module)
        {
            if (!IS_CLI) {
                return $this->query('php_install_package', $module);
            }


            if (!preg_match('!^[a-zA-Z0-9_-]+$!', $module)) {
                return error($module . ": invalid package name");
            }

            $args = '-d display_errors=0 -d track_errors=1 -d include_path=/usr/local/share/pear:/usr/share/pear';
            if (version_compare(platform_version(), '4.5', '<')) {
                $args .= ' -d disable_functions=ini_set';
            }
            $pearcmd = '/usr/share/pear/pearcmd.php';
            $proc = Util_Process_Tee::watch(new Util_Process_Sudo);
            $proc->log("Installing " . $module);
            if (file_exists($this->domain_fs_path() . '/usr/local/share/pear/pearcmd.php')) {
                $this->_unsetPearIni();
                $pearcmd = '/usr/local/share/pear/pearcmd.php';
            }

            $status = $proc->exec("php %s %s install -f -o %s",
                $args,
                $pearcmd,
                escapeshellarg($module)
            );
            return $status['success'];
        }

        private function _unsetPearIni()
        {
            $pearfile = $this->domain_fs_path() . '/usr/local/share/pear/PEAR.php';
            if (!file_exists($pearfile)) {
                return false;
            }
            $content = file_get_contents($pearfile, 0, null, 0, 1024);
            $changed = false;
            $pos = strpos($content, 'ini_set');
            if ($pos === false) {
                return false;
            }
            $content = file_get_contents($pearfile);
            file_put_contents($pearfile, str_replace('@ini_set', '// @ini_set', $content));
            return true;
        }

        /**
         * List PEAR packages installed for account
         *
         * Keys-
         * is_local (bool) : package is local to account
         * version (double): version number
         *
         * @return array
         */
        public function list_installed_packages()
        {
            if (!IS_CLI) {
                return $this->query('php_list_installed_packages');
            }
            $status = Util_Process::exec("pear list");
            if ($status instanceof Exception) {
                return $status;
            }
            $packages = array();

            $packageSizeSys = preg_match_all('!^([^\s]+)\s+([0-9,\. ]+)!m', $status['output'], $packageMatches);

            for ($i = 1; $i < $packageSizeSys; $i++) {
                $packages[$packageMatches[1][$i]] = array('is_local' => false, 'version' => $packageMatches[2][$i]);
            }


            $status = Util_Process_Sudo::exec("pear list");
            if ($status instanceof Exception) {
                return $status;
            }
            $packageSize = preg_match_all('!^([^\s]+)\s+([0-9,\. ]+)!m', $status['output'], $packageMatches);

            for ($i = 1; $i < $packageSize; $i++) {

                $packages[$packageMatches[1][$i]] = array(
                    'is_local' => true,
                    'version'  => trim($packageMatches[2][$i])
                );
            }
            ksort($packages);
            return $packages;
        }

        /**
         * string get_pear_description (string)
         * Fetches the description for a PEAR package
         *
         * @param  string $mModule package name
         * @return string description of the package
         */

        public function package_description($mModule)
        {
            $packages = $this->list_remote_packages();
            if (!isset($packages[$mModule])) {
                return false;
            }
            return $packages[$mModule]['description'];
        }

        /**
         * array list_remote_packages (void)
         * Queries PEAR for all available PEAR packages, analogous to
         * running pear list-all from the command line.
         *
         * @return array Listing of PEAR modules with the following indexes:
         * versions, description.  :KLUDGE: versions only contains one version
         * number, the most current on PEAR at this time.  This index is kept for
         * consistency with the "Package Manager" component of the control panel
         */
        public function list_remote_packages()
        {
            if (file_exists(TEMP_DIR . '/pear-cache') && ((time() - filemtime(TEMP_DIR . '/pear-cache')) < 86400)) {
                $data = unserialize(file_get_contents(TEMP_DIR . '/pear-cache'));
                return $data;
            }
            $status = Util_Process::exec("/usr/bin/pear list-all");
            if ($status instanceof Exception) {
                return $status;
            }
            $pear = array();
            $pearCount = preg_match_all('!^pear/([^\s]+)\s+([^\s]+)\s+([0-9\.]*)\s+(.*)$!m', $status['output'],
                $pearTmp);

            for ($i = 0; $i < $pearCount; $i++) {
                $pear[$pearTmp[1][$i]] = array(
                    'versions'    => array(trim($pearTmp[2][$i])),
                    'description' => $pearTmp[4][$i]
                );
            }
            file_put_contents(TEMP_DIR . '/pear-cache', serialize($pear));
            return $pear;
        }

        /**
         * Add PHP channel to PEAR package manager
         *
         * @param  string $xml URL reference to package.xml
         * @return bool
         */
        public function add_pear_channel($xml)
        {
            if (substr($xml, -4) != '.xml') {
                return error("channel `$xml' must refer to .xml");
            }
            $status = Util_Process_Sudo::exec('pear add-channel %s', $xml);
            return $status['success'];
        }

        /**
         * Remove PEAR channel from PEAR package manager
         *
         * @param  string $channel channel previously added
         * @return bool
         */

        public function remove_channel($channel)
        {
            $status = Util_Process_Sudo::exec('pear remove-channel %s', $channel);
            return $status['success'];
        }

        /**
         * List all channels configured in PHP PEAR package manager
         *
         * Sample response-
         * array(2) {
         *      [0]=>
         *      array(5) {
         *        ["channel"]=>    string(12) "pear.php.net"
         *        ["summary"]=>    string(40) "PHP Extension and Application Repository"
         *      }
         *      [1]=>
         *      array(5) {
         *        ["channel"]=>    string(12) "pecl.php.net"
         *        ["summary"]=>    string(31) "PHP Extension Community Library"
         *      }
         *    }
         *
         * @return array
         */
        public function list_channels()
        {
            $channels = array();
            $status = Util_Process_Sudo::exec('pear list-channels');
            if (!$status['success']) {
                return $channels;
            }
            $chmatches = null;
            if (!preg_match_all(Regex::PEAR_CHANNELS_LONG, $status['output'], $chmatches, PREG_SET_ORDER)) {
                return $channels;
            }
            foreach ($chmatches as $channel) {
                $channels[] = array(
                    'channel' => $channel['channel'],
                    'summary' => $channel['summary']
                );
            }
            return $channels;
        }

        /**
         * Retrieve PEAR channel information
         *
         * Basic wrapper to pear channel-info <channel> command
         * Sample response-
         * array(4) {
         *      ["server"]=>
         *      string(12) "pear.php.net"
         *      ["alias"]=>
         *      string(4) "pear"
         *      ["summary"]=>
         *      string(40) "PHP Extension and Application Repository"
         *      ["version"]=>
         *      NULL
         * }
         *
         * @param string $channel
         * @return array
         */
        public function get_channel_info($channel)
        {
            $info = array();
            $status = Util_Process_Sudo::exec('pear channel-info %s', $channel);
            if (!$status['success']) {
                return false;
            }
            $line = strtok($status['output'], "=");
            $parse = false;

            for ($idx = null; $line !== false; $line = strtok("\n")) {
                // delimiter ===
                if (!$parse) {
                    if ($line[0] != '=') {
                        continue;
                    } else {
                        $parse = true;
                    }
                }

                if ($idx) {
                    $info[$idx] = trim($line);
                }
                $idx = null;

                $lookup = strtok(" \n");
                if ($lookup == "Name") {
                    strtok(" ");
                    strtok(" ");
                    $idx = 'server';
                } else {
                    if ($lookup == "Alias") {
                        $idx = 'alias';
                    } else {
                        if ($lookup == "Summary") {
                            $idx = 'summary';
                        } else {
                            if ($lookup == "Version") {
                                // Special case if Version field is null
                                $version = null;
                                $line = strtok("\n");
                                if (false === strpos($line, "SERVER CAPABILITIES")) {
                                    $version = trim($line);
                                }
                                $info['version'] = $version;
                            } else {
                                if ($lookup[0] == "=") {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            return $info;
        }

        /**
         * string get_php_version()
         * Returns the available PHP interpreter version on the server
         *
         * @cache     yes
         * @privilege PRIVILEGE_ALL
         *
         * @return string
         */
        public function version()
        {
            $key = 'php.version';
            $ver = apcu_fetch($key);
            if ($ver) {
                return $ver;
            }
            $ver = \Opcenter\Php::version();
            apcu_add($key, $ver, 86400);
            return $ver;
        }

        /**
         * Enable fallback interpreter support
         *
         * @param null|string $mode specific personality in multi-personality environments
         * @return bool
         */
        public function enable_fallback($mode = null)
        {
            if (!IS_CLI) {
                return $this->query('php_enable_fallback', $mode);
            }
            if (!$mode) {
                $mode = $this->getPersonalities();
            }

            $file = file_get_contents($this->web_config_dir() . '/virtual/' .
                $this->site);
            // @todo helper function?
            $config = preg_replace(Regex::compile(
                Regex::PHP_COMPILABLE_STRIP_NONHTTP_APACHE_CONTAINER,
                ['port' => 80]
            ), '', $file);
            $serverip = $this->common_get_ip_address();
            $in = $serverip . ':80';
            foreach ((array)$mode as $m) {
                if (!$this->personalityExists($m)) {
                    error("unknown personality `%s' - not enabling", $m);
                    continue;
                }
                $port = $this->getPersonalityPort($m);
                $out = $serverip . ':' . $port;
                $newconfig = str_replace($in, $out, $config);
                $confpath = $this->getPersonalityPathFromPersonality($m, $this->site);
                file_put_contents($confpath, $newconfig) && info("enabled fallback for `%s'", $m);
            }
            Util_Account_Hooks::run('reload', ['php']);
            return true;
        }

        public function _housekeeping()
        {
            // composer.phar seems standard nowadays..
            if ($this->composer_exists()) {
                return true;
            } else {
                if (version_compare(platform_version(), '4.5', '<')) {
                    return false;
                }
            }

            $versions = file_get_contents('https://getcomposer.org/versions');
            if (!$versions) {
                return false;
            }
            $versions = json_decode($versions, true);
            $url = 'https://getcomposer.org/' . $versions['stable'][0]['path'];
            $res = Util_HTTP::download($url, self::COMPOSER_LOCATION);
            if (!$res) {
                return error("failed to download composer");
            }
            chmod(self::COMPOSER_LOCATION, 0755);
            copy(self::COMPOSER_LOCATION, $this->service_template_path("siteinfo") . self::COMPOSER_LOCATION);

            info("installed %s!", basename(self::COMPOSER_LOCATION));
            return true;
        }

        public function composer_exists()
        {
            return file_exists(self::COMPOSER_LOCATION);
        }

        public function _delete()
        {
            foreach ($this->get_fallbacks() as $fallback) {
                if ($this->fallback_enabled($fallback)) {
                    $this->disable_fallback($fallback);
                }
            }
        }

        public function get_fallbacks()
        {
            return $this->getPersonalities();
        }

        /**
         * Verify if fallback enabled for given personality
         *
         * @param string|null $mode
         * @return bool
         */
        public function fallback_enabled($mode = null)
        {
            if (is_null($mode)) {
                $mode = $this->getPersonalities();
                $mode = array_pop($mode);
            }
            return file_exists($this->getPersonalityPathFromPersonality($mode, $this->site));
        }

        /**
         * Disable PHP fallback support
         *
         * @return bool
         */
        public function disable_fallback($mode = '')
        {
            if (!IS_CLI) {
                return $this->query('php_disable_fallback');
            }
            if ($mode) {
                $personalities = [$mode];
            } else {
                $personalities = $this->getPersonalities();
            }
            foreach ($personalities as $personality) {
                if (!$this->personalityExists($personality)) {
                    error("unknown personality `%s', skipping", $personality);
                    continue;
                }
                $path = $this->getPersonalityPathFromPersonality($personality, $this->site);
                if (file_exists($path)) {
                    unlink($path);
                } else {
                    warn("fallback `%s' not enabled", $personality);
                }
            }
            // defer reloading to a later date
            return true;
        }
    }

?>
