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
     * Magento management
     *
     * An interface to wp-cli
     *
     * @package core
     */
    class Magento_Module extends Module_Support_Webapps
    {
        const APP_NAME = 'Magento';
        // primary domain document root
        const MAGENTO_CLI = '/usr/share/pear/n98-magerun.phar';
        const MAGENTO2_CLI = '/usr/share/pear/n98-magerun2.phar';
        // latest release
        const MAGENTO_CLI_URL = 'https://files.magerun.net/n98-magerun.phar';
        const MAGENTO2_CLI_URL = 'https://files.magerun.net/n98-magerun2.phar';

        const VERSION_CHECK_URL = 'http://mirror.apisnetworks.com/magento';
        const ADMIN_URL = '/admin';

        private $_versionCache = array();

        private $_aclList = array(
            'min' => array('/media', '/var', '/downloader'),
            'max' => array('/media/downloadable', '/downloader', '/var/cache', '/var/session')
        );

        /**
         * void __construct(void)
         *
         * @ignore
         */
        public function __construct()
        {

            parent::__construct();
            $this->exportedFunctions = array(
                '*' => PRIVILEGE_SITE | PRIVILEGE_USER
            );
        }

        /**
         * Install Magento into a pre-existing location
         *
         * @param string $hostname domain or subdomain to install Magento
         * @param string $path     optional path under hostname
         * @param array  $opts     additional install options
         */
        public function install($hostname, $path = '', array $opts = array())
        {
            $docroot = $this->_normalizePath($hostname, $path);
            if (!$docroot) {
                return error("failed to install Magento");
            }

            if (!parent::checkDocroot($docroot)) {
                return false;
            }
            if (!is_debug() && !$this->ssl_permitted()) {
                return error("account requires SSL to manage a store - add on service by opening a ticket");
            }

            $version = null;
            if (isset($opts['version'])) {
                $version = $opts['version'];
            }

            if (!isset($opts['autoupdate'])) {
                $opts['autoupdate'] = true;
            }

            if (isset($opts['email']) && !preg_match(Regex::EMAIL, $opts['email'])) {
                return error("invalid email address `%s' specified", $opts['email']);
            } else {
                $opts['email'] = $this->get_config('siteinfo', 'email');
            }

            $args = array();
            // cap to 1.x branch
            $vercap = !empty($args['version']) && $args['version'][0] === 2 && $this->mysql_version() < 50600;
            if (null !== $version) {
                if (!$this->_versionValid($version)) {
                    return error("unknown Magento version `%s'", $version);
                }
                if ($vercap) {
                    warn("capping magento version to 1.x, 2.x requires MySQL 5.6+");
                    $version = $this->_getMaxVersion(1);
                }
                $args['version'] = $version;
            } else {
                $args['version'] = $this->_getLastestVersion($vercap ? 1 : null);
            }

            $args['vername'] = 'apnscp-mirror-' . $args['version'];
            if (version_compare($args['version'], '2.0', '>=') && !$this->get_key()) {
                return error("Magento Connect key must be setup first, do so via Account > Settings");
            }

            $fqdn = $this->web_normalize_hostname($hostname);
            $args['baseurl'] = 'http://' . $fqdn;
            if ($path) {
                $args['baseurl'] .= '/' . $path;
            }

            $squash = array_get($opts, 'squash', false);
            if ($squash && $this->permission_level & PRIVILEGE_USER) {
                warn("must squash privileges as secondary user");
                $squash = true;
            }
            $opts['squash'] = $squash;

            $db = $this->_suggestDB($hostname);
            if (!$db) {
                return false;
            }

            $dbuser = $this->_suggestUser($db);
            if (!$dbuser) {
                return false;
            }
            $dbpass = $this->_suggestPassword();
            if (!parent::setupDatabase(['db' => $db, 'user' => $dbuser, 'password' => $dbpass])) {
                return false;
            }

            $args['dbuser'] = $dbuser;
            $args['dbpass'] = $dbpass;
            $args['dbname'] = $db;
            $args['dbhost'] = 'localhost';
            $args['docroot'] = $docroot;
            $magerunver = 1;
            if (version_compare($args['version'], '2.0', '>=')) {
                $magerunver = 2;
            }

            // ensure the docroot is owned by the target uid to permit installation
            // correct it at the end
            if (!$squash) {
                $this->file_chown($docroot, $this->user_id);
            }

            // copy custom config to user
            $magerunconf = $this->_copyMagerunConfig($magerunver);

            $cmd = 'install -n --installationFolder=%(docroot)s --dbHost=%(dbhost)s --baseUrl=%(baseurl)s ' .
                '--dbUser=%(dbuser)s --dbPass=%(dbpass)s --installSampleData=no --dbName=%(dbname)s --magentoVersionByName=' .
                '%(vername)s';
            $ret = $this->_exec($docroot, $cmd, $args, $magerunver);
            if ($magerunconf && $this->file_file_exists($magerunconf)) {
                $this->file_delete($magerunconf);
            }
            if (!$ret['success']) {
                info("removing temporary files");
                $this->file_delete($docroot, true);
                $this->sql_delete_mysql_database($db);
                $this->sql_delete_mysql_user($dbuser, 'localhost');
                if (false !== strpos($ret['stderr'], "to locate Magento version")) {
                    return error("failed to install magento: unknown Magento version `%s'",
                        $args['version']
                    );
                }
                return error("failed to install magento: %s", coalesce($ret['stderr'], $ret['stdout']));
            }
            $this->file_chmod($docroot . '/app/etc/local.xml', 644);
            /** post install fixup */
            // we install with some stupid defaults, change them
            $ret = $this->_exec($docroot, 'admin:user:delete -f admin');
            if (!$ret['success']) {
                warn("failed to delete placeholder admin");
            }
            $this->_exec($docroot, 'cache:enable');

            $autogenpw = false;
            if (!isset($opts['password'])) {
                $autogenpw = true;
                $opts['password'] = $this->_suggestPassword(10);
                info("autogenerated password `%s'", $opts['password']);
            }

            if (!isset($opts['user'])) {
                $opts['user'] = $this->username;
                info("setting admin user to `%s'", $this->username);
            }

            $args = array(
                'email'    => $opts['email'],
                'user'     => $opts['user'],
                'password' => $opts['password']
            );

            $this->_exec($docroot, 'admin:user:create %(user)s %(email)s %(password)s Store Admin', $args);
            if (!$ret['success']) {
                info("removing temporary files");
                $this->file_delete($docroot, true);
                $this->sql_delete_mysql_database($db);
                $this->sql_delete_mysql_user($dbuser, 'localhost');
                return error("failed to create admin user: %s", $ret['stdout']);
            }

            // by default, let's only open up ACLs to the bare minimum

            $files = array_map(function ($f) use ($docroot) {
                return $docroot . '/' . $f;
            }, $this->_aclList['min']);
            $this->file_touch($docroot . '/.htaccess');
            parent::fixRewriteBase($docroot, $path);
            $users = array(
                array(Web_Module::WEB_USERNAME => 7),
                array($this->username => 'drwx'),
                array(Web_Module::WEB_USERNAME => 'drwx'),
            );
            if (!$this->file_set_acls($files, $users, array(File_Module::ACL_MODE_RECURSIVE => true))) {
                warn("failed to set ACLs on `%s'", $docroot);
            }
            // simple confirmation
            $version = $this->get_version($hostname, $path);
            $params = array(
                'version'    => $version,
                'hostname'   => $hostname,
                'path'       => $path,
                'autoupdate' => (bool)$opts['autoupdate'],
                'fortify'    => 'min'
            );
            $this->_map('add', $docroot, $params);

            $this->_fixModelPHP7($docroot);
            $this->_fixConnectConfig($docroot);
            $url = 'http://' . $fqdn . '/' . $path;
            if ($this->_checkSSL($fqdn)) {
                $url = 'https://' . $fqdn . '/' . $path . '/';
                $args = array(
                    'path' => "/web/secure/base_url",
                    'url'  => rtrim($url,'/')
                );
                $this->_exec($docroot, 'config:set %(path)s %(url)s', $args);
                $this->_exec($docroot, 'cache:flush');
            }
            if ($magerunver === 1) {
                $this->_fixModelPHP7($docroot);
            }

            $msg = "Hello!" . "\r\n" .
                "This is a confirmation that Magento has been installed under " . $docroot .
                ". You may access Magento via " . $url . ". Access the administrative " .
                "panel at " . rtrim($url, "/") . self::ADMIN_URL . " using the following details:" . "\r\n\r\n" .
                "Username: " . $opts['user'] . "\r\n" .
                ($autogenpw ? "Password: " . $opts['password'] . "\r\n" : '');
            $msg .= "\r\nWhen installing plugins or themes, you will need to use your " .
                "control panel password!";
            $hdrs = "From: " . Crm_Module::FROM_NAME . " <" .
	            Crm_Module::FROM_ADDRESS . ">\r\nReply-To: " . Crm_Module::REPLY_ADDRESS;
            Mail::send($opts['email'], "Magento Installed", $msg, $hdrs);
            if (!$opts['squash']) {
                parent::unsquash($docroot);
            }
            return true;
        }

        /**
         * Get Magento key for use with Magento Connect
         *
         * @return mixed
         */
        public function get_key()
        {
            $file = $this->_keyAuthFile();
            if (!$this->file_file_exists($file)) {
                return null;
            }
            $contents = json_decode($this->file_get_file_contents($file), true);
            if (!isset($contents['http-basic']) || !isset($contents['http-basic']['repo.magento.com'])) {
                return null;
            }
            $tmp = $contents['http-basic']['repo.magento.com'];
            return array($tmp['username'], $tmp['password']);
        }

        /**
         * Get installed version
         *
         * @param string $hostname
         * @param string $path
         * @return null|string version number
         */
        public function get_version($hostname, $path = '')
        {
            if (!$this->valid($hostname, $path)) {
                return null;
            }
            $docroot = $this->_normalizePath($hostname, $path);
            $ret = $this->_exec($docroot, 'sys:info --format=json');
            if (!$ret['success']) {
                return null;
            }
            $info = json_decode($ret['stdout'], true);
            foreach ($info as $el) {
                if (strtolower($el['name']) === "version") {
                    return $el['value'];
                }
            }
            return null;

        }

        /**
         * Location is a valid WP install
         *
         * @param string $hostname or $docroot
         * @param string $path
         * @return bool
         */
        public function valid($hostname, $path = '')
        {
            if ($hostname[0] == '/') {
                $docroot = $hostname;
            } else {
                $docroot = $this->_normalizePath($hostname, $path);
                if (!$docroot) {
                    return false;
                }
            }

            return $this->file_file_exists($docroot . '/lib/Magento');
        }

        /**
         * Install and activate plugin
         *
         * @param string $hostnaem domain or subdomain of wp install
         * @param string $path     optional path component of wp install
         * @param string $plugin   plugin name
         * @param string $version  optional plugin version
         * @return bool
         */
        public function install_plugin($hostname, $path = '', $plugin, $version = 'stable')
        {
            $docroot = $this->_normalizePath($hostname, $path);
            if (!$docroot) {
                return error("invalid WP location");
            }

            return info("not implemented");
            return true;
        }

        /**
         * Uninstall a plugin
         *
         * @param string $hostname
         * @param string $path
         * @param string $plugin plugin name
         * @param string $force  delete even if plugin activated
         */
        public function uninstall_plugin($hostname, $path = '', $plugin, $force = false)
        {
            $docroot = $this->_normalizePath($hostname, $path);
            if (!$docroot) {
                return error("invalid WP location");
            }

            return info("not implemented");
            return true;
        }

        /**
         * Recovery mode to disable all plugins
         *
         * @param string $hostname subdomain or domain of WP
         * @param string $path     optional path
         * @return bool
         */
        public function disable_all_plugins($hostname, $path = '')
        {
            $docroot = $this->_normalizePath($hostname, $path);
            if (!$docroot) {
                return error("failed to determine path");
            }

            return info("not implemented");
            return info("plugin deactivation successful: %s", $ret['stdout']);
        }

        /**
         * Uninstall WP from a location
         *
         * @param        $hostname
         * @param string $path
         * @param string $delete "all", "db", or "files"
         * @return bool
         */
        public function uninstall($hostname, $path = '', $delete = 'all')
        {
            return parent::uninstall($hostname, $path, $delete);
        }

        /**
         * Get database configuration for a blog
         *
         * @param string $hostname domain or subdomain of wp blog
         * @param string $path     optional path
         * @return array
         */
        public function db_config($hostname, $path = '')
        {
            $docroot = $this->_normalizePath($hostname, $path);
            if (!$docroot) {
                return error("failed to determine Magento");
            }
            $file = $this->domain_fs_path() . $docroot . '/app/etc/local.xml';
            $code = simplexml_load_file($file, null, LIBXML_NOCDATA);
            $conn = $code->xpath('//connection');
            if (!$conn) {
                return error("failed to obtain Magento configuration for `%s'", $docroot);
            }
            $conn = array_pop($conn);
            return array(
                'user'     => (string)$conn->username,
                'host'     => (string)$conn->host,
                'db'       => (string)$conn->dbname,
                'password' => (string)$conn->password,
                'prefix'   => (string)$conn->prefix
            );
        }

        /**
         * Check if version is latest or get latest version
         *
         * @param null $version
         * @return int|string
         */
	    public function is_current($version = null)
	    {
		    return parent::is_current($version);
	    }

        /**
         * Change Magento admin credentials
         *
         * $fields is a hash whose indices match password
         *
         * @param string $domain
         * @param string $path
         * @param array  $fields
         * @return bool
         */
        public function change_admin($domain, $path = null, array $fields)
        {
            $docroot = $this->_normalizePath($domain, $path);
            if (!$docroot) {
                return warn("failed to change administrator information");
            }
            $admin = $this->get_admin($domain, $path);

            if (!$admin) {
                return error("cannot determine admin of Magento install");
            }
            $args = array(
                'username' => $admin
            );
            if (isset($fields['password'])) {
                $args['password'] = $fields['password'];
                $ret = $this->_exec($docroot, 'admin:user:change-password %(username)s %(password)s', $args);
                if (!$ret['success']) {
                    return error("failed to change admin password, `%s'", $ret['stderr']);
                }
            } else {
                return warn("no other fields besides password implemented");
            }
            return true;

        }

        /**
         * Get the primary admin for a Magento instance
         *
         * @param      $domain
         * @param null $path
         * @return bool|string admin or false on failure
         */
        public function get_admin($domain, $path = null)
        {
            $docroot = $this->_normalizePath($domain, $path);
            $ret = $this->_exec($docroot, 'admin:user:list --format=json');
            if (!$ret['success']) {
                return warn("failed to enumerate administrative users");
            }
            $users = json_decode($ret['stdout'], true);
            if (!$users) {
                return error("no administrative users found");
            }
            foreach ($users as $user) {
                if ($user['status'] === 'active') {
                    break;
                }
            }
            return $user['username'];
        }

        /**
         * Web application supports fortification
         *
         * @param string|null $mode optional mode (min, max)
         * @return bool
         */
        public function has_fortification($mode = null)
        {
            return parent::has_fortification($mode);
        }

        /**
         * @param        $hostname
         * @param string $path
         */
        public function fortify($hostname, $path = '', $mode = 'max')
        {
            $docroot = $this->_normalizePath($hostname, $path);
            if (!$docroot || !$this->valid($hostname, $path)) {
                return error("path `%s' is not a WP install", $docroot);
            } else {
                if ($mode != 'min' && $mode != 'max') {
                    return error("unknown mode `%s'", $mode);
                }
            }
            $prefs = $this->get_map($docroot);
            $files = array_map(function ($f) use ($docroot) {
                return $docroot . '/' . $f;
            }, $this->_aclList[$mode]);
            $users = array(
                array(Web_Module::WEB_USERNAME => 'drx'),
                array(Web_Module::WEB_USERNAME => 'rx'),
                array($this->username => 'drwx'),
            );
            $flags = array(
                File_Module::ACL_MODE_RECURSIVE => true,
                File_Module::ACL_MODE_DEFAULT   => false
            );
            if (!$this->file_set_acls($files, $users, $flags)) {
                return warn("fortification failed on `%s/%s'", $hostname, $path);
            }
            $prefs['fortify'] = $mode;
            $this->_map('add', $docroot, $prefs);
            return true;
        }

        /**
         * Relax permissions to allow write-access
         *
         * @param string $hostname
         * @param string $path
         * @return bool
         */
        public function unfortify($hostname, $path = '', $mode = 'max')
        {
            $docroot = $this->_normalizePath($hostname, $path);
            if (!$docroot || !$this->valid($hostname, $path)) {
                return error("path `%s' is not a WP install", $docroot);
            } else {
                if ($mode != 'min' && $mode != 'max') {
                    return error("unknown mode `%s'", $mode);
                }
            }
            $prefs = $this->_getPrefs($docroot);
            $files = array_map(function ($f) use ($docroot) {
                return $docroot . '/' . $f;
            }, $this->_aclList[$mode]);
            $users = array(
                array(Web_Module::WEB_USERNAME => 'rxw'),
                array(Web_Module::WEB_USERNAME => 'drwx'),
                $this->username => 'drwx'
            );
            if (!$this->file_set_acls($files, $users, array(File_Module::ACL_MODE_RECURSIVE => true))) {
                return warn("unfortification failed on `%s/%s'", $hostname, $path);
            }
            $prefs['fortify'] = null;
            $this->_map('add', $docroot, $prefs);
            return true;
        }

        /**
         * Update core, plugins, and themes atomically
         *
         * @param string $hostname subdomain or domain
         * @param string $path     optional path under hostname
         * @return bool
         */
        public function update_all($hostname, $path = '')
        {
            return $this->update($hostname, $path) && $this->update_plugins($hostname, $path) &&
                $this->update_themes($hostname, $path) || error("failed to update all components");
        }

        /**
         * Update Magento to latest version
         *
         * @param string $domain domain or subdomain under which WP is installed
         * @param string $path   optional subdirectory
         * @param string $version
         * @return bool
         */
        public function update($domain, $path = '', $version = null)
        {
            $docroot = $this->_normalizePath($domain, $path);
            if (!$docroot) {
                return error("update failed");
            }

            return info("to-do");

            return $ret['success'];
        }

        /**
         * Update Magento plugins
         *
         * @param string $hostname domain or subdomain
         * @param string $path     optional path within host
         * @param array  $plugins
         * @return bool|void
         */
        public function update_plugins($hostname, $path = '', $plugins = array())
        {
            $docroot = $this->_normalizePath($hostname, $path);
            if (!$docroot) {
                return error("update failed");
            }

            return info("to-do");

            $cmd = 'plugin update';
            $args = array();
            if (!$plugins) {
                $cmd .= ' --all';
            } else {
                for ($i = 0, $n = sizeof($plugins); $i < $n; $i++) {
                    $plugin = $plugins[$i];
                    $version = null;
                    if (isset($plugin['version'])) {
                        $version = $plugin['version'];
                    }
                    if (isset($plugin['name'])) {
                        $plugin = $plugin['name'];
                    }

                    $name = 'p' . $i;

                    $cmd .= ' %(' . $name . ')s';
                    $args[$name] = $plugin;
                    if ($version) {
                        $cmd .= ' --version=%(' . $name . 'v)s';
                        $args[$name . 'v'] = $version;
                    }
                }
            }

            $ret = $this->_exec($docroot, $cmd, $args);
            if (!$ret['success']) {
                return error("plugin update failed: `%s'", $ret['stderr']);
            }
            return $ret['success'];
        }

        /**
         * Update Magento themes
         *
         * @param string $hostname subdomain or domain
         * @param string $path     optional path under hostname
         * @param array  $themes
         * @return bool|void
         */
        public function update_themes($hostname, $path = '', $themes = array())
        {
            $docroot = $this->_normalizePath($hostname, $path);
            if (!$docroot) {
                return error("update failed");
            }
            return info("not implemented");
        }

        public function delete_key()
        {
            $file = $this->_keyAuthFile();
            if (!$this->file_file_exists($file)) {
                return error("failed to get Magento key file `%s'", $file);
            }
            $contents = json_decode($this->file_get_file_contents($file), true);
            if (!isset($contents['http-basic'])) {
                return true;
            }
            unset($contents['http-basic']['repo.magento.com']);
            return $this->file_put_file_contents($file, json_encode($contents));
        }

        public function set_key($publickey, $privatekey)
        {
            if (!ctype_alnum($publickey) || !ctype_alnum($privatekey)) {
                return error("invalid public and/or private magento key");
            }
            $file = $this->_keyAuthFile();
            $contents = array();
            if ($this->file_file_exists($file)) {
                $contents = $this->file_get_file_contents($file);
                $contents = json_decode($contents, true);
            }
            if (!isset($contents['http-basic'])) {
                $contents['http-basic'] = array();
            }
            $contents['http-basic']['repo.magento.com'] = array(
                'username' => $publickey,
                'password' => $privatekey
            );
            return $this->file_put_file_contents($file, json_encode($contents), true);
        }

        /**
         * Install wp-cli if necessary
         *
         * @return bool
         */
        public function _housekeeping()
        {
            if (version_compare((string)platform_version(), '4.5', '<=')) {
                // platform is too damn old
                return;
            }
            $clis = array(
                self::MAGENTO_CLI  => self::MAGENTO_CLI_URL,
                self::MAGENTO2_CLI => self::MAGENTO2_CLI_URL
            );
            foreach ($clis as $cli => $url) {
                if (!file_exists($cli)) {
                    $res = Util_HTTP::download($url, $cli);
                    if (!$res) {
                        return error("failed to install magento cli");
                    }
                    info("downloaded %s", basename($cli));
                }

                $local = $this->service_template_path('siteinfo') . '/' . $cli;
                if (!file_exists($local)) {
                    return copy($cli, $local);
                }
            }
        }

        /**
         * Requested version is known by magerun
         *
         * @param string $version
         * @return bool
         */
        private function _versionValid($version)
        {
            $versions = $this->_getVersions();
            return in_array($version, $versions);
        }

        /**
         * Get all current major versions
         *
         * @return array
         */
        protected function _getVersions()
        {
            $key = 'magento.versions';
            $cache = Cache_Super_Global::spawn();
            // @TODO
            if (false !== ($vers = $cache->get($key))) {
                return $vers;
            }

            $req = file_get_contents(self::VERSION_CHECK_URL . '?all');
            if (!$req) {
                return array();
            }
            $req = json_decode($req);
            $cache->set($key, $req, 43200);
            return $req;
        }

        /**
         * Get latest WP release
         *
         * @return string
         */
        protected function _getLastestVersion($branch = null)
        {
            $versions = $this->_getVersions();
            if (!$versions) {
                return null;
            }
            if (!$branch) {
                return array_pop($versions);
            }
            do {
                $version = array_pop($versions);
                if ($version[0] === $branch) {
                    return $version;
                }
            } while (true);
            return null;
        }

        private function _keyAuthFile()
        {
            $home = $this->user_get_home();
            $file = $home . '/.composer/auth.json';
            return $file;
        }

        private function _copyMagerunConfig($version = 1)
        {
            $f = resource_path('storehouse/magento/magento' . $version . '.yaml');
            if (!file_exists($f)) {
                return error("failed to locate magento download YAML");
            }
            $filename = '.n98-magerun' . ($version > 1 ? $version : '') . '.yaml';
            copy($f, $this->domain_fs_path() . '/tmp/' . $filename);
            $dest = $this->user_get_home() . '/' . $filename;
            $this->file_copy('/tmp/' . $filename, $dest);
            unlink($this->domain_fs_path() . '/tmp/' . $filename);
            return $dest;
        }

        private function _exec($path = null, $cmd, $args = array(), $ver = null)
        {
            if (is_null($ver)) {
                $ver = $this->_whichMajor($path);
            }

            $magerun = $ver == 1 ? self::MAGENTO_CLI : self::MAGENTO2_CLI;
            // client may override tz, propagate to bin
            $tz = date_default_timezone_get();
            $cli = 'php -d pdo_mysql.default_socket=' . escapeshellarg(ini_get("mysqli.default_socket")) .
                ' -d date.timezone=' . $tz . ' -d memory_limit=192m ' . $magerun . '';
            if (!is_array($args)) {
                $args = func_get_args();
                array_shift($args);
            }
            if ($path) {
                $cli = 'cd %(path)s && ' . $cli;
                $args['path'] = $path;
            }
            $cmd = $cli . ' ' . $cmd;
            $ret = $this->pman_run($cmd, $args);
            if (!$ret['success'] && $ret['stderr']) {
                $ret['stderr'] = $ret['stdout'];
            }
            return $ret;
        }

        /**
         * Get Magento major version
         *
         * @param $path
         * @return int
         */
        private function _whichMajor($path)
        {
            static $pathCache = array();
            if (isset($pathCache[$path])) {
                return $pathCache[$path];
            }

            // found in 2.0.0 and not in 1.9.2.4
            if ($this->file_file_exists($path . '/app/autoload.php')) {
                $ver = 2;
            } else {
                $ver = 1;
            }
            $pathCache[$path] = $ver;
            return $ver;
        }

        private function _fixModelPHP7($docroot)
        {
            // PHP7 fix
            // @see https://www.atwix.com/magento/magento-and-php-7/
            if (version_compare(platform_version(), '6.5', '<')) {
                return true;
            }
            $f = $docroot . '/app/code/core/Mage/Core/Model/Layout.php';
            $contents = $this->file_get_file_contents($f);
            $old = '$out .= $this->getBlock($callback[0])->$callback[1]();';
            $new = '$out .= $this->getBlock($callback[0])->{$callback[1]}();';
            $replacement = str_replace($old, $new, $contents);
            return $this->file_put_file_contents($f, $replacement);
        }

        private function _fixConnectConfig($docroot)
        {
            $file = $docroot . '/downloader/connect.cfg';
            $preamble = "::ConnectConfig::v::1.0::";
            if ($this->file_file_exists($file)) {
                $raw = $this->file_get_file_contents($file);
                if (!preg_match('/^((?:::[[[:alnum:].]*]*)+?)([sibNaO]:.*)$/mi', $raw, $preamble)) {
                    return error("cannot set Magento Connect FTP login information, " .
                        "config is malformed: %s", $raw);
                }
                $contents = unserialize($preamble[2]);
                $preamble = $preamble[1];
            } else {
                $contents = array();
            }
            $contents['remote_config'] = 'ftp://' . $this->username . '@' . $this->domain . ':debug@localhost';
            $contents['downloader_path'] = $this->domain_fs_path() . $docroot . '/downloader';
            $contents['magento_root'] = $this->domain_fs_path() . $docroot;
            $newdata = $preamble . serialize($contents);
            return $this->file_put_file_contents($file, $newdata);
        }

        private function _checkSSL($hostname)
        {
            if (!$this->ssl_cert_exists()) {
                if (!$this->letsencrypt_permitted()) {
                    return warn("no ssl found and platform too old for let's encrypt support - " .
                        "install a certificate manually (Web > SSL Certificates)");
                }
                if (!$this->letsencrypt_request(array($hostname))) {
	                // easy, make let's encrypt
	                return warn("failed to create a Let's Encrypt SSL certificate. Do so manually " .
		                "for `%s' via Web > SSL Certificates", $hostname);
                }
                return info("installed a free Let's Encrypt SSL certificate for this store front");
            }

            $certinfo = $this->ssl_get_certificates();
            if (isset($certinfo[0])) {
                // @todo get rid of multiple certificate support?
                $certinfo = array_pop($certinfo);
            }
            $crt = $this->ssl_get_certificate($certinfo['crt']);
            $key = $this->ssl_get_private_key($certinfo['key']);
            if (isset($certinfo['chain']) && $certinfo['chain']) {
                $chain = $this->ssl_get_certificate($certinfo['chain']);
            } else {
                $chain = null;
            }

            $sans = $this->ssl_get_alternative_names($crt);
            if (in_array($hostname, $sans)) {
                // domain already has SSL certup
                return true;
            }

            if (!$this->letsencrypt_is_ca($crt)) {
                return warn("ssl not active for `%s' in certificate, found hostnames: `%s'",
                    $hostname, join(", ", $sans)
                );
            }
            $sans[] = $hostname;
            if (!$this->letsencrypt_request($sans)) {
                warn("failed to generate new Let's Encrypt certificate with hostname `%s' added, "
                    . "reverting to old certificate setup", $hostname);
                if (!$this->ssl_install($key, $crt, $chain)) {
                    $msg = SERVER_NAME_SHORT . " :: " . $this->site . "\r\n\r\n" . var_export(array(
                            $key,
                            $crt,
                            $chain,
                            $certinfo
                        ), true);
                    Mail::send(Crm_Module::COPY_ADMIN, "WE FUCKED UP CAPTAIN", $msg);
                    return error("something went terribly wrong, site is now without SSL - emailing support staff...");
                }
            }
            return true;
        }
    }
