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
     * Ghost management
     *
     * A blogging platform built on Node
     *
     * @package core
     */
    class Ghost_Module extends \Module\Support\Webapps
    {
        const APP_NAME = "Ghost";
        const GHOST_CLI = '../artisan';
        protected $_aclList = [];
        const DEFAULT_VERSION_LOCK = 'major';
        private $_versionCache = array();

	            /**
         * void __construct(void)
         *
         * @ignore
         */
        public function __construct()
        {

            parent::__construct();
        }

	    public function plugin_status(string $hostname, string $path = '', string $plugin = null)
	    {
		    return false;
	    }

	    public function uninstall_plugin(string $hostname, string $path = '', string $plugin, bool $force = false): bool
	    {
		    return false;
	    }

	    public function disable_all_plugins(string $hostname, string $path = ''): bool
	    {
		    return false;
	    }

		public function get_versions(): array
	    {
	    	return [];
	    }

        /**
         * Install Laravel into a pre-existing location
         *
         * @param string $hostname domain or subdomain to install Laravel
         * @param string $path     optional path under hostname
         * @param array  $opts     additional install options
         */
        public function install(string $hostname, string $path = '', array $opts = array()): bool
        {
            $ret = Util_Process_Sudo::exec('composer global require "laravel/installer"');
            if (!$ret['success']) {
                return error("failed to install laravel installer via composer: `%s'",
                    coalesce($ret['stderr'], $ret['stdout'])
                );
            }
            var_dump($ret);
            $docroot = $this->getDocumentRoot($hostname, $path);
            if (!$docroot) {
                return error("failed to normalize path for `%s'", $hostname);
            }

            if (!parent::checkDocroot($docroot)) {
                return false;
            }

            if (isset($opts['version'])) {
                $version = $opts['version'];
            } else {
                $version = null;
            }

            if (!isset($opts['autoupdate'])) {
                $opts['autoupdate'] = true;
            }

            if (isset($opts['email']) && !preg_match(Regex::EMAIL, $opts['email'])) {
                return error("invalid email address `%s' specified", $opts['email']);
            } else {
                $opts['email'] = $this->get_config('siteinfo', 'email');
            }

            $args = array('mode' => 'download');
            if (!is_null($version)) {
                if (strcspn($version, ".0123456789")) {
                    return error("invalid version number, %s", $version);
                }
                $args['version'] = '--version=' . $version;
            } else {
                $args['version'] = null;
            }

            $ret = $this->_exec($docroot, 'core %(mode)s %(version)s', $args);

            if (!$ret['success']) {
                $vertmp = $version ? $version : 'LATEST';
                return error("failed to download WP version `%s', error: %s",
                    $vertmp,
                    $ret['stderr']
                );
            }
            $db = $this->_suggestDB($hostname);
            if (!$db) {
                return false;
            }

            $dbuser = $this->_suggestUser($db);
            if (!$dbuser) {
                return false;
            }
            $dbpass = $this->suggestPassword();
            $credentials = array(
                'db'       => $db,
                'user'     => $dbuser,
                'password' => $dbpass
            );

            if (!$this->sql_create_mysql_database($db)) {
                return error("failed to create suggested db `%s'", $db);
            } else {
                if (!$this->sql_add_mysql_user($dbuser, 'localhost', $dbpass)) {
                    $this->sql_delete_mysql_database($db);
                    return error("failed to create suggested user `%s'", $dbuser);
                } else {
                    if (!$this->sql_set_mysql_privileges($dbuser, 'localhost', $db,
                        array('read' => true, 'write' => true))
                    ) {
                        $this->sql_delete_mysql_user($dbuser, 'localhost');
                        $this->sql_delete_mysql_database($db);
                        return error("failed to set privileges on db `%s' for user `%s'", $db, $dbuser);
                    }
                }
            }
            if ($this->sql_add_mysql_backup($db, 'zip', 5, 2)) {
                info("added database backup task for `%s'", $db);
            }

            if (!$this->_generateNewConfig($hostname, $docroot, $credentials)) {
                info("removing temporary files");
                $this->file_delete($docroot, true);
                $this->sql_delete_mysql_database($db);
                $this->sql_delete_mysql_user($dbuser, 'localhost');
                return false;
            }

            if (!isset($opts['title'])) {
                $opts['title'] = "A Random Blog for a Random Reason";
            }
            $autogenpw = false;
            if (!isset($opts['password'])) {
                $autogenpw = true;
                $opts['password'] = $this->suggestPassword(10);
                info("autogenerated password `%s'", $opts['password']);
            }

            if (!isset($opts['user'])) {
                $opts['user'] = $this->username;
                info("setting admin user to `%s'", $this->username);
            }
            $opts['url'] = rtrim($hostname . '/' . $path, '/');

            $args = array(
                'email'    => $opts['email'],
                'mode'     => 'install',
                'url'      => $opts['url'],
                'title'    => $opts['title'],
                'user'     => $opts['user'],
                'password' => $opts['password']
            );

            $ret = $this->_exec($docroot, 'core %(mode)s --admin_email=%(email)s --skip-email ' .
                '--url=%(url)s --title=%(title)s --admin_user=%(user)s ' .
                '--admin_password=%(password)s', $args);
            if (!$ret['success']) {
                return error("failed to create database structure: %s", $ret['stderr']);
            }
            // by default, let's only open up ACLs to the bare minimum

            $files = array_map(function ($f) use ($docroot) {
                return $docroot . '/' . $f;
            }, $this->_aclList['min']);
            $this->file_touch($docroot . '/.htaccess');

            $users = array(
                array(Web_Module::WEB_USERNAME => 7),
                array($this->username => 'drwx'),
                array(Web_Module::WEB_USERNAME => 'drwx'),
            );
            if (!$this->file_set_acls($files, $users, array(File_Module::ACL_MODE_RECURSIVE => true))) {
                warn("failed to set ACLs on `%s/wp-content/'", $docroot);
            }
            $this->file_set_acls(array($docroot . '/'), $users);
            if (!$version) {
                $version = $this->_getLastestVersion();
            }
            $params = array(
                'version'    => $version,
                'hostname'   => $hostname,
                'autoupdate' => (bool)$opts['autoupdate'],
                'fortify'    => 'min'
            );
            $this->_map('add', $docroot, $params);
            if (false === strpos($hostname, ".")) {
                $hostname = $hostname . '.' . $this->domain;
            }
            $url = 'http://' . $hostname . '/' . $path;
            $msg = "Hello!" . "\r\n" .
                "This is a confirmation that Laravel has been installed under " . $docroot .
                ". You may access Laravel via " . $url . ". Access the administrative " .
                "panel at " . rtrim($url, "/") . '/wp-admin' . " using the following details:" . "\r\n\r\n" .
                "Username: " . $opts['user'] . "\r\n" .
                ($autogenpw ? "Password: " . $opts['password'] . "\r\n" : '');
            $msg .= "\r\nWhen installing plugins or themes, you will need to use your " .
                "control panel password!";
            $hdrs = "From: " . Crm_Module::FROM_NAME . " <" . Crm_Module::FROM_ADDRESS . ">\r\nReply-To: " . Crm_Module::REPLY_ADDRESS;
            Mail::send($opts['email'], "Wordpress Installed", $msg, $hdrs);
            info("Laravel installed - confirmation email with login info sent to %s", $opts['email']);
            return true;
        }

        /**
         * Get app root for Laravel
         *
         * @param string $hostname
         * @param string $path
         * @return string
         */
        protected function getDocumentRoot($hostname, $path = '')
        {
            // Laravel app root resides 1 level down
            $path = $this->web_normalize_path($hostname, $path);
            return dirname($path);
        }

        private function _exec($path = null, $cmd, array $args = array())
        {
            // client may override tz, propagate to bin
            $tz = date_default_timezone_get();
            $cli = 'php -d mysqli.default_socket=' . escapeshellarg(ini_get("mysqli.default_socket")) .
                ' -d date.timezone=' . $tz . ' -d memory_limit=64m ' . self::LARAVEL_CLI;
            if (!is_array($args)) {
                $args = func_get_args();
                array_shift($args);
            }

            $cmd = $cli . ' ' . $cmd;

            if ($path) {
                $cmd = 'cd %(path)s && ' . $cmd;
                $args['path'] = $path;
            }

            $ret = $this->pman_run($cmd, $args);
            if (!strncmp($ret['stdout'], "Error:", strlen("Error:"))) {
                // move stdout to stderr on error for consistency
                $ret['success'] = false;
                if (!$ret['stderr']) {
                    $ret['stderr'] = $ret['stdout'];
                }

            }
            return $ret;
        }

        private function _generateNewConfig($domain, $docroot, $dbcredentials, $ftpcredentials = array())
        {
            // generate db
            if (!isset($ftpcredentials['user'])) {
                $ftpcredentials['user'] = $this->username . '@' . $this->domain;
            }
            if (!isset($ftpcredentials['host'])) {
                $ftpcredentials['host'] = 'localhost';
            }
            if (!isset($ftpcredentials['password'])) {
                $ftpcredentials['password'] = '';
            }
            $xtraphp = '<<' . "\r\n" .
                "define('FTP_USER',%(ftpuser)s);" . "\n" .
                "define('FTP_HOST', %(ftphost)s);" . "\n" .
                ($ftpcredentials['password'] ?
                    "define('FTP_PASS', %(ftppass)s);" : '') . "\r\n";
            $args = array(
                'mode'     => 'config',
                'db'       => $dbcredentials['db'],
                'password' => $dbcredentials['password'],
                'user'     => $dbcredentials['user'],
                'ftpuser'  => $ftpcredentials['user'],
                'ftphost'  => 'localhost',
                'ftppass'  => $ftpcredentials['password']
            );


            $ret = $this->_exec($docroot,
                'core %(mode)s --dbname=%(db)s --dbpass=%(password)s --dbuser=%(user)s --dbhost=localhost --extra-php ' . $xtraphp,
                $args);
            if (!$ret['success']) {
                return error("failed to generate configuration, error: %s", $ret['stderr']);
            }
            return true;
        }

        /**
         * Get latest WP release
         *
         * @return string
         */
        private function _getLastestVersion()
        {
            $versions = $this->_getVersions();
            if (!$versions) {
                return null;
            }
            return $versions[0]['version'];
        }

        /**
         * Get all current major versions
         *
         * @return array
         */
        private function _getVersions()
        {
            $key = 'laravel.versions';
            $cache = Cache_Super_Global::spawn();
            if (false !== ($ver = $cache->get($key))) {
                return $ver;
            }
            $url = self::VERSION_CHECK_URL;
            $contents = file_get_contents($url);
            if (!$contents) {
                return array();
            }
            $versions = json_decode($contents, true);
            $versions = $versions['offers'];
            $cache->set($key, $versions, 43200);
            return $versions;
        }

        /**
         * Install and activate plugin
         *
         * @param string $hostname domain or subdomain of wp install
         * @param string $path     optional path component of wp install
         * @param string $plugin   plugin name
         * @param string $version  optional plugin version
         * @return bool
         */
        public function install_plugin(string $hostname, string $path = '', string $plugin, string $version = 'stable'): bool
        {
            $docroot = $this->getDocumentRoot($hostname, $path);
            if (!$docroot) {
                return error("invalid WP location");
            }

            $args = array($plugin);
            $ret = $this->_exec($docroot, 'plugin install %s --activate', $args);
            if (!$ret['success']) {
                return error("failed to install plugin `%s': %s", $plugin, $ret['stderr']);
            }
            info("installed plugin `%s'", $plugin);
            return true;
        }

        /**
         * Uninstall WP from a location
         *
         * @param        $hostname
         * @param string $path
         * @param string $delete remove all files under docroot
         * @return bool
         */
        public function uninstall(string $hostname, string $path = '', string $delete = 'all'): bool
        {

            return parent::uninstall($hostname, $path, $delete);
        }

	    /**
	     * Location is a valid WP install
	     *
	     * @param string $hostname or $docroot
	     * @param string $path
	     * @return bool
	     */
        public function valid(string $hostname, string $path = ''): bool
        {
            if ($hostname[0] == '/') {
                $docroot = $hostname;
            } else {
                $docroot = $this->getDocumentRoot($hostname, $path);
                if (!$docroot) {
                    return false;
                }
            }

            return false;
        }

        /**
         * Get database configuration for a blog
         *
         * @param string $hostname domain or subdomain of wp blog
         * @param string $path     optional path
         * @return bool|array
         */
        public function db_config(string $hostname, string $path = '')
        {
            $docroot = $this->getDocumentRoot($hostname, $path);
            if (!$docroot) {
                return error("failed to determine WP");
            }
            $code = 'include("./wp-config.php"); print serialize(array("user" => DB_USER, "password" => DB_PASSWORD, "db" => DB_NAME, "host" => DB_HOST, "prefix" => $table_prefix));';
            $cmd = 'cd %(path)s && php -d mysqli.default_socket=' . escapeshellarg(ini_get('mysqli.default_socket')) . ' -r %(code)s';
            $ret = $this->pman_run($cmd, array('path' => $docroot, 'code' => $code));
            if (!$ret['success']) {
                return error("failed to obtain WP configuration for `%s'", $docroot);
            }
            $data = unserialize($ret['stdout']);
            return $data;
        }

	    /**
	     * Check if version is latest or get latest version
	     *
	     * @param null|string $version
	     * @param string|null $branchcomp
	     * @return bool
	     */
	    public function is_current(string $version = null, string $branchcomp = null)
	    {
		    return parent::is_current($version, $branchcomp);
	    }

	    /**
	     * Change WP admin credentials
	     *
	     * $fields is a hash whose indices match wp_update_user
	     * common fields include: user_pass, user_login, and user_nicename
	     *
	     * @link https://codex.wordpress.org/Function_Reference/wp_update_user
	     *
	     * @param string $hostname
	     * @param string $path
	     * @param array  $fields
	     * @return bool
	     */
        public function change_admin(string $hostname, string $path = '', array $fields): bool
        {
            $docroot = $this->getDocumentRoot($hostname, $path);
            if (!$docroot) {
                return warn("failed to change administrator information");
            }
            $admin = $this->get_admin($hostname, $path);

            if (!$admin) {
                return error("cannot determine admin of WP install");
            }

            if (isset($fields['user_login'])) {
                return error("user login field cannot be changed in WP");
            }

            $args = array(
                'user' => $admin
            );
            $cmd = 'user update %(user)s';
            foreach ($fields as $k => $v) {
                $cmd .= ' --' . $k . '=%(' . $k . ')s';
                $args[$k] = $v;
            }

            $ret = $this->_exec($docroot, $cmd, $args);
            if (!$ret['success']) {
                return error("failed to update admin `%s', error: %s",
                    $admin,
                    $ret['stderr']
                );
            }


            if (isset($fields['user_pass'])) {
                info("user `%s' password changed", $admin);
            }

            return $ret['success'];
        }

	    /**
	     * Get the primary admin for a WP instance
	     *
	     * @param string      $hostname
	     * @param null|string $path
	     * @return string admin or false on failure
	     */
        public function get_admin(string $hostname, string $path = ''): ?string
        {
            $docroot = $this->getDocumentRoot($hostname, $path);
            $ret = $this->_exec($docroot, 'user list --role=administrator --field=user_login');
            if (!$ret['success']) {
                warn("failed to enumerate WP administrative users");
                return null;
            }
            $line = strtok($ret['stdout'], "\r\n");
            return $line;
        }

	    /**
	     * Get installed version
	     *
	     * @param string $hostname
	     * @param string $path
	     * @return string version number
	     */
        public function get_version(string $hostname, string $path = ''): ?string
        {
            if (!$this->valid($hostname, $path)) {
                return null;
            }
            $docroot = $this->getDocumentRoot($hostname, $path);
            $ret = $this->_exec($docroot, 'core version');
            if (!$ret['success']) {
                return null;
            }
            return trim($ret['stdout']);

        }

	    /**
	     * Update core, plugins, and themes atomically
	     *
	     * @param string $hostname subdomain or domain
	     * @param string $path     optional path under hostname
	     * @param string $version
	     * @return bool
	     */
        public function update_all(string $hostname, string $path = '', string $version = null): bool
        {
            return $this->update($hostname, $path, $version) && $this->update_plugins($hostname, $path) &&
                $this->update_themes($hostname, $path) || error("failed to update all components");
        }

	    /**
	     * Update Laravel to latest version
	     *
	     * @param string $hostname domain or subdomain under which WP is installed
	     * @param string $path     optional subdirectory
	     * @param string $version
	     * @return bool
	     */
        public function update(string $hostname, string $path = '', string $version = null): bool
        {
            $docroot = $this->getDocumentRoot($hostname, $path);
            if (!$docroot) {
                return error("update failed");
            }

	        if ($version) {
		        if (!\Opcenter\Versioning::valid($version)) {
			        return error("invalid version number, %s", $version);
		        }
		        $cmd .= ' --version=%(version)s';
		        $args['version'] = $version;
	        }
	        parent::setInfo($docroot, [
		        'version' => $this->get_version($hostname, $path),
		        'failed'  => !$ret['success']
	        ]);
            return $ret['success'];
        }

	    /**
	     * Update Laravel plugins
	     *
	     * @param string $hostname domain or subdomain
	     * @param string $path     optional path within host
	     * @param array  $plugins
	     * @return bool
	     */
        public function update_plugins(string $hostname, string $path = '', array $plugins = array()): bool
        {
            $docroot = $this->getDocumentRoot($hostname, $path);
            if (!$docroot) {
                return error("update failed");
            }

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
	     * Update Laravel themes
	     *
	     * @param string $hostname subdomain or domain
	     * @param string $path     optional path under hostname
	     * @param array  $themes
	     * @return bool
	     */
        public function update_themes(string $hostname, string $path = '', array $themes = array()): bool
        {
            $docroot = $this->getDocumentRoot($hostname, $path);
            if (!$docroot) {
                return error("update failed");
            }

            $cmd = 'theme update';
            $args = array();
            if (!$themes) {
                $cmd .= ' --all';
            } else {
                for ($i = 0, $n = sizeof($themes); $i < $n; $i++) {
                    $theme = $themes[$i];
                    $version = null;
                    if (isset($theme['version'])) {
                        $version = $theme['version'];
                    }
                    if (isset($theme['name'])) {
                        $plugin = $theme['name'];
                    }

                    $name = 'p' . $i;

                    $cmd .= ' %(' . $name . ')s';
                    $args[$name] = $theme;
                    if ($version) {
                        $cmd .= ' --version=%(' . $name . 'v)s';
                        $args[$name . 'v'] = $version;
                    }
                }
            }

            $ret = $this->_exec($docroot, $cmd, $args);
            if (!$ret['success']) {
                return error("theme update failed: `%s'", $ret['stderr']);
            }
            return $ret['success'];
        }

	    /**
	     * Web application supports fortification
	     *
	     * @param string|null $mode optional mode (min, max)
	     * @return bool
	     */
        public function has_fortification(string $mode = null): bool
        {
            return parent::has_fortification($mode);
        }

	    /**
	     * Restrict write-access by the app
	     *
	     * @param string $hostname
	     * @param string $path
	     * @param string $mode
	     * @return bool
	     */
        public function fortify(string $hostname, string $path = '', string $mode = 'max'): bool
        {
            parent::fortify($hostname, $path, $mode);
        }

	    /**
	     * Relax permissions to allow write-access
	     *
	     * @param string $hostname
	     * @param string $path
	     * @return bool
	     * @internal param string $mode
	     */
        public function unfortify(string $hostname, string $path = ''): bool
        {
            return parent::unfortify($hostname, $path, $mode);
        }

        /**
         * Laravel housekeeping
         *
         * @return bool
         */
        public function _housekeeping()
        {
            // nothing to do as Symfony is managed separately by
            // a the PHP module
            return true;
        }

	    public function next_version(string $version, string $maximalbranch = '99999999.99999999.99999999'): ?string
	    {
		    return parent::next_version($version, $maximalbranch);
	    }
    }


