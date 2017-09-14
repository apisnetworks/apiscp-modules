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
     * WordPress management
     *
     * An interface to wp-cli
     *
     * @package core
     */
    class Wordpress_Module extends Module_Support_Webapps
    {

        const APP_NAME = "WordPress";

        // primary domain document root
        const WP_CLI = '/usr/share/pear/wp-cli.phar';

        // latest release
        const WP_CLI_URL = 'https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar';

        const VERSION_CHECK_URL = 'https://api.wordpress.org/core/version-check/1.7/';
        protected $_aclList = array(
            'min' => array(
                '/wp-content',
                '/.htaccess',
                '/wp-config.php'
            ),
            'max' => array(
                '/wp-content/uploads',
                '/wp-content/cache',
                '/wp-content/wflogs'
            )
        );
        private $_versionCache = array();

        /**
         * void __construct(void)
         *
         * @ignore
         */
        public function __construct()
        {

            parent::__construct();
            $this->exportedFunctions = array(
                '*' => PRIVILEGE_SITE | PRIVILEGE_USER,
            );
        }

        /**
         * Install WordPress into a pre-existing location
         *
         * @param string $hostname domain or subdomain to install WordPress
         * @param string $path     optional path under hostname
         * @param array  $opts     additional install options
         * @return bool
         */
        public function install($hostname, $path = '', array $opts = array())
        {
            $docroot = $this->_normalizePath($hostname, $path);
            if (!$docroot) {
                return error("failed to install WP");
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

            $squash = array_get($opts, 'squash', false);
            if ($squash && $this->permission_level & PRIVILEGE_USER) {
                warn("must squash privileges as secondary user");
                $squash = true;
            }
            $opts['squash'] = $squash;

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

            // ensure the docroot is owned by the target uid to permit installation
            // correct it at the end
            if (!$squash) {
                $this->file_chown($docroot, $this->user_id);
            }
            $ret = $this->_exec($docroot, 'core %(mode)s %(version)s', $args);

            if (!$ret['success']) {
                $vertmp = $version ?? 'LATEST';
                return error("failed to download WP version `%s', error: %s",
                    $vertmp,
                    coalesce($ret['stdout'], $ret['stderr'])
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
            $dbpass = $this->_suggestPassword();
            $credentials = array(
                'db'       => $db,
                'user'     => $dbuser,
                'password' => $dbpass
            );

            if (!parent::setupDatabase($credentials)) {
                return false;
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
                $opts['password'] = $this->_suggestPassword(10);
                info("autogenerated password `%s'", $opts['password']);
            }

            if (!isset($opts['user'])) {
                $opts['user'] = $this->username;
                info("setting admin user to `%s'", $this->username);
            }
            // fix situations when installed on global subdomain
            $fqdn = $this->web_normalize_hostname($hostname);
            $opts['url'] = rtrim($fqdn. '/' . $path, '/');
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
                return error("failed to create database structure: %s", $ret['stdout']);
            }
            // by default, let's only open up ACLs to the bare minimum

            $this->fortify($hostname, $path, 'max');
            if (!$version) {
                $version = $this->_getLastestVersion();
            }
            $params = array(
                'version'    => $version,
                'hostname'   => $hostname,
                'autoupdate' => (bool)$opts['autoupdate'],
                'fortify'    => 'max',
                'options'    => $opts
            );
            $this->_map('add', $docroot, $params);

            $url = 'http://' . $fqdn. '/' . $path;
            $msg = "Hello!" . "\r\n" .
                "This is a confirmation that WordPress has been installed under " . $docroot .
                ". You may access WordPress via " . $url . ". Access the administrative " .
                "panel at " . rtrim($url, "/") . '/wp-admin' . " using the following details:" . "\r\n\r\n" .
                "Username: " . $opts['user'] . "\r\n" .
                ($autogenpw ? "Password: " . $opts['password'] . "\r\n" : '');
            $msg .= "\r\nWhen installing plugins or themes, you will need to use your " .
                "control panel password!";
            $hdrs = "From: " . Crm_Module::FROM_NAME . " <" . Crm_Module::FROM_ADDRESS . ">\r\nReply-To: " . Crm_Module::REPLY_ADDRESS;
            if (!is_debug()) {
                Mail::send($opts['email'], "Wordpress Installed", $msg, $hdrs);
            }

            if (!$opts['squash']) {
                parent::unsquash($docroot);
            }
            info("WordPress installed - confirmation email with login info sent to %s", $opts['email']);
            return true;
        }

        /**
         *
         */
        public function plugin_status($hostname, $path = '', $plugin = null)
        {
            $docroot = $this->_normalizePath($hostname, $path);
            if (!$docroot) {
                return error("invalid WP location");
            }
            $args = array(
                'plugin' => $plugin
            );
            $ret = $this->_exec($docroot, 'plugin status %s', $args);
            if (!$ret['success']) {
                return error("failed to get plugin status");
            }

            if (!preg_match_all(Regex::WORDPRESS_PLUGIN_STATUS, $ret['output'], $matches)) {
                return error("unable to parse WP plugin info");
            }

            return error("@XXX @TODO");
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

            $args = array(
                'plugin' => $plugin
            );
            $ret = $this->_exec($docroot, 'plugin install %(plugin)s --activate', $args);
            if (!$ret['success']) {
                return error("failed to install plugin `%s': %s", $plugin, coalesce($ret['stderr'], $ret['stdout']));
            }
            info("installed plugin `%s'", $plugin);
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

            $args = array(
                'plugin' => $plugin
            );
            $cmd = 'plugin uninstall %(plugin)s';
            if ($force) {
                $cmd .= ' --deactivate';
            }
            $ret = $this->_exec($docroot, $cmd, $args);

            if (!$ret['stdout'] || !strncmp($ret['stdout'], "Warning:", strlen("Warning:"))) {
                return error("failed to uninstall plugin `%s': %s", $plugin, coalesce($ret['stderr'], $ret['stdout']));
            }
            info("uninstalled plugin `%s'", $plugin);
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

            $ret = $this->_exec($docroot, 'plugin deactivate --all --skip-plugins');
            if (!$ret['success']) {
                return error("failed to deactivate all plugins: %s", coalesce($ret['stderr'], $ret['stdout']));
            }
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
                return error("failed to determine WP");
            }
            $code = 'set_error_handler(function() { global $table_prefix; print serialize(array("user" => DB_USER, "password" => DB_PASSWORD, "db" => DB_NAME, "host" => DB_HOST, "prefix" => $table_prefix)); die(); }); include("./wp-config.php"); trigger_error("");';
            $cmd = 'cd %(path)s && php -d mysqli.default_socket=%(socket)s -r %(code)s';
            $ret = $this->pman_run($cmd,
                array(
                    'path'   => $docroot,
                    'code'   => $code,
                    'socket' => ini_get('mysqli.default_socket')
                )
            );
            if (!$ret['success']) {
                return error("failed to obtain WP configuration for `%s'", $docroot);
            }
            $data = unserialize($ret['stdout']);
            return $data;
        }

        /**
         * Check if version is latest or get latest version
         *
         * @param null $version
         * @return int|string
         */
        public function is_current($version = null)
        {
            $latest = $this->_getLastestVersion();;
            if (!$version) {
                return $version;
            }
            if (version_compare($version, $latest, '=')) {
                return 1;
            } else {
                if (version_compare($version, $latest, '<')) {
                    return 0;
                } else {
                    return -1;
                }
            }
        }

        /**
         * Change WP admin credentials
         *
         * $fields is a hash whose indices match wp_update_user
         * common fields include: user_pass, user_login, and user_nicename
         *
         * @link https://codex.wordpress.org/Function_Reference/wp_update_user
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
                    coalesce($ret['stderr'], $ret['stdout'])
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
         * @param      $domain
         * @param null $path
         * @return bool|string admin or false on failure
         */
        public function get_admin($domain, $path = null)
        {
            $docroot = $this->_normalizePath($domain, $path);
            $ret = $this->_exec($docroot, 'user list --role=administrator --field=user_login');
            if (!$ret['success']) {
                return warn("failed to enumerate WP administrative users");
            }
            $line = strtok($ret['stdout'], "\r\n");
            return $line;
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
            $ret = $this->_exec($docroot, 'core version');
            if (!$ret['success']) {
                return null;
            }
            return trim($ret['stdout']);

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

            return $this->file_file_exists($docroot . '/wp-config.php') || $this->file_file_exists($docroot . '/wp-config-sample.php');
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
            return $this->update_themes($hostname, $path) && $this->update_plugins($hostname, $path) &&
                $this->update($hostname, $path) || error("failed to update all components");
        }

        /**
         * Update WordPress to latest version
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

            $cmd = 'core update';
            $args = array();
            if ($version) {
                if (!is_scalar($version) || strcspn($version, ".0123456789")) {
                    return error("invalid version number, %s", $version);
                }
                $cmd .= ' --version=%(version)s';
                $args['version'] = $version;
            }

            $ret = $this->_exec($docroot, $cmd, $args);
            if (!$ret['success']) {
                return error("update failed: `%s'", coalesce($ret['stderr'], $ret['stdout']));
            }
            info("updating WP database if necessary");
            $ret = $this->_exec($docroot, 'core update-db');
            if (!$ret['success']) {
                return warn("failed to update WP database - " .
                    "login to WP admin panel to manually perform operation");
            }
            return $ret['success'];
        }

        /**
         * Update WordPress plugins
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
                return error("plugin update failed: `%s'", coalesce($ret['stderr'], $ret['stdout']));
            }
            return $ret['success'];
        }

        /**
         * Update WordPress themes
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
                return error("theme update failed: `%s'", coalesce($ret['stderr'], $ret['stdout']));
            }
            return $ret['success'];
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
         * Restrict write-access by the app
         *
         * @param        $hostname
         * @param string $path
         */
        public function fortify($hostname, $path = '', $mode = 'max')
        {
            if (!parent::fortify($hostname, $path, $mode)) {
            	return false;
            }
            if ($mode === 'min') {
            	// allow direct access on min to squelch FTP dialog
            	$path = $this->_normalizePath($hostname, $path) . '/wp-admin/includes/file.php';
            	if (file_exists($this->domain_fs_path() . $path)) {
            		$this->file_chown($path, \Web_Module::WEB_USERNAME);
	            }
            }
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
            return parent::unfortify($hostname, $path, $mode);
        }

        /**
         * Install wp-cli if necessary
         *
         * @return bool
         */
        public function _housekeeping()
        {
            if (file_exists(self::WP_CLI) && filemtime(self::WP_CLI) < filemtime(__FILE__)) {
                unlink(self::WP_CLI);
            }
            if (!file_exists(self::WP_CLI)) {
                $url = self::WP_CLI_URL;
                $res = Util_HTTP::download($url, self::WP_CLI);
                if (!$res) {
                    return error("failed to install wp-cli module");
                }
                info("downloaded wp-cli");
            }

            $local = $this->service_template_path('siteinfo') . '/' . self::WP_CLI;
            if (!file_exists($local)) {
                return copy(self::WP_CLI, $local);
            }
            return true;
        }

        private function _exec($path = null, $cmd, array $args = array())
        {
            // client may override tz, propagate to bin
            $tz = date_default_timezone_get();
            $cli = 'php -d mysqli.default_socket=' . escapeshellarg(ini_get("mysqli.default_socket")) .
                ' -d date.timezone=' . $tz . ' -d memory_limit=128m ' . self::WP_CLI;
            if (!is_array($args)) {
                $args = array_slice(func_get_args(), 2);
            }
            if ($path) {
                $cmd = '--path=%(path)s ' . $cmd;
                $args['path'] = $path;
            }
            $cmd = $cli . ' ' . $cmd;
            // $from_email isn't always set, ensure WP can send via wp-includes/pluggable.php
            $ret = $this->pman_run($cmd, $args, array('SERVER_NAME' => $this->domain));
            if (0 === strpos($ret['stdout'], "Error:")) {
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

            $xtraphp = '<<EOF ' . "\n" .
                "// defer updates to CP" . "\n" .
                "define('WP_AUTO_UPDATE_CORE', false); " . "\n" .
                "define('FTP_USER',%(ftpuser)s);" . "\n" .
                "define('FTP_HOST', %(ftphost)s);" . "\n" .
                ($ftpcredentials['password'] ?
                    "define('FTP_PASS', %(ftppass)s);" : '') . "\n" .
                "EOF";
            $args = array(
                'mode'     => 'config',
                'db'       => $dbcredentials['db'],
                'password' => $dbcredentials['password'],
                'user'     => $dbcredentials['user'],
                'ftpuser'  => $ftpcredentials['user'],
                'ftphost'  => 'localhost',
                'ftppass'  => $ftpcredentials['password'],
            );


            $ret = $this->_exec($docroot,
                'core %(mode)s --dbname=%(db)s --dbpass=%(password)s --dbuser=%(user)s --dbhost=localhost --extra-php ' . $xtraphp,
                $args);
            if (!$ret['success']) {
                return error("failed to generate configuration, error: %s", coalesce($ret['stderr'], $ret['stdout']));
            }
            return true;
        }

        /**
         * Get latest WP release
         *
         * @return string
         */
        protected function _getLastestVersion()
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
        protected function _getVersions()
        {
            $key = 'wp.versions';
            $cache = Cache_Super_Global::spawn();
            if (false !== ($ver = $cache->get($key))) {
                return $ver;
            }
            $url = self::VERSION_CHECK_URL;
            $context = stream_context_create(['http' => ['timeout' => 5]]);
            $contents = file_get_contents($url, null, $context);
            if (!$contents) {
                return array();
            }
            $versions = json_decode($contents, true);
            $versions = $versions['offers'];
            $cache->set($key, $versions, 43200);
            return $versions;
        }
    }
