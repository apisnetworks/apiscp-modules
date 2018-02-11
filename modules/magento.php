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
    class Magento_Module extends \Module\Support\Webapps\Magento
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

	    const DEFAULT_VERSION_LOCK = 'major';

        protected $_aclList = array(
            'min' => array('/media', '/var', '/downloader', '/generated', '/pub/static'),
            'max' => array('/media/downloadable', '/downloader', '/var/cache', '/var/session', '/var/page_cache', '/var/log', '/generated/code', '/generated/metadata', '/pub/static')
        );

        /**
         * void __construct(void)
         *
         * @ignore
         */
        public function __construct()
        {

            parent::__construct();
        }

	    /**
	     * Install Magento into a pre-existing location
	     *
	     * @param string $hostname domain or subdomain to install Magento
	     * @param string $path     optional path under hostname
	     * @param array  $opts     additional install options
	     * @return bool
	     */
        public function install(string $hostname, string $path = '', array $opts = array()): bool
        {
            $docroot = $this->getDocumentRoot($hostname, $path);
            if (!$docroot) {
                return error('failed to install Magento');
            }

            if (!parent::checkDocroot($docroot)) {
                return false;
            }
            if (!is_debug() && !$this->ssl_permitted()) {
                return error('Account requires SSL enabled on account to manage a Magento store');
            }
            if (empty($opts['ssl'])) {
            	return error('Magento requires SSL to operate');
            }
            if (!parent::configureSsl($hostname)) {
		        return false;
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
            }
            $opts['email'] = $this->get_config('siteinfo', 'email');


            $args = array();
            // cap to 1.x branch
            $vercap = !empty($args['version']) && $args['version'][0] === 2 && $this->mysql_version() < 50600;
            if (!$vercap && !\Opcenter\Php::extensionEnabled('intl')) {
            	warn('intl extension missing - Magento capped to 1.x branch');
            	$vercap = true;
            }
            if (version_compare(Opcenter\Php::version(), '7.1', '<')) {
                warn('Magento 2.x requires PHP 7.1+. Capping to 1.x');
                $version = $this->getLatestVersion('1');
            } else if (null !== $version) {
                if (!$this->_versionValid($version)) {
                    return error("unknown Magento version `%s'", $version);
                }
                if ($vercap) {
                    warn('capping magento version to 1.x');
                    $version = $this->getLatestVersion('1');
                }
            } else {
                $version = $this->getLatestVersion($vercap ? '1' : null);
            }
            $args['version'] = $version;

            if (version_compare($args['version'], '2', '>=')) {
	            if (version_compare($args['version'], '2.2', '>=') && version_compare(Opcenter\Php::version(), '7.1', '<')) {
		            return error('Magento 2.2+ required for PHP 7.1');
	            }
	            $args['vername'] = 'magento-ce-' . $args['version'];
            } else {
            	// 1.x
	            $args['vername'] = 'apnscp-mirror-' . $args['version'];
            }
            if (!$this->get_key() && version_compare($args['version'], '2.0', '>=')) {
                return error('Magento Connect key must be setup first, do so via Account > Settings');
            }
            $fqdn = $this->web_normalize_hostname($hostname);
            $args['baseurl'] = 'http://' . $fqdn;
            if ($path) {
                $args['baseurl'] .= '/' . $path;
            }

            $squash = array_get($opts, 'squash', false);
            if ($squash && $this->permission_level & PRIVILEGE_USER) {
                warn('must squash privileges as secondary user');
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
            $dbpass = $this->suggestPassword();
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
                info('removing temporary files');
                $this->file_delete($docroot, true);
                $this->sql_delete_mysql_database($db);
                $this->sql_delete_mysql_user($dbuser, 'localhost');
                if (false !== strpos($ret['stderr'], 'to locate Magento version')) {
                    return error("failed to install magento: unknown Magento version `%s'",
                        $args['version']
                    );
                }
                return error('failed to install magento: %s', coalesce($ret['stderr'], $ret['stdout']));
            }
	        /** post install fixup */
	        // we install with some stupid defaults, change them
	        $ret = $this->_exec($docroot, 'admin:user:delete -f admin');
	        if (!$ret['success']) {
		        warn('failed to delete placeholder admin');
	        }
	        $this->_exec($docroot, 'cache:enable');

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

	        $args = array(
                'email'    => $opts['email'],
                'user'     => $opts['user'],
                'password' => $opts['password']
            );
	        if ($magerunver === 1) {
		        $this->_exec($docroot, 'admin:user:create %(user)s %(email)s %(password)s Store Admin', $args);
	        } else {
		        $this->_exec($docroot, 'admin:user:create --admin-user %(user)s --admin-email %(email)s ' .
					'--admin-password %(password)s --admin-firstname Store --admin-lastname Admin', $args);
	        }
	        if (!$ret['success']) {
		        info('removing temporary files');
		        $this->file_delete($docroot, true);
		        $this->sql_delete_mysql_database($db);
		        $this->sql_delete_mysql_user($dbuser, 'localhost');
		        return error('failed to create admin user: %s', $ret['stdout']);
	        }

	        // by default, let's only open up ACLs to the bare minimum

	        $files = array_map(function ($f) use ($docroot) {
                return $docroot . '/' . $f;
            }, $this->_aclList['min']);
	        $this->file_touch($docroot . '/.htaccess');
	        parent::fixRewriteBase($docroot, $path);
	        parent::fixSymlinkTraversal($docroot);
	        if ($magerunver === 2) {
		        parent::fixRewriteBase($docroot . '/pub', rtrim($path, '/') .'/');
		        parent::fixRewriteBase($docroot . '/pub/static', rtrim($path, '/') . '/static');
	        }
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
            );
	        $this->_map('add', $docroot, $params);
	        parent::fortify($hostname, $path, 'max');
	        if ($this->guessMajor($docroot) === 1) {
		        $this->file_chmod($docroot . '/app/etc/local.xml', 644);
		        $this->_fixModelPHP7($docroot);
	        }
            $this->_fixConnectConfig($docroot);
            $url = 'https://' . $fqdn . '/' . $path . '/';
            $args = array(
                'path' => 'web/secure/base_url',
                'url'  => rtrim($url,'/') . '/'
            );
            $this->_exec($docroot, 'config:set %(path)s %(url)s', $args);
            if ($magerunver === 2) {
                $this->_exec($docroot, 'config:set web/secure/use_in_frontend 1');
            }
            $this->_exec($docroot, 'cache:flush');

	        /**
	         * @todo relink domain/subdomain to pub/
	         * setup cron
	         * ssl
	         */
            if ($magerunver === 1) {
                $this->_fixModelPHP7($docroot);
            }

            if (array_get($opts, 'notify', true)) {
	            $msg = 'Hello!' . "\r\n" .
		            'This is a confirmation that Magento has been installed under ' . $docroot .
		            '. You may access Magento via ' . $url . '. Access the administrative ' .
		            'panel at ' . rtrim($url, '/') . self::ADMIN_URL . ' using the following details:' . "\r\n\r\n" .
		            'Username: ' . $opts['user'] . "\r\n" .
		            ($autogenpw ? 'Password: ' . $opts['password'] . "\r\n" : '');
	            $msg .= "\r\nWhen installing plugins or themes, you will need to use your " .
		            'control panel password!';
	            $hdrs = 'From: ' . Crm_Module::FROM_NAME . ' <' .
		            Crm_Module::FROM_ADDRESS . ">\r\nReply-To: " . Crm_Module::REPLY_ADDRESS;
	            Mail::send($opts['email'], 'Magento Installed', $msg, $hdrs);
            }

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
            if (!isset($contents['http-basic']['repo.magento.com'])) {
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
        public function get_version(string $hostname, string $path = ''): ?string
        {
            if (!$this->valid($hostname, $path)) {
                return null;
            }

            $approot = $this->getAppRoot($hostname, $path);

            $ret = $this->_exec($approot, 'sys:info --format=json', []);

            if (!$ret['success']) {
                return null;
            }
            $info = json_decode($ret['stdout'], true);
            foreach ($info as $el) {
                if (strtolower($el['name']) === 'version') {
                    return $el['value'];
                }
            }
            return null;

        }

		protected function getAppRoot(string $hostname, string $path = ''): ?string {
			return parent::getAppRoot($hostname, $path);
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
	        return $this->guessMajor($docroot) !== null;
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
                return error('invalid WP location');
            }

            return info('not implemented');
        }

	    /**
	     * Uninstall a plugin
	     *
	     * @param string      $hostname
	     * @param string      $path
	     * @param string      $plugin plugin name
	     * @param bool|string $force  delete even if plugin activated
	     * @return bool
	     */
        public function uninstall_plugin(string $hostname, string $path = '', string $plugin, bool $force = false): bool
        {
            $docroot = $this->getDocumentRoot($hostname, $path);
            if (!$docroot) {
                return error('invalid Magento location');
            }

            return info('not implemented');
        }

        /**
         * Recovery mode to disable all plugins
         *
         * @param string $hostname subdomain or domain of WP
         * @param string $path     optional path
         * @return bool
         */
        public function disable_all_plugins(string $hostname, string $path = ''): bool
        {
            $docroot = $this->getDocumentRoot($hostname, $path);
            if (!$docroot) {
                return error('failed to determine path');
            }

            return info('not implemented');
        }

        /**
         * Uninstall WP from a location
         *
         * @param        $hostname
         * @param string $path
         * @param string $delete "all", "db", or "files"
         * @return bool
         */
        public function uninstall(string $hostname, string $path = '', string $delete = 'all'): bool
        {
	        /**
	         * @todo delete app whose docroot is one level below app root
	         */
            return parent::uninstall($hostname, $path, $delete);
        }

        /**
         * Get database configuration for a blog
         *
         * @param string $hostname domain or subdomain of wp blog
         * @param string $path     optional path
         * @return array|bool
         */
        public function db_config(string $hostname, string $path = '')
        {
            $docroot = $this->getDocumentRoot($hostname, $path);
            if (!$docroot) {
                return error('failed to determine Magento');
            }
            if ($this->guessMajor($docroot) === 1) {
	            $file = $this->domain_fs_path() . $docroot . '/app/etc/local.xml';
	            $code = simplexml_load_string(file_get_contents($file, null, LIBXML_NOCDATA));
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
            $file = $this->domain_fs_path() . dirname($docroot) . '/app/etc/env.php';
            if (!file_exists($file) || null === ($conn = array_get(include $file, 'db'))) {
            	return [];
            }
            return [
	            'user'     => array_get($conn, 'connection.default.username'),
	            'host'     => array_get($conn, 'connection.default.host'),
	            'db'       => array_get($conn, 'connection.default.dbname'),
	            'password' => array_get($conn, 'connection.default.password'),
	            'prefix'   => array_get($conn, 'table_prefix'),
            ];
        }

	    /**
	     * Check if version is latest or get latest version
	     *
	     * @param string|null $version
	     * @param string|null $branchcomp
	     * @return int|string
	     */
	    public function is_current(string $version = null, string $branchcomp = null)
	    {
		    return parent::is_current($version, $branchcomp);
	    }

        /**
         * Change Magento admin credentials
         *
         * $fields is a hash whose indices match password
         *
         * @param string $hostname
         * @param string $path
         * @param array  $fields
         * @return bool
         */
        public function change_admin(string $hostname, string $path = '', array $fields): bool
        {
            $approot = $this->getAppRoot($hostname, $path);
            if (!$approot) {
                return warn('failed to change administrator information');
            }
            $admin = $this->get_admin($hostname, $path);

            if (!$admin) {
                return error('cannot determine admin of Magento install');
            }
            $args = array(
                'username' => $admin
            );
            if (isset($fields['password'])) {
                $args['password'] = $fields['password'];
                $ret = $this->_exec($approot, 'admin:user:change-password %(username)s %(password)s', $args);
                if (!$ret['success']) {
                    return error("failed to change admin password, `%s'", $ret['stderr']);
                }
            } else {
                return warn('no other fields besides password implemented');
            }
            return true;

        }

        /**
         * Get the primary admin for a Magento instance
         *
         * @param string $hostname
         * @param string|null $path
         * @return null|string admin or false on failure
         */
        public function get_admin(string $hostname, string $path = ''): ?string
        {
            $approot = $this->getAppRoot($hostname, $path);
            $ret = $this->_exec($approot, 'admin:user:list --format=json');
            if (!$ret['success']) {
                warn('failed to enumerate administrative users');
                return null;
            }
            $users = json_decode($ret['stdout'], true);
            if (!$users) {
                error('no administrative users found');
                return null;
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
        public function has_fortification(string $mode = null): bool
        {
            return parent::has_fortification($mode);
        }

	    /**
	     * @param string $hostname
	     * @param string $path
	     * @param string $mode
	     * @return bool
	     */
        public function fortify(string $hostname, string $path = '', string $mode = 'max'): bool
        {
            return parent::fortify($hostname, $path, $mode);
        }

        /**
         * Relax permissions to allow write-access
         *
         * @param string $hostname
         * @param string $path
         * @return bool
         */
        public function unfortify(string $hostname, string $path = ''): bool
        {
        	return parent::unfortify($hostname, $path);
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
            $ret = ($this->update($hostname, $path, $version) && $this->update_plugins($hostname, $path) &&
		            $this->update_themes($hostname, $path)) || error('failed to update all components');

	        parent::setInfo($this->getDocumentRoot($hostname, $path), [
		        'version' => $this->get_version($hostname, $path),
		        'failed'  => !$ret
	        ]);

	        return $ret;
        }

        /**
         * Update Magento to latest version
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
                return error('update failed');
            }

            return error('Magento updates not supported yet');
        }

        /**
         * Update Magento plugins
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
                return error('update failed');
            }

	        return info('to-do');
        }

        /**
         * Update Magento themes
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
                return error('update failed');
            }
            return info('not implemented');
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
                return error('invalid public and/or private magento key');
            }
            $file = $this->_keyAuthFile();
            $contents = array();
            if ($this->file_file_exists($file)) {
                $contents = $this->file_get_file_contents($file);
                $contents = json_decode($contents, true);
            } else if (!$this->file_file_exists(dirname($file))) {
            	$this->file_create_directory(dirname($file), 0755, true);
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
	     * @throws \Exception
	     */
        public function _housekeeping(): bool
        {
            $clis = array(
                self::MAGENTO_CLI  => self::MAGENTO_CLI_URL,
                self::MAGENTO2_CLI => self::MAGENTO2_CLI_URL
            );
            foreach ($clis as $cli => $url) {
                if (!file_exists($cli)) {
                    $res = Util_HTTP::download($url, $cli);
                    if (!$res) {
                        return error('failed to install magento cli');
                    }
                    info('downloaded %s', basename($cli));
                }

                $local = $this->service_template_path('siteinfo') . '/' . $cli;
                if (!file_exists($local)) {
                    return copy($cli, $local);
                }
            }

            return true;
        }

        /**
         * Requested version is known by magerun
         *
         * @param string $version
         * @return bool
         */
        private function _versionValid($version): bool
        {
            $versions = $this->_getVersions();
            return in_array($version, $versions);
        }

        /**
         * Get all current major versions
         *
         * @return array
         */
        protected function _getVersions(): array
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

        private function _keyAuthFile()
        {
            $home = $this->user_get_home();

	        return $home . '/.composer/auth.json';
        }


        private function _copyMagerunConfig($version = 1)
        {
            $f = resource_path('storehouse/magento/magento' . $version . '.yaml');
            if (!file_exists($f)) {
                return error('failed to locate magento download YAML');
            }
            $filename = '.n98-magerun' . ($version > 1 ? $version : '') . '.yaml';
            copy($f, $this->domain_fs_path() . '/tmp/' . $filename);
            $dest = $this->user_get_home() . '/' . $filename;
            $this->file_copy('/tmp/' . $filename, $dest);
            unlink($this->domain_fs_path() . '/tmp/' . $filename);
            return $dest;
        }

        private function _exec(string $path = null, $cmd, array $args = array(), $ver = null)
        {

	        if ($path && null === $ver) {
		        $ver = $this->guessMajor($path);
	        }

	        $magerun = $ver === 1 ? self::MAGENTO_CLI : self::MAGENTO2_CLI;
	        // client may override tz, propagate to bin
	        $tz = date_default_timezone_get();
	        $cli = 'php -d pdo_mysql.default_socket=' . escapeshellarg(ini_get('mysqli.default_socket')) .
                ' -d date.timezone=' . $tz . ' -d memory_limit=192m ' . $magerun . '';

	        if (!is_array($args)) {
		        $args = func_get_args();
		        array_shift($args);
	        }
			$user = $this->username;
	        if ($path) {
		        $cli = 'cd %(path)s && ' . $cli;
		        $args['path'] = $path;
		        $stat = $this->file_stat($path);
		        $user = !empty($stat['owner']) && $stat['uid'] >= \a23r::get_class_from_module('user')::MIN_UID ?
			        $stat['owner'] : $this->username;
	        }
            $cmd = $cli . ' ' . $cmd;
            $ret = $this->pman_run($cmd, $args, null, ['user' => $user]);
            if (!$ret['success'] && $ret['stderr']) {
                $ret['stderr'] = $ret['stdout'];
            }
            return $ret;
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
            $preamble = '::ConnectConfig::v::1.0::';
            if ($this->file_file_exists($file)) {
                $raw = $this->file_get_file_contents($file);
                if (!preg_match('/^((?:::[[[:alnum:].]*]*)+?)([sibNaO]:.*)$/mi', $raw, $preamble)) {
                    return error('cannot set Magento Connect FTP login information, ' .
	                    'config is malformed: %s', $raw);
                }
                $contents = \Util_PHP::unserialize($preamble[2]);
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

	    /**
	     * Get plugin status
	     *
	     * @param string      $hostname domain or subdomain
	     * @param null|string $path     optional path under hostname
	     * @param null|string $plugin   specific plugin to query
	     * @return array|bool
	     */
	    public function plugin_status(string $hostname, string $path = '', string $plugin = null)
	    {
		    return error("not implemented yet");
	    }

	    /**
	     * Get all available versions
	     *
	     * @return array
	     */
	    public function get_versions(): array
	    {
		    return $this->_getVersions();
	    }

	    public function next_version(string $version, string $maximalbranch = '99999999.99999999.99999999'): ?string
	    {
		    return parent::next_version($version, $maximalbranch);
	    }
    }
