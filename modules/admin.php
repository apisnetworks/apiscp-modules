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
     *  Provides administrative functions
     *
     * @package core
     */
    class Admin_Module extends Module_Skeleton
    {
        const ADMIN_HOME = '/etc/appliance';
        // @var string under ADMIN_HOME
        const ADMIN_CONFIG = '.config/';
        const ADMIN_CONFIG_LEGACY = '/etc/appliance/appliance.ini';

        /**
         * {{{ void __construct(void)
         *
         * @ignore
         */
        public function __construct()
        {
            parent::__construct();
            $this->exportedFunctions =
                array('*' => PRIVILEGE_ADMIN);
        }
        /* }}} */

        /**
         * List all domains on the server
         *
         * @return array
         */
        public function get_domains()
        {
            $q = $this->pgsql->query("SELECT domain,site_id FROM siteinfo ORDER BY domain");
            $domains = array();
            while (null !== ($row = $q->fetch_object())) {
                $domains[$row->site_id] = $row->domain;
            }
            return $domains;
        }

        /**
         * Get e-mail from domain
         *
         * @param  string $domain
         * @return string
         */
        public function get_address_from_domain($domain)
        {
            if (!preg_match(Regex::DOMAIN, $domain)) {
                return error("invalid domain `%s'", $domain);
            }
            $siteid = $this->get_site_id_from_domain($domain);
            if (!$siteid) {
                return false;
            }
            $q = $this->pgsql->query("SELECT email FROM siteinfo WHERE site_id = " . intval($siteid));
            if ($this->pgsql->num_rows() > 0) {
                return $q->fetch_object()->email;
            }
            return false;
        }

        /**
         * Translate domain to id
         *
         * @param  string $domain domain
         * @return int
         */
        public function get_site_id_from_domain($domain)
        {
            if (!preg_match(Regex::DOMAIN, $domain)) {
                return error("invalid domain `%s'", $domain);
            }
            $q = $this->pgsql->query("SELECT site_id FROM siteinfo WHERE domain = '" . $domain . "'");
            if ($this->pgsql->num_rows() > 0) {
                return $q->fetch_object()->site_id;
            }
            $id = Auth::get_site_id_from_domain($domain);
            return $id;

        }

        public function get_meta_from_domain($domain, $service, $class = null)
        {

            if (!IS_CLI) {
                return $this->query('admin_get_meta_from_domain', $domain, $service, $class);
            }
            $site = $domain;

            // $domain passed as site
            if (substr($domain, 0, 4) != 'site' || intval($domain) != substr($domain, 4)) {
                $tmp = Auth::get_site_id_from_domain($domain);
                if (!$tmp) {
                    return error("unknown domain `$domain'");
                }
                $site = 'site' . $tmp;
            } else {
                if (!Auth::site_exists($site)) {
                    return error("site `%s' out of bounds", $site);
                }
            }
            $file = '/home/virtual/' . $site . '/info/current/' . $service;
            $new = '/home/virtual/' . $site . '/info/new/' . $service . '.new';
            if (file_exists($new)) {
                $file = $new;
            } else {
                if (!file_exists($file)) {
                    return error("service `$service' not installed for `$domain'");
                }
            }

            $meta = Util_Conf::parse_ini($file);
            if (!$class) {
                return $meta;
            }
            if (!isset($meta[$class])) {
                // @XXX DEBUG from CRM
                Error_Reporter::report(join(" ",
                        array($domain, $service, $class)) . " " . Error_Reporter::get_debug_bt());
                return error("meta `%s' does not exist for `%s'",
                    $class, $service);
            }
            return $meta[$class];
        }

        /**
         * Get appliance admin email
         *
         * @return string|null
         */
        public function get_email()
        {
            $ini = $this->_get_admin_config();
            return $ini['adminemail'] ?? null;
        }

        /**
         * Set appliance admin email
         *
         * @param string $email
         * @return bool
         */
        public function set_email($email)
        {
            if (!IS_CLI) {
                return $this->query('admin_set_email', $email);
            }
            if (!preg_match(Regex::EMAIL, $email)) {
                return error("invalid email `%s'", $email);
            }
            $ini = $this->_get_admin_config();
            $ini['adminemail'] = $email;
            $data = '[DEFAULT]' . "\n" . implode("\n", array_key_map(function ($k, $v) {
                    return $k . ' = ' . $v;
                }, $ini)) . "\n";
            \Preferences::set('email', $email);
            return (bool)file_put_contents(self::ADMIN_CONFIG_LEGACY, $data);
        }

        public function _housekeeping()
        {
            $configHome = static::ADMIN_HOME . '/' . self::ADMIN_CONFIG;
            if (!is_dir($configHome)) {
                mkdir($configHome) && chmod($configHome, 0700);
            }
	        $defplan = \Opcenter\Service::PLAN_PATH . '/' .
		        \Opcenter\Service::DEFAULT_SVC_NAME;
            if (is_dir($defplan)) {
	            return;
            }
            // plan name change
            $dh = opendir(\Opcenter\Service::PLAN_PATH);
            if (!$dh) {
            	return error("Plan path `%s' missing, account creation will fail until fixed",
		            \Opcenter\Service::PLAN_PATH
	            );
            }
            while (false !== ($f = readdir($dh))) {
            	if ($f === '..' || $f === '.') {
            		continue;
	            }
	            $path = \Opcenter\Service::PLAN_PATH . '/' . $f;
            	if (is_link($path)) {
            		unlink($path);
            		break;
	            }
            }
	        if ($f !== false) {
		        info("old default plan `%s' renamed to `%s'",
		            $f, \Opcenter\Service::DEFAULT_SVC_NAME
	            );
	        }
	        symlink(dirname($defplan) . '/.skeleton', $defplan);
        }

        protected function _get_admin_config()
        {
            if (!file_exists(self::ADMIN_CONFIG_LEGACY)) {
                return [];
            }
            return parse_ini_file(self::ADMIN_CONFIG_LEGACY);
        }

	    /**
	     * Force bulk update of webapps
	     *
	     * @param int|string $limit optional limit or site for batching
	     * @return bool
	     */
        public function update_webapps($limit = null): bool {
	        $launcher = \Module\Support\Webapps\Updater::launch();
	        if (ctype_digit($limit)) {
		        $launcher->batch((int)$limit);
	        } else if ($limit) {
		        $launcher->limitSite($limit);
	        }
	        return (bool)$launcher->run();
        }

        public function locate_webapps($site = null): array {
        	return \Module\Support\Webapps\Finder::find($site);
        }
    }