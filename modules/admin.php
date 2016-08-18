<?php

	/**
	 *  @ignore
	 *  +------------------------------------------------------------+
	 *  | apnscp esprit                                              |
	 *  +------------------------------------------------------------+
	 *  | Copyright (c) 2008 Apis Networks                           |
	 *  +------------------------------------------------------------+
	 *  | This code may not be publically disclosed or disseminated  |
	 *  | upon any entity outside Apis Networks.                     |
	 *  +------------------------------------------------------------+
	 *  | Author: Matt Saladna (msaladna@apisnetworks.com)           |
	 *  +------------------------------------------------------------+
	 */

	/**
	 *  Provides administrative functions
	 *  @package core
	 */

	class Admin_Module extends Module_Skeleton {

		/**
		 * {{{ void __construct(void)
		 * @ignore
		 */
		public function __construct() {
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
		public function get_domains() {
			$q = $this->pgsql->query("SELECT domain,site_id FROM siteinfo ORDER BY domain");
			$domains = array();
			while (false !== ($row = $q->fetch_object())) {
				$domains[$row->site_id] = $row->domain;
			}
			return $domains;
		}

		/**
		 * Translate domain to id
		 * 
		 * @param  string $domain domain
		 * @return int
		 */
		public function get_site_id_from_domain($domain) {
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error("invalid domain `%s'", $domain);
			}
			$q = $this->pgsql->query("SELECT site_id FROM siteinfo WHERE domain = '".$domain."'");
			if ($this->pgsql->num_rows() > 0) {
				return $q->fetch_object()->site_id;
			}
			$id = Auth::get_site_id_from_domain($domain);
			return $id;

		}

		/**
		 * Get e-mail from domain
		 * 
		 * @param  string $domain
		 * @return string
		 */
		public function get_address_from_domain($domain) {
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
		
		public function get_meta_from_domain($domain, $service, $class = null)
		{
			
			if (!IS_CLI) return $this->query('admin_get_meta_from_domain', $domain, $service, $class);
            $site = $domain;
            
            // $domain passed as site
			if (substr($domain, 0, 4) != 'site' || intval($domain) != substr($domain, 4)) {
				$tmp = Auth::get_site_id_from_domain($domain);
				if (!$tmp) return error("unknown domain `$domain'");
				$site = 'site' . $tmp;
			} else if (!Auth::site_exists($site)) {
				return error("site `%s' out of bounds", $site);
			}
			$file = '/home/virtual/' . $site . '/info/current/' . $service;
			$new  = '/home/virtual/' . $site . '/info/new/' . $service . '.new';
			if (file_exists($new)) {
				$file = $new;
			} else if (!file_exists($file)) {
				return error("service `$service' not installed for `$domain'");
			}
			
			$meta = Util_Conf::parse_ini($file);
			if (!$class) return $meta;
			if (!isset($meta[$class])) {
                // @XXX DEBUG from CRM
                Error_Reporter::report(join(" ", array($domain, $service, $class)). " " . Error_Reporter::get_debug_bt());
                return error("meta `%s' does not exist for `%s'", 
                    $class, $service);
            }
			return $meta[$class];
		}

	}
?>
