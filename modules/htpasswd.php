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
	 *  htaccess/htpasswd
	 *
	 * @package core
	 */
	class Htpasswd_Module extends Module_Skeleton
	{
		const HTPASSWD_DIR = '/var/www/.htfiles';
		const DEF_REALM_NAME = 'Restricted Area';

		/**
		 * {{{ void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = array(
				'is_protected'    => PRIVILEGE_SITE,
				'get_locations'   => PRIVILEGE_SITE,
				'delete_location' => PRIVILEGE_SITE,
				'edit_location'   => PRIVILEGE_SITE,
				'location_info'   => PRIVILEGE_SITE
			);
		}

		public function is_protected($host, $path = '/')
		{

		}

		public function protect_location(
			$host,
			$path = '/',
			$realm = self::DEF_REALM_NAME,
			$type = 'digest'
		) {

		}

		public function get_locations($host)
		{

		}

		public function delete_location($host, $path)
		{

		}

		public function edit_location($host, $path, $opts)
		{

		}

		public function location_info($host, $path)
		{

		}

		public function user_exists($host, $user)
		{

		}

		public function add_user($host, $user, $passwd = null)
		{

		}

		public function delete_user($host, $user)
		{

		}

		public function get_users($host)
		{

		}

		public function get_groups($host)
		{

		}

		public function change_password($host, $user)
		{

		}

		public function create_group($host, $group, $users = array())
		{

		}

		public function user_in_group($host, $user, $group)
		{

		}

		public function remove_user_group($host, $user, $group)
		{

		}

		public function add_user_group($host, $user, $group)
		{

		}

		public function delete_group($host, $group)
		{

		}

		public function deauthorize_role($host, $role)
		{

		}

		public function authorize_role($host, $role)
		{

		}

		public function is_authorized($host, $role, $path = '/')
		{

		}

		/**
		 * Load .htpasswd
		 *
		 * @param string $host host
		 * @return string .htpasswd contents
		 */
		private function _load_htpasswd($host)
		{
			if (!preg_match(Regex::HTTP_HOST)) {
				return error($host . ": invalid host");
			}
			$htpasswd = $this->domain_fs_path() . self::HTPASSWD_DIR . '/' . $host;
			if (!file_exists($htpasswd)) {
				return error(self::HTPASSWD_DIR . "/" . $host . ": htpasswd does not exist");
			}

			return file_get_contents($htpasswd);
		}

		private function _load_htaccess($host, $path = '/')
		{

		}
	}

?>
