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
	 * Majordomo mailing list functions
	 *
	 * @package core
	 */
	class Majordomo_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable
	{
		const DEPENDENCY_MAP = [
			'mail'
		];
		const  POSTFIX_LOCAL_ALIASES_FILE = '/etc/postfix/aliases';
		const  MAJORDOMO_SETUID = 'nobody';

		/**
		 * {{{ void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();

			include_once(INCLUDE_PATH . '/lib/configuration_driver.php');
			include(INCLUDE_PATH . '/lib/modules/majordomo/config_skeleton.php');
			$this->exportedFunctions = array(
				'*'                                 => PRIVILEGE_SITE,
				'list_mailing_lists_backend'        => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'create_mailing_list_backend'       => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'delete_mailing_list_backend'       => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'get_mailing_list_users_backend'    => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'get_domain_from_list_name_backend' => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC
			);


			$this->majordomo_skeleton = $__majordomo_skeleton;
			$this->majordomo_preamble = $__majordomo_preamble;
		}

		public function get_mailing_list_users($list)
		{
			if (!IS_CLI) {
				return $this->query('majordomo_get_mailing_list_users', $list);
			}

			if (!preg_match(Regex::MAILING_LIST_NAME, $list)) {
				return error("Invalid list " . $list);
			}

			if (!file_exists($this->domain_fs_path() . '/var/lib/majordomo/lists/' . $list)) {
				return error("Invalid list name " . $list);
			}
			return file_get_contents($this->domain_fs_path() . '/var/lib/majordomo/lists/' . $list);
		}

		public function create_mailing_list($list, $password, $email = null, $domain = null)
		{
			$list = strtolower(trim($list));

			if (!$domain) {
				$domain = $this->get_service_value('siteinfo', 'domain');
			}
			if (!$email) {
				$email = trim($this->get_service_value('siteinfo', 'email'));
			}

			$email = strtolower($email);

			if (!preg_match(Regex::MAILING_LIST_NAME, $list)) {
				return error("Invalid list name");
			} else {
				if (file_exists($this->domain_fs_path() . '/var/lib/majordomo/config/' . $list)) {
					return error("Mailing list already exists");
				} else {
					if (!$password) {
						return error("Invalid argument: missing password");
					} else {
						if (!in_array($domain, $this->email_list_virtual_transports())) {
							return error("Domain not configured to handle mail");
						} else {
							if (!preg_match(Regex::EMAIL, $email)) {
								return error("Invalid owner e-mail address");
							}
						}
					}
				}
			}

			$status = $this->query('majordomo_create_mailing_list_backend',
				$list,
				$password,
				$email,
				$domain
			);

			if ($status instanceof Exception) {
				return $status;
			}

			$this->email_add_alias($list, $domain, $list . '+' . $domain);
			$this->email_add_alias($list . '-approval', $domain, $email);
			$this->email_add_alias($list . '-owner', $domain, $email);
			$this->email_add_alias('owner-' . $list, $domain, $list . '-owner');
			$this->email_add_alias($list . '-request', $domain, $list . '-request+' . $domain);

			if (!$this->email_address_exists('majordomo-owner', $domain)) {
				$this->email_add_alias('majordomo-owner', $domain, $email);
			}
			if (!$this->email_address_exists('majordomo', $domain)) {
				$this->email_add_alias('majordomo', $domain, 'majordomo+' . $domain);
			}

			return true;
		}

		public function set_mailing_list_users($list, $members)
		{
			if (!IS_CLI) {
				if (!preg_match(Regex::MAILING_LIST_NAME, $list)) {
					return error("`%s': invalid list name", $list);
				}

				if (is_array($members)) {
					$members = join("\n", $members);
				}
				return $this->query('majordomo_set_mailing_list_users', $list, $members);
			}

			if (!file_exists($this->domain_fs_path() . '/var/lib/majordomo/lists/' . $list)) {
				return error("list `%s' does not exist", $list);
			}

			// ensure list ends in newline
			$members = trim($members) . "\n";
			file_put_contents($this->domain_fs_path() . '/var/lib/majordomo/lists/' . $list, $members);
			chown($this->domain_fs_path() . '/var/lib/majordomo/lists/' . $list, self::MAJORDOMO_SETUID);
			chgrp($this->domain_fs_path() . '/var/lib/majordomo/lists/' . $list, (int)$this->group_id);
			return $this->file_chmod('/var/lib/majordomo/lists/' . $list, 644);
		}

		public function create_mailing_list_backend($list, $password, $email, $domain)
		{
			$aclprefix = $prefix = $this->domain_fs_path();

			if (version_compare(platform_version(), "4.5", '>=')) {
				$aclprefix = $this->domain_shadow_path();
			}
			if (file_exists($prefix . '/var/lib/majordomo/lists/' . $list)) {
				return error("list `%s' already exists", $list);
			}

			/** check that we have the very basic majordomo mapping */
			$mapping = system('/usr/sbin/postalias -q majordomo+' . $domain . ' ' . self::POSTFIX_LOCAL_ALIASES_FILE . ' > /dev/null',
				$ret);
			if ($ret === 1) {

				// alias not found, add it
				file_put_contents(self::POSTFIX_LOCAL_ALIASES_FILE,
					trim(file_get_contents(self::POSTFIX_LOCAL_ALIASES_FILE)) . "\n" .
					'majordomo+' . $domain . ': "| env HOME=/usr/lib/majordomo MAJORDOMO_CF=' . $prefix . '/etc/majordomo-' . $domain . '.cf  /usr/lib/majordomo/majordomo"');
				// delete in case it was replicated by an alias addition
				$this->email_remove_alias('majordomo', $domain);
				$this->email_add_alias('majordomo', $domain, 'majordomo+' . $domain);
				$proc = new Util_Account_Editor($this->getAuthContext()->getAccount());
				// let this run independently
				if (version_compare(platform_version(), '7.5', '>=')) {
					$svc = 'mlist';
				} else {
					$svc = 'majordomo';
				}
				$proc->setConfig($svc, 'enabled', 1);
				$proc->edit();
			}

			file_put_contents($prefix . '/etc/majordomo-' . $domain . '.cf',
				preg_replace('/^\s*\$whereami.+$/m', '$whereami = "' . $domain . '";',
					file_get_contents($prefix . '/etc/majordomo.cf')));
			chown($prefix . '/etc/majordomo-' . $domain . '.cf', (int)$this->user_id);
			chgrp($prefix . '/etc/majordomo-' . $domain . '.cf', (int)$this->group_id);
			if (!file_exists($prefix . '/var/lib/majordomo/')) {
				mkdir($prefix . '/var/lib/majordomo/') &&
				chown($prefix . '/var/lib/majordomo/', self::MAJORDOMO_SETUID) &&
				chgrp($prefix . '/var/lib/majordomo/', $this->group_id);

				system('setfacl -d -m user:' . $this->user_id . ':7 ' . $aclprefix . '/var/lib/majordomo/');
			}

			foreach (array('archives', 'digest', 'lists', 'OLDLOGS', 'tmp') as $dir) {
				if (!file_exists($prefix . '/var/lib/majordomo/' . $dir)) {
					mkdir($prefix . '/var/lib/majordomo/' . $dir);
				}
				chown($prefix . '/var/lib/majordomo/' . $dir, self::MAJORDOMO_SETUID) &&
				chgrp($prefix . '/var/lib/majordomo/' . $dir, (int)$this->group_id) &&
				chmod($prefix . '/var/lib/majordomo/' . $dir, 02771) &&
				system('setfacl -m user:postfix:7 -d -m user:' . $this->user_id . ':7 ' . $aclprefix . '/var/lib/majordomo/' . $dir);
			}

			file_put_contents(self::POSTFIX_LOCAL_ALIASES_FILE,
				trim(file_get_contents(self::POSTFIX_LOCAL_ALIASES_FILE)) . "\n" .
				$list . '+' . $domain . ': "|  env HOME=/usr/lib/majordomo /usr/lib/majordomo/wrapper resend -C ' . $prefix . '/etc/majordomo-' . $domain . '.cf -l ' . $list . ' -h ' . $domain . ' ' . $list . '-outgoing+' . $domain . '"' . "\n" .
				$list . '-outgoing+' . $domain . ': :include:' . $prefix . '/var/lib/majordomo/lists/' . $list . "\n" .
				$list . '-request+' . $domain . ': "| env HOME=/usr/lib/majordomo MAJORDOMO_CF=' . $prefix . '/etc/majordomo-' . $domain . '.cf  /usr/lib/majordomo/request-answer ' . $list . ' -h ' . $domain . '"' . "\n");
			// add aliases
			Util_Process::exec('/usr/sbin/postalias -w /etc/postfix/aliases');
			foreach (array($list, $list . '.config', $list . '.intro', $list . '.info') as $file) {
				touch($prefix . '/var/lib/majordomo/lists/' . $file);
				chown($prefix . '/var/lib/majordomo/lists/' . $file, self::MAJORDOMO_SETUID);
				chgrp($prefix . '/var/lib/majordomo/lists/' . $file, (int)$this->group_id);

			}
			file_put_contents($prefix . '/var/lib/majordomo/lists/' . $list, $email . "\n");
			file_put_contents($prefix . '/var/lib/majordomo/lists/' . $list . '.config',
				$this->change_configuration_options(array(
					'admin_passwd'  => $password,
					'resend_host'   => $domain,
					'restrict_post' => $list,
					'sender'        => 'owner-' . $list
				)));

			chmod($prefix . '/var/lib/majordomo/', 0755);
			chmod($prefix . '/var/lib/majordomo/lists/', 02751);
			chmod($prefix . '/var/lib/majordomo/lists/' . $list, 0644);
			system("setfacl -d -m user:" . self::MAJORDOMO_SETUID . ":7 -m user:postfix:7 " . $aclprefix . '/var/lib/majordomo/*');
			system("setfacl -m user:" . (int)$this->user_id . ":7 " . $aclprefix . '/var/lib/majordomo/lists/' . $list . '*');
			system('setfacl -R -m user:' . self::MAJORDOMO_SETUID . ':7 -m user:postfix:7 ' . $aclprefix . '/var/lib/majordomo/');
			return true;
		}

		public function change_configuration_options(array $options)
		{
			$configuration = $this->majordomo_skeleton;
			foreach ($options as $option => $value) {
				if (!isset($configuration[$option])) {
					continue;
				}
				if ($configuration[$option]['type'] == enum) {
					$configuration[$option]['value'] = in_array($value, $configuration[$option]['values']) ?
						$value :
						(isset($configuration[$option]['default']) ? $configuration[$option]['default'] : '');
				} else {
					$configuration[$option]['value'] = $value;
				}
			}
			return $this->generate_configuration($configuration);
		}

		public function generate_configuration(array $config)
		{
			$configuration = $this->majordomo_preamble;
			foreach ($config as $opt_name => $opt_params) {

				$configuration .= wordwrap('# ' . $opt_params['help'], 72, "\n# ") . "\n" . $opt_name;
				if ($opt_params['type'] == text) {
					$configuration .= " << END \n" . (isset($opt_params['value']) ? $opt_params['value'] : (isset($opt_params['default']) ? $opt_params['default'] : '')) . "\n" . "END";
				} else {
					$configuration .= ' = ';
					if ($opt_params['type'] == bool) {
						$configuration .= (isset($opt_params['value']) ? ($opt_params['value'] ? "yes" : "no") : ((isset($opt_params['default']) && $opt_params['default']) ? "yes" : "no"));
					} else {
						$configuration .= (isset($opt_params['value']) ? $opt_params['value'] : (isset($opt_params['default']) ? $opt_params['default'] : ''));
					}
				}
				$configuration .= "\n\n";

			}
			return $configuration;

		}

		public function load_configuration_options($list)
		{
			return $this->_parse_configuration($this->file_get_file_contents('/var/lib/majordomo/lists/' . $list . '.config'));
		}

		public function save_configuration_options($list, $data)
		{
			// FIXME: we lose the 0 otherwise, which is significant
			return $this->file_put_file_contents('/var/lib/majordomo/lists/' . $list . '.config', $data, true) &&
				$this->file_chmod('/var/lib/majordomo/lists/' . $list . '.config', 644);
		}

		public function _delete()
		{
			foreach ($this->list_mailing_lists() as $list) {
				$this->delete_mailing_list($list);
			}
		}

		public function list_mailing_lists()
		{
			if (!IS_CLI) {
				return $this->query('majordomo_list_mailing_lists');
			}

			$entries = array();
			if (!file_exists($this->domain_fs_path() . '/var/lib/majordomo/lists/')) {
				return $entries;
			}
			$dh = dir($this->domain_fs_path() . '/var/lib/majordomo/lists/');
			while (false !== ($entry = $dh->read())) {
				/* should check .config/.info/.intro/.auto */
				if (false !== strpos($entry, '.')) {
					continue;
				}
				$entries[] = $entry;
			}
			$dh->close();
			return $entries;
		}

		public function delete_mailing_list($list)
		{
			if (!IS_CLI) {
				return $this->query('majordomo_delete_mailing_list', $list);
			}

			$list = trim(strtolower($list));
			if (!preg_match(Regex::MAILING_LIST_NAME, $list)) {
				return error("Invalid list name");
			} else {
				if (!$this->mailing_list_exists($list)) {
					return error("mailing list `%s' does not exist", $list);
				}
			}

			$domain = $this->get_domain_from_list_name($list);

			foreach (array($list, $list . '.config', $list . '.intro', $list . '.info') as $file) {
				$path = $this->domain_fs_path() . '/var/lib/majordomo/lists/' . $file;
				if (file_exists($path)) {
					unlink($path);
				}
			}

			// that was the last mailing list
			$moreLists = $this->mailing_lists_exist();

			if (!$moreLists) {
				$this->email_remove_alias('majordomo', $domain);
			}
			foreach (explode("\n", file_get_contents(self::POSTFIX_LOCAL_ALIASES_FILE)) as $line) {
				if (preg_match('!' . $list . '(?:-outgoing|-request)?\+' . $domain . ':!', $line)) {
					continue;
				} else {
					if (!$moreLists && preg_match('!majordomo\+' . $domain . ':!', $line)) {
						continue;
					}
				}
				$lines[] = $line;
			}

			$this->email_remove_alias($list, $domain);
			$this->email_remove_alias($list . '-approval', $domain);
			$this->email_remove_alias($list . '-owner', $domain);
			$this->email_remove_alias('owner-' . $list, $domain);
			$this->email_remove_alias($list . '-request', $domain);


			file_put_contents(self::POSTFIX_LOCAL_ALIASES_FILE, join("\n", $lines));
			Util_Process::exec("postalias -r /etc/postfix/aliases");

			return true;

		}

		public function mailing_list_exists($list)
		{
			if (!IS_CLI) {
				return $this->query('majordomo_mailing_list_exists', $list);
			}
			return file_exists($this->domain_fs_path() . '/var/lib/majordomo/lists/' . $list . '.config');
		}

		public function get_domain_from_list_name($list)
		{
			if (!IS_CLI) {
				return $this->query('majordomo_get_domain_from_list_name', $list);
			}

			if (!preg_match(Regex::MAILING_LIST_NAME, $list)) {
				return error("Invalid list " . $list);
			}

			if (!file_exists($this->domain_fs_path() . '/var/lib/majordomo/lists/' . $list)) {
				return error($list . ' does not exist');
			}
			$file = $this->domain_fs_path() . '/var/lib/majordomo/lists/' . $list . '.config';
			if (preg_match('/^\s*resend_host\s*=[ \t]*([^\s]+)/m', file_get_contents($file), $domain)) {
				$domain = $domain[1];
			} else {
				$domain = $this->get_service_value('siteinfo', 'domain');
			}
			return $domain;
		}

		/**
		 * @return bool At least one mailing list exists
		 */
		public function mailing_lists_exist()
		{
			if (!IS_CLI) {
				return $this->query('majordomo_mailing_lists_exist');
			}

			if (!file_exists($this->domain_fs_path() . '/var/lib/majordomo/lists/')) {
				return false;
			}

			$glob = glob($this->domain_fs_path() . '/var/lib/majordomo/lists/');
			return sizeof($glob) > 1;

		}

		// currently handled by create_mailing_list

		private function _parse_configuration($text)
		{
			if (!preg_match_all(Regex::MAJORDOMO_CONFIG_ENTRY, $text, $matches, PREG_SET_ORDER)) {
				return false;
			}
			$base = $this->majordomo_skeleton;
			foreach ($matches as $match => $value) {
				if (isset($base[$value[1]])) {
					$base[$value[1]]['value'] = trim(($base[$value[1]]['type'] == text) ? str_replace("END", "",
						$value[2]) : $value[2]);
				}
			}
			return array_merge($base, array_intersect_key($base, $base));
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}

		public function _create()
		{
			// TODO: Implement _create() method.
		}

		public function _edit()
		{
			// TODO: Implement _edit() method.
		}

		public function _create_user(string $user)
		{
			// TODO: Implement _create_user() method.
		}

		public function _delete_user(string $user)
		{
			// TODO: Implement _delete_user() method.
		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			// TODO: Implement _edit_user() method.
		}


	}