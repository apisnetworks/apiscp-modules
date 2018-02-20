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
	 * Provides common functionality associated with SSH
	 *
	 * @package core
	 */
	class Ssh_Module extends Module_Skeleton
	{
		const PAM_SVC_NAME = 'ssh';

		/**
		 * {{{ void __construct(void)
		 *
		 * @ignore
		 */

		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = array(
				'*'       => PRIVILEGE_SITE,
				'enabled' => PRIVILEGE_SITE | PRIVILEGE_USER
			);
		}

		public function deny_user($user)
		{
			return Util_Pam::remove_entry($user, self::PAM_SVC_NAME);
		}

		public function permit_user($user)
		{
			if ($this->auth_is_demo()) {
				return error("SSH disabled for demo account");
			}
			return Util_Pam::add_entry($user, self::PAM_SVC_NAME);
		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			if ($userold === $usernew) {
				return;
			}

			if (!$this->enabled() || !$this->user_enabled($userold)) {
				return true;
			}
			// @TODO nuke active ssh sessions?
			Util_Pam::remove_entry($userold, self::PAM_SVC_NAME);
			Util_Pam::add_entry($usernew, self::PAM_SVC_NAME);
			return true;
		}

		public function enabled()
		{
			$check = (bool)$this->get_service_value('ssh', 'enabled');
			if ($this->permission_level & PRIVILEGE_USER) {
				$check = $check && $this->user_enabled($this->username);
			}
			return $check;
		}

		public function user_enabled($user)
		{
			if (!$this->get_config('ssh', 'enabled')) {
				return warn("ssh not enabled on account");
			}

			return Util_Pam::check_entry($user, self::PAM_SVC_NAME);
		}

		public function _housekeeping()
		{
			if (SSH_EMBED_TERMINAL) {
				dlog("Loading terminal...");
				Service_Terminal::autostart();
			}


		}

		public function _create()
		{
			// stupid thor...
			$conf = Auth::profile()->conf->new;
			$admin = $conf['siteinfo']['admin_user'];
			if ($this->auth_is_demo() && Util_Pam::check_entry($admin, self::PAM_SVC_NAME)) {
				Util_Pam::remove_entry($admin, self::PAM_SVC_NAME);
			}
		}
	}