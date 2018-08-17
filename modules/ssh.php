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
	class Ssh_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable
	{
		const PAM_SVC_NAME = 'ssh';
		const DEPENDENCY_MAP = [
			'siteinfo', 'ipinfo', 'ipinfo6', 'users', 'auth'
		];
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
			return (new Util_Pam($this->getAuthContext()))->remove($user, self::PAM_SVC_NAME);
		}

		public function permit_user($user)
		{
			if ($this->auth_is_demo()) {
				return error("SSH disabled for demo account");
			}
			return (new Util_Pam($this->getAuthContext()))->add($user, self::PAM_SVC_NAME);
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
			$pam = new Util_Pam($this->getAuthContext());
			$pam->remove($userold, self::PAM_SVC_NAME);
			$pam->add($usernew, self::PAM_SVC_NAME);
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

			return (new Util_Pam($this->getAuthContext()))->check($user, self::PAM_SVC_NAME);
		}

		public function _housekeeping()
		{
			if (SSH_EMBED_TERMINAL && !APNSCPD_HEADLESS) {
				dlog("Loading terminal...");
				Service_Terminal::autostart();
			} else {
				Service_Terminal::stop();
			}
		}

		public function _create()
		{
			// stupid thor...
			$conf = $this->getAuthContext()->getAccount()->new;
			$admin = $conf['siteinfo']['admin_user'];
			$pam = new Util_Pam($this->getAuthContext());
			if ($this->auth_is_demo() && $pam->check($admin, self::PAM_SVC_NAME)) {
				$pam->remove($admin, self::PAM_SVC_NAME);
			}
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}

		public function _delete()
		{
			// TODO: Implement _delete() method.
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


	}