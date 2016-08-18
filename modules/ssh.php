<?php
	/**
	 * Provides common functionality associated with SSH
	 * @package core
	 */
	class Ssh_Module extends Module_Skeleton {
		/**
		 * {{{ void __construct(void)
		 * @ignore
		 */

		public function __construct() {
			parent::__construct();
			$this->exportedFunctions = array(
				'*' => PRIVILEGE_SITE,
				'enabled' => PRIVILEGE_SITE|PRIVILEGE_USER
			);
		}

		public function deny_user($user) {
			return Util_Pam::remove_entry($user, 'ssh');
		}

		public function permit_user($user) {
			if ($this->auth_is_demo()) {
				return error("SSH disabled for demo account");
			}
			return Util_Pam::add_entry($user, 'ssh');
		}

		public function user_enabled($user) {
			if (!$this->get_config('ssh','enabled'))
				return warn("ssh not enabled on account");

			return Util_Pam::check_entry($user, 'ssh');
		}
        
        public function enabled() {
	        $check = (bool)$this->get_service_value('ssh','enabled');
            if ($this->permission_level & PRIVILEGE_USER) {
				$check = $check && $this->user_enabled($this->username);
            }
	        return $check;
        }


        public function _edit_user($user, $usernew)
        {
            if (!$this->enabled() || !$this->user_enabled($user)) {
                return true;
            }

            // @TODO nuke active ssh sessions?
            mute_warn();
            $this->deny_user($user);
            $this->permit_user($usernew);
            unmute_warn();
            return true;
        }

		public function _housekeeping()
		{
			dlog("Loading terminal...");
			Service_Terminal::autostart();


		}

		public function _create() {
			// stupid thor...
			$conf = Auth::profile()->conf->new;
			$admin = $conf['siteinfo']['admin_user'];
			if ($this->auth_is_demo() && Util_Pam::check_entry($admin, 'ssh')) {
				Util_Pam::remove_entry($admin, 'ssh');
			}
		}
	}
?>
