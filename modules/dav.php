<?php
	declare(strict_types=1);
	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * Unauthorized copying of this file, via any medium, is
	 * strictly prohibited without consent. Any dissemination of
	 * material herein is prohibited.
	 *
	 * For licensing inquiries email <licensing@apisnetworks.com>
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, May 2017
	 */

	class Dav_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable {
		const PAM_FILE = 'dav.pamlist';

		public function _create() {
			$path = $this->domain_fs_path() . '/etc/' . self::PAM_FILE;
			if (!DAV_ENABLED) {
				touch($path);
				return;
			}
			file_put_contents($path, $this->username ."\n");
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

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			// TODO: Implement _edit_user() method.
		}


	}