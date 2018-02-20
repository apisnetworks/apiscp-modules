<?php
	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * Unauthorized copying of this file, via any medium, is
	 * strictly prohibited without consent. Any dissemination of
	 * material herein is prohibited.
	 *
	 * For licensing inquiries email <licensing@apisnetworks.com>
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, July 2017
	 */

	class Diskquota_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable {
		public function _edit()
		{
			// TODO: Implement _edit() method.
		}

		public function _delete()
		{
			// TODO: Implement _delete() method.
		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			// TODO: Implement _edit_user() method.
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			$hasAmnesty = $ctx->getOldServiceValue('diskquota', 'amnesty');
			if ($hasAmnesty && !empty($ctx['quota']) && empty($ctx['amnesty'])) {
				// quota set independent of amnesty, clear amnesty flag
				// as storage has been permanently upgraded
				$ctx['amnesty'] = null;
			}
			if (!$ctx['enabled']) {
				return true;
			}
			if (!is_float($ctx['quota'])) {
				$tmp = (float)$ctx['quota'];
				if ($ctx['quota'] != $tmp) {
					return error("invalid diskquota encountered, `%s'", $ctx['quota']);
				}
				$ctx['quota'] = $tmp;
			}
			return true;
		}

		public function _create()
		{
			// TODO: Implement _create() method.
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