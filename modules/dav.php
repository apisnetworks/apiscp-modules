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
 * Written by Matt Saladna <matt@apisnetworks.com>, May 2017
 */

class Dav_Module extends Module_Skeleton {
	const PAM_FILE = 'dav.pamlist';

	public function _create() {
		$path = $this->domain_fs_path() . '/etc/' . self::PAM_FILE;
		if (!DAV_ENABLED) {
			touch($path);
			return;
		}
		file_put_contents($path, $this->username ."\n");
	}
}