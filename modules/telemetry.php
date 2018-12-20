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
	class Telemetry_Module extends Module_Skeleton
	{
		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = ['*' => PRIVILEGE_SERVER_EXEC];
			if (!TELEMETRY_ENABLED) {
				$this->exportedFunctions = ['*' => PRIVILEGE_NONE];
			}
		}

		public function collect()
		{

		}

		public function _cron()
		{
			/**
			 * Prevent losing configuration settings in allkeys-lru purge
			 */
			$cache = \Cache_Global::spawn();
			$cache->get(CONFIGURATION_KEY);
			\Lararia\JobDaemon::snapshot();
		}
	}