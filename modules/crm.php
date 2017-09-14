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
	 * Written by Matt Saladna <matt@apisnetworks.com>, July 2017
	 */

	/**
	 * User tracking, trouble tickets
	 *
	 * @package core
	 */
	class Crm_Module extends Module_Skeleton
	{
		const FROM_ADDRESS = CRM_FROM_ADDRESS;

		// @ignore
		const REPLY_ADDRESS = CRM_REPLY_ADDRESS;
		const FROM_NAME = CRM_FROM_NAME;
		const FROM_NO_REPLY_ADDRESS = CRM_FROM_NO_REPLY_ADDRESS;
		const MAX_SMS_LENGTH = 150;
		// lowercase list of ticket subject priorities that cannot change
		const COPY_ADMIN = CRM_FROM_ADDRESS;

		const TICKET_STCLOSE = 'close';
		const TICKET_STAPPEND = 'append';
		const TICKET_STOPEN = 'open';
		const PRIORITIES = array('normal', 'high', 'outage');
		const LOW_PRIORITY_SUBJECTS = array('billing');

		// @var string
		// @ignore
		const SHORT_COPY_ADMIN = CRM_SHORT_COPY_ADMIN;

		// @ignore
		private static $CRM_SERVER_HOST = CRM_TICKET_HOST;
		// @ignore
		private static $CRM_SERVER_USER = CRM_TICKET_USER;
		// @ignore
		private static $CRM_SERVER_PASSWORD = CRM_TICKET_PASSWORD;
		// @ignore
		private static $CRM_SERVER_DATABASE = CRM_TICKET_DB;

		/**
		 * void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = array(
				'*'                       => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'append_ticket_via_email' => PRIVILEGE_ADMIN
			);
		}

		/**
		 * Verify CRM module is configured
		 *
		 * @return bool
		 */
		public function configured(): bool
		{
			return false;
		}

		public function enabled() {
			return true;
		}
	}
