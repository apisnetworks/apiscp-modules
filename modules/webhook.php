<?php
	/**
	 * Webhook functions
	 *
	 * @package core
	 * @author Matt Saladna <matt@apisnetworks.com>
	 */
	class Webhook_Module extends Module_Skeleton {
		public $exportedFunctions;

		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions =  array(
				'*' => PRIVILEGE_SITE,
			);
		}

		public function dispatch($funcs) {
			// todo
		}

		public function init() {
			// perform filter fetching
			$prefs = $this->common_load_preferences();
		}
	}
?>
