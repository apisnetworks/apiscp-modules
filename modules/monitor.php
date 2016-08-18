<?php
	/**
	 * Monitoring structure for EWNS
	 * @package core
	 */
	class Monitor_Module extends Module_Skeleton {
		private $events;
		/**
		 * {{{ void __construct(void)
		 * @ignore
		 */
		public function __construct() {
			parent::__construct();
			$this->events = array('domain'    => PRIVILEGE_SITE,
								 'disk'      => PRIVILEGE_SITE,
								 'billing'   => PRIVILEGE_SITE,
								 'bandwidth' => PRIVILEGE_SITE);
			$this->exportedFunctions = array('get_event_data' => PRIVILEGE_SITE,
											 'add_event'      => PRIVILEGE_SITE|PRIVILEGE_USER);
		}
		/** }}} */

		public function add_event($mEventName, $mEventThreshold) {
			if ($mEventThreshold > 100 || $mEventThreshold < 0) {
				return new ArgumentError("Threshold range must be between 100 and 0");
			}
			$this->mysql->query("REPLACE INTO `monitor_information` (`domain`, `service_name`) VALUES();");
		}

		/** {{{ array get_event_data string
		 * @param string $mEventName
		 * @return array associative array containing the following indexes:
		 *      - name:      event name
		 *      - msg_type:  type of message, either "short" or "long"
		 *      - recipient: e-mail address of the designated event recipient
		 * @throws ArgumentError if event name is not defined
		 */
		public function get_event_data($mEventName) {
			$q = $this->mysql->query("SELECT
									`email`,
									`sms`
								 FROM
									`monitor_information`
								 WHERE
										`service_name` = '".$this->mysql->escape($mEventName)."'
									AND
										`domain`       = '".$this->domain."'
									AND
										`username`     = '".$this->username."'");
			$row = $q->fetch_object();
			if ($row == false || $q->num_rows = 0)
				return NULL;
			else {
				return array('name' => $mEventName, 'msg_type' => ($row->sms == 1 ? 'short' : 'long'), 'recipient' => $row->email);
			}
		}
		/* }}} */


	}
?>
