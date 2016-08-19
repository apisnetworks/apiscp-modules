<?php
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
	 * Billing and referral module
	 *
	 * @package core
	 */
	class Billing_Module extends Module_Skeleton
	{
		// minimum balance for a payout request
		const PAYOUT_MINBAL = 25.00;
		const MAX_REFERRAL_COUNT = 6;
		// minimum number of days to accrue a referral
		const REF_MINDAYS = 90;
		const PMT_CREDIT = 'credit';
		const PMT_CHECK = 'check';
		// @ignore
		const PMT_PAYPAL = 'paypal';
		private static $billing_db;
		// @ignore
		private static $billing_db_write;
		// @ignore
		private static $BILLING_SERVER_HOST = BILLING_HOST_READ;
		// @ignore
		private static $BILLING_SERVER_HOST_WRITE = BILLING_HOST_WRITE;
		// @ignore
		private static $BILLING_SERVER_HOST_BACKUP = BILLING_HOST_BACKUP;
		private static $BILLING_SERVER_USER = BILLING_USER;
		private static $BILLING_SERVER_PASSWORD = BILLING_PASSWORD;
		private static $BILLING_SERVER_DATABASE = BILLING_DB;
		private static $connected = true;
		/**
		 * Recognized preferences in [change,get]_payout_preferences
		 * tender:   tender method
		 * freeze:   account frozen
		 * balance:  credit hosting balance
		 *
		 * @var array
		 */
		private static $_PAYOUT_OPTIONS = array('tender', 'freeze', 'balance');
		private $_package_remap = array(
			'Minimalist' => 'Essential',
			'Basic'      => 'Developer',
			'Advanced'   => 'Business',
			'Super'      => 'Enterprise'
		);

		/**
		 * void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();

			$this->exportedFunctions = array(
				'*'                       => PRIVILEGE_SITE,
				'add_referral'            => PRIVILEGE_ADMIN,
				'get_invoice_from_domain' => PRIVILEGE_ADMIN,
				'get_package_by_invoice'  => PRIVILEGE_ADMIN,

				/** necessary for sanity checks */
				'get_invoice'             => PRIVILEGE_SITE | PRIVILEGE_USER
			);
			$this->_connect();
		}

		private function _connect()
		{
			Error_Reporter::suppress_php_error('mysqli::real_connect');
			self::$billing_db = mysqli_init();
			self::$billing_db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);
			if ((is_debug() || !self::$billing_db->real_connect(self::$BILLING_SERVER_HOST,
						self::$BILLING_SERVER_USER,
						self::$BILLING_SERVER_PASSWORD,
						self::$BILLING_SERVER_DATABASE,
						null,
						null))
				&& !self::$billing_db->real_connect(self::$BILLING_SERVER_HOST_BACKUP,
					self::$BILLING_SERVER_USER,
					self::$BILLING_SERVER_PASSWORD,
					self::$BILLING_SERVER_DATABASE,
					null,
					null)
			) {
				self::$connected = false;
				self::$billing_db = new MySQLError("Unable to contact the billing server at this time");
			}
		}

		public function _firstCall()
		{
			$this->_connect();
			return parent::_firstCall();
		}

		/**
		 * @return string current payment method, enum: [credit, check, paypal, cash, other]
		 */
		public function get_payment_method()
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			$rs = self::$billing_db->query("SELECT method FROM subscription_data WHERE subscription_number = '" . $this->get_hosting_subscription() . "' LIMIT 1");
			if (!$rs)
				return error("unable to connect to billing server at this time");
			if ($rs->num_rows < 1)
				return false;
			$rec = $rs->fetch_object();
			return $rec->method;

		}

		public function get_hosting_subscription()
		{
			$cache = Cache_Account::spawn();
			$key = 'billing:subscription';
			if (!is_debug() && false !== ($subscription = $cache->get($key))) {
				return $subscription;
			} else if (!self::$connected) {
				return error("unable to connect to billing server at this time");
			}
			$invoice = $this->get_invoice();
			if (!$invoice) return false;
			$rs = self::$billing_db->query("SELECT subscription_number FROM
				subscription_data WHERE subscription_data.invoice =
				'" . self::$billing_db->escape_string($invoice) . "'
				ORDER BY date_signup DESC LIMIT 1");
			if ($rs->num_rows < 1) return false;
			$subscription = $rs->fetch_object()->subscription_number;
			$cache = $cache->set($key, $subscription, 7200);
			return $subscription;
		}

		public function get_invoice()
		{
			if (is_debug()) return 'APNS-HOSTING-IJDMWSNZ6TI8V3O7';
			$invoice = $this->get_config('billing', 'invoice');
			if ($invoice) return $invoice;
			if ($this->get_config('billing', 'parent_invoice'))
				return $this->get_config('billing', 'parent_invoice');
			$key = $this->get_config('siteinfo', 'domain') . ':billing:invoice';

			$invoice = apc_fetch($key, $success);
			if ($success) return $invoice;
			else if (!IS_APIS) return -1;
			Error_Reporter::report("unknown invoice for " . $this->domain);
			$rs = self::$billing_db->query("
			SELECT
				subscription_data.invoice
			FROM subscription_data
			INNER JOIN `domain_information` LEFT JOIN cancellation_data cd ON
					((SELECT sd.subscription_number FROM subscription_data as sd
					WHERE domain = COALESCE(domain_information.original_domain,
					domain_information.domain) AND type = 'Webhosting'
					ORDER by date_signup DESC LIMIT 1) =
					cd.subscription_number) WHERE
					COALESCE(domain_information.original_domain,
					domain_information.domain) = subscription_data.domain AND
					subscription_data.subscription_number = (SELECT sd.subscription_number
					FROM subscription_data as sd WHERE domain =
					COALESCE(domain_information.original_domain,domain_information.domain)
					AND type = 'Webhosting' ORDER by date_signup DESC LIMIT 1) AND
					domain_information.domain = '" . $this->get_config('siteinfo', 'domain') . "' AND
					subscription_data.type = 'Webhosting'");
			if (!$rs || $rs->num_rows < 1) return -1;
			$invoice = $rs->fetch_object()->invoice;
			apc_store($key, $invoice);
			return $invoice;
		}

		/**
		 * @deprecated
		 * @see get_next_payment()
		 *
		 * @return array
		 */
		public function get_next_payment_date()
		{
			deprecated_func("use get_next_payment()");
			return $this->get_next_payment();
		}

		/**
		 * Next payment date and amount for the account
		 *
		 * Array fields-
		 * date:   date of next payment for account.  In the event the
		 *         information cannot be found (reseller account for example),
		 *         -1 is returned.
		 * amount: amount for next payment
		 *
		 * @return array
		 */
		public function get_next_payment()
		{
			$key = 'billing:nxpy';
			$cache = Cache_Account::spawn();
			if (!is_debug() && (false !== ($details = $cache->get($key)))) {
				return $details;
			}
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			$pdata = array('date' => -1, 'amount' => 0);

			$subscription = $this->get_hosting_subscription();

			if (strncmp('C-', $subscription, 2)) {
				$details = $this->_get_paypal_next_payment($subscription);
			} else {
				$details = $this->_get_cc_next_payment($subscription);
			}

			$ttl = 7200;
			if (!$details) {
				$ret = $pdata;
				$ttl = 30;
			} else {
				$ret = $details;
			}
			$cache->set($key, $ret, $ttl);
			return $ret;
		}

		private function _get_paypal_next_payment($subscription)
		{
			$invoice = $this->get_invoice();
			$q = "SELECT
					unix_timestamp(sd.date_signup) as date_signup,
					sd.initial_term,
					sd.initial_price,
					sd.initial_term_type,
					COALESCE(sd.recurring_price, sd.initial_price) AS recurring_price,
					COALESCE(sd.recurring_term, sd.initial_term) AS recurring_term,
                    COALESCE(sd.recurring_term_type, sd.initial_term_type) AS recurring_term_type,
                    sd.subscription_number,
					unix_timestamp(COALESCE(MAX(`pd`.`date_payment`),`sd`.`date_signup`)) as last_payment,
					unix_timestamp(`cd`.date_cancelled) as date_cancelled
			 FROM `subscription_data` sd
			 LEFT JOIN `cancellation_data` cd
			 USING (subscription_number, invoice)
			 LEFT JOIN `payment_data` pd
			 USING (subscription_number, invoice)
			 WHERE sd.invoice = '" . $invoice . "' AND subscription_number = '" . $subscription . "'
					GROUP BY (sd.invoice) ORDER BY date_signup DESC LIMIT 1";
			$rs = self::$billing_db->query($q);
			if ($rs->num_rows == 0) return false;

			$row = $rs->fetch_object();
			$term1 = $row->initial_term;
			$termt1 = $row->initial_term_type;
			$termp1 = $row->initial_price;
			$termp2 = $row->recurring_price;
			$term2 = $row->recurring_term;
			$termt2 = $row->recurring_term_type;
			$date_signup = $row->date_signup;
			$last_payment = $row->last_payment;

			// BEGIN

			// date on which it is expected to recur; when checking, include
			// a 1.5 day discrepancy between the two
			$firstRecurringDate = strtotime("+ " . $term1 . " " . $termt1 .
				(($term1 > 1) ?
					sprintf('s') :
					sprintf('')),
				$date_signup);

			// follow up expected recurring date

			$secondRecurringDate = strtotime("+ " . $term2 . " " . $termt2 .
				(($term2 > 1) ?
					sprintf('s') :
					sprintf('')),
				strtotime("+ " . $term1 . " " . $termt1 .
					(($term1 > 1) ?
						sprintf('s') :
						sprintf('')),
					$date_signup));
			if ($last_payment >= $secondRecurringDate - 86400 * 3) {
				$paymentItr = strtotime("+ " . $term2 . " " . $termt2 .
					(($term2 > 1) ?
						sprintf('s') :
						sprintf('')), $last_payment);
			} else if ($last_payment < $secondRecurringDate - 86400 * 3) {
				$paymentItr = $firstRecurringDate;
			} else {
				$paymentItr = $secondRecurringDate;
			}

			$paymentItr = strtotime(date("Y-m-d", $paymentItr));

			$i = 0;
			$cutoff = strtotime('+1 day', strtotime(date("Y-m-d") . ' 00:00:00'));
			$timesMissed = 1;
			$prevPaymentItr = $paymentItr;


			/**
			 * -If the initial term is zero then it is a passthru subscription
			 *
			 * - If the last payment occurred before the second payment date,
			 *   then there is no need to calculate the number of missed payments, because
			 *   the number missed is 1
			 */
			for ($timesMissed = 0; $paymentItr < $cutoff - 86400 && $i < 200; $i++, $timesMissed++) {
				if (0)
					print date('r', $paymentItr) . " < " . date('r', $cutoff) . "<br />";
				if ($paymentItr <= $last_payment) {
					$timesMissed = 0;
				}
				$prevPaymentItr = $paymentItr;
				$paymentItr = strtotime("+ " . $term2 . " " . $termt2 .
					(($term2 > 1) ?
						sprintf('s') :
						sprintf('')),
					$paymentItr);
			}
			return array(
				'amount' => $termp2,
				'missed' => $timesMissed > 0,
				'date'   => $paymentItr
			);
		}

		private function _get_cc_next_payment($subscription)
		{
			$db = self::$billing_db;
			$pdata = array('amount' => 0, 'date' => -1, 'missed' => false);
			$rs = $db->query("SELECT txn_date, txn_amt
	     		FROM recurring_batch WHERE subscription_number = '" . $subscription . "'");
			if ($rs->num_rows < 1) {
				//$db->query("SELECT cancellation_date, ");
				return false;
			}
			$rs = $rs->fetch_object();
			$pdata['date'] = strtotime($rs->txn_date);
			$pdata['amount'] = floatval($rs->txn_amt);
			return $pdata;
		}

		/**
		 * array list_payments
		 *
		 * @return array
		 */
		public function list_payments()
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			$cache = Cache_Account::spawn();
			$key = 'f:billing_payments';
			if (false !== ($payments = $cache->get($key))) {
				return $payments;
			}
			$invoices = $this->get_all_invoices();
			if (!$invoices) return false;
			$q = "SELECT
				UNIX_TIMESTAMP(date_payment) as `date`,
				subscription_number,
				subscription_data.type,
				level,
				method,
				note,
				\"recurring\" as txt,
				payment_amount as amount
				FROM payment_data
				JOIN subscription_data
				USING (subscription_number)
				WHERE subscription_data.invoice IN('" . join("','", $invoices) . "') UNION 
				SELECT 
					UNIX_TIMESTAMP(date_signup) as `date`,
					subscription_number, 
					`type`, 
					level, 
					method,
					notes as note,
					\"nonrecurring\" as txt, 
					initial_price as amount 
				FROM 
					subscription_data 
				WHERE 
					invoice IN('" . join("','", $invoices) . "') 
					AND 
					method = 'check'
				ORDER BY `date` DESC";
			$rs = self::$billing_db->query($q);
			$recs = array();
			while (false != ($row = ($rs->fetch_object()))) {
				$recs[] = array(
					'date'    => $row->date,
					'amount'  => $row->amount,
					'service' => $row->type . '->' . $row->level,
					'number'  => $row->subscription_number,
					'note'    => $row->note,
					'type'    => $row->method
				);
			}
			$cache->set($key, $recs, 86400);
			return $recs;

		}

		private function get_all_invoices()
		{
			$invoice = array($this->get_invoice());
			if (!$invoice) return false;
			$addons = (array)$this->get_config('billing', 'addons');
			if (!$addons) return $invoice;
			return array_merge($invoice, $addons);
		}

		/**
		 * Fetch billing status from backend billing server
		 *
		 * @deprecated @see get_billing_status()
		 * @return int
		 */
		public function get_standing_status()
		{
			deprecated(__FUNCTION__ . ": use get_billing_status()");
			return $this->get_billing_status();

		}

		public function get_billing_status($invoice = '')
		{
			return $this->get_status($invoice);
		}

		/**
		 * int get_standing_status()
		 *
		 * Fetch recurring subscription status from billing server
		 *
		 *  1  - subscription in good standing
		 * -1 - subscription cancelled, account within 90 days of expiring
		 * 0  - subscription cancelled, account outside 90 days of expiring
		 * null - cannot find subscription
		 *
		 * @return int
		 */
		public function get_status($invoice = '')
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time") || -1;
			$curinvoice = $this->get_invoice();
			if (!$curinvoice) return null;

			if ($invoice) {
				$curinvoice = $invoice;
				$invoices = $this->get_all_invoices();
				if (!in_array($invoice, $invoices)) return error("invoice `$invoice' not found");

			}
			$invoice = $curinvoice;

			$q = self::$billing_db->query("SELECT count(subscription_data.invoice) as srec,
				count(cancellation_data.invoice) as crec
				FROM subscription_data
				LEFT JOIN cancellation_data USING(subscription_number,invoice)
				WHERE invoice = '" . $invoice . "'");


			$srs = $q->fetch_object();
			$renew = $srs->srec;
			$cancel = $srs->crec;
			// can't locate
			if ($renew < 1) return null;
			// renewals > cancellations
			if ($renew > $cancel) return 1;
			$date = $this->get_next_payment();
			$nextpmt = ($date['date'] - time()) / 86400;
			// next payment date > 90 days
			if ($nextpmt > 90) return -1;
			// past due or within 90 days
			return 0;

		}

		/**
		 * bool is_billed()
		 *
		 * @return bool billing record exists
		 */
		public function is_billed()
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			return (bool)$this->get_hosting_subscription();
		}

		public function is_referred($invoice)
		{
			$stmt = self::$billing_db->prepare("SELECT 1 FROM referral_profiles rp JOIN referral_data rd
				ON(rd.parent_id = rp.id) WHERE invoice = ?");
			$stmt->bind_params("s", $invoice);
			$rs = $stmt->execute();
			return $stmt && $rs->num_rows > 0;
		}

		/**
		 * array get_payment_information(string)
		 *
		 * @param string $transnum transaction number
		 * @param int    $date     unix timestamp of date of transaction
		 * @return array
		 */
		public function get_payment_information($transnum, $date, $type = "paypal")
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			$invoices = $this->get_all_invoices();
			if (!$invoices) return false;
			$invoiceq = "subscription_data.invoice IN('" . join("','", $invoices) . "')";
			$db = self::$billing_db;
			$q = "(SELECT
                unix_timestamp(date_signup) as `date`,
                '" . $this->domain . "' as domain,
                subscription_number,
                type,
                paypal_email as email,
                name,
                subscription_data.invoice,
                subscription_data.notes as note,
                subscription_data.level,
                \"new\" as txt,
                initial_price as amount,
                method,
                subscription_number as txn_id,
                NULL as cc_number,
                NULL as exp_date,
                NULL as cc_type
            FROM
                subscription_data
            WHERE
                $invoiceq
                AND
                method = 'check'
                AND
                subscription_number = ?
                AND
                date_signup = from_unixtime(?))
            UNION
         (SELECT
                unix_timestamp(date_payment) as `date`,
                '" . $this->domain . "' as domain,
                subscription_number as s,
                subscription_data.type,
                (SELECT paypal_email FROM subscription_data WHERE subscription_number = s),
                (SELECT name FROM subscription_data WHERE subscription_number = s),
                payment_data.invoice,
                payment_data.note as note,
                subscription_data.level,
                \"recurring\" as txt,
                payment_amount as amount,
                method as method,
                COALESCE(txn_number, subscription_number) as txn_id,
                cc_number,
                date_format(exp_date,'%m/%y') as exp_date,
                cc_type
            FROM
                subscription_data
            JOIN
                payment_data
            USING (subscription_number)
            WHERE
                $invoiceq
                AND
                subscription_number = ?
                AND
                date_payment = from_unixtime(?))
            ORDER BY `date` DESC LIMIT 1;";
			$stmt = $db->prepare($q);
			$stmt->bind_param("sdsd", $transnum, $date, $transnum, $date);

			$stmt->execute();

			$stmt->bind_result($date, $domain, $number,
				$type, $email, $name, $invoice, $note, $level,
				$txt, $amount, $method, $txn_id, $cc_number,
				$exp_date, $cc_type);

			if (false === $stmt->fetch()) {
				$stmt->close();
				return null;
			}

			$data = array(
				'date'           => $date,
				'amount'         => $amount,
				'domain'         => $domain,
				'service_level'  => $level,
				'name'           => $name,
				'email'          => $email,
				'note'           => $note,
				'service_type'   => $type,
				'method'         => $txt,
				'payment_method' => $method,
				'reference'      => $number,
				'txn_id'         => $txn_id,
				'invoice'        => $invoice,
				'cc_type'        => $cc_type,
				'cc_number'      => $cc_number,
				'cc_exp'         => $exp_date
			);

			$stmt->close();
			return $data;
		}

		/**
		 * Update profile information
		 *
		 * @param string $fname
		 * @param string $lname
		 * @param string $email
		 * @param string $address
		 * @param string $city
		 * @param string $state
		 * @param string $zip
		 * @param string $country
		 * @return bool
		 */
		public function edit_referral_profile($fname, $lname,
		                                      $email = '')
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");

			$errors = array();
			$invoice = $this->get_invoice();
			$this->setup_write();

			if (!$invoice) return error("no invoice found for account");
			if (!$this->referral_profile_exists())
				return error("Create a referral profile first");

			if (!$email) $email = null;
			else if (!preg_match(Regex::EMAIL, $email))
				return error("Invalid e-mail address");

			if (strlen($fname) < 2 || strlen($lname) < 2)
				return error("Invalid name");
			$stmt = self::$billing_db_write->prepare("UPDATE referral_profiles SET
														 fname = ?,
														 lname = ?,
														 email = ?
													WHERE invoice = '" . $invoice . "';");
			if (!$stmt) return error("cannot update profile");
			$stmt->bind_param("sss",
				$fname,
				$lname,
				$email
			);
			$stmt->execute();

			if (self::$billing_db->error)
				return new MySQLError($stmt);

			return true;
		}

		private function setup_write()
		{
			if (is_null(self::$billing_db_write)) {
				self::$billing_db_write = mysqli_init();
				self::$billing_db_write->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);
				if ((false === self::$billing_db_write->real_connect(
						self::$BILLING_SERVER_HOST_WRITE,
						self::$BILLING_SERVER_USER,
						self::$BILLING_SERVER_PASSWORD,
						self::$BILLING_SERVER_DATABASE,
						null,
						null))
				) {
					self::$billing_db_write = new MySQLError("Unable to contact the billing server at this time");
					return error("unable to contact master billing server, please try again later");
				}
			}
			return true;
		}

		/**
		 * Check if referral profile exists
		 *
		 * @return bool
		 */
		public function referral_profile_exists()
		{
			$invoice = $this->get_invoice();
			return $this->_referral_profile_exists($invoice);
		}

		/**
		 * Check if referral profile for invoice exists
		 *
		 * @param $invoice string
		 * @return bool
		 */
		private function _referral_profile_exists($invoice)
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			if (!$invoice) return false;
			$q = self::$billing_db->query("SELECT 1 FROM referral_profiles WHERE invoice = '" .
				self::$billing_db->escape_string($invoice) . "'");
			return $q && $q->num_rows > 0;
		}

		public function ssn_is_set($mSSN)
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			$rs = self::$billing_db->query("SELECT 1 WHERE length(ssn) = 9 AND domain = '" . $this->domain . "'");
			return ($rs->num_rows > 0);
		}

		/**
		 * Get referral username
		 *
		 * @return string
		 */
		public function get_referral_username()
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			if (!$this->referral_profile_exists())
				return null;
			$invoice = $this->get_invoice();
			if (!$invoice) return null;
			$rs = self::$billing_db->query("SELECT username FROM referral_profiles WHERE invoice = '" . $invoice . "'");
			$rs = $rs->fetch_object();
			return $rs->username;
		}

		/**
		 * Set minimum balance for a payout
		 *
		 * @param double $amount
		 * @return bool
		 */
		public function edit_payout_amount($amount)
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			if (($amount != floatval($amount)) || ($amount < 20))
				return error("Invalid amount `$amount'");
			$this->setup_write();
			$invoice = $this->get_invoice();
			if (!$invoice) return error("no invoice attached to account");
			$stmt = self::$billing_db_write->prepare("UPDATE referral_profiles
				SET payout_amount = ? WHERE invoice IN(?);");
			$stmt->bind_param("ds", $amount, $invoice);
			$stmt->execute();
			return (bool)$stmt;
		}

		/**
		 * float get_payout_amount()
		 *
		 * @return float
		 */
		public function get_payout_amount()
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			if (!$this->referral_profile_exists())
				return $this->get_minimum_payout_amount();
			$invoice = $this->get_invoice();
			if (!$invoice) return error("no invoice attached to account");
			$rs = self::$billing_db->query("SELECT payout_amount FROM referral_profiles WHERE invoice = '" . $invoice . "'");
			$rs = $rs->fetch_object();
			return $rs->payout_amount;
		}

		/**
		 * float get_minimum_payout_amount
		 *
		 * @return float
		 */
		public function get_minimum_payout_amount()
		{
			return (float)self::PAYOUT_MINBAL;
		}

		/**
		 * Get current referral balance
		 *
		 * @return double
		 */
		public function referral_balance()
		{
			if (!self::$connected)
				return error('unable to connect to billing server at this time');
			$invoice = $this->get_invoice();
			if (!$invoice) return error("no invoice attached to account");
			$id = $this->_get_referral_id($invoice);
			if ($id < 1) return 0;
			$rs = self::$billing_db->query("SELECT SUM(credit) AS sum FROM referrals WHERE parent_id = " . $id . " AND status IS NULL");
			if (!$rs) return 0;
			return $rs->fetch_object()->sum;
		}

		/**
		 * Get referral profile ID
		 *
		 * @return int profile id > 0
		 */
		private function _get_referral_id($invoice = null)
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			if (is_null($invoice))
				$invoice = $this->get_invoice();

			if (!$this->referral_profile_exists())
				return false;

			$q = self::$billing_db->query("SELECT id FROM referral_profiles WHERE invoice = '" . $invoice . "'");
			if (!$q || $q->num_rows < 1)
				return false;
			return $q->fetch_object()->id;
		}

		/**
		 * Get multiplier used in commission credit
		 *
		 * @return int
		 */
		public function referral_multiplier()
		{
			$ref = $this->_referral_level_metadata();
			if (!$ref) return 1;
			$count = $ref['count'];
			if ($count < 2) $multiplier = 1;
			else if ($count < 4) $multiplier = 1.5;
			else if ($count < 6) $multiplier = 2;
			else                  $multiplier = 2.5;
			if (date('Y') < 2010) $multiplier *= 2;
			return $multiplier;
		}

		/**
		 * Get referral level statistics
		 * array(5) {
		 *    ["age"]
		 *    ["clients"]
		 *    ["age-days"]
		 *    ["count"]
		 *    ["max"]
		 * }
		 *
		 * @return array
		 */
		private function _referral_level_metadata()
		{
			$invoice = $this->get_invoice();
			if (!$invoice) return error("no invoice attached to account");
			$id = $this->_get_referral_id($invoice);
			if ($id < 1) $id = -1;
			$q = "SELECT COUNT(r.parent_id) AS c1, DATEDIFF(NOW(), s.date_signup) AS c2, TO_DAYS(s.date_signup) AS c3
				FROM subscription_data s LEFT JOIN referral_profiles rp USING(invoice) LEFT JOIN referrals r
				ON (rp.id = r.parent_id AND r.status IS NULL AND r.invoice NOT LIKE 'APNS-SPECIAL%')
				WHERE s.invoice = '" . $invoice . "' ORDER BY s.date_signup";
			$rs = self::$billing_db->query($q);
			if (!$rs || $rs->num_rows < 1) return false;
			$rs = $rs->fetch_object();
			$meta = array(
				'age'     => floor($rs->c2 / 365) * 2,
				'client'  => $rs->c1,
				'age-day' => $rs->c3,
				'count'   => null,
				'method'  => null,
				'max'     => false
			);
			$meta['count'] = MAX($meta['age'], $meta['client']);
			if ($meta['count'] == $meta['client']) $meta['method'] = 'client';
			else $meta['method'] = 'age';
			$meta['max'] = $meta['count'] >= self::MAX_REFERRAL_COUNT;
			return $meta;
		}

		/**
		 * Minimum requirement for next referral level
		 * array(2) {
		 *    ["method"] => 254
		 *  ["client"] => 2
		 * }
		 *
		 * @return array
		 */
		public function referral_upgrade_needed()
		{
			$next = array('method' => 'client', 'next' => 2);
			$invoice = $this->get_invoice();
			if (!$invoice) return $next;
			$ref = $this->_referral_level_metadata();
			$next['method'] = $ref['method'];
			if ($next['method'] == 'client') {
				// client upgrade/2 clients
				if ($ref['client'] > 0 && $ref['client'] % 2) $next['next'] = 2;
				else $next['next'] = 1;
			} else {
				$next['age'] = $ref['age-day'];

			}
			if ($ref['max']) {
				$next['next'] = null;
			}
			return $next;
		}

		/**
		 * Get earned commissions
		 *
		 * Sample response
		 * array(1) {
		 * [0]=>
		 * array(5) {
		 * ["domain"]=>
		 * string(8) "test.com"
		 * ["accrued"]=>
		 * string(5) "30.00"
		 * ["level"]=>
		 * string(5) "Basic"
		 * ["maturity"]=>
		 * int(1172293200)
		 * ["status"]=>
		 * NULL
		 * }
		 *
		 * domain  (string):
		 * accrued (float)
		 *
		 * @return array
		 *
		 */

		public function get_referrals()
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			/**
			 * Very ugly first run
			 *
			 * @TODO Clean-up code, better implementation of second tier
			 *       Include payout amounts
			 */
			$invoice = $this->get_invoice();
			if (!$invoice) return error("no invoice attached to account");
			$rs = self::$billing_db->query("
				SELECT
					UNIX_TIMESTAMP(maturity) as maturity,
					credit,
					sd.domain,
					sd.level,
					r.status
				FROM
					referral_profiles rp
				JOIN
					referrals r ON (r.parent_id = rp.id)
				LEFT JOIN
					subscription_data sd ON (sd.invoice = r.invoice)
				LEFT JOIN
					payment_data pd on (pd.invoice = sd.invoice)
				WHERE rp.invoice = '" . $this->get_invoice() . "'
				GROUP BY (r.invoice)
				HAVING (SUM(pd.payment_amount) > 0 OR SUM(pd.payment_amount) IS NULL)
				ORDER BY maturity");
			$referrals = array();
			while ($row = $rs->fetch_object()) {
				$referrals[] = array(
					'domain'   => $row->domain,
					'revenue'  => (float)$row->credit,
					'maturity' => (int)$row->maturity,
					'status'   => $row->status
				);
			}
			return $referrals;


		}

		/**
		 * array get_customer_referral_information()
		 *
		 * @return array
		 */
		public function get_customer_referral_information()
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			$invoice = $this->get_invoice();
			if (!$invoice) return error("no invoice attached to account");
			$rs = self::$billing_db->query("SELECT fname,
													 lname,
													 username,
													 email,
													 payout_amount,
													 preference,
													 date_created,
													 date_ended
											 FROM
												 referral_profiles
											 WHERE
												 invoice = '" . $invoice . "'");

			return ($rs->num_rows > 0 ? $rs->fetch_array() : false);

		}

		/**
		 * Create initial referral profile
		 *
		 * @param string $username
		 * @param string $firstName
		 * @param string $lastName
		 * @param string $email optional e-mail [defaults to account if unset]
		 *
		 * @return bool
		 */
		public function create_referral_profile($username, $firstName, $lastName,
		                                        $email = '')
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			$invoice = $this->get_invoice();
			if (!$invoice) return error("no invoice attached to account");
			$errors = array();
			$this->setup_write();
			if ($this->referral_profile_exists())
				return error("Referral profile already exists for this domain");

			if (!$email) $email = null;
			else if (!preg_match(Regex::EMAIL, $email))
				return error("invalid e-mail address");

			if (!preg_match('/^[a-z0-9]{3,}$/', $username))
				return error("Invalid username.  Usernames may only contain letters and numbers and must be at least 3 characters long.");
			else if (strlen($firstName) < 2 || strlen($lastName) < 2)
				return error("invalid name");

			$rs = self::$billing_db->query("SELECT 1 from referral_profiles WHERE username = '" . $username . "'");
			if ($rs->num_rows > 0) return error("username `" . $username . "' is already in use");

			$stmt = self::$billing_db_write->prepare("INSERT INTO
													referral_profiles
														(username,
														 fname,
														 lname,
														 email,
														 domain,
														 payout_amount,
														 preference,
														 options,
														 invoice)
												 VALUES(?,
														 ?,
														 ?,
														 ?,
														 ?,
														 ?,
														 'paypal',
														 'balance',
														 ?);");
			$min = $this->get_minimum_payout_amount();
			$invoice = $this->get_invoice();
			$stmt->bind_param("sssssds",
				$username,
				$firstName,
				$lastName,
				$email,
				$this->domain,
				$min,
				$invoice
			);
			$stmt->execute();
			if (self::$billing_db_write->error)
				return new MySQLError(self::$billing_db_write->error);
			$ID = self::$billing_db_write->insert_id;
			if ($this->_add_referral($ID, str_replace('APNS-HOSTING', 'APNS-SPECIAL', $this->get_invoice()), 5))
				info("added $5 credit for signing up!");
			return true;
		}

		private function _add_referral($ref_id, $invoice, $credit)
		{
			if (!self::setup_write()) {
				Error_Reporter::report(sprintf("Unable to add referral %s for %d ($%d)",
					$invoice,
					$ref_id,
					$credit
				));
				return false;
			}
			$stmt = self::$billing_db_write->stmt_init();
			$stmt->prepare("INSERT INTO referrals (parent_id, invoice, credit, maturity) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 90 DAY));");
			$stmt->bind_param("dsd", $ref_id, $invoice, $credit);

			return $stmt->execute();
		}

		/**
		 * Change referral payout options
		 *
		 * @param string $pref preference
		 * @param mixed  $val  value
		 * @return bool
		 */
		public function change_payout_preference($pref, $val)
		{

			if (!in_array($pref, self::$_PAYOUT_OPTIONS))
				return error("unrecognized preference `$pref'");
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			$invoice = $this->get_invoice();
			if (!$invoice) return error("no invoice attached to account");
			if ($pref == 'tender') {
				if ($val != "paypal" && $val != "check")
					return error("Invalid tender type `$val'");
				$query = "preference = '" . $pref . "'";
			} else {
				if ($pref == 'frozen') return error("cannot unfreeze account");
				if ($val)
					$query = "options = TRIM(LEADING ',' FROM CONCAT(options,'," . $pref . "'))";
				else
					$query = "options = options & ~(FIND_IN_SET('" . $pref . "',options))";
			}
			$this->setup_write();
			self::$billing_db_write->query("UPDATE referral_profiles SET " . $query . "  WHERE invoice = '" . $invoice . "'");
			return self::$billing_db->affected_rows > 0;
		}

		/**
		 * Fetch payout option
		 *
		 * @param  string $pref preference
		 * @return string|bool
		 */
		public function get_payout_preference($pref)
		{
			if (!in_array($pref, self::$_PAYOUT_OPTIONS))
				return error("unrecognized preference `$pref'");
			$invoice = $this->get_invoice();
			if (!$invoice) return error("no invoice attached to account");

			if ($pref == 'tender') {
				$field = 'preference';
			} else {
				$field = 'find_in_set(\'' . $pref . '\',options) > 0';
			}
			$q = self::$billing_db->query("SELECT " . $field . " FROM referral_profiles WHERE invoice = '" . $invoice . "'");
			if (!$q || $q->num_rows < 1) return false;
			$res = $q->fetch_row();
			return $res[0];
		}

		/**
		 * Record a new referral
		 *
		 * @param string $invoice  new account invoice
		 * @param string $pinvocie parent invoice
		 * @return bool
		 */
		public function add_referral($invoice, $pinvoice)
		{
			$credit = $this->get_credit_from_invoice($invoice);
			if (!$credit)
				return error("invoice `$invoice' ineligible");
			if (!$this->setup_write())
				return error("cannot connect to billing db");
			$ref_id = $this->_get_referral_id($pinvoice);
			if (!$ref_id) return error("no referral profile for `$pinvoice'");
			$credit = $this->get_credit_from_invoice($invoice);
			return $this->_add_referral($ref_id, $invoice, $credit);
		}

		/**
		 * Get referral credit by invoice
		 *
		 * @param string $invoice
		 * @return float
		 */
		public function get_credit_from_invoice($invoice)
		{
			$q = self::$billing_db->query("SELECT level FROM subscription_data WHERE invoice = '" .
				self::$billing_db->escape_string($invoice) . "'");
			if (!$q || $q->num_rows < 1) return false;
			return $this->get_credit_from_package_type($q->fetch_object()->level);
		}

		/**
		 * Get referral credit by package type
		 *
		 * @param string $package package type (minimalist, basic, advanced, super)
		 * @return float
		 */
		public function get_credit_from_package_type($package)
		{
			$base = 5;
			switch (strtolower($package)) {
				case 'super':
				case 'enterprise':
					return $base * 6;
				case 'business':
				case 'advanced':
					return $base * 4;
				case 'developer':
				case 'basic':
					return $base * 2;
				default:
					return $base * 1;
			}
		}

		/**
		 * Get hosting invoice by domain
		 *
		 * @param string $domain domain name
		 * @return string
		 */
		public function get_invoice_from_domain($domain)
		{
			if (!self::$connected) return error("cannot connect to billing DB server");
			$parent = $this->dns_get_parent_domain($domain);
			if (!$parent) return error("no such domain `$domain'");

			$db = self::$billing_db;
			$rs = $db->query("SELECT di_invoice FROM domain_information WHERE domain = '$parent'")->fetch_object();
			if (!$rs) return error("cannot find invoice from domain `%s'", $domain);
			// really shouldn't happen ever
			if (!$rs->di_invoice) {
				Error_Reporter::print_debug_bt();
			}

			return $rs->di_invoice;
		}

		/**
		 * Retrieve Web hosting renewal hash for service
		 *
		 * @return mixed
		 */
		public function get_renewal_hash($invoice = null)
		{
			if (self::$billing_db instanceof Exception)
				return false;
			$curinvoice = $this->get_invoice();
			if (!$curinvoice) return null;

			$invoices = $this->get_all_invoices();
			if ($invoice && !in_array($invoice, $invoices))
				return error($invoice . ": unrecognized invoice");
			else if (!$invoice)
				$invoice = $curinvoice;

			$rs = self::$billing_db->query("SELECT
				subscription_notices.status,
				subscription_notices.type,
				subscription_notices.level,
				subscription_data.domain,
				subscription_number,
				subscription_notices.hash
				FROM subscription_data
				JOIN subscription_notices
				USING(subscription_number)
 				WHERE subscription_notices.invoice = '" . $invoice . "'
 				AND
 				subscription_notices.status = 'complete'
				ORDER BY
				subscription_notices.date_cancelled DESC");
			if ($rs->num_rows < 1)
				return false;
			while (false != ($rec = $rs->fetch_object())) {
				if ($rec->type == 'Webhosting') {
					if ($rec->status != 'complete')
						return null;
					return $rec->hash;
				}
			}
			debug("renewal hash not found on account " . $this->domain);
			return null;
		}

		public function get_customer_since()
		{
			$key = 'billing:cst';
			$cache = Cache_Account::spawn();
			if (false !== ($since = $cache->get($key))) {
				return $since;
			}
			if (self::$billing_db instanceof Exception)
				return -1;
			$invoice = $this->get_invoice();
			if (!$invoice) return -1;

			$rs = self::$billing_db->query("SELECT min(date_signup) as date_signup
				FROM subscription_data WHERE invoice = '" . $invoice . "'");
			if ($rs->num_rows < 1) return false;
			$rec = $rs->fetch_object();
			$since = strtotime($rec->date_signup);
			$cache->set($key, $since);
			return $since;
		}

		public function get_billing_information()
		{
			if (self::$billing_db instanceof Exception)
				return array();
			$subscription = $this->get_hosting_subscription();
			$rs = self::$billing_db->query("
											SELECT
												first_name,
												last_name,
												city,
												state,
												zip_code,
												country,
												company,
												RTRIM(CONCAT(address1,' ',COALESCE(address2,''))) as address,
												phone,
												email
											FROM
												billing_information
											WHERE
												subscription_number = '" . $subscription . "'");
			$arr = $rs->fetch_assoc();
			return $arr ? $arr : array();

		}

		public function get_credit_card_information()
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			$rs = self::$billing_db->query("SELECT
				cc_number,
				cc_type,
				NULL as cvm,
				EXTRACT(YEAR_MONTH FROM cc_exp) as cc_exp
			FROM
				recurring_batch
			WHERE
				subscription_number = '" . $this->get_hosting_subscription() . "'
				AND
				recurring_batch.cid IS NOT NULL");

			$arr = $rs->fetch_assoc();
			return $arr ? $arr : array();
		}

		public function change_credit_card_information($expyear, $expmonth,
		                                               $cvm = null, $number = null, $type = null)
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			if (strlen($number) > 4 && !$cvm ||
				$cvm && (strlen($cvm) > 4 || strlen($cvm) < 3 || intval($cvm) != $cvm)
			)
				return error("CSC should be 3 - 4 digits long");
			$this->setup_write();
			$db = self::$billing_db_write;
			$invoices = $this->get_all_invoices();
			if (!$invoices) return error("no active invoices");

			$invoiceq = "'" . join("','", $invoices) . "'";
			$exp = '20' . $expyear . '-' . $expmonth . '-00';

			if (!$number) {
				/** detach credit card from system */
				$db->query("UPDATE recurring_batch SET cid = NULL WHERE invoice
						IN(" . $invoiceq . ");");

				if ($db->affected_rows < 1) {
					return error("cannot disable recurring billing - invoice not found in system");
				}
				return info("recurring billing halted; account will be closed in 15 days") || true;
			}


			$rs = $db->query("SELECT cid FROM recurring_batch WHERE invoice IN (" . $invoiceq . ") LIMIT 1");
			if (!$rs || $rs->num_rows < 1) {
				return error("cannot update card details, billing info not in database");
			}

			$oldcid = $rs->fetch_object()->cid;

			if (strlen($number) == 4) {
				/** changed exp date */
				if (!ctype_digit($expmonth) || $expmonth < 1 || $expmonth > 12 ||
					!ctype_digit($expyear) || ($expyear < date('y')) || ($expyear > date('y') + 10)
				) {
					return error("Invalid expiration date");
				} else if (!ctype_digit($number)) {
					return error("Please include the last four digits of the card");
				}
				// update card throughout the billing db...
				$q = "UPDATE recurring_batch SET cc_exp = '" . $exp . "' WHERE cid = '" . $oldcid . "'";
				$rs = $db->query($q);
				if (!$rs || $db->error) {
					Error_Reporter::report(__LINE__ . ": " . $db->error);
					return error("failed to update credit card expiration");
				}
				return $db->affected_rows > 0;
			}

			// new card entered...
			if (!in_array($type, array('mc', 'discover', 'visa', 'amex'))) {
				return error($type . ": invalid card type");
			} else if (!self::_verify_credit_card_number($number, $type)) {
				return error($number . ": invalid card number");
			} else if (!ctype_digit($expmonth) || $expmonth < 1 || $expmonth > 12 ||
				!ctype_digit($expyear) || ($expyear < date('y')) || ($expyear > date('y') + 10)
			) {
				return error($expmonth . "-" . $expyear . ": invalid expiration date");
			}

			$salt = $this->_generateSalt();
			$cid_hash = $this->_makeHash($number, $salt);

			$query = "INSERT INTO credit_cards " .
				"(cid, cc, expdate, cvm, fraud_score, avs, salt) " .
				"VALUES('" . $cid_hash . "','" . $number . "','" . $exp . "'," . $cvm . ", 0,NULL, X'" . bin2hex($salt) . "');";
			$rs = $db->query($query);
			if (!$rs || $db->error) {
				Error_Reporter::report(__LINE__ . ": " . $db->error);
				return error("failed to add card to billing profile");
			}

			$rs = $db->query("UPDATE recurring_batch SET cid = '" . $cid_hash . "',
					txn_retry = 0, cc_number = '" . substr($number, -4) . "', cc_type = '" . $type . "',
					cc_exp = '20" . $expyear . "-" . $expmonth . "-00'
					WHERE INVOICE IN(" . $invoiceq . ")");

			$q = $db->query("SELECT 1 FROM recurring_batch WHERE
					cid = '" . $cid_hash . "' AND
					subscription_number = '" . $this->get_hosting_subscription() . "'");

			if (!$q || $db->error) Error_Reporter::report(__LINE__ . ": " . $db->error);

			return $q->num_rows > 0;
		}

		/**
		 * Ensure that we have a correctly formatted credit card
		 * number and corresponding card type
		 */
		private static function _verify_credit_card_number($number, $type)
		{
			$number = trim($number);
			if (!ctype_digit($number)) {
				return error($number . ": not a number");
			} else if ($type == 'mc' && (strlen($number) != 16 || $number[0] != '5')) {
				return false;
			} else if ($type == 'visa' && (strlen($number) != 13 && strlen($number) != 16 || $number[0] != '4')) {
				return false;
			} else if ($type == 'discover' && (strlen($number) != 16 || substr($number, 0, 4) != '6011')) {
				return false;
			} else if ($type == 'amex' && (strlen($number) != 15 || (substr($number, 0, 2) != '34' && substr($number, 0, 2) != '37'))) {
				return false;
			}

			$card_mod = '';
			$sum = 0;
			for ($alt = false, $i = strlen($number) - 1; $i >= 0; $i--) {
				if ($alt) {
					$sum += $number[$i] * 2 - ($number[$i] * 2 > 9 ? 9 : 0);
				} else {
					$sum += $number[$i];
				}
				$alt = !$alt;
			}

			return $sum % 10 == 0;
		}

		private function _generateSalt()
		{
			$salt = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);
			if (!$salt) {
				return mt_rand(1e16, 1e17);
			}
			return $salt;
		}

		private function _makeHash($cc, $salt)
		{
			return hash_hmac('sha512', $cc, $salt);
		}

		public function change_billing_information($firstname, $lastname, $company = null,
		                                           $address, $city, $state,
		                                           $zip, $country, $phone = null,
		                                           $email = null)
		{
			if (!self::$connected)
				return error("unable to connect to billing server at this time");
			if (!$this->setup_write()) return false;
			$country = strtolower($country);
			if (strlen($country) != 2) error($country . ": invalid country");
			if ($country == 'us') $state = strtoupper($state);
			if (!$state) error("missing state");

			$address1 = explode("\n", wordwrap($address, 32, "\n"));

			if (is_array($address1)) {
				$address2 = isset($address1[1]) ? $address1[1] : null;
				$address1 = $address1[0];
			} else {
				$address2 = null;
			}

			if (Error_Reporter::is_error()) return false;

			$invoices = $this->get_all_invoices();
			if (!$invoices) {
				return false;
			}

			$stmt = self::$billing_db_write->stmt_init();
			$stmt->prepare("UPDATE billing_information
				SET first_name = ?,
				last_name = ?,
				city = ?,
				state = ?,
				zip_code = ?,
				country = ?,
				company = ?,
				address1 = ?,
				address2 = ?,
				phone = ?,
				email = ?
				WHERE invoice IN('" . join("','", $invoices) . "')");
			$stmt->bind_param("sssssssssss",
				$firstname,
				$lastname,
				$city,
				$state,
				$zip,
				$country,
				$company,
				$address1,
				$address2,
				$phone,
				$email
			);
			$stmt->execute();

			$ret = $stmt && $stmt->affected_rows >= 0;
			if (!$ret) Error_Reporter::report(__LINE__ . ": " . self::$billing_db_write->error);
			$stmt->close();

			return $ret;
		}

		public function get_package_type()
		{
			$invoice = $this->get_invoice();
			return $this->get_package_by_invoice($invoice);
		}

		public function get_package_by_invoice($invoice)
		{
			$cache = Cache_Account::spawn();
			$key = 'billing:pkgbyinv';
			if (false !== ($pkg = $cache->get($key))) {
				return $pkg;
			}
			if (!self::$connected)
				return error("unable to connect to billing server at this time");

			if (!$invoice) return warn("cannot locate billing information");
			$invoice = self::$billing_db->escape_string($invoice);
			$q = self::$billing_db->query("SELECT subscription_name FROM
				subscription_data
				WHERE
				invoice = '" . $invoice . "' ORDER BY date_signup DESC LIMIT 1");
			if ($q->num_rows < 1) return false;
			$name = $q->fetch_object()->subscription_name;
			$pkg = substr($name, strpos($name, '>') + 1,
				strlen($name) - strlen(substr($name, 0, strpos($name, '>'))) - strlen(substr($name, strrpos($name, "("))) - 2);
			if (isset($this->_package_remap[$pkg])) {
				$pkg = $this->_package_remap[$pkg];
			}
			if (!$this->permission_level & PRIVILEGE_ADMIN) {
				$cache->set($key, $pkg, 43200);
			}
			return $pkg;
		}

		/**
		 * Claim referral from token
		 *
		 * @param  $token string 40 character hash
		 * @return bool
		 */
		public function claim_referral($token)
		{
			if (!self::$connected)
				return error("unable to connect to billing server");
			if (!ctype_xdigit($token)) return error("invalid token `$token'");
			$q = self::$billing_db->query("SELECT invoice FROM referrals WHERE hash = '" . self::$billing_db->escape_string($token) . "' AND parent_id IS NULL");
			if (!$q || $q->num_rows < 1) return error("invalid token `$token'");

			$id = $this->_get_referral_id();
			if (!$id) return error("cannot claim without referral profile");
			$md = $this->claim_metadata($token);
			if (!self::setup_write()) return false;

			self::$billing_db_write->query("UPDATE referrals SET hash = NULL, parent_id = " . $this->_get_referral_id() . " WHERE hash = '" . $token . "'");
			if (self::$billing_db_write->affected_rows < 1) return false;

			info('added $' . number_format($md['revenue'], 0) . ' credit for domain `' . $md['domain'] . "' ");
			return true;
		}

		public function claim_metadata($token)
		{
			if (!self::$connected)
				return error("unable to connect to billing server");
			if (!ctype_xdigit($token)) return error("invalid token `$token'");

			$q = self::$billing_db->query("
				SELECT
					domain,
					credit,
					UNIX_TIMESTAMP(maturity) AS maturity
				FROM
					referrals
				JOIN
					subscription_data USING(invoice)
				WHERE
					hash = '" . self::$billing_db->escape_string($token) . "'");
			if (!$q || !$q->num_rows) return false;
			$row = $q->fetch_object();
			$data = array(
				'domain'   => $row->domain,
				'revenue'  => (float)$row->credit,
				'maturity' => (int)$row->maturity
			);

			return $data;

		}


	}

?>
