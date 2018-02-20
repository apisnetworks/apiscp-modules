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
	 * Billing and referral module
	 *
	 * @package core
	 */
	class Billing_Module extends Module_Skeleton
	{
		// @ignore
		private static $BILLING_SERVER_HOST = BILLING_HOST_READ;
		// @ignore
		private static $BILLING_SERVER_HOST_WRITE = BILLING_HOST_WRITE;
		// @ignore
		private static $BILLING_SERVER_HOST_BACKUP = BILLING_HOST_BACKUP;
		private static $BILLING_SERVER_USER = BILLING_USER;
		private static $BILLING_SERVER_PASSWORD = BILLING_PASSWORD;
		private static $BILLING_SERVER_DATABASE = BILLING_DB;

		/**
		 * Recognized preferences in [change,get]_payout_preferences
		 * tender:   tender method
		 * freeze:   account frozen
		 * balance:  credit hosting balance
		 *
		 * @var array
		 */
		private static $_PAYOUT_OPTIONS = array('tender', 'freeze', 'balance');

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
		}

		/**
		 * @return string current payment method, enum: [credit, check, paypal, cash, other]
		 */
		public function get_payment_method()
		{
			return 'other';

		}

		/**
		 * Currently active subscription number attached to invoice
		 *
		 * @return mixed|NULL
		 */
		public function get_hosting_subscription()
		{
			return $this->get_config('billing', 'invoice');
		}

		/**
		 * Invariant invoice tied to an account
		 *
		 * @return int|mixed|NULL|string
		 */
		public function get_invoice()
		{
			$invoice = $this->get_config('billing', 'invoice');
			if ($invoice) {
				return $invoice;
			}
			if ($this->get_config('billing', 'parent_invoice')) {
				return $this->get_config('billing', 'parent_invoice');
			}
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
			return [
				'date'   => -1,
				'amount' => 0
			];
		}

		/**
		 * array list_payments
		 *
		 * Sample response:
		 * Array
		 * (
		 *  [0] => Array
		 *  (
		 *      [date] => 1469937612
		 *      [amount] => 65.00
		 *      [service] => Webhosting->Developer
		 *      [number] => C-2ALQUJ67SSQXIDJEESZFRMZ
		 *      [note] =>
		 *      [type] => credit
		 *  )
		 * )
		 *
		 * @return array
		 */
		public function list_payments()
		{
			$recs = [];
			return $recs;

		}

		private function get_all_invoices()
		{
			$invoice = array($this->get_invoice());
			if (!$invoice) {
				return false;
			}
			$addons = (array)$this->get_config('billing', 'addons');
			if (!$addons) {
				return $invoice;
			}
			return array_merge($invoice, $addons);
		}

		/**
		 * Fetch billing status from backend billing server
		 *
		 * @param string $invoice
		 * @return int
		 */
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
		 * @param string $invoice
		 * @return int
		 */
		public function get_status($invoice = '')
		{
			return 1;
		}

		/**
		 * bool is_billed()
		 *
		 * @return bool billing record exists
		 */
		public function is_billed()
		{
			return (bool)$this->get_hosting_subscription();
		}

		public function is_referred($invoice)
		{
			return false;
		}

		/**
		 * array get_payment_information(string)
		 *
		 * Sample response:
		 * Array
		 * (
		 *  [date] => 1469937612
		 *  [amount] => 65
		 *  [domain] => apnscp.com
		 *  [service_level] => Developer
		 *  [name] => Tark Sammons
		 *  [email] => tark.sammons@apnscp.com
		 *  [note] =>
		 *  [service_type] => Webhosting
		 *  [method] => recurring
		 *  [payment_method] => credit
		 *  [reference] => C-2ALQUJ67SSQXIDJEESZFRMZ
		 *  [txn_id] => 11111
		 *  [invoice] => APNSCP-CJKFHECZO35
		 *  [cc_type] => visa
		 *  [cc_number] => 1111
		 *  [cc_exp] => 03/20
		 * )
		 *
		 * @param string $transnum transaction number
		 * @param int    $date     unix timestamp of date of transaction
		 * @return array
		 */
		public function get_payment_information($transnum, $date, $type = "paypal")
		{
			return [];
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
		public function edit_referral_profile(
			$fname,
			$lname,
			$email = ''
		) {
			return error("not implemented");
		}

		/**
		 * Check if referral profile exists
		 *
		 * @return bool
		 */
		public function referral_profile_exists()
		{
			return false;
		}

		/**
		 * Get referral username
		 *
		 * @return string
		 */
		public function get_referral_username()
		{
			return null;
		}

		/**
		 * Set minimum balance for a payout
		 *
		 * @param double $amount
		 * @return bool
		 */
		public function edit_payout_amount($amount)
		{
			return error("not implemented");
		}

		/**
		 * float get_payout_amount()
		 *
		 * @return float
		 */
		public function get_payout_amount()
		{
			return null;
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
			return 0;
		}

		/**
		 * Get multiplier used in commission credit
		 *
		 * @return int
		 */
		public function referral_multiplier()
		{
			return 1;
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
		 * string(8) "apnscp.com"
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
			return [];
		}

		/**
		 * array get_customer_referral_information()
		 *
		 * @return array
		 */
		public function get_customer_referral_information()
		{
			return false;

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
		public function create_referral_profile(
			$username,
			$firstName,
			$lastName,
			$email = ''
		) {
			return error("not implemented");
		}

		/**
		 * Change referral payout options
		 *
		 * @param string $pref preference ['frozen', 'tender']
		 * @param mixed  $val  payment preference ['paypal', 'check']
		 * @return bool
		 */
		public function change_payout_preference($pref, $val)
		{
			return error("not implemented");
		}

		/**
		 * Fetch payout option
		 *
		 * @param  string $pref preference
		 * @return string|bool
		 */
		public function get_payout_preference($pref)
		{
			return error("not implemented");
		}

		/**
		 * Record a new referral
		 *
		 * @param string $invoice  new account invoice
		 * @param string $pinvoice parent invoice (referral profile)
		 * @return bool
		 */
		public function add_referral($invoice, $pinvoice)
		{
			return error("not implemented");
		}

		/**
		 * Get referral credit by invoice
		 *
		 * @param string $invoice
		 * @return float
		 */
		public function get_credit_from_invoice($invoice)
		{
			return false;
		}

		/**
		 * Get referral credit by package type
		 *
		 * @param string $package package type
		 * @return float
		 */
		public function get_credit_from_package_type($package)
		{
			return 1;
		}

		/**
		 * Get hosting invoice by domain
		 *
		 * @param string $domain domain name
		 * @return string
		 */
		public function get_invoice_from_domain($domain)
		{
			return null;
		}

		/**
		 * Retrieve billing renewal hash for service
		 *
		 * @return mixed
		 */
		public function get_renewal_hash($invoice = null)
		{
			return null;
		}

		/**
		 * Get customer since
		 *
		 * @return int unix timestamp or -1 for connectivity issues
		 */
		public function get_customer_since()
		{
			return -1;
		}

		/**
		 * Get billing information attached to account
		 *
		 * Array
		 * (
		 *  [first_name] => Tark
		 *  [last_name] => Sammons
		 *  [city] => Atlanta
		 *  [state] => Georgia
		 *  [zip_code] => 30308
		 *  [country] => US
		 *  [company] =>
		 *  [address] => 123 Anywhere St
		 *  [phone] => 867-5309
		 *  [email] => tark.sammons@apnscp.com
		 * )
		 *
		 * @return array
		 */
		public function get_billing_information()
		{
			return array();
		}

		public function get_credit_card_information()
		{
			if (!self::$connected) {
				return error("unable to connect to billing server at this time");
			}
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

		public function change_credit_card_information(
			$expyear,
			$expmonth,
			$cvm = null,
			$number = null,
			$type = null
		) {
			return error("not implemented");
		}

		/**
		 * Update billing information on account
		 *
		 * @param string      $firstname
		 * @param string      $lastname
		 * @param string|null $company
		 * @param string      $address
		 * @param string      $city
		 * @param string      $state
		 * @param string      $zip
		 * @param string      $country
		 * @param string|null $phone
		 * @param string|null $email
		 * @return bool
		 */
		public function change_billing_information(
			$firstname,
			$lastname,
			$company = null,
			$address,
			$city,
			$state,
			$zip,
			$country,
			$phone = null,
			$email = null
		) {
			return error("not implemented");
		}

		/**
		 * Get current package
		 *
		 * @return string|null
		 */
		public function get_package_type()
		{
			$invoice = $this->get_invoice();
			return $this->get_package_by_invoice($invoice);
		}

		/**
		 * Get package name from invoice
		 *
		 * @param $invoice
		 * @return mixed|null
		 */
		public function get_package_by_invoice($invoice)
		{
			return null;
		}

		/**
		 * Claim referral from token
		 *
		 * @param  $token string 40 character hash
		 * @return bool
		 */
		public function claim_referral($token)
		{
			return error("not implemented");
		}

		/**
		 * Get data about a referral
		 * Sample return:
		 *  Array(
		 *      [domain] => apnscp.com
		 *      [revenue] => 20.00
		 *      [maturity] => 1469937612
		 *  )
		 *
		 * @param string $token
		 * @return array|bool|void
		 */
		public function claim_metadata($token)
		{
			return error("not implemented");
		}

		/**
		 * Used by TemplateEngine to confirm module is setup
		 *
		 * @return bool
		 */
		public function configured()
		{
			return false;
		}

	}