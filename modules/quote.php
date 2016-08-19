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
	 * Client feedback module from a bygone era
	 *
	 * @package core
	 */
	class Quote_Module extends Module_Skeleton
	{

		private static $CRM_SERVER_HOST = CRM_TICKET_HOST;
		private static $CRM_SERVER_USER = CRM_TICKET_USER;

		// @ignore
		private static $CRM_SERVER_PASSWORD = CRM_TICKET_PASSWORD;
		// @ignore
		private static $CRM_SERVER_DATABASE = CRM_TICKET_DB;
		// @ignore
		public $exportedFunctions = array('*' => PRIVILEGE_SITE);
		// @ignore
		private $_db;
		private $_metaCache = array();

		/**
		 * void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();
		}

		public function __destruct()
		{
			$this->_db = null;
		}

		public function update($quote, $rating = 5, $name = null, $site = null)
		{
			if ($rating < 1 || $rating > 5) return error("invalid rating `$rating'");
			if (!$this->has_quote()) return $this->add($quote, $rating, $name, $site);
			$invoice = $this->billing_get_invoice();
			if (!$invoice) return false;
			$quote = trim($quote);
			if (!$quote) return error("missing quote data");
			$def = array(
				'site'    => $site,
				'name'    => $name,
				'quote'   => Util_HTML_BBCode::clean2HTML($quote),
				'rating'  => $rating,
				'invoice' => $invoice,
			);

			$db = $this->_connect();
			$stmt = $db->prepare('UPDATE quotes
				SET quote = CONCAT(quote,"\r\n\r\nUpdate ", DATE_FORMAT(NOW(), "%M %d, %Y"), ":\r\n", :quote), 
					name = :name, site = :site, rating = :rating
				WHERE invoice = :invoice');
			return $stmt->execute($def);

		}

		public function has_quote()
		{
			return (bool)$this->get();
		}

		public function get()
		{
			$invoice = $this->billing_get_invoice();
			if (!$invoice) return false;
			$db = $this->_connect();
			$q = "SELECT quote, name, id, rating, site, UNIX_TIMESTAMP(since)
				FROM quotes WHERE invoice = '" . $invoice . "'";
			$rs = $db->query($q);
			if ($rs->rowCount() < 1) return array();
			return $rs->fetch(PDO::FETCH_ASSOC);
		}

		private function _connect()
		{
			if ($this->_db instanceof PDO)
				return $this->_db;
			Error_Reporter::suppress_php_error('PDO::.*');
			$db = self::$CRM_SERVER_DATABASE;
			$host = self::$CRM_SERVER_HOST;
			$user = self::$CRM_SERVER_USER;
			$password = self::$CRM_SERVER_PASSWORD;
			$dsn = 'mysql:dbname=' . $db . ';host=' . $host;
			try {
				$this->_db = new PDO($dsn, $user, $password);
			} catch (PDOException $e) {
				Error_Reporter::report("unable to connect to quote db - falling back" . $e->getMessage());
				$this->_db = null;
				return error("unable to connect to ticket database - use help@apisnetworks.com");
			}
			return $this->_db;

		}

		/**
		 * Add client feedback
		 *
		 * @param string $quote
		 * @param array  $meta
		 */
		public function add($quote, $rating = 5, $name = null, $site = null)
		{
			if ($this->auth_is_demo()) return error("cannot add testimonial for demo account");
			if ($rating < 1 || $rating > 5) return error("invalid rating `$rating'");
			$invoice = $this->billing_get_invoice();
			if (!$invoice) return false;
			$quote = trim($quote);
			if (!$quote) return error("missing quote data");
			$def = array(
				'site'    => $site,
				'name'    => $name,
				'since'   => null,
				'quote'   => $quote,
				'invoice' => $invoice,
				'rating'  => $rating
			);
			$def['since'] = $this->billing_get_customer_since();
			$db = $this->_connect();
			$def['quote'] = Util_HTML_BBCode::clean2HTML($def['quote']);
			$stmt = $db->prepare("INSERT INTO quotes
				(id, quote, since, name, rating, site, invoice)
				VALUES
				(null,
				:quote,
				FROM_UNIXTIME(:since),
				:name,
				:rating,
				:site,
				:invoice)");
			Mail::send('matt+feedback@apisnetworks.com', 'Client Testimonial - ' . $site, var_export($def, true));
			return $stmt->execute($def);

		}

		public function get_random()
		{
			$db = $this->_connect();
			$q = "SELECT id, name, site,
				UNIX_TIMESTAMP(since) AS since, quote " .
				"FROM quotes ORDER BY RAND() LIMIT 1";
			$rs = $db->query($q);
			if ($rs->rowCount() < 1) return array();
			return $rs->fetch(PDO::FETCH_ASSOC);
		}

		public function get_all()
		{
			$db = $this->_connect();
			if (!$db) return false;
			$quotes = array();
			$q = "SELECT quote, name, id, rating, site, UNIX_TIMESTAMP(since)
				FROM quotes";
			$rs = $db->query($q);
			if ($rs->rowCount() < 1) return array();
			while (false !== ($r = $rs->fetchObject())) {
				$quotes[] = array(
					'quote'  => $r->quote,
					'name'   => $r->name,
					'id'     => $r->id,
					'rating' => $r->rating,
					'site'   => $r->site
				);
			}
			return $quotes;
		}


	}