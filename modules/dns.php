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
	 * Provides DNS functions to apnscp.
	 *
	 * @package core
	 */
	class Dns_Module extends Module_Skeleton
	{
		/**
		 * @var string TSIG key
		 * @ignore
		 */
		private static $dns_key = DNS_TSIG_KEY;
		/** primary nameserver */
		const INTERNAL_NAMESERVER = DNS_INTERNAL_MASTER;
		const EXTERNAL_NAMESERVER = DNS_EXTERNAL_NS;
		const NAMEBASED_INTERFACE_FILE = '/etc/virtualhosting/interface';
		// default DNS TTL for records modified via update()
		const DYNDNS_TTL = 300;
		// default DNS TTL for records
		const DNS_TTL = 43200;
		// netmask of allowable IP addresses
		const IP_ALLOCATION_BLOCK = DNS_ALLOCATION_CIDR;
		// standard hosts file location
		const HOSTS_FILE = '/etc/hosts';

		/** mapping of RR types to constants */
		private static $rec_2_const = array(
			'ANY'   => DNS_ANY,
			'A'     => DNS_A,
			'AAAA'  => DNS_AAAA,
			'MX'    => DNS_MX,
			'NS'    => DNS_NS,
			'SOA'   => DNS_SOA,
			'TXT'   => DNS_TXT,
			'CNAME' => DNS_CNAME,
			'SRV'   => DNS_SRV,
			'PTR'   => DNS_PTR,
			'HINFO' => DNS_HINFO,
			'A6'    => DNS_A6,
			'NAPTR' => DNS_NAPTR
		);
		/** array of 1 or more nameservers used */
		private static $nameservers;

		/** external MySQL connection to apnscp.domains */
		private static $domain_db;

		/** array of allowed RR types */

		/**
		 * Legal DNS resource records
		 * A
		 * AAAA
		 * MX
		 * CNAME
		 * DNAME
		 * HINFO
		 * TXT
		 * NS
		 * SRV
		 *
		 * @var array
		 */
		private static $permitted_records = array('a', 'aaaa',
			'mx', 'cname', 'dname', 'hinfo', 'txt', 'ns', 'srv',
			'a6', 'naptr', 'any', 'soa');

		/**
		 * {{{ void __construct(void)
		 */
		public function __construct()
		{
			parent::__construct();

			$this->exportedFunctions = array(
				'*'                      => PRIVILEGE_SITE,
				'get_whois_record'       => PRIVILEGE_ALL,
				'record_exists'          => PRIVILEGE_ALL,
				'remove_zone_backend'    => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'get_all_domains'        => PRIVILEGE_ADMIN,
				'get_parent_domain'      => PRIVILEGE_ADMIN,
				'remove_zone'            => PRIVILEGE_ADMIN,
				'get_server_from_domain' => PRIVILEGE_ADMIN,
				'release_ip'             => PRIVILEGE_ADMIN,
				'ip_allocated'           => PRIVILEGE_ADMIN
			);
		}

		private static function _connect_db()
		{
			if (!is_null(self::$domain_db) && self::$domain_db->ping()) {
				return self::$domain_db;
			}
			$db = new mysqli();
			$db->init();
			if ((!$db->real_connect(DNS_DOMAIN_HOST, DNS_DOMAIN_USER, DNS_DOMAIN_PASSWORD) &&
					!$db->real_connect(DNS_DOMAIN_HOST_BACKUP, DNS_DOMAIN_USER_BACKUP, DNS_DOMAIN_PASSWORD_BACKUP)) ||
				!$db->select_db(DNS_DOMAIN_DB)
			) {
				return error("Cannot connect to domain server at this time");
			}

			self::$domain_db = &$db;
			return $db;
		}



		// {{{ domain_expiration()

		/**
		 * Query database for domain expiration
		 *
		 * A return of 0 indicates failure
		 * null indicates unknown expiration
		 *
		 * @param string $domain domain owned by the account
		 * @return int expiration as unix timestamp
		 */
		public function domain_expiration($domain)
		{
			if (!self::_connect_db()) return 0;
			if (!$this->owned_zone($domain))
				return error($domain . ": not owned by account");

			$q = self::$domain_db->query("
				SELECT
					UNIX_TIMESTAMP(domain_expire) as expiration
				FROM
					domain_information
				WHERE
					domain = '" . self::$domain_db->escape_string($domain) . "'
					AND
					site_id = " . $this->site_id);
			if ($q->num_rows < 1) return null;

			return $q->fetch_object()->expiration;
		}

		/**
		 * Fetches all domains across all servers
		 *
		 * @return array
		 */
		public function get_all_domains()
		{
			self::_connect_db();
			$q = self::$domain_db->query("SELECT domain FROM domain_information ORDER BY domain");
			$domains = array();
			while (($row = $q->fetch_object())) {
				$domains[] = $row->domain;
			}
			return $domains;

		}

		/**
		 * Get server on which a domain is hosted
		 *
		 * @param string $domain
		 * @param bool   $all   show all server matches
		 * @param        mixed  when $all = true: array of all servers, else server
		 */
		public function get_server_from_domain($domain, $all = false)
		{
			self::_connect_db();
			$rs = self::$domain_db->query("SELECT server_name FROM domain_information WHERE domain = '" .
				self::$domain_db->escape_string($domain) . "'");
			$servers = array();
			while ($row = $rs->fetch_object()) {
				$servers[] = $row->server_name;
			}
			if (!$all && count($servers) > 1) {
				warn("domain `%s' present on `%d' servers",
					$domain, count($servers));
			}
			if ($all) return $servers;
			return array_pop($servers);
		}

		/**
		 *  Get primary domain affiliated with account
		 *
		 * @param string $domain
		 * @return string
		 */
		public function get_parent_domain($domain)
		{
			self::_connect_db();
			$db = self::$domain_db;
			$domain = strtolower($domain);

			$stmt = $db->stmt_init();
			$stmt->prepare("SELECT COALESCE(parent_domain,domain) AS domain " .
				"FROM domain_information WHERE domain = ?");
			$stmt->bind_param("s", $domain);
			$rs = $stmt->execute();
			$stmt->store_result();
			if (!$rs || $stmt->num_rows < 1) return false;
			$parent = null;
			$stmt->bind_result($parent);
			$stmt->fetch();

			return $parent;
		}

		/**
		 * string get_whois_record (string)
		 *
		 * Query WHOIS server for record
		 *
		 * @privilege PRIVILEGE_ALL
		 *
		 * @param  string $domain domain name to look up the whois record for
		 *
		 * @return string whois data
		 *
		 */
		public function get_whois_record($domain)
		{
			Error_Reporter::suppress_php_error('require_once');
			if (!preg_match(Regex::DOMAIN, $domain))
				return error($domain . ": invalid domain");
			if (!class_exists('Net_Whois', false) &&
				!include('Net/Whois.php')
			) {
				return error("Unable to include Whois module");
			}

			$whois = new Net_Whois();
			$data = $whois->query($domain);
			if (PEAR::isError($data)) {
				return new SocketError($data->message);
			}
			return $data;
		}

		/**
		 * array get_zone_information (string)
		 *
		 * Reads zone information for a given domain on the nameservers.
		 *
		 * @return array
		 */
		public function get_zone_information($domain = null)
		{
			if (is_null($domain))
				$domain = $this->domain;

			if (!$this->permission_level & (PRIVILEGE_ADMIN) && !$this->owned_zone($domain)) {
				return error("access denied - cannot view zone `" . $domain . "'");
			}
			$rec = $this->_get_zone_information_raw($domain);
			if (is_null($rec)) {
				return new apnscpException("Non-authorative for zone " . $domain);
			}
			return $rec;

		}

		/**
		 * Unauthenticated call for get_zone_information
		 *
		 * @param $domain
		 */
		private function _get_zone_information_raw($domain)
		{
			$data = $this->_get_zone_information_raw_raw($domain);
			$zoneData = array();
			$offset = strlen($domain) + 1; // domain.com.
			foreach (explode("\n", $data) as $line) {
				if (strstr($line, 'Transfer failed.')) {
					return null;
				}
				if (preg_match(Regex::DNS_AXFR_REC, $line, $match)) {

					list ($name, $ttl, $class, $rr, $parameter) = array_slice($match, 1);
					$rr = strtoupper($rr);
					// TXT records should always be balanced with quotes
					// assume this to be the case if " present
					// don't pretty-print if more than 1 quote pair present
					if ($rr == 'TXT' && $parameter[0] == '"') {
						if (strpos($parameter, '"', 1) === strlen($parameter)-1) {
							// parameter formatted as "foobar"
							$parameter = substr($parameter, 1, -1);
						} else if (preg_match(Regex::DNS_TXT_PRETTY_PRINT, $parameter)) {
							// balanced quotes, no spaces within quotes, e.g.
							// "v=spf1" "ip4:64.22.68.1/24" "mx" "-all"
							$parameter = str_replace('"', '', $parameter);
						}
					}
					$zoneData[$rr][] = array(
						'name'      => $name,
						'subdomain' => rtrim(substr($name, 0, strlen($name) - $offset), '.'),
						'domain'    => $domain,
						'class'     => $class,
						'ttl'       => $ttl,
						'parameter' => $parameter
					);
				}

			}
			return $zoneData;
		}

		private function _get_zone_information_raw_raw($domain)
		{
			$data = Util_Process::exec("dig -t AXFR -y '" . self::$dns_key . "' @" . self::INTERNAL_NAMESERVER . " " . $domain);
			return $data['success'] ? $data['output'] : false;
		}

		public function export($zone = null)
		{
			if (is_null($zone))
				$zone = $this->domain;

			if (!$this->permission_level & (PRIVILEGE_ADMIN) && !$this->owned_zone($zone)) {
				return error("access denied - cannot view zone `%s'", $zone);
			}
			$recs = $this->_get_zone_information_raw($zone);
			if (is_null($recs)) {
				return error("failed to export zone `%s'", $zone);
			}
			$soa = $recs['SOA'][0];
			$soadata = preg_split('/\s+/', $soa['parameter']);
			$format = ";; " . "\n" .
				";; Domain:\t" . $zone . "\n" .
				";; Exported:\t" . date("r") . "\n" .
				";; " . "\n" .
				'$ORIGIN . ' . "\n" .
				"@\t" . $soa['ttl'] . "\tIN\tSOA\t$zone.\t" . $soadata[1] . " ( " . "\n" .
				"\t" . $soadata[2] . "\t; serial" . "\n" .
				"\t" . $soadata[3] . "\t; refresh" . "\n" .
				"\t" . $soadata[4] . "\t; retry" . "\n" .
				"\t" . $soadata[5] . "\t; expire" . "\n" .
				"\t" . $soadata[6] . ")\t; minimum" . "\n\n";
			$buffer = array();
			$buffer[] = ";; NS Records (YOU MUST CHANGE THIS)";
			foreach ($recs['NS'] as $ns) {
				$ns['parameter'] = 'YOU_MUST_CHANGE_THIS_VALUE';
				$buffer[] = $ns['name'] . "\t" . $ns['ttl'] .
					"\t" . "IN NS\t" . $ns['parameter'];
			}
			$buffer[] = "";
			$ignore = array('SOA', 'NS', 'TSIG');
			foreach (self::$permitted_records as $rr) {
				$rr = strtoupper($rr);
				if (in_array($rr, $ignore) || !isset($recs[$rr])) {
					continue;
				}
				$buffer[] = ";; " . $rr . " Records";
				foreach ($recs[$rr] as $r) {
					$buffer[] = $r['name'] . "\t" . $r['ttl'] .
						"\t" . "IN " . $rr . "\t" . $r['parameter'];
				}
				$buffer[] = "\n";
			}
			$format .= join("\n", $buffer);
			return $format;
		}

		/**
		 * Query hosting nameservers for DNS records of named category
		 *
		 * {@see get_zone_information()}
		 *
		 * example:
		 * Account has two MX records assigned, first the
		 * default MX on debug.com, and a second user-created MX on debug.debug.com.
		 * debug.debug.com was designated an e-mail domain through Mail Routing
		 * {@see Email_Module::add_virtual_transport()}
		 *
		 * apis> $c->dns_get_records_by_rr("MX");
		 *
		 * array(2)
		 *    apis>
		 *    array(2) {
		 *      [0]=>
		 *      array(4) {
		 *        ["name"]=>
		 *        string(10) "debug.com."
		 *        ["class"]=>
		 *        string(2) "IN"
		 *        ["ttl"]=>
		 *        string(5) "86400"
		 *        ["parameter"]=>
		 *        string(18) "10 mail.debug.com."
		 *      }
		 *      [1]=>
		 *      array(4) {
		 *        ["name"]=>
		 *        string(16) "debug.debug.com."
		 *        ["class"]=>
		 *        string(2) "IN"
		 *        ["ttl"]=>
		 *        string(5) "86400"
		 *        ["parameter"]=>
		 *        string(24) "10 mail.debug.debug.com."
		 *      }
		 *    }
		 *
		 * @param  string $rr resource record [MX, A, AAAA, CNAME, DNAME, TXT, SRV]
		 * @param  string $zone
		 * @return array resource records
		 *
		 */
		public function get_records_by_rr($rr, $zone = null)
		{
			if (is_null($zone))
				$zone = $this->domain;

			if (!$this->owned_zone($zone)) {
				if (!$this->owned_zone($rr)) {
					return error("access denied - cannot view zone `" . $zone . "'");
				}
				// confusing half-assed backwards
				// accept arguments in either form
				$t = $rr;
				$rr = $zone;
				$zone = $t;
			}

			$rr = strtolower($rr);
			if ($rr !== 'any' && !in_array($rr, self::$permitted_records))
				return error("`$rr' invalid resource record type");

			$recs = $this->get_zone_information($zone);
			if (!$recs) return array();
			if ($rr == 'any') {
				return $recs;
			}
			if (!isset($recs[strtoupper($rr)])) return array();

			return $recs[strtoupper($rr)];
		}

		/**
		 * Get DNS record(s)
		 *
		 * @param string $subdomain optional subdomain
		 * @param string $rr        optional RR type
		 * @param string $domain    optional domain
		 * @return array
		 */
		public function get_records($subdomain = '', $rr = 'any', $domain = null)
		{
			if (!$domain) {
				$domain = $this->domain;
			}
			if (!$this->owned_zone($domain)) {
				return error("cannot view DNS information for unaffiliated domain `" . $domain . "'");
			}
			$recs = $this->_get_records_raw($subdomain, $rr, $domain);
			if ($recs instanceof Exception) return error($recs->getMessage());
			return $recs;

		}

		/**
		 * get_records() unauthenticated DNS wrapper
		 *
		 * @param string $subdomain optional subdomain
		 * @param string $rr        optional RR type
		 * @param string $domain    optional domain
		 * @return array
		 */
		private function _get_records_raw($subdomain = '', $rr = 'any', $domain = null)
		{
			if ($subdomain == '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}
			$rr = strtolower($rr);
			if ($rr !== "any" && !in_array($rr, self::$permitted_records))
				return error("`$rr' invalid resource record type");
			$rr = strtoupper($rr);
			$recs = $this->_get_zone_information_raw($domain);
			// zone error, Transfer failed, i.e. zone not provisioned
			if (is_null($recs)) {
				return array();
			}
			$domain .= '.';
			if ($subdomain !== '') {
				$domain = $subdomain . '.' . $domain;
			}

			$newrecs = array();
			if ($rr == 'ANY') {
				$keys = array_keys($recs);
			} else if (!isset($recs[$rr])) {
				return $newrecs;
			} else {
				$keys = array($rr);

			}
			foreach ($keys as $tmp) {
				foreach ($recs[$tmp] as $rec) {
					$rec['rr'] = $tmp;
					if ($rec['name'] == $domain) {
						$newrecs[] = $rec;
					}
				}
			}
			return $newrecs;
		}

		/**
		 * Get DNS record(s) from a third-party nameserver
		 *
		 * When using same nameservers as hosting ns, ensure ns uses split-view
		 *
		 * @param  string $subdomain   optional subdomain
		 * @param  string $rr          optional RR type
		 * @param  string $domain      optional domain
		 * @param  array  $nameservers optional nameserver to query
		 * @return array
		 */
		public function get_records_external($subdomain = '', $rr = 'any', $domain = null, array $nameservers = null)
		{
			if (!$domain) {
				$domain = $this->domain;
			}
			$host = $domain;
			if ($subdomain) {
				$host = $subdomain . '.' . $host;
			}
			$rr = strtoupper($rr);
			$rrsym = $this->record2const($rr);
			if ($rrsym < 1) {
				return error("unknown rr record type `%s'", $rr);
			}
			if (!$nameservers) {
				$nameservers = self::EXTERNAL_NAMESERVER;
			}
			for ($i = 0; $i < 5; $i++) {
				$recraw = Error_Reporter::silence(function() use($host, $rrsym, $nameservers) {
					return dns_get_record($host, $rrsym, $nameservers);	
				});
				if ($recraw !== false) {
					break;
				}
				usleep(500000);
			}
			if ($recraw === false) {
				$host = ltrim(join(".", array($subdomain, $domain)),'.');
				return error("failed to get external raw records for `%s' on `%s'", $rr, $host);
			}

			$records = array();
			foreach ((array)$recraw as $r) {
				$target = null;

				// most records
				if (isset($r['target'])) {
					$target = $r['target'];
				}
				// A
				if (isset($r['ip'])) {
					$target = $r['ip'];
				}
				// SRV
				if (isset($r['weight'])) {
					// ignore PRI that comes before WEIGHT
					// it is handled next
					$target = $r['weight'] . ' ' . $target .
						$r['port'];
				}
				// MX, SRV
				if (isset($r['pri'])) {
					$target = $r['pri'] . ' ' . $target;
				}
				// TXT
				if (isset($r['txt'])) {
					$target = $r['txt'];
				}
				// HINFO
				if (isset($r['cpu'])) {
					$target = $r['cpu'] . ' ' . $r['os'];
				}
				// SOA
				if (isset($r['mname'])) {
					$target = $r['mname'] . ' ' . $r['rname'] . ' ' .
						$r['serial'] . ' ' . $r['refresh'] . ' ' .
						$r['retry'] . ' ' . $r['expire'] . ' ' .
						$r['minimum-ttl'];
				}
				// AAAA, A6
				if (isset($r['ipv6'])) {
					$target = $r['ipv6'];
				}
				// A6
				if (isset($r['masklen'])) {
					$target = $r['masklen'] . ' ' . $target . ' ' .
						$r['chain'];
				}
				// NAPTR
				if (isset($r['order'])) {
					$target = $r['order'] . ' ' . $r['pref'] . ' ' .
						$r['flags'] . ' ' . $r['services'] . ' ' .
						$r['regex'] . ' ' . $r['replacement'];
				}
				$records[] = array(
					"name"      => $host,
					'subdomain' => $subdomain,
					'domain'    => $domain,
					'class'     => 'IN',
					'type'      => $rr,
					'ttl'       => $r['ttl'],
					'parameter' => $target
				);
			}
			return $records;
		}

		/**
		 * Get authoritative nameservers for given hostname
		 *
		 * Example response:
		 *  Array
		 *   (
		 *   [0] => Array
		 *      (
		 *      [host] => ns2.apisnetworks.com
		 *      [type] => A
		 *      [ip] => 96.126.122.82
		 *      [class] => IN
		 *      [ttl] => 83137
		 *   )
		 * )
		 *
		 * @param string $host hostname
		 * @return array authoritative nameservers
		 */
		public function get_authns_from_host($host)
		{
			$nameservers = self::EXTERNAL_NAMESERVER;
			$authns = dns_get_record($host, $this->record2const('ns'), $nameservers);
			$tmp = array();
			foreach ($authns as $a) {
				if ($a['type'] == 'NS') {
					$tmp[] = $a['target'];
				}

			}
			return $tmp;
		}

		/**
		 * Returns the host name of the Internet host specified by $ip with timeout
		 *
		 * @param string $ip
		 * @param int    $timeout
		 * @return string
		 */
		public function gethostbyaddr_t($ip, $timeout = 1000)
		{
			return Net_Gethost::gethostbyaddr_t($ip, $timeout);
		}

		/**
		 * Returns the IP of the Internet host specified by $host with timeout
		 *
		 * @param string $name
		 * @param int    $timeout
		 * @return bool|null|string
		 */
		public function gethostbyname_t($name, $timeout = 1000)
		{
			return Net_Gethost::gethostbyname_t($name, $timeout);
		}

		/**
		 * bool remove_record (string, string)
		 * Removes a record from a zone.
		 *
		 * @param  string $zone      base domain
		 * @param  string $subdomain subdomain, leave blank for base domain
		 * @param  string $rr        resource record type, possible values:
		 *                           [MX, TXT, A, AAAA, NS, CNAME, DNAME, SRV]
		 * @param  string $param     record context
		 * @return bool operation completed successfully or not
		 *
		 */
		public function remove_record($zone, $subdomain, $rr, $param = null)
		{
			$subdomain = rtrim($subdomain, '.');
			if (!$zone) $zone = $this->domain;
			if (!$this->owned_zone($zone))
				return error($zone . ": not owned by account");
			$rr = strtolower($rr);
			if ($subdomain == '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}

			if (substr($subdomain, -strlen($zone)) == $zone) {
				$subdomain = substr($subdomain, 0, -strlen($zone));
			}
			if (!in_array($rr, self::$permitted_records))
				return error("`$rr' invalid resource record type");
			$record = rtrim($subdomain, ".");
			if ($record !== $zone) {
				$record = trim(preg_replace('/\.' . $zone . '$/', '', $record) . '.' . $zone, '.') . '.';
			}
			// only supply parameter if parameter is provided
			if ($rr == 'txt' && $param) {
				$param = '"' . join('" "', str_split(trim($param, '"'), 253)) . '"';
				if ($param[0] !== '"' && $param[strlen($param) - 1] !== '"') {
					$param = '"' . str_replace('"', '\\"', $param) . '"';
				}
			}

			$nsUpdateCmd = 'zone ' . $zone . ".\n" .
				'prereq yxrrset ' . $record . ' ' . $rr . "\n" .
				'update delete ' . $record . ' ' . $rr . (!is_null($param) ? (' ' . $param) : '');
			$status = self::__send($nsUpdateCmd);
			if (!$status['success']) {
				return self::__parse($status['stderr'], $subdomain, $subdomain, $nsUpdateCmd);
			}

			return true;
		}

		public function record_exists($zone, $subdomain, $rr = 'ANY', $parameter = null)
		{
			if ($subdomain == '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}

			$record = trim($subdomain . '.' . $zone, '.');
			$rr = strtoupper($rr);
			if ($this->record2const($rr) < 1) {
				return error("unknown RR class `%s'", $rr);
			}
			$status = Util_Process::exec('dig +time=1 +tcp +short @%s %s %s',
				self::INTERNAL_NAMESERVER,
				escapeshellarg($record),
				array_key_exists($rr, self::$rec_2_const) ? $rr : 'ANY'
			);
			// make sure there is some data in the response
			if (!$parameter)
				$parameter = '.';
			else
				$parameter = str_replace("'", "\\'", preg_quote($parameter));
			return preg_match("!" . $parameter . "!i", $status['output']);
		}

		/**
		 * Modify a DNS record
		 *
		 * @param string $zone
		 * @param string $subdomain
		 * @param string $rr
		 * @param string $parameter
		 * @param array  $newdata new zone data (name, rr, ttl, parameter)
		 * @return bool
		 */
		public function modify_record($zone, $subdomain, $rr, $parameter, array $newdata)
		{
			if (!$this->owned_zone($zone))
				return error($zone . ": not owned by account");

			if ($subdomain == '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}
			$rr = strtolower($rr);
			$newdata = array_merge(
				array('name'      => $subdomain,
				      'rr'        => $rr,
				      'ttl'       => null,
				      'parameter' => $parameter),
				$newdata);
			$newdata['rr'] = strtolower($newdata['rr']);
			if (!$newdata['name'] && $newdata['rr'] == 'cname') {
				return error("CNAME record cannot coexist with zone root, see RFC 1034 section 3.6.2");
			}
			if (!in_array($rr, self::$permitted_records)) {
				return error("`%s': invalid resource record type", $rr);
			} else if (!in_array($newdata['rr'], self::$permitted_records)) {
				return error("`%s': invalid resource record type", $newdata['rr']);
			}

			if (false !== (strpos($newdata['name'], " "))) {
				return error("DNS record `%s' may not contain spaces", $newdata['name']);
			}

			if ($subdomain !== $zone . ".")
				$subdomain = ltrim(preg_replace('/\.' . $zone . '$/', '', rtrim($subdomain, '.')) . '.' . $zone . '.', '.');

			if ($newdata['name'] !== $zone . '.')
				$newdata['name'] = ltrim(preg_replace('/\.' . $zone . '$/', '', rtrim($newdata['name'], '.')) . '.' . $zone . '.', '.');

			if ($newdata['rr'] == "mx" && preg_match('/(\S+) ([0-9]+)$/', $newdata['parameter'], $mx_flip)) {
				// user entered MX record in reverse, e.g. mail.apisnetworks.com 10
				$newdata['parameter'] = $mx_flip[2] . " " . $mx_flip[1];
			}
			if ($newdata['rr'] == 'txt') {
				$newdata['parameter'] = '"' . join('" "', str_split(trim($newdata['parameter'], '"'), 253)) . '"';
			}
			if ($rr == 'txt') {
				$parameter = '"' . join('" "', str_split(trim($parameter, '"'), 253)) . '"';
			}

			$rectmp = preg_replace('/\.?' . $zone . '\.?$/', '', $newdata['name']);

			if ($newdata['name'] !== $subdomain && $newdata['rr'] !== $rr &&
				$this->record_exists($zone, $rectmp, $newdata['rr'], $parameter)
			) {
				return error("Target record `" . $newdata['name'] . "' exists");
			}
			$nsUpdateCmd = 'zone ' . $zone . "\n" .
				'prereq yxrrset ' . $subdomain . ' ' . $rr . "\n" .
				'update delete ' . $subdomain . ' ' . $rr . " " . $parameter . "\n" .
				'update add ' . $newdata['name'] . ' ' . $newdata['ttl'] . " " . $newdata['rr'] . ' ' . $newdata['parameter'];

			$resp = self::__send($nsUpdateCmd);
			$parseresp = self::__parse(
				$resp['stderr'],
				$subdomain,
				$newdata['name'],
				$nsUpdateCmd
			);
			if (!$parseresp) {
				// nsUpdate failed, rollback records
				warn("record update failed");
				return ($subdomain == $newdata['name'] && $rr == $newdata['rr'] ||
					!$this->record_exists($zone, $subdomain, $rr, $parameter)) &&
				$this->record_exists($zone, $newdata['name'], $newdata['rr'], $newdata['parameter']);
			}
			return true;

		}


		/**
		 * Add a DNS record to a domain
		 *
		 * @param string $zone      zone name (normally domain name)
		 * @param string $subdomain name of the record to add
		 * @param string $rr        resource record type [MX, A, AAAA, CNAME, NS, TXT, DNAME]
		 * @param string $param     parameter value
		 * @param int    $ttl       TTL value, default value 86400
		 *
		 * @return bool
		 */
		public function add_record($zone, $subdomain, $rr, $param, $ttl = self::DNS_TTL)
		{
			if ((strcmp($zone, 'apisnetworks.com') && is_debug())) {
				//return info("not setting DNS record in development mode");
			}

			if (!$this->owned_zone($zone))
				return error($zone . " not owned by account");

			$rr = strtolower($rr);
			if ($subdomain === '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}

			if ($rr == "cname" && !$subdomain) {
				return error("CNAME record cannot coexist with zone root, see RFC 1034 section 3.6.2");
			} else if ($rr == "ns" && !$subdomain) {
				return error("Set nameserver records for zone root through domain registrar");
			}

			if (false !== ($pos = strpos($subdomain, " "))) {
				return error("hostname must not contain any spaces");
			}
			if (substr($subdomain, -strlen($zone)) == $zone)
				$subdomain = substr($subdomain, 0, -strlen($zone));
			if (!in_array($rr, self::$permitted_records))
				return error($rr . ": invalid resource record type");
			if ($subdomain !== $zone . ".")
				$subdomain = ltrim(preg_replace('/\.' . $zone . '$/', '', rtrim($subdomain, '.')) . '.' . $zone . '.', '.');
			if ($rr == "mx" && preg_match('/(\S+) ([0-9]+)$/', $param, $mx_flip)) {
				// user entered MX record in reverse, e.g. mail.apisnetworks.com 10
				$param = $mx_flip[2] . " " . $mx_flip[1];
			}
			if ($rr == "txt") {
				$param = '"' . join('" "', str_split(trim($param, '"'), 253)) . '"';
			}
			// zones are defined by hostname
			// each base host already has a NS and SOA record defined

			$nsUpdateCmd = 'zone ' . $zone . "\n";

			$nsUpdateCmd .= 'update add ' . $subdomain . ' ' . $ttl . ' ' . $rr . " " . $param;
			$status = self::__send($nsUpdateCmd);
			if (!$status['success']) {
				return self::__parse(
					$status['stderr'],
					$subdomain,
					$subdomain,
					$nsUpdateCmd
				);
			}
			return true;

		}


		/**
		 * Requested domain is manageable by the account
		 *
		 * @param  string $zone zone name
		 * @return bool
		 */
		private function owned_zone($zone)
		{
			if (is_debug() || (Auth::profile()->level & PRIVILEGE_ADMIN)) return true;
			$aliases = $this->aliases_list_aliases();
			return ($zone == $this->domain) || in_array($zone, $aliases);
		}

		/**
		 * Check whether a domain is hosted on any server
		 *
		 * @param string $domain
		 * @param bool   $ignore_on_account domains hosted on account ignored
		 * @return bool
		 */
		public function domain_hosted($domain, $ignore_on_account = false)
		{
			self::_connect_db();
			$ignore_on_account = (bool)$ignore_on_account;

			$domain = strtolower($domain);
			if (substr($domain, 0, 4) == "www.") {
				$domain = substr($domain, 4);
			}

			if ($ignore_on_account) {
				return !$this->domain_on_account($domain);
			}

			$q = "SELECT di_invoice, server_name, site_id FROM domain_information WHERE domain = ?";

			$stmt = self::$domain_db->prepare($q);

			$invoice = $server = $site_id = null;
			$stmt->bind_param("s", $domain);
			$stmt->bind_result($invoice, $server, $site_id);
			$stmt->execute();
			$stmt->store_result();
			$stmt->fetch();
			$hosted = $stmt->num_rows > 0;
			$stmt->close();
			if (!$hosted) return false;
			return $hosted;
		}

		public function domain_on_account($domain) {
			self::_connect_db();

			if (substr($domain, 0, 4) == "www.") {
				$domain = substr($domain, 4);
			}

			$q = "select IF(d.di_invoice != \"\", d.di_invoice,d2.di_invoice) AS invoice " .
					"FROM domain_information d LEFT JOIN domain_information d2 ON " .
					"d.parent_domain = d2.domain WHERE d.domain = ?";

			$stmt = self::$domain_db->prepare($q);

			$invoice = null;
			$stmt->bind_param("s", $domain);
			$stmt->bind_result($invoice);
			$stmt->execute();
			$stmt->store_result();
			$stmt->fetch();
			$hosted = $stmt->num_rows > 0;
			$stmt->close();
			return $hosted && $invoice == $this->get_config('billing','invoice');
		}

		/**
		 * Translate RR into PHP constant
		 *
		 * NB Used by DNS Manager
		 *
		 * @param string $rr
		 * @return int
		 */
		public static function record2const($rr)
		{
			$rr = strtoupper($rr);
			return isset(self::$rec_2_const[$rr]) ? self::$rec_2_const[$rr] : 0;
		}

		public function get_hosting_nameservers()
		{
			if (!isset(self::$nameservers)) {
				self::$nameservers = preg_split('/[,\s]+/', DNS_HOSTING_NS);
			}
			return self::$nameservers;
		}

		/**
		 * Lookup and compare nameservers for domain to host
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function domain_uses_nameservers($domain)
		{
			// IMPORTANT:
			// if the server trusts
			$dns = $this->get_records_external(null, 'ns', $domain);
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error("malformed domain `%s'", $domain);
			}
			$found = false;
			$ns = self::EXTERNAL_NAMESERVER;
			if (is_array($ns)) {
				$ns = array_pop($ns);
			}
			foreach ($dns as $r) {
				if (rtrim($r['parameter'], '.') == $ns) {
					$found = true;
					break;
				}
			}
			return $found;

		}

		/**
		 * Get recently expiring domains
		 *
		 * @param int  $days        lookahead n days
		 * @param bool $showExpired show domains expired within the last 10 days
		 *
		 * @return array
		 */
		public function get_pending_expirations($days = 30, $showExpired = true)
		{
			self::_connect_db();
			$db = self::$domain_db;
			$days = intval($days);
			if ($days > 365 || $days < 1) $days = 30;
			$server = substr(SERVER_NAME, 0, strpos(SERVER_NAME, '.'));
			$q = "SELECT domain, unix_timestamp(domain_expire) as expire " .
				"FROM domain_information WHERE " .
				"site_id = '" . $this->site_id . "' AND server_name = '" . $server . "' AND " .
				"domain_expire <= DATE_ADD(NOW(), INTERVAL " . $days . " DAY) AND domain_expire >= " .
				"DATE_SUB(NOW(), INTERVAL " . ($showExpired ? "10" : "0") . " DAY) ORDER BY domain_expire";

			$rs = $db->query($q);
			$domains = array();
			while (null !== ($row = $rs->fetch_object())) {
				$domains[] = array(
					'domain' => $row->domain,
					'ts'     => $row->expire
				);
			}
			return $domains;
		}

		/*
		 * Check zone for errors
		 *
		 * Additional DNS records are formatted as arguments
		 * to add_record()-
		 * check_zone("debug.com",["mail","a",86400,"127.0.0.1"])
		 *
		 * Hostname, RR, TTL, and parameter are required
		 *
		 * @param $zone zone - usually a domain
		 * @param $recs additional DNS records used in check
		 *
		 * @return bool
		 */
		public function check_zone($zone, array $recs = array())
		{
			$tmpfile = tempnam('/tmp', 'f');
			Util_Process::exec('dig +authority +multiline +noquestion +nostats +noadditional +nocmd  -t AXFR -y ' .
				'%s @%s %s > %s',
				escapeshellarg(self::$dns_key),
				self::INTERNAL_NAMESERVER,
				$zone,
				$tmpfile,
				array('mute_stderr' => true)
			);
			if ($recs) {
				$str = '';
				foreach ($recs as $rec) {
					$str .= $rec[0] . " " . $rec[1] . " " . $rec[2] . " " . $rec[3] . "\n";
				}
				file_put_contents($tmpfile, $str, FILE_APPEND);
			}
			$status = Util_Process::exec('/usr/sbin/named-checkzone ' . $zone . ' ' . $tmpfile);
			unlink($tmpfile);
			return $status['success'];
		}

		/**
		 * Update hostname with caller's IP address
		 *
		 * @param string $hostname fqdn
		 * @param string $ip       optional ip address to skip detection
		 * @return string ip address
		 */
		public function update($hostname, $ip = null)
		{
			$chunk = $this->web_split_host($hostname);
			$domain = $chunk['domain'];
			$subdomain = $chunk['subdomain'];
			if (!$this->owned_zone($domain)) {
				return error("restricted zone `%s' specified", $domain);
			}
			if (!$ip) {
				$ip = Auth::client_ip();
			}
			if (false === ip2long($ip)) {
				return error("cannot detect ip!");
			}
			$record = $this->get_records($subdomain, 'A', $domain);
			if (count($record) > 1) {
				warn("%d records found for `%s'", count($record), $hostname);
			}
			if (!$record) {
				// no record set
				warn("no DNS record exists, setting new record for `%s'", $hostname);
				$add = $this->add_record($domain, $subdomain, 'A', $ip, self::DYNDNS_TTL);
				if (!$add) return $add;
				return $ip;
			}

			$newparams = array('ttl' => self::DYNDNS_TTL, 'parameter' => $ip);
			$ret = true;
			foreach ($record as $r) {
				if (!$this->modify_record($domain, $subdomain, $r['rr'], $r['parameter'], $newparams)) {
					$ret = false;
					error("record modification failed for `%s'", $hostname);
				}
			}
			return $ret ? $ip : $ret;
		}

		/**
		 * Check whether IP is assigned
		 *
		 * Assigned IP addresses will have PTRs. Unassigned will be empty.
		 *
		 * @param $ip string ip address
		 * @return bool
		 */
		public function ip_allocated($ip)
		{
			return gethostbyaddr($ip) !== $ip;
		}

		/**
		 * Release IP into allocation pool
		 *
		 * @param $ip
		 * @return bool
		 */
		public function release_ip($ip)
		{
			return $this->__deleteIP($ip);
		}

		private static function __parse($resp, $orig, $new = '', $nsCMD = '')
		{
			if (!$resp) return true;
			if (strstr($resp, 'NXRRSET')) {
				return error("Non-existent DNS record `" . $orig . "'");
			} else if (strstr($resp, 'YXRRSET')) {
				return error("DNS record `" . $new . "' exists");
			} else if (strstr($resp, "NOTAUTH")) {
				return error("Non-authoritative response on zone `$orig'");
			} else if (strstr($resp, "REFUSED")) {
				return error("DNS server refused record `$orig'");
			} else if (strstr($resp, 'invalid rdata format: not a valid number')) {
				if (strstr($nsCMD, " mx ")) {
					return error("MX records must be of format {NUMERIC PRIORITY} {HOSTNAME}");
				} else {
					return error("SRV records must be of format {NUMERIC PRIORITY} {WEIGHT} {PORT} {TARGET}");
				}
			} else if (strstr($resp, ": unbalanced quotes")) {
				return error("missing opening or ending quotation (\") mark");
			} else if (strstr($resp, ": bad dotted quad")) {
				return error("DNS record must be of numeric format, e.g. 127.0.0.1");
			} else if (strstr($resp, ": timed out") && $nsCMD) {
				usleep(5000);
				return self::__send($nsCMD) || fatal("cannot connect to DNS server");
			}
			Error_Reporter::report("Unknown DNS resp - " . $resp);
			return error("DNS server refused record: `%s'", trim($resp));
		}

		public function _delete()
		{
			$conf = Auth::profile()->conf->cur;
			if (!$this->get_service_value('ipinfo', 'namebased')) {
				$ips = (array)$this->get_service_value('ipinfo', 'ipaddrs');
				// pass the domain to verify the PTR isn't detached incorrectly
				// from another domain that has recycled it
				$domain = $this->get_service_value('siteinfo', 'domain');
				foreach ($ips as $ip) {
					$this->__deleteIP($ip, $domain);
				}
			}

			foreach (array_keys($this->web_list_domains()) as $domain) {
				if ($this->owned_zone($domain))
					$this->remove_zone($domain);
				else
					dlog("Skipping stray zone $domain");
			}
		}

		public function _create()
		{
			$ipinfo = Auth::profile()->conf->cur['ipinfo'];
			$siteinfo = Auth::profile()->conf->cur['siteinfo'];
			$domain = $siteinfo['domain'];
			$ip = $ipinfo['namebased'] ? $ipinfo['nbaddrs'] : $ipinfo['ipaddrs'];
			$this->add_zone($domain, $ip[0]);
			if (!$ipinfo['namebased']) {
				$this->__addIP($ip[0], $siteinfo['domain']);
			}
		}

		public function _edit()
		{
			$conf_cur = Auth::profile()->conf->cur['ipinfo'];
			$conf_new = Auth::profile()->conf->new['ipinfo'];
			$domainold = Auth::profile()->conf->cur['siteinfo']['domain'];
			$domainnew = Auth::profile()->conf->new['siteinfo']['domain'];

			// changing to IP address, no IP address specified in commandline
			// this can't happen yet, because configuration requires an IP before
			// it can be committed (and therefore invoke editVirtDomain.sh)
			if ($conf_cur['namebased'] && !$conf_new['namebased'] && !$conf_new['ipaddrs']) {
				$ip = $this->_findFreePTR();
				$conf_new['ipaddrs'] = array($ip);
				info("allocated ip `%s'", $ip);
			}
			// domain name change via auth_change_domain()
			if ($domainold !== $domainnew) {
				$ip = $conf_new['namebased'] ? array_pop($conf_new['nbaddrs']) :
					array_pop($conf_new['ipaddrs']);
				$this->remove_zone($domainold);
				$this->add_zone($domainnew, $ip);
				// domain name changed
				if (!$conf_new['namebased']) {
					$this->__changePTR($ip, $domainnew, $domainold);
				}
			}

			if ($conf_new === $conf_cur) return;
			$ipadd = $ipdel = array();

			if ($conf_cur['namebased'] && !$conf_new['namebased']) {
				// enable ip hosting
				$ipadd = $conf_new['ipaddrs'];
			} else if (!$conf_cur['namebased'] && $conf_new['namebased']) {
				// disable ip hosting
				$ipdel = $conf_cur['ipaddrs'];
			} else {
				// add/remove ip hosting
				$ipdel = array_diff((array)$conf_cur['ipaddrs'], (array)$conf_new['ipaddrs']);
				$ipadd = array_diff((array)$conf_new['ipaddrs'], (array)$conf_cur['ipaddrs']);
			}

			$domain = Auth::profile()->conf->new['siteinfo']['domain'];
			foreach ($ipdel as $ip) {
				$this->__deleteIP($ip);
			}

			foreach ($ipadd as $ip) {
				$this->__addIP($ip, $domain);
			}

			$domains = array_keys($this->web_list_domains());
			if ($conf_cur['namebased'] && !$conf_new['namebased']) {
				// added ip-based hosting
				$ipdel = $conf_cur['nbaddrs'];
			} else if (!$conf_cur['namebased'] && $conf_new['namebased']) {
				// removed ip-based hosting
				$ipadd = $conf_new['nbaddrs'];
			}
			// change DNS
			// there will always be a 1:1 pairing for IP addresses
			foreach ($ipadd as $newip) {
				$oldip = array_pop($ipdel);
				$newparams = array('ttl' => self::DNS_TTL, 'parameter' => $newip);
				foreach ($domains as $domain) {
					$records = $this->get_records_by_rr('A', $domain);
					foreach ($records as $r) {
						if ($r['parameter'] !== $oldip) continue;
						if (!$this->dns_modify_record($r['domain'], $r['subdomain'], 'A', $oldip, $newparams)) {
							$frag = ltrim($r['subdomain'] . ' . ' . $r['domain'], '.');
							error("failed to modify record for `" . $frag . "'");
						} else {
							$pieces = array($r['subdomain'], $r['domain']);
							$host = trim(join(".", $pieces), ".");
							info("modified `%s'", $host);
						}
					}
				}
			}

			return;
		}

		/**
		 * @param        $ip
		 * @param string $domain confirm PTR rDNS matches domain
		 * @return bool
		 */
		private function __deleteIP($ip, $domain = '')
		{
			$rev = $this->__reverseIP($ip);
			$node = substr($rev, 0, strpos($rev, '.'));
			$fqdn = $rev . '.in-addr.arpa.';
			if ($domain) {
				$domain = ' ' . rtrim($domain) . '.';
			}
			$cmd = 'prereq yxrrset ' . $fqdn . ' PTR' . $domain . "\n" .
				'update delete ' . $fqdn . ' PTR';
			$resp = self::__send($cmd);
			if (!is_debug() && !$resp['success']) {
				error("cannot release $ip - " . $resp[1]);
				return false;

			}
			info("Released $ip");
			return true;
		}

		/**
		 * Change PTR name
		 *
		 * @param        $ip IP address to alter
		 * @param        $hostname new PTR name
		 * @param string $chk optional check hostname to verify
		 * @return bool
		 */
		private function __changePTR($ip, $hostname, $chk = '') {
			$rev = $this->__reverseIP($ip);
			$fqdn = $rev . '.in-addr.arpa.';

			if ($chk) {
				$chk = ' ' . rtrim($chk, '.') . '.';
			}
			$cmd = 'prereq yxrrset ' . $fqdn . ' PTR' . $chk . "\n";
				'update delete ' . $fqdn . ' ' . self::DNS_TTL . ' PTR ' . "\n" .
				'update add ' . $fqdn . ' ' . self::DNS_TTL . ' PTR ' . $hostname;

			$resp = self::__send($cmd);
			if (!is_debug() && !$resp['success']) {
				error("cannot change PTR for $ip - " . $resp[1]);
				report($cmd, var_export($resp, true));
				return false;
			}
			// update ARP tables
			return true;
		}

		private function __addIP($ip, $hostname = '')
		{
			$rev = $this->__reverseIP($ip);
			$fqdn = $rev . '.in-addr.arpa.';

			if (!$hostname) {
				$hostname = 'unresolved.apisnetworks.com.';
			} else {
				$hostname = rtrim($hostname, '.') . '.';
			}

			// no zone should be specificied
			$cmd = 'prereq nxrrset ' . $fqdn . ' PTR' . "\n" .
				'update add ' . $fqdn . ' ' . self::DNS_TTL . ' PTR ' . $hostname;
			$resp = self::__send($cmd);
			if (!is_debug() && !$resp['success']) {
				error("cannot add $ip - " . $resp[1]);
				report($cmd, var_export($resp, true));
				return false;
			}
			// update ARP tables
			$this->_announceIP($ip);
			info("Added $ip");
			return true;
		}

		public function remove_zone($domain)
		{
			if (is_debug()) {
				return info("not removing zone `%s' in debug", $domain);
			}
			$nsCmd = 'zone apnscp.' . "\n" .
				'class IN' . "\n" .
				'update add delete.apnscp. ' . self::DNS_TTL . ' TXT ' . $domain;
			$resp = self::__send($nsCmd);
			if (!$resp['success']) {
				warn("Could not remove $domain - " . $resp[1]);
				return true;
			}
			info("Removed domain $domain");
			return true;
		}

		public function add_zone($domain, $ip)
		{
			if (is_debug()) {
				return info("not creating DNS zone for `%s' in development mode", $domain);
			}
			$buffer = Error_Reporter::flush_buffer();
			$res = $this->_get_zone_information_raw($domain);

			if (!is_null($res)) {
				Error_Reporter::set_buffer($buffer);
				warn("DNS for zone `%s' already exists, not overwriting", $domain);
				return true;
			}
			// make sure DNS does not exist yet for the parent
			list($a, $b) = explode(".", $domain, 2);
			$res = $this->_get_zone_information_raw($b);
			Error_Reporter::set_buffer($buffer);
			if (!is_null($res)) {
				warn("DNS for zone `%s' already exists, not overwriting", $b);
				return true;
			}

			if (is_array($ip)) $ip = array_pop($ip);

			if (ip2long($ip) === false) {
				return error("`%s': invalid address", $ip);
			}

			// nameserver zone replication service port
			$port = 25500;
			$msg = $err = null;
			$socket = fsockopen(self::INTERNAL_NAMESERVER, $port, $err, $msg);
			if (!$socket) {
				Error_Reporter::report("failed to add domain `%s' with `%s': (%x) %s",
					$domain, $ip, $err, $msg);
			}
			$args = join("|", array($domain, $ip));
			$len = fwrite($socket, $args);
			fclose($socket);
			if ($len < 1) {
				return error("error sending domain `%s' to nameserver", $domain);
			}
			info("Added domain `%s'", $domain);

			$revZone = $this->__reverseIP($domain) . ".add.apnscp.";
			$nsCmd = 'zone apnscp.' . "\n" .
				'class IN' . "\n" .
				'update add add.apnscp. ' . self::DNS_TTL . ' TXT ' . $domain . "\n" .
				'prereq nxdomain ' . $revZone . "\n" .
				'update add ' . $revZone . ' ' . self::DNS_TTL . ' A ' . $ip;

			$resp = self::__send($nsCmd);
			if (!$resp['success']) {
				error("Could not add $domain - " . $resp[1]);
			}


			return true;
		}

		/**
		 * Import zone data for domain, overwriting configuration on server
		 *
		 * @param string      $domain
		 * @param string      $nameserver
		 * @param string|null $key
		 */
		public function import_zone($domain, $nameserver, $key = null)
		{
			$myip = Util_Conf::server_ip();
			$domain = strtolower($domain);
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error("invalid zone `%s' - not a domain name", $domain);
			} else if (!preg_match(Regex::DOMAIN, $nameserver)) {
				return error("invalid nameserver to query `%s'", $nameserver);
			} else if ($key && false === strpos($key, ':')) {
				return error("invalid dns key `%s', must be in format name:key", $key);
			}
			if ($key) {
				$key = '-y' . $key;
			}

			$cmd = 'dig %(key)s -b%(ip)s @%(nameserver)s %(zone)s +norecurse +nocmd +nonssearch +noadditional +nocomments +nostats AXFR ';
			$proc = Util_Process_Safe::exec($cmd, array(
				'key'        => $key,
				'ip'         => $myip,
				'zone'       => $domain,
				'nameserver' => $nameserver
			));
			$output = $proc['output'];
			if (!$proc['success'] || false !== strpos($output, "; Transfer failed")) {
				$output = $proc['stderr'] ? $proc['stderr'] : $proc['output'];
				return error("axfr failed: %s", $output);
			}
			// empty out old zone first
			$nrecs = 0;
			$zoneinfo = $this->get_zone_information($domain);
			if (false === $zoneinfo) {
				return error("unable to get old zone information - is this domain added to your account?");
			}
			foreach ($zoneinfo as $rr => $recs) {
				foreach ($recs as $rec) {
					$tmp = strtoupper($rr);
					// skip SOA + apex record
					if ($tmp === 'SOA' || $tmp === 'NS' && !$rec['subdomain']) {
						continue;
					}
					if (!$this->remove_record($domain, $rec['subdomain'], $rr, $rec['parameter'])) {
						warn("failed to purge record `%s` %s %s %s",
							$rec['name'],
							$rr,
							$rec['ttl'],
							$rec['parameter']
						);
						continue;
					}
					$nrecs++;
				}
			}
			info("purged %d old records", $nrecs);
			$nrecs = 0;
			$regex = Regex::compile(Regex::DNS_AXFR_REC_DOMAIN, str_replace(".", "\\.", $domain));
			foreach (explode("\n", $output) as $line) {

				if (strlen($line) < 1 || $line[0] == ';') continue;
				if (!preg_match($regex, $line, $rec)) continue;
				$tmp = strtoupper($rec['rr']);
				// skip SOA + apex record
				if ($tmp === 'SOA' || $tmp === 'NS' && !$rec['subdomain'] || $rec['class'] !== 'IN') {
					continue;
				}
				$subdomain = trim($rec['subdomain'], '.');
				if (!$this->add_record($domain, $subdomain, $rec['rr'], $rec['parameter'], $rec['ttl'])) {
					warn("failed to add record `%s` -> `%s` (RR: %s, TTL: %s)",
						$subdomain,
						$rec['parameter'],
						$rec['rr'],
						$rec['ttl']
					);
					continue;
				}
				$nrecs++;
			}

			info("imported %d records", $nrecs);
			return true;
		}

		private function __reverseIP($ip)
		{
			$ip = explode('.', $ip);
			return join('.', array_reverse($ip));
		}

		private static function __send($cmd)
		{
			$key = explode(':', self::$dns_key);
			$cmd = 'server ' . self::INTERNAL_NAMESERVER . "\n" .
				'key ' . $key[0] . ' ' . $key[1] . "\n" .
				$cmd . "\n" . 'send' . "\n";
			$file = tempnam('/tmp', 'dns');
			file_put_contents($file, $cmd, LOCK_EX);
			chmod($file, 0600);
			$status = Util_Process::exec("nsupdate " . $file, array('mute_stderr' => true));
			unlink($file);
			usleep(5000);
			return $status;
		}

		private function _findFreePTR()
		{

			$ipmask = Net_IPv4::parseAddress(self::IP_ALLOCATION_BLOCK);
			if (!$ipmask instanceof Net_IPv4) {
				fatal("cannot allocate IP address, invalid allocation block");
			}
			$min = ip2long($ipmask->ip) + 1;
			$max = ip2long($ipmask->broadcast);
			for ($i = $min; $i < $max; $i++) {
				$ip = long2ip($i);
				if (!$this->ip_allocated($ip)) {
					return $ip;
				}
			}
			fatal("cannot find free ip address!");
		}

		private function _announceIP($ip)
		{
			$iface = $this->_getInterface();
			$proc = new Util_Process_Schedule('+2 minutes');
			$newpath = join(PATH_SEPARATOR, array('/sbin', getenv('PATH')));
			$proc->setEnvironment('PATH', $newpath);
			$ret = $proc->run(
				'arping -U -I %s -c 1 %s',
				$iface,
				$ip
			);
			return $ret['success'];
		}

		private function _getInterface()
		{
			// default in case file is missing
			$iface = 'eth0';
			if (!file_exists(self::NAMEBASED_INTERFACE_FILE)) {
				warn("missing interface file `%s', assuming main iface is `%s'",
					self::NAMEBASED_INTERFACE_FILE, $iface);
				return $iface;
			}
			$iface = file_get_contents(self::NAMEBASED_INTERFACE_FILE);
			return trim($iface);
		}
	}

?>
