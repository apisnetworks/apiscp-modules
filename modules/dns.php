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
	 * Provides DNS functions to apnscp.
	 *
	 * @package core
	 */
	class Dns_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable, \Module\Skeleton\Contracts\Proxied
	{
		/** primary nameserver */
		const MASTER_NAMESERVER = DNS_INTERNAL_MASTER;
		const AUTHORITATIVE_NAMESERVER = DNS_AUTHORITATIVE_NS;
		const RECURSIVE_NAMESERVER = DNS_RECURSIVE_NS;

		const DYNDNS_TTL = 300;
		// default DNS TTL for records modified via update()
		const DNS_TTL = 43200;
		// default DNS TTL for records
		const IP_ALLOCATION_BLOCK = DNS_ALLOCATION_CIDR;
		// netmask of allowable IP addresses
		const HOSTS_FILE = '/etc/hosts';
		// standard hosts file location
		/**
		 * @var string TSIG key
		 * @ignore
		 */
		protected static $dns_key = DNS_TSIG_KEY;
		/** mapping of RR types to constants */
		protected static $rec_2_const = array(
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
			'NAPTR' => DNS_NAPTR,
			'CAA'   => DNS_CAA,
		);
		/** array of 1 or more nameservers used */
		protected static $nameservers;

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
		protected static $permitted_records = array(
			'a',
			'aaaa',
			'mx',
			'cname',
			'dname',
			'hinfo',
			'txt',
			'ns',
			'srv',
			'a6',
			'naptr',
			'any',
			'soa',
			'caa'
		);

		/**
		 * {{{ void __construct(void)
		 */
		public function __construct()
		{
			parent::__construct();

			$this->exportedFunctions = array(
				'*'                      => PRIVILEGE_SITE,
				'configured'             => PRIVILEGE_ALL,
				'get_whois_record'       => PRIVILEGE_ALL,
				'get_records_by_rr'      => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'get_records'            => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'record_exists'          => PRIVILEGE_ALL,
				'remove_zone_backend'    => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'get_all_domains'        => PRIVILEGE_ADMIN,
				'get_parent_domain'      => PRIVILEGE_ADMIN,
				'remove_zone'            => PRIVILEGE_ADMIN,
				'get_server_from_domain' => PRIVILEGE_ADMIN,
				'release_ip'             => PRIVILEGE_ADMIN,
				'ip_allocated'           => PRIVILEGE_ADMIN,
				'add_zone'               => PRIVILEGE_ADMIN,
				'add_zone_backend'       => PRIVILEGE_ADMIN|PRIVILEGE_SITE|PRIVILEGE_SERVER_EXEC,
				'gethostbyaddr_t'        => PRIVILEGE_ALL,
				'gethostbyname_t'        => PRIVILEGE_ALL,
				'get_provider'           => PRIVILEGE_ALL
			);
		}

		public function _proxy(): \Module_Skeleton
		{
			$provider = $this->get_provider();
			if ($provider === 'builtin') {
				return $this;
			}
			return \Module\Provider::get('dns', $provider, $this->getAuthContext());
		}

		/**
		 * Get DNS provider
		 *
		 * @return string
		 */
		public function get_provider(): string
		{
			return $this->get_service_value('dns', 'provider', 'builtin');
		}

		/**
		 * Query database for domain expiration
		 *
		 * On multi-server lookups that perform DNS lookups independent,
		 * perform batch lookups and pull those records from the database
		 *
		 * A return of 0 indicates failure
		 * null indicates unknown expiration
		 *
		 * @param string $domain domain owned by the account
		 * @return int expiration as unix timestamp
		 */
		public function domain_expiration($domain)
		{
			return null;
		}

		/**
		 * Fetches all domains across all servers
		 *
		 * @return array
		 */
		public function get_all_domains()
		{
			return [];
		}

		/**
		 * Get server on which a domain is hosted
		 *
		 * @param string $domain
		 * @param bool   $all show all server matches, $all = true: array of all servers, else server
		 * @return string|array
		 */
		public function get_server_from_domain($domain, $all = false)
		{
			return SERVER_NAME_SHORT;
		}

		/**
		 * Get primary domain affiliated with account
		 *
		 * In multi-server setups query the master DB to find
		 * domains whose invoice matches the parent invoice or domains
		 * that share the same site ID
		 *
		 * @param string $domain
		 * @return string
		 */
		public function get_parent_domain($domain)
		{
			return null;
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
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error($domain . ": invalid domain");
			}
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
		 * Export zone configuration in BIND-friendly notation
		 *
		 * @param string|null $zone
		 * @return bool|string|void
		 */
		public function export($zone = null)
		{
			if (is_null($zone)) {
				$zone = $this->domain;
			}

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
			foreach (static::$permitted_records as $rr) {
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
		 * Requested domain is manageable by the account
		 *
		 * @param  string $zone zone name
		 * @return bool
		 */
		protected function owned_zone(string $zone): bool
		{
			if (is_debug()) {
				return true;
			}
			if ($this->getAuthContext()->level & PRIVILEGE_ADMIN) {
				return true;
			}
			$aliases = $this->aliases_list_aliases();
			return ($zone === $this->domain) || in_array($zone, $aliases);
		}

		/**
		 * Unauthenticated call for get_zone_information
		 *
		 * @param string $domain
		 * @return array|null
		 */
		protected function _get_zone_information_raw($domain): ?array
		{
			if (null === ($data = $this->_get_zone_information_raw_raw($domain))) {
				return [];
			}

			$zoneData = array();
			$offset = strlen($domain) + 1; // domain.com.
			foreach (explode("\n", $data) as $line) {
				if (false !== strpos($line, 'Transfer failed.')) {
					return null;
				}
				if (!preg_match(Regex::DNS_AXFR_REC, $line, $match)) {
					continue;
				}
				list ($name, $ttl, $class, $rr, $parameter) = array_slice($match, 1);
				$rr = strtoupper($rr);
				// TXT records should always be balanced with quotes
				// assume this to be the case if " present
				// don't pretty-print if more than 1 quote pair present
				if ($rr == 'TXT' && $parameter[0] == '"') {
					if (strpos($parameter, '"', 1) === strlen($parameter) - 1) {
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
			return $zoneData;
		}

		protected function _get_zone_information_raw_raw($domain): ?string
		{
			if (!static::MASTER_NAMESERVER) {
				error("Cannot fetch zone information for `%s': no master nameserver configured in config.ini",
					$domain);
				return null;
			}
			$data = Util_Process::exec("dig -t AXFR -y '%s' @%s %s",
				self::$dns_key, static::MASTER_NAMESERVER, $domain);
			return $data['success'] ? $data['output'] : null;
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
				$nameservers = array(static::RECURSIVE_NAMESERVER);
			}
			for ($i = 0; $i < 5; $i++) {
				$recraw = Error_Reporter::silence(function () use ($host, $rrsym, $nameservers) {
					return dns_get_record($host, $rrsym, $nameservers);
				});
				if ($recraw !== false) {
					break;
				}
				usleep(500000);
			}
			if ($recraw === false) {
				$host = ltrim(join(".", array($subdomain, $domain)), '.');
				warn("failed to get external raw records for `%s' on `%s'", $rr, $host);
				return [];
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
			return isset(static::$rec_2_const[$rr]) ? static::$rec_2_const[$rr] : 0;
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
		 * Check whether a domain is hosted on any server
		 *
		 * In multi-server setups, use an aggregate database to log
		 * all domains across all servers and query that DB rather than
		 * domainmap
		 *
		 * @param string $domain
		 * @param bool   $ignore_on_account domains hosted on account ignored
		 * @return bool
		 */
		public function domain_hosted($domain, $ignore_on_account = false)
		{
			$domain = strtolower($domain);
			if (substr($domain, 0, 4) == "www.") {
				$domain = substr($domain, 4);
			}
			$ignore_on_account = (bool)$ignore_on_account;
			$site_id = \Auth::get_site_id_from_domain($domain);
			if ($ignore_on_account) {
				return $site_id && $site_id != $this->site_id;
			}
			return (bool)$site_id;
		}

		/**
		 * Domain exists and is under the account on a multi-server instance
		 *
		 * Useful when doing cross-server transfers to ensure the domain to add
		 * is part of the account, which will allow the domain to be added via
		 * the aliases_add_shared_domain @{see Aliases_Module::add_shared_domain}
		 *
		 * Implementation details are available on github.com/apisnetworks/apnscp-modules
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function domain_on_account($domain)
		{

			return true;
		}

		/**
		 * Lookup and compare nameservers for domain to host
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function domain_uses_nameservers($domain)
		{
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error("malformed domain `%s'", $domain);
			}
			$hostingns = $this->get_hosting_nameservers();
			if (!$hostingns) {
				// not configured under [dns] hosting_ns in config.ini
				return true;
			}
			$dns = mute(function () use ($domain) {
				return static::get_authns_from_host($domain);
			});
			$found = false;
			if (!$dns) {
				return $found;
			}
			foreach ($dns as $ns) {
				if (in_array($ns, $hostingns)) {
					return true;
				}
			}
			return false;
		}

		/**
		 * Get configured hosting nameservers
		 *
		 * Toggled via config.ini > [dns] > hosting_ns
		 *
		 * @return mixed
		 */
		public function get_hosting_nameservers()
		{
			if (null === static::$nameservers) {
				static::$nameservers = preg_split('/[,\s]+/', DNS_HOSTING_NS, -1, PREG_SPLIT_NO_EMPTY);
			}
			return static::$nameservers;
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
		 * @return array|null authoritative nameservers or resolver chain incomplete
		 */
		public function get_authns_from_host($host): ?array
		{
			$nameservers = [static::RECURSIVE_NAMESERVER];
			$authns = silence(function () use ($host, $nameservers) {
				return dns_get_record($host, static::record2const('ns'), $nameservers);
			});
			if ($authns) {
				// domain is properly delegated, nameserver returns affirmative
				$tmp = array();
				foreach ($authns as $a) {
					if ($a['type'] == 'NS') {
						$tmp[] = $a['target'];
					}
				}
				return $tmp;
			}

			// domain delegated to hosting nameservers, but hosting servers don't
			// have dns provisioned yet for domain
			//
			// crawl
			$resolver = new Net_DNS2_Resolver([
				'nameservers' => $nameservers,
				'recurse'     => true
			]);
			try {
				$nameservers = $this->get_authns_from_host_recursive($host, $resolver);
			} catch (Net_DNS2_Exception $e) {
				warn("NS lookup failed for `%s': %s", $host, $e->getMessage());
				return array();
			}
			return $nameservers;
		}

		/**
		 * Fallback authoritative NS lookup
		 *
		 * Crawl the entire TLD hierarchy to find the last known nameserver
		 *
		 * @param string            $host
		 * @param Net_DNS2_Resolver $resolver
		 * @param string            $seen
		 * @return array|null nameservers or null if resolve failed before reaching end
		 */
		protected function get_authns_from_host_recursive($host, Net_DNS2_Resolver $resolver, $seen = '')
		{
			$components = explode(".", $host);
			$nameservers = null;
			try {
				$lookup = array_pop($components) . '.' . $seen;
				$res = $resolver->query($lookup, 'NS');
				if ($res->answer) {
					$nameservers = array_filter(array_map(function ($arr) {
						return gethostbyname($arr->nsdname);
					}, $res->answer));
					$resolver->setServers($nameservers);
				}
			} catch (Net_DNS2_Exception $e) {
				if ($components) {
					// resolver chain broken
					warn("failed to recurse on `%s': %s", $lookup, $e->getMessage());
				}
				return null;
			}
			if (!$components) {
				return array_map(function ($a) {
					return $a->nsdname;
				}, $res->authority);
			}
			$resolver->recurse = 0;
			return $this->get_authns_from_host_recursive(join(".", $components), $resolver, $lookup);

		}

		/**
		 * Get recently expiring domains
		 *
		 * Sample response:
		 * Array(
		 *  [0] => Array(
		 *      'domain' => 'apnscp.com',
		 *      'ts' => 1469937612
		 *  )
		 * )
		 *
		 * @param int  $days        lookahead n days
		 * @param bool $showExpired show domains expired within the last 10 days
		 *
		 * @return array
		 */
		public function get_pending_expirations($days = 30, $showExpired = true)
		{
			return [];
		}

		public function check_zone($zone, array $recs = array())
		{
			$tmpfile = tempnam('/tmp', 'f');
			Util_Process::exec('dig +authority +multiline +noquestion +nostats +noadditional +nocmd  -t AXFR -y ' .
				'%s @%s %s > %s',
				escapeshellarg(self::$dns_key),
				static::AUTHORITATIVE_NAMESERVER,
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
		 * Update hostname with caller's IP4 address
		 *
		 * @param string $hostname fqdn
		 * @param string $ip       optional ip address to skip detection
		 * @return string|bool ip address
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
				$add = $this->add_record($domain, $subdomain, 'A', $ip, static::DYNDNS_TTL);
				if (!$add) {
					return $add;
				}
				return $ip;
			}

			$newparams = array('ttl' => static::DYNDNS_TTL, 'parameter' => $ip);
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
			return (array)$recs;

		}

		/**
		 * get_records() unauthenticated DNS wrapper
		 *
		 * @param string $subdomain optional subdomain
		 * @param string $rr        optional RR type
		 * @param string $domain    optional domain
		 * @return array
		 */
		protected function _get_records_raw($subdomain = '', $rr = 'any', $domain = null)
		{
			if ($subdomain == '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}
			$rr = strtolower($rr);
			if ($rr !== "any" && !in_array($rr, static::$permitted_records)) {
				return error("`$rr' invalid resource record type");
			}
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
			} else {
				if (!isset($recs[$rr])) {
					return $newrecs;
				} else {
					$keys = array($rr);

				}
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
			if (!$this->owned_zone($zone)) {
				return error($zone . " not owned by account");
			}

			$rr = strtolower($rr);
			if ($subdomain === '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}

			if ($rr == "cname" && !$subdomain) {
				return error("CNAME record cannot coexist with zone root, see RFC 1034 section 3.6.2");
			} else {
				if ($rr == "ns" && !$subdomain) {
					return error("Set nameserver records for zone root through domain registrar");
				}
			}

			if (false !== ($pos = strpos($subdomain, " "))) {
				return error("hostname must not contain any spaces");
			}
			if (substr($subdomain, -strlen($zone)) == $zone) {
				$subdomain = substr($subdomain, 0, -strlen($zone));
			}
			if (!in_array($rr, static::$permitted_records)) {
				return error($rr . ": invalid resource record type");
			}
			if ($subdomain !== $zone . ".") {
				$subdomain = ltrim(preg_replace('/\.' . $zone . '$/', '', rtrim($subdomain, '.')) . '.' . $zone . '.',
					'.');
			}
			if ($rr == "mx" && preg_match('/(\S+) ([0-9]+)$/', $param, $mx_flip)) {
				// user entered MX record in reverse, e.g. mail.apisnetworks.com 10
				$param = $mx_flip[2] . " " . $mx_flip[1];
			}
			if ($rr == "txt") {
				$param = '"' . join('" "', str_split(trim($param, '"'), 253)) . '"';
			}
			// zones are defined by hostname
			// each base host already has a NS and SOA record defined

			/**
			 * Implement your own!
			 */
			return true;

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
			if (!$this->owned_zone($zone)) {
				return error($zone . ": not owned by account");
			}

			if ($subdomain == '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}
			$rr = strtolower($rr);
			$newdata = array_merge(
				array(
					'name'      => $subdomain,
					'rr'        => $rr,
					'ttl'       => null,
					'parameter' => $parameter
				),
				$newdata);
			$newdata['rr'] = strtolower($newdata['rr']);
			if (!$newdata['name'] && $newdata['rr'] == 'cname') {
				return error("CNAME record cannot coexist with zone root, see RFC 1034 section 3.6.2");
			}
			if (!in_array($rr, static::$permitted_records)) {
				return error("`%s': invalid resource record type", $rr);
			} else {
				if (!in_array($newdata['rr'], static::$permitted_records)) {
					return error("`%s': invalid resource record type", $newdata['rr']);
				}
			}

			if (false !== (strpos($newdata['name'], " "))) {
				return error("DNS record `%s' may not contain spaces", $newdata['name']);
			}

			if ($subdomain !== $zone . ".") {
				$subdomain = ltrim(preg_replace('/\.' . $zone . '$/', '', rtrim($subdomain, '.')) . '.' . $zone . '.',
					'.');
			}

			if ($newdata['name'] !== $zone . '.') {
				$newdata['name'] = ltrim(preg_replace('/\.' . $zone . '$/', '',
						rtrim($newdata['name'], '.')) . '.' . $zone . '.', '.');
			}

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
			$resp = true;
			/**
			 * Implement your own!
			 */
			if (!$resp) {
				// nsUpdate failed, rollback records
				warn("record update failed");
				return ($subdomain == $newdata['name'] && $rr == $newdata['rr'] ||
						!$this->record_exists($zone, $subdomain, $rr, $parameter)) &&
					$this->record_exists($zone, $newdata['name'], $newdata['rr'], $newdata['parameter']);
			}
			return true;

		}

		public function record_exists($zone, $subdomain, $rr = 'ANY', $parameter = null)
		{
			if (!static::AUTHORITATIVE_NAMESERVER) {
				warn("no authoritative nameserver configured - can't verify record `%s'",
					ltrim($subdomain . '.' . $zone, ".")
				);
				return true;
			}
			if ($subdomain == '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}

			$record = trim($subdomain . '.' . $zone, '.');
			$rr = strtoupper($rr);
			if ($this->record2const($rr) < 1) {
				return error("unknown RR class `%s'", $rr);
			}
			$status = Util_Process::exec('dig +time=3 +tcp +short @%s %s %s',
				static::AUTHORITATIVE_NAMESERVER,
				escapeshellarg($record),
				array_key_exists($rr, static::$rec_2_const) ? $rr : 'ANY'
			);
			// make sure there is some data in the response
			if (!$parameter) {
				$parameter = '.';
			} else {
				$parameter = str_replace("'", "\\'", preg_quote($parameter, '!'));
			}
			return preg_match("!" . $parameter . "!i", $status['output']);
		}

		/**
		 * Release IP into allocation pool
		 *
		 * @param $ip     IP address to release
		 * @param $domain additional truthiness check before releasing IP
		 * @return bool
		 */
		public function release_ip($ip, $domain = null)
		{
			deprecated_func('use ipinfo_release_ip()');
			return $this->ipinfo_release_ip($ip, $domain);
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

		/**
		 * Release PTR assignment from an IP
		 *
		 * @param        $ip
		 * @param string $domain confirm PTR rDNS matches domain
		 * @return bool
		 */
		protected function __deleteIP($ip, $domain = null)
		{
			return true;
		}

		public function _delete()
		{
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
				if ($this->owned_zone($domain)) {
					$this->remove_zone($domain);
				} else {
					dlog("Skipping stray zone $domain");
				}
			}
		}

		/**
		 * Remove a zone from DNS management
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function remove_zone($domain)
		{
			if (is_debug()) {
				return info("not removing zone `%s' in debug", $domain);
			}
			return true;
		}

		public function _create()
		{
			$ipinfo = $this->getAuthContext()->conf('ipinfo');
			$siteinfo = $this->getAuthContext()->conf('siteinfo');
			$domain = $siteinfo['domain'];
			$ip = $ipinfo['namebased'] ? $ipinfo['nbaddrs'] : $ipinfo['ipaddrs'];
			$this->add_zone($domain, $ip[0]);
			if (!$ipinfo['namebased']) {
				$this->__addIP($ip[0], $siteinfo['domain']);
			}
		}

		/**
		 * @param string $domain
		 * @param string $ip
		 * @return bool|void
		 */
		public function add_zone($domain, $ip)
		{
			if (!$this->configured()) {
				return warn("cannot create DNS zone for `%s' - DNS is not configured for account", $domain);
			}
			return $this->query('dns_add_zone_backend', $domain, $ip);
		}

		/**
		 * Create DNS zone privileged mode
		 *
		 * @param string $domain
		 * @param string $ip
		 * @return bool
		 */
		public function add_zone_backend(string $domain, string $ip): bool {
			if (is_debug()) {
				return info("not creating DNS zone for `%s' in development mode", $domain);
			} else if (!static::MASTER_NAMESERVER) {
				return error("rndc not configured in config.ini. Cannot add zone `%s'", $domain);
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

			if (is_array($ip)) {
				$ip = array_pop($ip);
			}

			if (inet_pton($ip) === false) {
				return error("`%s': invalid address", $ip);
			}

			info("Added domain `%s'", $domain);

			/**
			 * Now actually add the domain...
			 */
			return true;
		}

		/**
		 * Add an IP address to hosting
		 *
		 * @param string $ip
		 * @param string $hostname
		 * @return bool
		 */
		protected function __addIP($ip, $hostname = '')
		{
			return true;
		}

		public function _edit()
		{
			$conf_old = $this->getAuthContext()->conf('ipinfo', 'old');
			$conf_new = $this->getAuthContext()->conf('ipinfo', 'new');
			$domainold = \array_get($this->getAuthContext()->conf('siteinfo', 'old'), 'domain');
			$domainnew = \array_get($this->getAuthContext()->conf('siteinfo', 'new'), 'domain');

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

			if ($conf_new === $conf_old) {
				return;
			}
			$ipadd = $ipdel = array();

			if ($conf_old['namebased'] && !$conf_new['namebased']) {
				// enable ip hosting
				$ipadd = $conf_new['ipaddrs'];
			} else if (!$conf_old['namebased'] && $conf_new['namebased']) {
				// disable ip hosting
				$ipdel = $conf_old['ipaddrs'];
			} else {
				// add/remove ip hosting
				$ipdel = array_diff((array)$conf_old['ipaddrs'], (array)$conf_new['ipaddrs']);
				$ipadd = array_diff((array)$conf_new['ipaddrs'], (array)$conf_old['ipaddrs']);
			}

			foreach ($ipdel as $ip) {
				// NB __changePTR is called before to update domain on change
				$this->__deleteIP($ip, $domainnew);
			}

			foreach ($ipadd as $ip) {
				$this->__addIP($ip, $domainnew);
			}

			$domains = array_keys($this->web_list_domains());
			if ($conf_old['namebased'] && !$conf_new['namebased']) {
				// added ip-based hosting
				$ipdel = $conf_old['nbaddrs'];
			} else {
				if (!$conf_old['namebased'] && $conf_new['namebased']) {
					// removed ip-based hosting
					$ipadd = $conf_new['nbaddrs'];
				}
			}
			// change DNS
			// there will always be a 1:1 pairing for IP addresses
			foreach ($ipadd as $newip) {
				$oldip = array_pop($ipdel);
				$newparams = array('ttl' => static::DNS_TTL, 'parameter' => $newip);
				foreach ($domains as $domain) {
					$records = $this->get_records_by_rr('A', $domain);
					foreach ($records as $r) {
						if ($r['parameter'] !== $oldip) {
							continue;
						}
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
		 * Check whether IP is assigned
		 *
		 * Assigned IP addresses will have PTRs. Unassigned will be empty.
		 *
		 * @param $ip string ip address
		 * @return bool
		 */
		public function ip_allocated($ip)
		{
			return \Opcenter\Net\Common::ip_allocated($ip);
		}

		/**
		 * Change PTR name
		 *
		 * @param        $ip       IP address to alter
		 * @param        $hostname new PTR name
		 * @param string $chk      optional check hostname to verify
		 * @return bool
		 */
		protected function __changePTR($ip, $hostname, $chk = '')
		{
			return true;
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
		 * @return array|null resource records
		 *
		 */
		public function get_records_by_rr(string $rr, string $zone = null): ?array
		{
			if (is_null($zone)) {
				$zone = $this->domain;
			}

			if (!$this->owned_zone($zone)) {
				if (!$this->owned_zone($rr)) {
					error("access denied - cannot view zone `" . $zone . "'");
					return null;
				}
				// confusing half-assed backwards
				// accept arguments in either form
				$t = $rr;
				$rr = $zone;
				$zone = $t;
			}

			$rr = strtolower($rr);
			if ($rr !== 'any' && !in_array($rr, static::$permitted_records)) {
				error("`$rr' invalid resource record type");
				return null;
			}

			$recs = $this->get_zone_information($zone);
			if (!$recs) {
				return array();
			}
			if ($rr == 'any') {
				return $recs;
			}
			if (!isset($recs[strtoupper($rr)])) {
				return array();
			}

			return $recs[strtoupper($rr)];
		}

		/**
		 * array get_zone_information (string)
		 *
		 * Reads zone information for a given domain on the nameservers.
		 *
		 * @param string|null $domain domain or current domain to check
		 * @return array
		 */
		public function get_zone_information($domain = null): ?array
		{
			if (is_null($domain)) {
				$domain = $this->domain;
			}

			if (!$this->permission_level & (PRIVILEGE_ADMIN) && !$this->owned_zone($domain)) {
				error("access denied - cannot view zone `" . $domain . "'");
				return null;
			}
			$rec = $this->_get_zone_information_raw($domain);
			if (is_null($rec)) {
				error("Non-authorative for zone " . $domain);
				return null;
			}
			return $rec;

		}

		/**
		 * Import zone data for domain, overwriting configuration on server
		 *
		 * @param string      $domain
		 * @param string      $nameserver
		 * @param string|null $key
		 * @return bool
		 */
		public function import_zone($domain, $nameserver, $key = null)
		{
			$myip = Util_Conf::server_ip();
			$domain = strtolower($domain);
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error("invalid zone `%s' - not a domain name", $domain);
			} else {
				if (!preg_match(Regex::DOMAIN, $nameserver)) {
					return error("invalid nameserver to query `%s'", $nameserver);
				} else {
					if ($key && false === strpos($key, ':')) {
						return error("invalid dns key `%s', must be in format name:key", $key);
					}
				}
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

				if ('' === $line || $line[0] == ';') {
					continue;
				}
				if (!preg_match($regex, $line, $rec)) {
					continue;
				}
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
			if (!$zone) {
				$zone = $this->domain;
			}
			if (!$this->owned_zone($zone)) {
				return error($zone . ": not owned by account");
			}
			$rr = strtolower($rr);
			if ($subdomain == '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}

			if (substr($subdomain, -strlen($zone)) == $zone) {
				$subdomain = substr($subdomain, 0, -strlen($zone));
			}
			if (!in_array($rr, static::$permitted_records)) {
				return error("`$rr' invalid resource record type");
			}
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

			/**
			 * Now purge the record
			 */

			return true;
		}

		/**
		 * Reverse an IP address
		 */
		protected function __reverseIP($ip)
		{
			$ip = explode('.', $ip);
			return join('.', array_reverse($ip));
		}

		public function configured(): bool
		{
			return \get_class($this) !== self::class;
		}
		/**
		 * Get interface names to use with hosting
		 *
		 * @return bool|string
		 */
		protected function _getInterface()
		{
			return \Opcenter\Net\Iface::interfaces();
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}

		public function _create_user(string $user)
		{
			return;
		}

		public function _delete_user(string $user)
		{
			return;
		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			return;
		}

	}