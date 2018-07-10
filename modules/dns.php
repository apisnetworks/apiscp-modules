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
	class Dns_Module extends Module_Support_Dns
	{
		/**
		 * apex markers are marked with @
		 */
		protected const HAS_ORIGIN_MARKER = false;
		/** primary nameserver */
		const MASTER_NAMESERVER = DNS_INTERNAL_MASTER;
		const AUTHORITATIVE_NAMESERVER = DNS_AUTHORITATIVE_NS;
		const RECURSIVE_NAMESERVER = DNS_RECURSIVE_NS;
		const UUID_RECORD = '_apnscp_uuid';

		const DYNDNS_TTL = 300;
		// default DNS TTL for records modified via update()
		// @var int DNS_TTL default DNS TTL
		const DNS_TTL = DNS_DEFAULT_TTL;
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
		 * Legal DNS resource records permitted by provider
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
			'A', 'AAAA', 'MX', 'CNAME', 'DNAME', 'HINFO',
			'TXT', 'NS', 'SRV', 'A6', 'NAPTR', 'ANY', 'SOA', 'CAA'
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
				'get_all_domains'        => PRIVILEGE_ADMIN,
				'get_parent_domain'      => PRIVILEGE_ADMIN,
				'get_server_from_domain' => PRIVILEGE_ADMIN,
				'release_ip'             => PRIVILEGE_ADMIN,
				'ip_allocated'           => PRIVILEGE_ADMIN,
				'gethostbyaddr_t'        => PRIVILEGE_ALL,
				'gethostbyname_t'        => PRIVILEGE_ALL,
				'get_provider'           => PRIVILEGE_ALL,
				'uuid'                   => PRIVILEGE_ALL,
				'provisioning_records'   => PRIVILEGE_SITE,
				'remove_zone'            => PRIVILEGE_ADMIN,
				'remove_zone_backend'    => PRIVILEGE_ADMIN|PRIVILEGE_SITE|PRIVILEGE_SERVER_EXEC,
				'add_zone'               => PRIVILEGE_ADMIN,
				'add_zone_backend'       => PRIVILEGE_ADMIN|PRIVILEGE_SITE|PRIVILEGE_SERVER_EXEC,
			);
		}

		/**
		 * Provider loader
		 *
		 * @return Module_Skeleton
		 */
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
		 * Get DNS UUID for host
		 *
		 * @return null|string
		 */
		public function uuid(): ?string {
			return DNS_UUID ?: null;
		}

		/**
		 * Get DNS UUID record name
		 *
		 * @return string
		 */
		public function uuid_name(): string {
			return static::UUID_RECORD;
		}

		/**
		 * DNS is configured for account
		 *
		 * @return bool
		 */
		public function configured(): bool
		{
			return \get_class($this) !== self::class;
		}

		/**
		 * Query database for domain expiration
		 *
		 * On multi-server lookups that perform DNS lookups independent,
		 * perform batch lookups and pull those records from the database
		 *
		 *
		 * A return of 0 indicates failure
		 * null indicates unknown expiration
		 *
		 * @param string $domain domain owned by the account
		 * @return null|int expiration as unix timestamp
		 */
		public function domain_expiration(string $domain): ?int
		{
			return null;
		}

		/**
		 * Fetches all domains across all servers
		 *
		 * Used in multi-server layouts
		 *
		 * @return array
		 */
		public function get_all_domains(): array
		{
			return array_keys(\Opcenter\Map::load(\Opcenter\Map::DOMAIN_MAP)->fetchAll());
		}

		/**
		 * Get server on which a domain is hosted
		 *
		 * @param string $domain
		 * @param bool   $all show all server matches, $all = true: array of all servers, else server
		 * @return string|array
		 */
		public function get_server_from_domain(string $domain, bool $all = false)
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
		 * @return bool|string primary domain or false on error
		 */
		public function get_parent_domain(string $domain)
		{
			if (false === ($id = \Opcenter\Map::load(\Opcenter\Map::DOMAIN_MAP)->fetch($domain))) {
				return false;
			}
			return \Auth::get_domain_from_site_id((int)substr($id, 4));
		}

		/**
		 * Query WHOIS server for record
		 *
		 * @param  string $domain domain name to look up the whois record for
		 * @return string|bool whois data
		 *
		 */
		public function get_whois_record(string $domain)
		{
			Error_Reporter::suppress_php_error('require_once');
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error('%s: invalid domain', $domain);
			}
			if (!class_exists('Net_Whois', false) &&
				!include 'Net/Whois.php'
			) {
				return error('Unable to include Whois module');
			}

			$whois = new Net_Whois();
			$data = $whois->query($domain);
			if (PEAR::isError($data)) {
				return error("Failed to lookup whois data: `%s'", $data->message);
			}
			return $data;
		}

		/**
		 * Export zone configuration in BIND-friendly notation
		 *
		 * @param string|null $zone
		 * @return bool|string
		 */
		public function export(string $zone = null)
		{
			if (null === $zone) {
				$zone = $this->domain;
			}

			if (!$this->permission_level & PRIVILEGE_ADMIN && !$this->owned_zone($zone)) {
				return error("access denied - cannot view zone `%s'", $zone);
			}
			$recs = $this->get_zone_data($zone);
			if (null === $recs) {
				return error("failed to export zone `%s'", $zone);
			}
			$soa = $recs['SOA'][0];
			$soadata = preg_split('/\s+/', $soa['parameter']);
			$format = ';; ' . "\n" .
				";; Domain:\t" . $zone . "\n" .
				";; Exported:\t" . date('r') . "\n" .
				';; ' . "\n" .
				'$ORIGIN . ' . "\n" .
				"@\t" . $soa['ttl'] . "\tIN\tSOA\t$zone.\t" . $soadata[1] . ' ( ' . "\n" .
				"\t" . $soadata[2] . "\t; serial" . "\n" .
				"\t" . $soadata[3] . "\t; refresh" . "\n" .
				"\t" . $soadata[4] . "\t; retry" . "\n" .
				"\t" . $soadata[5] . "\t; expire" . "\n" .
				"\t" . $soadata[6] . ")\t; minimum" . "\n\n";
			$buffer = array();
			$buffer[] = ';; NS Records (YOU MUST CHANGE THIS)';
			foreach ($recs['NS'] as $ns) {
				$ns['parameter'] = 'YOU_MUST_CHANGE_THIS_VALUE';
				$buffer[] = $ns['name'] . "\t" . $ns['ttl'] .
					"\t" . "IN NS\t" . $ns['parameter'];
			}
			$buffer[] = '';
			$ignore = array('SOA', 'NS', 'TSIG');
			foreach (static::$permitted_records as $rr) {
				$rr = strtoupper($rr);
				if (!isset($recs[$rr]) || in_array($rr, $ignore, true)) {
					continue;
				}
				$buffer[] = ';; ' . $rr . ' Records';
				foreach ($recs[$rr] as $r) {
					$buffer[] = $r['name'] . "\t" . $r['ttl'] .
						"\t" . 'IN ' . $rr . "\t" . $r['parameter'];
				}
				$buffer[] = "\n";
			}
			$format .= implode("\n", $buffer);
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
			return ($zone === $this->domain) || in_array($zone, $aliases, true);
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
		 * @return array|bool false on error
		 */
		public function get_records_external(string $subdomain = '', string $rr = 'any', string $domain = null, array $nameservers = null)
		{
			if (!$domain) {
				$domain = $this->domain;
			}
			$host = $domain;
			if ($subdomain) {
				$host = $subdomain . '.' . $host;
			}
			$rr = strtoupper($rr);
			if (self::record2const($rr) < 1) {
				return error("unknown rr record type `%s'", $rr);
			}
			if (!$nameservers) {
				$nameservers = array(static::RECURSIVE_NAMESERVER);
			}
			$resolvers = [];
			foreach ($nameservers as $ns) {
				if (strspn($ns,'1234567890.') === \strlen($ns)) {
					$resolvers[] = $ns;
				} else if ($ip = Net_Gethost::gethostbyname_t($ns)) {
					$resolvers[] = $ip;
				}
			}
			$resolver = new Net_DNS2_Resolver([
				'nameservers' => $resolvers,
				'ns_random' => true
			]);

			for ($i = 0; $i < 5; $i++) {
				// @todo remove dependency on dig
				$recraw = Error_Reporter::silence(function () use ($host, $rr, $resolver) {
					try {
						return $resolver->query($host, $rr);
					} catch (Net_DNS2_Exception $e) {
						return false;
					}
				});
				if (!empty($recraw->answer)) {
					break;
				}
				usleep(50000);
			}
			if (empty($recraw->answer)) {
				$host = ltrim(implode('.', array($subdomain, $domain)), '.');
				warn("failed to get external raw records for `%s' on `%s'", $rr, $host);
				return [];
			}

			$records = array();
			foreach ($recraw->answer as $r) {
				$target = null;

				// most records
				if (isset($r->target)) {
					$target = $r->target;
				}
				// A
				if (isset($r->ip)) {
					$target = $r->ip;
				}
				// SRV
				if (isset($r->weight)) {
					// ignore PRI that comes before WEIGHT
					// it is handled next
					$target = $r->weight . ' ' . $target .
						$r->port;
				}
				// MX, SRV
				if (isset($r->pri)) {
					$target = $r->pri . ' ' . $target;
				}
				// TXT
				if (isset($r->txt)) {
					$target = $r->txt;
				}
				// HINFO
				if (isset($r->cpu)) {
					$target = $r->cpu . ' ' . $r->os;
				}
				// SOA
				if (isset($r->mname)) {
					$target = $r->mname . ' ' . $r->rname . ' ' .
						$r->serial . ' ' . $r->refresh . ' ' .
						$r->retry . ' ' . $r->expire . ' ' .
						$r->minimum;
				}
				// AAAA, A6
				if (isset($r->ipv6)) {
					$target = $r->ipv6;
				}
				// A6
				if (isset($r->masklen)) {
					$target = $r->masklen . ' ' . $target . ' ' .
						$r->chain;
				}
				// NAPTR
				if (isset($r->order)) {
					$target = $r->order . ' ' . $r->pref . ' ' .
						$r->flags . ' ' . $r->services . ' ' .
						$r->regex . ' ' . $r->replacement;
				}
				$records[] = array(
					'name'      => $host,
					'subdomain' => $subdomain,
					'domain'    => $domain,
					'class'     => 'IN',
					'type'      => $rr,
					'ttl'       => $r->ttl,
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
		public static function record2const($rr): int
		{
			$rr = strtoupper($rr);
			return static::$rec_2_const[$rr] ?? 0;
		}

		/**
		 * Returns the host name of the Internet host specified by $ip with timeout
		 *
		 * @param string $ip
		 * @param int    $timeout
		 * @return string|null|bool
		 */
		public function gethostbyaddr_t(string $ip, int $timeout = 1000)
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
		public function gethostbyname_t(string $name, int $timeout = 1000)
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
		public function domain_hosted(string $domain, bool $ignore_on_account = false): bool
		{
			$domain = strtolower($domain);
			if (0 === strpos($domain, "www.")) {
				$domain = substr($domain, 4);
			}
			$ignore_on_account = (bool)$ignore_on_account;
			$site_id = \Auth::get_site_id_from_domain($domain);
			if ($ignore_on_account) {
				return $site_id && $site_id !== $this->site_id;
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
		public function domain_on_account(string $domain): bool
		{
			return false;
		}

		/**
		 * Lookup and compare nameservers for domain to host
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function domain_uses_nameservers(string $domain): bool
		{
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error("malformed domain `%s'", $domain);
			}
			$hostingns = $this->get_hosting_nameservers($domain);
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
				if (in_array($ns, $hostingns, true)) {
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
		 * @return array
		 */
		public function get_hosting_nameservers(string $domain = null): array
		{
			if (null === static::$nameservers) {
				static::$nameservers = preg_split('/[,\s]+/', DNS_HOSTING_NS, -1, PREG_SPLIT_NO_EMPTY);
			}
			return (array)static::$nameservers;
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
		protected function get_authns_from_host_recursive($host, Net_DNS2_Resolver $resolver, $seen = ''): ?array
		{
			$components = explode('.', $host);
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
			return $this->get_authns_from_host_recursive(implode('.', $components), $resolver, $lookup);

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
		public function get_pending_expirations(int $days = 30, bool $showExpired = true): array
		{
			return [];
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
		public function check_zone(string $zone, array $recs = []): bool
		{
			$tmpfile = tempnam('/tmp', 'f');
			Util_Process_Safe::exec('dig +authority +multiline +noquestion +nostats +noadditional +nocmd  -t AXFR -y ' .
				'%s @%s %s > %s',
				self::$dns_key,
				static::AUTHORITATIVE_NAMESERVER,
				$zone,
				$tmpfile,
				array('mute_stderr' => true)
			);
			if ($recs) {
				$str = '';
				foreach ($recs as $rec) {
					$str .= $rec[0] . ' ' . $rec[1] . ' ' . $rec[2] . ' ' . $rec[3] . "\n";
				}
				file_put_contents($tmpfile, $str, FILE_APPEND);
			}
			$status = Util_Process_Safe::exec('/usr/sbin/named-checkzone ' . $zone . ' ' . $tmpfile);
			unlink($tmpfile);
			return $status['success'];
		}

		/**
		 * Update hostname with caller's IP4 address
		 *
		 * @param string $hostname fqdn
		 * @param string $ip       optional ip address to skip detection
		 * @return string|bool ip address or false on failure
		 */
		public function update(string $hostname, string $ip = null)
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
				return error('cannot detect ip!');
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
		 * @return array|bool
		 */
		public function get_records(string $subdomain = '', string $rr = 'any', string $domain = null)
		{
			if (!$domain) {
				$domain = $this->domain;
			}
			if (!$this->owned_zone($domain)) {
				return error('cannot view DNS information for unaffiliated domain `' . $domain . "'");
			}
			$recs = $this->get_records_raw($subdomain, $rr, $domain);
			return (array)$recs;

		}

		/**
		 * get_records() unauthenticated DNS wrapper
		 *
		 * @param string $subdomain optional subdomain
		 * @param string $rr        optional RR type
		 * @param string $domain    optional domain
		 * @return array|bool records or false on failure
		 */
		protected function get_records_raw(string $subdomain = '', string $rr = 'ANY', string $domain = null)
		{
			if ($subdomain == '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}
			$rr = strtoupper($rr);
			if ($rr !== 'any' && !in_array($rr, static::$permitted_records, true)) {
				return error("`$rr' invalid resource record type");
			}
			$rr = strtoupper($rr);
			$recs = $this->get_zone_data($domain);
			// zone error, Transfer failed, i.e. zone not provisioned
			if (null === $recs) {
				return array();
			}
			$domain .= '.';
			if ($subdomain !== '') {
				$domain = $subdomain . '.' . $domain;
			}

			$newrecs = [];
			$keys = [$rr];
			if ($rr == 'ANY') {
				$keys = array_keys($recs);
			} else if (!isset($recs[$rr])) {
				return $newrecs;
			}
			foreach ($keys as $tmp) {
				foreach ($recs[$tmp] as $rec) {
					$rec['rr'] = $tmp;
					if ($rec['name'] === $domain) {
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
		public function add_record(string $zone, string $subdomain, string $rr, string $param, int $ttl = self::DNS_TTL): bool
		{
			if (!$this->owned_zone($zone)) {
				return error('%s not owned by account', $zone);
			}
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}
			/**
			 * Implement your own!
			 */
			return true;
		}

		/**
		 * Fixup a DNS record before submitting
		 *
		 * @param string $zone
		 * @param string $subdomain
		 * @param string $rr
		 * @param string $param
		 * @param int    $ttl
		 * @return bool
		 */
		protected function canonicalizeRecord(string &$zone, string &$subdomain, string &$rr, string &$param, int &$ttl = null): bool
		{

			$rr = strtoupper($rr);
			if ($rr == 'CNAME' && !$subdomain && $this->hasCnameApexRestriction()) {
				return error('CNAME record cannot coexist with zone root, see RFC 1034 section 3.6.2');
			}

			if ($rr === 'NS' && !$subdomain) {
				return error("Set nameserver records for zone root through domain registrar");
			}

			if (!\in_array($rr, static::$permitted_records, true)) {
				return error($rr . ': invalid resource record type');
			}

			if (false !== strpos($subdomain, ' ')) {
				return error("DNS record `%s' must not contain any spaces", $subdomain);
			}
			if (!static::HAS_ORIGIN_MARKER && substr($subdomain, -\strlen($zone)) === $zone) {
				$subdomain = substr($subdomain, 0, -\strlen($zone));
			}

			if (!static::HAS_ORIGIN_MARKER && $subdomain === '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			} else if (static::HAS_ORIGIN_MARKER && $subdomain === '') {
				$subdomain = '@';
			}

//			if ($subdomain && ($subdomain !== $zone)) {
//				$subdomain = ltrim(preg_replace('/\.' . $zone . '$/', '', rtrim($subdomain, '.')) . '.' . $zone . '.',
//					'.');
//			}
			if ($rr == 'MX' && preg_match('/(\S+) (\d+)$/', $param, $mx_flip)) {
				// user entered MX record in reverse, e.g. mail.apisnetworks.com 10
				$param = $mx_flip[2] . ' ' . $mx_flip[1];
			}

			// per RFC 4408 section 3.1.3,
			// TXT records limits contiguous length to 255 characters, but
			// may also concatenate
			if ($rr == 'TXT' && $param) {
				$param = '"' . implode('" "', str_split(trim($param, '"'), 253)) . '"';
				if ($param[0] !== '"' && $param[strlen($param) - 1] !== '"') {
					$param = '"' . str_replace('"', '\\"', $param) . '"';
				}
			}
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
		public function modify_record(string $zone, string $subdomain, string $rr, string $parameter, array $newdata): bool
		{
			if (!$this->owned_zone($zone)) {
				return error($zone . ': not owned by account');
			}

			$ttl = (int)self::DNS_TTL;
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $parameter, $ttl)) {
				return false;
			}

			$newdata = new \Opcenter\Dns\Record($zone, array_merge([
				'name'      => $subdomain,
				'rr'        => $rr,
				'ttl'       => null,
				'parameter' => $parameter
			], $newdata));

			if (!$this->canonicalizeRecord($zone, $newdata['name'], $newdata['rr'], $newdata['parameter'], $newdata['ttl'])) {
				return false;
			}

			$rectmp = preg_replace('/\.?' . $zone . '\.?$/', '', $newdata['name']);

			if ($newdata['name'] !== $subdomain && $newdata['rr'] !== $rr &&
				$this->record_exists($zone, $rectmp, $newdata['rr'], $parameter)
			) {
				return error('Target record `' . $newdata['name'] . "' exists");
			}

			$old = new \Opcenter\Dns\Record($zone, [
				'name' => $subdomain,
				'rr' => $rr,
				'parameter' => $parameter
			]);

			if (false === ($ret = $this->atomicUpdate($zone, $old, $newdata))) {
				// nsUpdate failed, rollback records
				warn('record update failed');
				return ( ($subdomain === $newdata['name'] && $rr === $newdata['rr']) ||
						!$this->record_exists($zone, $subdomain, $rr, $parameter) ) &&
					$this->record_exists($zone, $newdata['name'], $newdata['rr'], $newdata['parameter']);
			}
			return (bool)$ret;
		}

		/**
		 * Perform an atomic update of a record allowing reversion on failure
		 *
		 * @param string $zone
		 * @param \Opcenter\Dns\Record $old
		 * @param \Opcenter\Dns\Record $newdata
		 * @return bool|null true if record succeeded false on failure null to halt reversion
		 */
		protected function atomicUpdate(string $zone, \Opcenter\Dns\Record $old, \Opcenter\Dns\Record $newdata): ?bool {
			return false;
		}

		/**
		 * DNS record exists
		 *
		 * @param string $zone
		 * @param string $subdomain
		 * @param string $rr
		 * @param string $parameter
		 * @return bool
		 */
		public function record_exists(string $zone, string $subdomain, string $rr = 'ANY', string $parameter = null): bool
		{
			if (!static::AUTHORITATIVE_NAMESERVER) {
				warn("no authoritative nameserver configured - can't verify record `%s'",
					ltrim($subdomain . '.' . $zone, '.')
				);
				return true;
			}
			if (!static::HAS_ORIGIN_MARKER && $subdomain == '@') {
				$subdomain = '';
				warn("record `@' alias for domain - record stripped");
			}
			$record = trim($subdomain . '.' . $zone, '.');
			$rr = strtoupper($rr);
			if (static::record2const($rr) < 1) {
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
			return (bool)preg_match('!' . $parameter . '!i', $status['output']);
		}


		/**
		 * Add zone to DNS server
		 *
		 * @param string $domain
		 * @param string $ip
		 * @return bool|void
		 */
		public function add_zone(string $domain, string $ip): bool
		{
			if (!$this->configured()) {
				return warn("cannot create DNS zone for `%s' - DNS is not configured for account", $domain);
			}

			$buffer = Error_Reporter::flush_buffer();
			$res = $this->zoneAxfr($domain);
			if (null !== $res) {
				Error_Reporter::set_buffer($buffer);
				warn("DNS for zone `%s' already exists, not overwriting", $domain);

				return true;
			}

			if ($this->query('dns_add_zone_backend', $domain, $ip)) {
				foreach ($this->provisioning_records($domain) as $record) {
					if (!$this->add_record($domain, $record['name'], $record['rr'], $record['parameter'],
						$record['ttl'])) {
						warn("Failed to add DNS record `%s' on `%s' (rr: %s)", $domain, $record['name'], $record['rr']);
					}
				}
			}
			return true;
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
			}

			if (!static::MASTER_NAMESERVER) {
				return error("rndc not configured in config.ini. Cannot add zone `%s'", $domain);
			}
			$buffer = Error_Reporter::flush_buffer();
			$res = $this->get_zone_data($domain);

			if (null !== $res) {
				Error_Reporter::set_buffer($buffer);
				warn("DNS for zone `%s' already exists, not overwriting", $domain);

				return true;
			}
			// make sure DNS does not exist yet for the parent
			[$a, $b] = explode('.', $domain, 2);
			$res = $this->get_zone_data($b);
			Error_Reporter::set_buffer($buffer);
			if (null !== $res) {
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
			return true;
		}

		/**
		 * Remove a zone from DNS management
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function remove_zone(string $domain): bool
		{
			if (!$this->configured()) {
				return warn("cannot create DNS zone for `%s' - DNS is not configured for account", $domain);
			}
			$record = $this->get_records(static::UUID_RECORD, 'TXT', $domain);
			if ( null !== $this->uuid() && null !== ($record = array_get($record, '0.parameter', null)))
			{
				return warn("Bypassing DNS removal. DNS UUID for `%s' is `%s'. Server UUID is `%s'", $domain, $record, $this->uuid());
			}
			return $this->query('dns_remove_zone_backend', $domain);
		}

		/**
		 * Remove zone from nameserver
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function remove_zone_backend(string $domain): bool
		{
			return warn("cannot remove zone - DNS provider `%s' not configured fully", $this->get_service_value('dns','provider','builtin'));
		}

		/**
		 * Check whether IP is assigned
		 *
		 * Assigned IP addresses will have PTRs. Unassigned will be empty.
		 *
		 * @param $ip string ip address
		 * @return bool
		 */
		public function ip_allocated($ip): bool
		{
			return \Opcenter\Net\IpCommon::ip_allocated($ip);
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
			if (null === $zone) {
				$zone = $this->domain;
			}

			if (!$this->owned_zone($zone)) {
				if (!$this->owned_zone($rr)) {
					error('access denied - cannot view zone `' . $zone . "'");
					return null;
				}
				// confusing half-assed backwards
				// accept arguments in either form
				$t = $rr;
				$rr = $zone;
				$zone = $t;
			}

			$rr = strtoupper($rr);
			if ($rr !== 'any' && !in_array($rr, static::$permitted_records, true)) {
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
		public function get_zone_information(string $domain = null): ?array
		{
			$domain = $domain ?? $this->domain;

			if (!$this->permission_level & PRIVILEGE_ADMIN && !$this->owned_zone($domain)) {
				error('access denied - cannot view zone `' . $domain . "'");
				return null;
			}
			$rec = $this->get_zone_data($domain);
			if (null === $rec) {
				error('Non-authorative for zone ' . $domain);
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
		public function import_from_ns(string $domain, string $nameserver, $key = null): bool
		{
			$myip = Util_Conf::server_ip();
			$domain = strtolower($domain);
			if (!preg_match(Regex::DOMAIN, $domain)) {
				return error("invalid zone `%s' - not a domain name", $domain);
			}

			if (!preg_match(Regex::DOMAIN, $nameserver)) {
				return error("invalid nameserver to query `%s'", $nameserver);
			}

			if ($key && false === strpos($key, ':')) {
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
			if (!$proc['success'] || false !== strpos($output, '; Transfer failed')) {
				$output = $proc['stderr'] ?: $proc['output'];
				return error('axfr failed: %s', $output);
			}
			return $this->import($domain, output);
		}

		/**
		 * Import raw AXFR records into zone
		 *
		 * @param string $domain
		 * @param string $axfr
		 * @return bool
		 */
		public function import(string $domain, string $axfr): bool
		{
			// empty out old zone first
			$nrecs = 0;
			$zoneinfo = $this->get_zone_information($domain);
			if (false === $zoneinfo) {
				return error('unable to get old zone information - is this domain added to your account?');
			}
			foreach ($zoneinfo as $rr => $recs) {
				foreach ($recs as $rec) {
					$tmp = strtoupper($rr);
					// skip SOA + apex record
					if ($tmp === 'SOA' || ($tmp === 'NS' && !$rec['subdomain'])) {
						continue;
					}
					if (!$this->remove_record($domain, $rec['subdomain'], $rr, $rec['parameter'])) {
						warn('failed to purge record `%s` %s %s %s',
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
			info('purged %d old records', $nrecs);

			$nrecs = 0;
			$regex = Regex::compile(Regex::DNS_AXFR_REC_DOMAIN, str_replace('.', "\\.", $domain));
			foreach (preg_split("/[\r\n]{1,2}/", $axfr) as $line) {

				if ('' === $line || $line[0] == ';') {
					continue;
				}
				if (!preg_match($regex, $line, $rec)) {
					continue;
				}
				$tmp = strtoupper($rec['rr']);
				// skip SOA + apex record
				if ($tmp === 'SOA' || ($tmp === 'NS' && !$rec['subdomain']) || $rec['class'] !== 'IN') {
					continue;
				}
				$subdomain = trim($rec['subdomain'], '.');
				if (!$this->add_record($domain, $subdomain, $rec['rr'], $rec['parameter'], $rec['ttl'])) {
					warn('failed to add record `%s` -> `%s` (RR: %s, TTL: %s)',
						$subdomain,
						$rec['parameter'],
						$rec['rr'],
						$rec['ttl']
					);
					continue;
				}
				$nrecs++;
			}

			info('imported %d records', $nrecs);
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
		public function remove_record(string $zone, string $subdomain, string $rr, string $param = null): bool
		{
			$subdomain = rtrim($subdomain, '.');
			if (!$zone) {
				$zone = $this->domain;
			}
			if (!$this->owned_zone($zone)) {
				return error($zone . ': not owned by account');
			}
			$ttl = self::DNS_TTL;
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param)) {
				return false;
			}
			// only supply parameter if parameter is provided


			/**
			 * Now purge the record
			 */

			return true;
		}

		public function release_ip(string $ip): bool
		{
			deprecated_func('use ipinfo_release_ip');
			return $this->ipinfo_release_ip($ip);
		}

		/**
		 * Get all zone records parsed
		 *
		 * @param string $domain
		 * @return array|null
		 */
		protected function get_zone_data(string $domain): ?array
		{
			if (null === ($data = $this->zoneAxfr($domain))) {
				return [];
			}

			$zoneData = array();
			$offset = strlen($domain) + 1; // domain.com.
			$regexp = \Regex::compile(\Regex::DNS_AXFR_REC, ['rr' => implode('|', static::$permitted_records + [99999 => 'SOA'])]);
			foreach (explode("\n", $data) as $line) {
				if (false !== strpos($line, 'Transfer failed.')) {
					return null;
				}
				if (!preg_match($regexp, $line, $match)) {
					continue;
				}
				[$name, $ttl, $class, $rr, $parameter] = array_slice($match, 1);
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

		/**
		 * Get module default
		 *
		 * @param string $key
		 * @return mixed|null
		 */
		public function get_default(string $key)
		{
			switch (strtolower($key)) {
				case 'ttl':
					return static::DNS_TTL;
				default:
					return null;
			}
		}

		/**
		 * Perform a full zone transfer
		 *
		 * @param string $domain
		 * @return null|string
		 */
		protected function zoneAxfr($domain): ?string
		{
			if (!static::MASTER_NAMESERVER) {
				error("Cannot fetch zone information for `%s': no master nameserver configured in config.ini",
					$domain);

				return null;
			}
			$data = Util_Process::exec("dig -t AXFR -y '%s' @%s %s",
				$this->getTsigKey($domain), static::MASTER_NAMESERVER, $domain, [-1, 0]);

			return $data['success'] ? $data['output'] : null;
		}

		/**
		 * Get AXFR key for domain
		 *
		 * @param string $domain
		 * @return null|string
		 */
		private function getTsigKey(string $domain): ?string
		{
			return static::$dns_key;
		}

		/**
		 * Abides by DNS RFC that restricts DNS records from having an apex CNAME
		 *
		 * See also RFC 1034 section 3.6.2
		 * @return bool
		 */
		protected function hasCnameApexRestriction(): bool
		{
			return true;
		}

		/**
		 * Get provisioning DNS records to setup automatically
		 *
		 * @param string $zone zone name
		 * @return \Opcenter\Dns\Record[]
		 */
		public function provisioning_records(string $zone): array
		{
			$myip = $this->site_ip_address();
			$records = [
				new \Opcenter\Dns\Record($zone, ['name' => '', 'ttl' => static::DNS_TTL, 'rr' => 'a', 'parameter' => $myip]),
				new \Opcenter\Dns\Record($zone, ['name' => 'www', 'ttl' => static::DNS_TTL, 'rr' => 'a', 'parameter' => $myip]),
				new \Opcenter\Dns\Record($zone, ['name' => 'ftp', 'ttl' => static::DNS_TTL, 'rr' => 'a', 'parameter' => $myip]),
			];

			if ( ($this->email_enabled() && $this->get_service_value('mail', 'provider') !== 'builtin' ) || $this->email_transport_exists($zone)) {
				$records = array_merge($records, $this->email_get_records($zone));
			}

			if ($this->uuid()) {
				$records[] = new \Opcenter\Dns\Record($zone, [
					'name'      => static::UUID_RECORD,
					'ttl'       => static::DNS_TTL,
					'rr'        => 'txt',
					'parameter' => $this->uuid()
				]);
			}

			return array_merge($records, []);
		}

		/**
		 * Release PTR assignment from an IP
		 *
		 * @param        $ip
		 * @param string $domain confirm PTR rDNS matches domain
		 * @return bool
		 */
		protected function __deleteIP(string $ip, string $domain = null): bool
		{
			// @todo move to ipinfo
			return true;
		}

		/**
		 * Add an IP address to hosting
		 *
		 * @param string $ip
		 * @param string $hostname
		 * @return bool
		 */
		protected function __addIP(string $ip, string $hostname = ''): bool
		{
			return true;
		}

		/**
		 * Change PTR name
		 *
		 * @param string $ip       IP address to alter
		 * @param string $hostname new PTR name
		 * @param string $chk      optional check hostname to verify
		 * @return bool
		 */
		protected function __changePTR(string $ip, string $hostname, string $chk = ''): bool
		{
			return true;
		}

		public function _delete()
		{
			if (!$this->configured()) {
				return warn("DNS not configured for `%s', bypassing DNS hooks", $this->domain);
			}
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
					$this->remove_zone_backend($domain);
				} else {
					dlog("Skipping stray zone $domain");
				}
			}
			return true;
		}

		public function _create()
		{
			if (!$this->configured()) {
				return warn("DNS not configured for `%s', bypassing DNS hooks", $this->domain);
			}
			$ipinfo = $this->getAuthContext()->conf('ipinfo');
			$siteinfo = $this->getAuthContext()->conf('siteinfo');
			$domain = $siteinfo['domain'];
			$ip = $ipinfo['namebased'] ? $ipinfo['nbaddrs'] : $ipinfo['ipaddrs'];
			$this->add_zone($domain, $ip[0]);

			if (!$ipinfo['namebased']) {
				$this->__addIP($ip[0], $siteinfo['domain']);
			}
			if (!$this->domain_uses_nameservers($domain)) {
				warn("Domain `%s' doesn't use assigned nameservers. Change nameservers to %s",
					$domain, implode(',', $this->get_hosting_nameservers($domain))
				);
			}

			return true;
		}

		public function _edit()
		{
			if (!$this->configured()) {
				return warn("DNS not configured for `%s', skipping edit hook", $this->domain);
			}
			$conf_old = $this->getAuthContext()->conf('ipinfo', 'old');
			$conf_new = $this->getAuthContext()->conf('ipinfo', 'new');
			$domainold = \array_get($this->getAuthContext()->conf('siteinfo', 'old'), 'domain');
			$domainnew = \array_get($this->getAuthContext()->conf('siteinfo', 'new'), 'domain');
			if (\array_get($this->getAuthContext()->conf('dns','old'), 'provider') !== array_get($this->getAuthContext()->conf('dns', 'new'), 'provider')) {
				$this->_create();
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
			} else if (!$conf_old['namebased'] && $conf_new['namebased']) {
				// removed ip-based hosting
				$ipadd = $conf_new['nbaddrs'];
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
							error('failed to modify record for `' . $frag . "'");
						} else {
							$pieces = array($r['subdomain'], $r['domain']);
							$host = trim(implode('.', $pieces), '.');
							info("modified `%s'", $host);
						}
					}
				}
			}

			return;
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
