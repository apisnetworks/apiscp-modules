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
	 * Provides interface bindings to apnscp.
	 *
	 * @package core
	 */
	class Ipinfo_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable
	{
		// netmask of allowable IP addresses
		const IP_ALLOCATION_BLOCK = DNS_ALLOCATION_CIDR;

		const NAMEBASED_INTERFACE_FILE = '/etc/virtualhosting/interface';

		/**
		 * {{{ void __construct(void)
		 */
		public function __construct()
		{
			parent::__construct();

			$this->exportedFunctions = array(
				'*'                      => PRIVILEGE_SITE,
				'release_ip'             => PRIVILEGE_ADMIN,
				'ip_allocated'           => PRIVILEGE_ADMIN,
			);
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
			return $this->__deleteIP($ip, $domain);
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
		}

		public function _create()
		{
			$ipinfo = Auth::profile()->conf->cur['ipinfo'];
			$siteinfo = Auth::profile()->conf->cur['siteinfo'];
			$domain = $siteinfo['domain'];
			$ip = $ipinfo['namebased'] ? $ipinfo['nbaddrs'] : $ipinfo['ipaddrs'];
			//$this->add_zone($domain, $ip[0]);
			if (!$ipinfo['namebased']) {
				$this->_addIP($ip[0], $siteinfo['domain']);
			}
		}

		/**
		 * Add an IP address to hosting
		 *
		 * @param string $ip
		 * @param string $hostname
		 * @return bool
		 */
		protected function _addIP($ip, $hostname = '')
		{
			return true;
		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			// TODO: Implement _edit_user() method.
		}

		public function _create_user(string $user)
		{
			// TODO: Implement _create_user() method.
		}

		public function _delete_user(string $user)
		{
			// TODO: Implement _delete_user() method.
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
				$ip = \Opcenter\Net\Ip4::allocate();
				$conf_new['ipaddrs'] = array($ip);
				info("allocated ip `%s'", $ip);
			}
			// domain name change via auth_change_domain()
			if ($domainold !== $domainnew) {
				$ip = $conf_new['namebased'] ? array_pop($conf_new['nbaddrs']) :
					array_pop($conf_new['ipaddrs']);
				//$this->remove_zone($domainold);
				//$this->add_zone($domainnew, $ip);
				// domain name changed
				if (!$conf_new['namebased']) {
					//$this->__changePTR($ip, $domainnew, $domainold);
				}
			}

			if ($conf_new === $conf_cur) {
				return;
			}
			$ipadd = $ipdel = array();

			if ($conf_cur['namebased'] && !$conf_new['namebased']) {
				// enable ip hosting
				$ipadd = $conf_new['ipaddrs'];
			} else {
				if (!$conf_cur['namebased'] && $conf_new['namebased']) {
					// disable ip hosting
					$ipdel = $conf_cur['ipaddrs'];
				} else {
					// add/remove ip hosting
					$ipdel = array_diff((array)$conf_cur['ipaddrs'], (array)$conf_new['ipaddrs']);
					$ipadd = array_diff((array)$conf_new['ipaddrs'], (array)$conf_cur['ipaddrs']);
				}
			}

			foreach ($ipdel as $ip) {
				// NB __changePTR is called before to update domain on change
				$this->__deleteIP($ip, $domainnew);
			}

			foreach ($ipadd as $ip) {
				$this->_addIP($ip, $domainnew);
			}

			$domains = array_keys($this->web_list_domains());
			if ($conf_cur['namebased'] && !$conf_new['namebased']) {
				// added ip-based hosting
				$ipdel = $conf_cur['nbaddrs'];
			} else {
				if (!$conf_cur['namebased'] && $conf_new['namebased']) {
					// removed ip-based hosting
					$ipadd = $conf_new['nbaddrs'];
				}
			}
			// change DNS
			// there will always be a 1:1 pairing for IP addresses
			foreach ($ipadd as $newip) {
				$oldip = array_pop($ipdel);
				$class = apnscpFunctionInterceptor::get_autoload_class_from_module('dns');
				$newparams = array('ttl' => $class::DNS_TTL, 'parameter' => $newip);
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
			return gethostbyaddr($ip) !== $ip;
		}

		/**
		 * Announce an IP address via ARP
		 *
		 * @param string $ip
		 * @return bool
		 */
		protected function _announceIP($ip)
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

		/**
		 * Get interface names to use with hosting
		 *
		 * @return bool|string
		 */
		protected function _getInterface()
		{
			// default in case file is missing
			$iface = 'eth0';
			if (!file_exists(static::NAMEBASED_INTERFACE_FILE)) {
				warn("missing interface file `%s', assuming main iface is `%s'",
					static::NAMEBASED_INTERFACE_FILE, $iface);
				return $iface;
			}
			$iface = file_get_contents(static::NAMEBASED_INTERFACE_FILE);
			return trim($iface);
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return $ctx->preflight();
		}
	}