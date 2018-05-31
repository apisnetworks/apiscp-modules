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
	 * Provides SSL certificate management for Apache
	 *
	 * @package core
	 */
	class Ssl_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable
	{
		const DEPENDENCY_MAP = [
			'apache', 'siteinfo'
		] ;

		const CRT_PATH = '/etc/httpd/conf/ssl.crt';
		const KEY_PATH = '/etc/httpd/conf/ssl.key';
		const CSR_PATH = '/etc/httpd/conf/ssl.csr';

		const X509_DAYS = 1095; /* 3 years for self-signed */

		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = array(
				'generate_csr'             => PRIVILEGE_ALL,
				'generate_privatekey'      => PRIVILEGE_ALL,
				'get_alternative_names'    => PRIVILEGE_ALL,
				'get_certificate'          => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'get_csr'                  => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'get_private_key'          => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'get_public_key'           => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'is_self_signed'           => PRIVILEGE_ALL,
				'key_exists'               => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'parse_certificate'        => PRIVILEGE_ALL,
				'permitted'                => PRIVILEGE_ALL,
				'privkey_info'             => PRIVILEGE_ALL,
				'request_info'             => PRIVILEGE_ALL,
				'resolve_chain'            => PRIVILEGE_ALL,
				'sign_certificate'         => PRIVILEGE_ALL,
				'valid'                    => PRIVILEGE_ALL,
				'verify_certificate_chain' => PRIVILEGE_ALL,
				'verify_key'               => PRIVILEGE_ALL,
				'verify_x509_key'          => PRIVILEGE_ALL,

				'*' => PRIVILEGE_SITE,
			);
		}

		/**
		 * Check if certificate is installed for account
		 *
		 * @return bool
		 */
		public function cert_exists()
		{
			if (!IS_CLI) {
				return $this->query('ssl_cert_exists');
			}
			$conf = $this->get_certificates();
			return count($conf) > 0;
		}

		/**
		 * Get certificate names installed on account
		 *
		 * @return array
		 */
		public function get_certificates()
		{
			if (!IS_CLI) {
				return $this->query('ssl_get_certificates');
			}
			// @TODO apache parser, maybe Augeas?
			$that = $this;
			$parser = function ($config) use ($that) {
				$conf = array();
				$token = strtok($config, "\n \t");
				while ($token !== false) {
					switch (strtoupper($token)) {
						case 'LISTEN':
							$key = 'host';
							break;
						case 'SSLCERTIFICATEFILE':
							$key = 'crt';
							break;
						case 'SSLCERTIFICATEKEYFILE':
							$key = 'key';
							break;
						case 'SSLCERTIFICATECHAINFILE':
							$key = 'chain';
							break;
						default:
							$key = null;
							break;
					}
					if (!is_null($key)) {
						$token = trim(strtok("\t \n"));

						$constant = $key === 'chain' ? 'crt' : $key;
						if ($constant == 'key' || $constant == 'crt') {
							// if no matching file, invalidate certificate
							if (!file_exists($token)) {
								return array();
							}
						}
						$token = $that->file_canonicalize_site($token);
						// let's assume everything is organized nicely in /etc/httpd/conf/ssl.x
						$conf[$key] = basename($token);
					}
					$token = strtok(" \t\n");
				}
				if (isset($conf['chain']) && count($conf) === 1) {
					// separate config parser
					return $conf;
				} else {
					if (!isset($conf['crt']) || !isset($conf['key'])) {
						return array();
					}
				}
				return $conf;
			};

			// old format for multiple IP/personalities per account
			$masterconfig = glob('/etc/httpd/conf/virtual/' . $this->site . '{,.*}', GLOB_BRACE);
			$sitecerts = array();
			$accountaddr = $this->common_get_ip_address();

			foreach ($masterconfig as $config) {
				$cert = array();
				$site = basename($config);
				if (!file_exists('/etc/httpd/conf/' . $site . '.ssl')) {
					return $sitecerts;
				}
				$file = '/etc/httpd/conf/virtual/' . $site;
				if (!file_exists($file)) {
					continue;
				}
				$config = file_get_contents($file);
				$newcert = $parser($config);
				if (!$newcert) {
					continue;
				}
				$cert = array_merge($cert, $newcert);
				$sslextra = '/etc/httpd/conf/' . basename($file) . '.ssl/custom';
				if (file_exists($sslextra)) {
					$config = file_get_contents($sslextra);
					$cert = array_merge($cert, $parser($config));
				}
				// remove port info
				if (isset($cert['host'])) {
					$tmp = strpos($cert['host'], ":");
					if ($tmp) {
						$cert['host'] = substr($cert['host'], 0, $tmp);
					}
				} else {
					$cert['host'] = $accountaddr;
				}
				$sitecerts[] = $cert;
			}
			return $sitecerts;
		}

		public function key_exists($key = 'server.key')
		{
			if (!IS_CLI) {
				return $this->query('ssl_key_exists', $key);
			}
			// default key name
			$name = basename($key, ".key");
			if ($this->permission_level & PRIVILEGE_SITE) {
				$key = $this->domain_fs_path() . self::KEY_PATH .
					'/' . $name . '.key';
			} else {
				if ($key[0] !== '/') {
					$key = self::KEY_PATH . '/' . $name;
				}
			}

			return file_exists($key);
		}

		public function install($key, $cert, $chain = null)
		{
			if (!IS_CLI) {
				return $this->query('ssl_install', $key, $cert, $chain);
			}
			if (!$this->permitted()) {
				return error("account requires assigned IP address for SSL");
			}

			if (!$this->valid($cert, $key)) {
				return error("certificate is not valid for given key");
			}


			if ($this->is_self_signed($cert)) {
				$chain = null;
			} else if (!$chain) {
				// try to resolve hierarchy
				$supplemental = $this->resolve_chain($cert);
				if (!$supplemental) {
					return error("certificate chain is irresolvable - contact support for help");
				}
				info("downloaded chain certificates to satisfy requirement, one or more additional pathways may be missing");
				$chain = join("\n", $supplemental);
			} else if (!$this->verify_certificate_chain($cert, $chain)) {
				return error("chain not valid for certificate");
			}

			$this->file_purge();
			$prefix = $this->domain_fs_path();
			$crtfile = $prefix . self::CRT_PATH . '/server.crt';
			$keyfile = $prefix . self::KEY_PATH . '/server.key';
			// build up in case Ensim is being stupid
			$this->file_shadow_buildup_backend(
				$prefix . self::CSR_PATH . '/server.csr'
			);
			// cert overwritten or moved
			$overwrite = false;
			// backup just in case
			foreach (array($crtfile, $keyfile) as $file) {
				/**
				 * make sure its constituents exist
				 * overlayfs ghosts merged layer if r/w doesn't contain
				 * parent dir
				 */
				$this->file_shadow_buildup_backend($file);
				$dir = dirname($file);
				if (!is_dir($dir)) {
					mkdir($dir, 0700, true);
					chown($dir, 'root');
					chgrp($dir, $this->group_id);
					chmod($dir, 0700);
				} else if (file_exists($file)) {
					$overwrite = true;
					$old = file_get_contents($file);
					file_put_contents($file . '-old', $old);
				}
			}
			$this->file_purge();
			file_put_contents($crtfile, $cert);
			chown($crtfile, 'root');
			chgrp($crtfile, $this->group_id);
			chmod($crtfile, 0600);
			file_put_contents($keyfile, $key);
			chown($keyfile, 'root');
			chgrp($keyfile, $this->group_id);
			chmod($keyfile, 0600);

			$chainconfig = $this->_getSSLExtraConfig();
			if ($chain) {
				if (!file_exists(dirname($chainconfig))) {
					mkdir(dirname($chainconfig), 0711);
				}
				file_put_contents($prefix . self::CRT_PATH . '/bundle.crt', $chain);
				$chainfile = join(DIRECTORY_SEPARATOR, array($prefix, self::CRT_PATH, 'bundle.crt'));
				if (file_exists($chainconfig)) {
					$contents = file($chainconfig, FILE_IGNORE_NEW_LINES);
					$newcontents = array();
					$directive = "SSLCertificateChainFile";
					foreach ($contents as $line) {

						if (0 === strpos($line, $directive)) {
							continue;
						}
						$newcontents[] = $line;
					}
					$newcontents[] = $directive . " " . $chainfile;
					file_put_contents($chainconfig, join("\n", $newcontents));
					// bundle perms don't really matter since it's public knowledge
				} else {
					file_put_contents($chainconfig, 'SSLCertificateChainFile ' . $chainfile);
				}
			}

			// pre-flight checks done, let's install
			if (!$overwrite || !$this->enabled()) {
				$cmd = new Util_Account_Editor($this->getAuthContext()->getAccount());
				$cmd->setConfig('openssl', 'enabled', 1);
				// ensure HTTP config is rebuild
				$cmd->edit();
			}
			$this->file_purge();
			\Opcenter\Http\Apache::reload();
			info("reloading web server in 2 minutes, stay tuned!");

			return true;
		}

		public function permitted()
		{
			return true;
		}

		public function enabled(): bool {
			return (bool)$this->get_service_value('openssl', 'enabled');
		}

		/**
		 * Verify that the named certificate and key
		 *
		 * @param string $cert x509 certificate
		 * @param string $pkey private key
		 * @return bool
		 */
		public function valid($cert, $pkey)
		{
			return openssl_x509_check_private_key($cert, $pkey);
		}

		/**
		 * Check if certificate issuer matches requestor
		 *
		 * @param $crt
		 * @return bool|void
		 */
		public function is_self_signed($crt)
		{
			$crt = $this->parse_certificate($crt);
			// self-signed will be suitable for
			// alternative calculation, let's evaluate this first
			if (isset($crt['purposes'])) {
				$purpose = array_shift($crt['purposes']);
				return $purpose[0] && $purpose[0] == $purpose[1];
			}
			if (!isset($crt['issuer']) || !isset($crt['subject'])) {
				return error("invalid certificate");
			}
			$a = $crt['issuer'];
			$b = $crt['subject'];

			foreach ($a as $k => $v) {
				if (!isset($b[$k]) ||
					$b[$k] != $v
				) {
					return false;
				}
			}
			return true;
		}

		/**
		 * Parse certificate and return information
		 *
		 * @param mixed $crt resource pointed by openssl_x509_read or string
		 * @return array
		 */
		public function parse_certificate($crt)
		{
			if (!$crt) {
				return error("no certificate!");
			}

			if (is_array($crt)) {
				if (isset($crt['purposes'])) {
					// assume it's already parsed
					return $crt;
				} else {
					return error("unsupported certificate data type, " .
						"got array expected: string, resource, or parsed certificate");
				}
			}
			if (!is_resource($crt)) {
				if ($this->_isDer($crt)) {
					$crt = $this->_convertDer2Pem($crt);
				}
				$crt = openssl_x509_read($crt);
				if (!$crt) {
					return error("unable to parse certificate: %s", $this->_getError());
				}
			}
			$info = openssl_x509_parse($crt);
			if (is_resource($crt)) {
				openssl_x509_free($crt);
			}
			if (!$info) {
				return error($this->_getError());
			}
			return $info;
		}

		private function _isDer($cert)
		{
			return 0 !== strpos($cert, '-----');
		}

		private function _convertDer2Pem($data)
		{
			$pem = chunk_split(base64_encode($data), 64, "\n");
			$pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";
			return $pem;

		}

		/**
		 * Copy last OpenSSL error triggered by
		 * openssl_* function to error buffer
		 * {@link Error_Reporter::add_error}
		 *
		 * @return bool
		 */
		private function _getError()
		{
			$err = openssl_error_string();
			if (!$err) {
				return true;
			}
			list($class, $code, $loc, $sym, $txt) = explode(':', $err);
			return sprintf("%s: openssl `%s': %s (%s)",
				$code, $class, $loc, $txt);
		}

		/**
		 * Resolve a certificate chain, downloading certificates as necessary
		 *
		 * @param string $crt initial certificate
		 * @return bool|string
		 */
		public function resolve_chain($crt)
		{
			$buffer = Error_Reporter::flush_buffer();
			// error out if any resolution fails
			$chain = $this->_resolveChain($crt, array());
			$isError = Error_Reporter::is_error();
			Error_Reporter::merge_buffer($buffer);
			if ($isError) {
				return false;
			}
			// remove initial cert returning
			// resulting chain
			array_pop($chain);
			return join("\n", $chain);

		}

		private function _resolveChain($crt, $seen)
		{
			/**
			 * Some vendors, like GeoTrust supply a DER-formatted certificate
			 */
			if ($this->_isDer($crt)) {
				$crt = $this->_convertDer2Pem($crt);
			}

			if ($this->is_self_signed($crt)) {
				// terminated endpoint
				return array($crt);
			}
			$info = $this->parse_certificate($crt);

			if (!isset($info['extensions'])) {
				return array();
			} else {
				if (!isset($info['extensions']['subjectKeyIdentifier'])) {
					error("missing subjectKeyIdentifier fingerprint!");
				}
			}
			$fingerprint = $info['extensions']['subjectKeyIdentifier'];

			if (array_search($fingerprint, $seen)) {
				return error("chain loop detected, fingerprint: %s", $fingerprint);
			}
			$seen[] = $fingerprint;

			$extensions = $info['extensions'];
			if (!isset($extensions['authorityInfoAccess'])) {
				// no further keys
				return array();
			}

			if (!preg_match_all(Regex::SSL_CRT_URI, $extensions['authorityInfoAccess'], $matches)) {
				error("can't find URI to match in authorityInfoAccess: %s",
					$extensions['authorityInfoAccess']);
				return array();
			}

			// in certain situations, OCSP is prefixed with URI, defeating the regex
			// so a second pass to look for a non-OCSP URL
			$url = $matches['url'][0];
			foreach ($matches['url'] as $candidate) {
				if (false !== stripos($candidate, "ocsp")) {
					continue;
				}
				$url = $candidate;
			}

			$chainedcrt = $this->_downloadChain($url);
			if (!$chainedcrt) {
				error("failed to resolve chain!");
				return array();
			}

			info("downloaded extra chain `%s'", $url);
			return array_merge(
				$this->_resolveChain($chainedcrt, $seen),
				(array)$crt
			);
		}

		/**
		 * Download a certificate to resolve a chain
		 *
		 * @param $url
		 * @return mixed
		 * @throws Exception
		 */
		private function _downloadChain($url)
		{
			if (extension_loaded('curl')) {
				$adapter = new HTTP_Request2_Adapter_Curl();
			} else {
				$adapter = new HTTP_Request2_Adapter_Socket();
			}

			$http = new HTTP_Request2(
				$url,
				HTTP_Request2::METHOD_GET,
				array(
					'adapter' => $adapter
				)
			);

			try {
				$response = $http->send();
				$code = $response->getStatus();
				switch ($code) {
					case 200:
						break;
					case 403:
						return error("URL request forbidden by server");
					case 404:
						return error("URL not found on server");
					case 302:
						$newLocation = $response->getHeader('location');
						return $this->_downloadChain($newLocation);
					default:
						return error("URL request failed, code `%d': %s",
							$code, $response->getReasonPhrase());
				}
				// this returns nothing as xfer is saved directly to disk
				$cert = $response->getBody();
			} catch (HTTP_Request2_Exception $e) {
				return error("fatal error retrieving URL: `%s'", $e->getMessage());
			}
			return $cert;
		}

		/**
		 * Verify cert2 is a chain to cert1
		 *
		 * @param mixed $cert1 ssl certificate
		 * @param mixed $cert2 ssl certificate
		 * @return int 1 if cert2 is intermediate of cert1, -1 if cert1 intermediate of cert2, 0 if no match
		 */
		public function verify_certificate_chain($cert1, $cert2)
		{
			$resp = $this->_verify_certificate_chain_real($cert1, $cert2);
			if ($resp || null === $resp) {
				return (int)$resp;
			}

			return $this->_verify_certificate_chain_real($cert2, $cert1) ? -1 : 0;
		}

		/**
		 * Actual chain verification logic
		 *
		 * @param mixed $cert1
		 * @param mixed $cert2
		 * @return int|null
		 */
		private function _verify_certificate_chain_real($cert1, $cert2)
		{
			// basicConstraints: CA:TRUE or FALSE
			// if CA:FALSE, authorityKeyIdentifier refers to chain
			// if CA:TRUE, subjectKeyIdentifier == crt authorityKeyIdentifier

			$icert = $this->parse_certificate($cert1);
			$ichain = $this->parse_certificate($cert2);
			if (!isset($ichain['extensions'])) {
				return null;
			}
			$keyidentifier = $icert['extensions']['authorityKeyIdentifier'];
			if (0 === strpos($keyidentifier, "keyid:")) {
				$keyidentifier = trim(substr($keyidentifier, 6));
			}
			if ($keyidentifier == $ichain['extensions']['subjectKeyIdentifier']) {
				return 1;
			}
			return 0;
		}

		private function _getSSLExtraConfig()
		{
			return $this->web_site_config_dir() . '.ssl/custom';
		}

		public function delete($key, $crt, $chain = null)
		{
			if (!IS_CLI) {
				return $this->query('ssl_delete', $key, $crt, $chain);
			}
			// flipped argument order
			if (substr($key, -4) == ".crt" && substr($crt, -4) == ".key") {
				$tmp = $crt;
				$crt = $key;
				$key = $tmp;
			}
			if (!$this->get_certificate($crt)) {
				return error("invalid certificate `%s' specified", $crt);
			} else {
				if (!$this->get_private_key($key)) {
					return error("invalid private key `%s' specified", $key);
				}
			}
			if ($chain && !$this->get_certificate($chain)) {
				return error("invalid certificate chain `%s' specified", $chain);
			}
			if (!$this->_delete_wrapper($crt)) {
				// return on crt, since http config builder depends on .crt
				// presence to include SSL support
				return error("failed to delete certificate `%s'", $crt);
			}

			if (!$this->_delete_wrapper($key)) {
				warn("failed to remove ssl key `%s'", $key);
			}

			if ($chain && !$this->_delete_wrapper($chain)) {
				warn("failed to remove ssl chain certficiate `%s'", $chain);
			}
			$sslextra = $this->_getSSLExtraConfig();

			if (file_exists($sslextra)) {
				$contents = file_get_contents($sslextra);
				$newconfig = array();
				foreach (explode("\n", $contents) as $line) {
					if (preg_match('!/' . preg_quote($chain, '!') . '$!', $line)) {
						info("detected and removed certificate chain from http config");
						continue;
					}
					$newconfig[] = $line;
				}
				file_put_contents($sslextra, join("\n", $newconfig));
			}
			// reload HTTP server and rebuild config
			$editor = new Util_Account_Editor($this->getAuthContext()->getAccount());
			$editor->setConfig('openssl', 'enabled', 0);
			$status = $editor->edit();
			if (!$status) {
				return error("failed to deactivate openssl on account");
			}
			$proc = new Util_Process_Schedule('now');
			return $proc->run('/sbin/service httpd reload');
		}

		/**
		 * Get raw certificate
		 *
		 * @param string $name certificate name
		 * @return bool|string
		 */
		public function get_certificate($name = 'server.crt')
		{
			if (!IS_CLI) {
				return $this->query('ssl_get_certificate', $name);
			}
			$name = basename($name, ".crt");
			if ($this->permission_level & PRIVILEGE_SITE) {
				$file = $this->domain_fs_path() . self::CRT_PATH .
					'/' . $name . '.crt';
			} else {
				if ($name[0] != '/') {
					$file = self::CRT_PATH . $name . '.crt';
				} else {
					$file = $name . '.crt';
				}
			}

			if (!file_exists($file)) {
				return error("certificate `%s' does not exist", $name);
			}
			return file_get_contents($file);
		}

		public function get_private_key($name = 'server.key')
		{
			if (!IS_CLI) {
				return $this->query('ssl_get_private_key', $name);
			}
			$name = basename($name, ".key");
			if ($this->permission_level & PRIVILEGE_SITE) {
				$file = $this->domain_fs_path() . self::KEY_PATH .
					'/' . $name . '.key';
			} else {
				if ($name[0] != '/') {
					$file = self::KEY_PATH . $name . '.key';
				} else {
					$file = $name . '.key';
				}
			}

			if (!file_exists($file)) {
				return error("private key `%s' does not exist", $name);
			}
			return file_get_contents($file);
		}

		private function _delete_wrapper($file)
		{
			$prefix = $this->domain_fs_path();
			$ext = substr($file, -4);
			switch ($ext) {
				case '.key':
					$folder = self::KEY_PATH;
					break;
				case '.csr':
					$folder = self::CSR_PATH;
					break;
				case '.crt':
					$folder = self::CRT_PATH;
					break;
				default:
					return error("cannot delete SSL asset: unknown extension `%s'", $ext);
			}
			$file = join(DIRECTORY_SEPARATOR, array($prefix, $folder, $file));
			if (!file_exists($file)) {
				return false;
			}
			return unlink($file);
		}

		/**
		 * Generate new private key
		 *
		 * @param int $bits
		 * @return string
		 */
		public function generate_privatekey($bits = 2048)
		{
			$bits = intval($bits);
			$pow = log($bits) / log(2);
			if ($pow - ceil($pow) > 0) {
				return error("pkey bits %d invalid", $bits);
			} else {
				if ($bits < 384) {
					return error("pkey must be at least 384 bits");
				} else {
					if ($bits > 8192) {
						return error("8192 bit pkey limit");
					}
				}
			}
			$digestalg = 'sha1';
			if (function_exists('openssl_get_md_methods')) {
				$methods = openssl_get_md_methods();
				if (in_array('sha512', $methods)) {
					$digestalg = 'sha512';
				} else {
					if (in_array('sha256', $methods)) {
						$digestalg = 'sha256';
					} else {
						if (!in_array('sha1', $methods)) {
							return error("no suitable digest method found for privkey generation");
						}
					}
				}
			}

			$opts = array(
				'private_key_bits' => $bits,
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
				'digest_alg'       => $digestalg
			);
			$res = openssl_pkey_new($opts);
			if (!$res) {
				return error("private key generation failed! error: %s",
					$this->_getError());
			}
			openssl_pkey_export($res, $key);
			openssl_pkey_free($res);
			return $key;
		}

		/**
		 * Generate certificate signing request for a CA
		 *
		 * @param string $privkey  private key
		 * @param string $host     common name for which the SSL certificate is valid
		 * @param string $country  2-letter country code
		 * @param string $state    state
		 * @param string $locality city/province
		 * @param string $org      optional organization
		 * @param string $orgunit  optional organizational unit (company section)
		 * @param string $email    contact e-mail
		 * @return string certificate signing request
		 */
		public function generate_csr(
			$privkey,
			$host,
			$country = '',
			$state = '',
			$locality = '',
			$org = '',
			$orgunit = '',
			$email = ''
		) {
			$sinfo = array(
				'countryName'            => strtoupper((string)$country),
				'stateOrProvinceName'    => $state,
				'localityName'           => $locality,
				'organizationName'       => $org,
				'organizationalUnitName' => $orgunit,
				'commonName'             => $host,
				'emailAddress'           => $email
			);
			if (!preg_match(Regex::DOMAIN_WC, $host)) {
				return error("invalid hostname `%s'", $host);
			} else if ($sinfo['countryName'] && (!ctype_alpha($sinfo['countryName']) ||
					strlen($sinfo['countryName']) != 2))
			{
				return error("invalid 2-character country `%s'",
					$sinfo['countryName']);
			} else if (!$sinfo['stateOrProvinceName']) {
				return error("no state value specified");
			} else if (!$sinfo['localityName']) {
				return error("missing state/locality name");
			} else if (strlen($sinfo['emailAddress']) > 0 &&
				!preg_match(Regex::EMAIL, $sinfo['emailAddress']))
			{
				return error("invalid e-mail address `%s'",
					$sinfo['emailAddress']);
			}
			foreach ($sinfo as $k => $v) {
				if (!$v) {
					unset($sinfo[$k]);
				}
			}
			$privkey = trim($privkey);
			if (!openssl_get_privatekey($privkey)) {
				return error("could not get key structure " .
					"from private key");
			}

			$cnf = array();
			$res = openssl_pkey_get_private($privkey);
			$csr = openssl_csr_new($sinfo, $res, $cnf);
			if (!$csr) {
				return error($this->_getError());
			}

			$txt = null;
			if (!openssl_csr_export($csr, $txt)) {
				return error($this->_getError());
			}
			return $txt;
		}

		/**
		 * Get certificate signing request parameters
		 *
		 * Sample response:
		 *   array(7) {
		 *   ["C"]=>
		 *   string(2) "US"
		 *   ["ST"]=>
		 *   string(7) "Georgia"
		 *   ["L"]=>
		 *   string(7) "Lilburn"
		 *   ["O"]=>
		 *   string(13) "Apis Networks"
		 *   ["OU"]=>
		 *   string(4) "Test"
		 *   ["CN"]=>
		 *   string(8) "test.com"
		 *   ["emailAddress"]=>
		 *   string(25) "msaladna@apisnetworks.com"
		 *   }
		 *
		 * @param string $csr
		 * @return array req parameters using shorthand notation
		 */
		public function request_info($csr)
		{
			$res = openssl_csr_get_subject($csr);
			if (!$res) {
				return error($this->_getError());
			}
			return $res;
		}

		/**
		 * Get public key from certificate
		 *
		 * Array (
		 * [bits] => 4096
		 * [key] => -----BEGIN PUBLIC KEY-----
		 *        ...
		 *      ...
		 *    [rsa] => Array ( [n] => .., [e] => ..,)
		 *  [type] => 0
		 *
		 * @param string $name certificate name
		 * @return array|bool
		 */
		public function get_public_key($name)
		{
			if (!IS_CLI) {
				return $this->query('ssl_get_public_key', $name);
			}
			$name = basename($name, ".key");
			$key = $this->get_certificate($name);
			if (!$key) {
				return error("unable to get named certificate `%s'", $name);
			}
			$res = openssl_pkey_get_public($key);
			$details = openssl_pkey_get_details($res);
			openssl_pkey_free($res);

			return $details;

		}

		/**
		 * Order a mixed arrangement of certificates in ascending order to root
		 *
		 * @param array $certs
		 * @return array
		 */
		public function order_certificates(array $certs)
		{
			foreach ($certs as $cert) {

			}
		}

		public function get_csr($name)
		{
			if (!IS_CLI) {
				return $this->query('ssl_get_csr', $name);
			}
			$name = basename($name, ".csr");
			if ($this->permission_level & PRIVILEGE_SITE) {
				$file = $this->domain_fs_path() . self::CSR_PATH .
					'/' . $name . '.csr';
			} else {
				if ($name[0] != '/') {
					$file = self::CSR_PATH . $name . '.csr';
				} else {
					$file = $name . '.csr';
				}
			}

			if (!file_exists($file)) {
				return error("certificate request `%s' does not exist", $name);
			}
			return file_get_contents($file);

		}

		/**
		 * Create a self-signed certificate
		 *
		 * @param string $csr     certificate signing request {@link generate_csr}
		 * @param string $privkey private key to sign certificate
		 * @param int    $days    number days valid
		 * @param float  $serial  serial number
		 * @return string signed certificate
		 */
		public function sign_certificate(
			$csr,
			$privkey,
			$days = 365,
			$serial = null
		) {
			$days = intval($days);
			if ($days > 365 * 5) {
				return error("max certificate validity 5 years");
			} else {
				if ($days < 1) {
					return error("invalid certificate validity");
				}
			}
			$csr = trim($csr);
			if (!$serial) {
				$serial = sprintf("%s", date_format(new DateTime(), 'YmdHis'));
			}
			$serial = (int)$serial;
			if (floatval($serial) != $serial) {
				return error("non-numeric `%s' serial specified", $serial);
			}
			if (!openssl_csr_get_public_key($csr)) {
				return error("invalid CSR");
			}

			$crt = openssl_csr_sign($csr, null, $privkey, $days, array(), $serial);

			if (!$crt) {
				return error($this->_getError());
			}
			if (!openssl_x509_export($crt, $certout)) {
				return error($this->_getError());
			}
			return $certout;

		}

		/**
		 * Verify the given private key matches the self-signed certificate
		 *
		 * @param string $crt
		 * @param string $privkey
		 * @return bool
		 */
		public function verify_x509_key($crt, $privkey)
		{
			return openssl_x509_check_private_key($crt, $privkey);
		}

		public function verify_key($key)
		{
			if (!$key) {
				return error("no key specified");
			}
			$info = $this->privkey_info($key);
			if (!$info) {
				return error("invalid key detected");
			}
			return true;
		}

		/**
		 * Get private key details
		 *
		 * @param $privkey
		 * @return array
		 */
		public function privkey_info($privkey)
		{
			$res = openssl_pkey_get_private($privkey);
			$details = openssl_pkey_get_details($res);
			return $details;
		}

		/**
		 * Get hostnames for which a certificate is valid
		 *
		 * @param resource|string $certificate
		 * @return array
		 */
		public function get_alternative_names($certificate)
		{
			$certificate = $this->parse_certificate($certificate);
			if (!is_array($certificate)) {
				return error("invalid certificate");
			}
			$commonname = $certificate['subject']['CN'];
			$extensions = array($commonname);
			if (isset($certificate['extensions']) && isset($certificate['extensions']['subjectAltName'])) {
				$alt = $certificate['extensions']['subjectAltName'];
				foreach (explode(",", $alt) as $name) {
					$name = trim($name);
					if (strncmp($name, "DNS:", 4)) {
						report("gibberish line? %s certificate: %s",
							$name,
							var_export($certificate, true)
						);
						continue;
					}
					$tmp = substr($name, 4);
					if ($tmp !== $commonname) {
						$extensions[] = $tmp;
					}
				}
			}
			return $extensions;
		}

		public function _create()
		{
			$this->_edit();
		}

		public function _edit()
		{
			$conf_new = $this->getAuthContext()->getAccount()->new;
			$conf_cur = $this->getAuthContext()->getAccount()->cur;
			$domainprefix = $this->domain_fs_path();
			$renameWrapper = function ($mode) use ($domainprefix) {
				$certdir = $domainprefix . self::CRT_PATH;
				if ($mode === 'disable') {
					foreach (glob($certdir . '/*.crt') as $cert) {
						rename($cert, $cert . '-disabled');
						info("disabled certificate " . basename($cert));
					}
					return;
				}
				$pkeyfile = $domainprefix . self::KEY_PATH . '/server.key';
				if (!file_exists($pkeyfile)) {
					// cert won't work without private key
					return false;
				}
				$pkey = file_get_contents($pkeyfile);
				foreach (glob($certdir . '/*.crt-disabled') as $cert) {
					$crt = file_get_contents($cert);
					$file = basename($cert);
					// server.crt is hardcoded SSL CRT
					if ($file === "server.crt" && !$this->valid($crt, $pkey)) {
						info("removing dangling certificate `%s' that does not match pkey modulus", $cert);
						unlink($cert);
						// using certificate will break site
						continue;
					}
					rename($cert, substr($cert, 0, -9));
					info("enabled certificate " . substr(basename($cert), 0, -9));
				}
			};

			$ssl = \Opcenter\SiteConfiguration::getModuleRemap('openssl');
			if (version_compare(platform_version(), '6', '>=')) {
				// Luna and on do things differently
				if (!$conf_new[$ssl]['enabled']) {
					$renameWrapper('disable');
				} else if ($conf_new[$ssl]['enabled'] && !$conf_cur[$ssl]['enabled']) {
					$renameWrapper('enable');
				}
				return;
			}
			if (!$conf_cur['ipinfo']['namebased'] && $conf_new['ipinfo']['namebased'] ||
				!$conf_new[$ssl]['enabled'] && $conf_cur[$ssl]['enabled']
			) {
				$renameWrapper('disable');
			} else {
				if (!$conf_new['ipinfo']['namebased']) {
					$ssl = dirname($this->_getSSLExtraConfig());
					if (!file_exists($ssl)) {
						mkdir($ssl, 0711);
					}
					$renameWrapper('enable');

				}
			}
		}

		private function _convertPem2Der($data)
		{
			$begin = "CERTIFICATE-----";
			$end = "-----END";
			$data = substr($data, strpos($data, $begin) + strlen($begin));
			$data = substr($data, 0, strpos($data, $end));
			$der = base64_decode($data);
			return $der;
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}

		public function _delete()
		{
			// TODO: Implement _delete() method.
		}

		public function _create_user(string $user)
		{
			// TODO: Implement _create_user() method.
		}

		public function _delete_user(string $user)
		{
			// TODO: Implement _delete_user() method.
		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			// TODO: Implement _edit_user() method.
		}


	}