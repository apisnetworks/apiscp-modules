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
     * CloudFlare integration utilities
     *
     * @author  Matt Saladna <matt@apisnetworks.com>
     * @package core
     */
    class Cloudflare_Module extends Module_Skeleton
    {
        // CloudFlare API key
        // @ignore
        const ENDPOINT = 'https://api.cloudflare.com/host-gw.html';
        private static $_API_KEY = CLOUDFLARE_API_KEY;

        // CF endpoint URL
        private static $_API_USER = CLOUDFLARE_API_USER;
        public $exportedFunctions = array(
            '*' => PRIVILEGE_SITE
        );

        public function __construct()
        {
            parent::__construct();
        }

        /**
         * Create a new CloudFlare user
         *
         * @param string|null $email
         * @param null        $passwd
         * @return bool
         */
        public function create($email = null, $passwd)
        {
            if (!($key = $this->_getCredentials())) {
                return error("account exists - api key `%s'", $key['key']);
            }
            if (!$email) {
                $email = $this->get_config('siteinfo', 'email');
            } else {
                if (!preg_match(Regex::EMAIL, $email)) {
                    return error("invalid email address provided `%s'", $email);
                }
            }

            $cf = $this->_getProviderAPI();
            $id = $this->_getUniqueID();
            $resp = $cf->create_user($email, $passwd, null, $id);
            if (!$this->_isSuccess($resp)) {
                return error("user creation failed - `%s'",
                    $this->_getFailureReason($resp));
            }
            $resp = $this->_parse($resp);
            $prefs = $this->common_load_preferences();
            if (!isset($prefs['cloudflare'])) {
                $prefs['cloudflare'] = array();
            }
            $prefs['cloudflare']['key'] = $resp['user_api_key'];
            $prefs['cloudflare']['uniqid'] = $resp['unique_id'];
            $prefs['cloudflare']['user'] = $resp['user_key'];
            $prefs['cloudflare']['email'] = $resp['cloudflare_email'];
            $this->common_save_preferences($prefs);
            return $resp['user_api_key'];
        }

        private function _getCredentials()
        {
            $prefs = $this->common_load_preferences();
            if (!isset($prefs['cloudflare']) || !isset($prefs['cloudflare']['key'])) {
                return false;
            }
            return $prefs['cloudflare'];
        }

        /**
         * Get CF provider API implementation
         *
         * @return \Cloudflare\Provider
         */
        private function _getProviderAPI()
        {
            $api = new Cloudflare\Provider(self::$_API_KEY);
            return $api;
        }

        private function _getUniqueID()
        {
            $subscription = $this->billing_get_hosting_subscription();
            $pos = strpos($subscription, '-');
            return $pos ? substr($subscription, ++$pos) : null;
        }

        private function _isSuccess(stdClass $resp)
        {
            return $resp->result === "success";
        }

        /**
         * Get failure reason from response
         *
         * @param stdClass $resp CF response
         * @return string|null      message
         */
        private function _getFailureReason($resp)
        {
            if (is_debug()) {
                var_dump($resp);
            }
            if (is_array($resp) && $resp['error']) {
                $msg = "API communication error: " . $resp['error'];
                Error_Reporter::report($msg);
                return $msg;
            }
            if (!isset($resp->msg)) {
                Error_Reporter::report(var_export($resp, true));
                return error("arg is not a valid CF response");
            }

            if ($this->_isSuccess($resp)) {
                return null;
            }

            return $resp->msg;
        }

        /**
         * Parse a response object to array
         *
         * @param stdClass $resp
         * @return array
         */
        private function _parse(stdClass $resp)
        {
            if (!$this->_isSuccess($resp)) {
                return array();
            }
            return (array)$resp->response;
        }

        /**
         * Add a zone to CF management
         *
         * @param string $zone       zone name
         * @param array  $subdomains subdomains that CF should host, if blank copy all active subdomains
         * @return bool|array failure or target nameservers
         */
        public function add_zone($zone, array $subdomains = array(), $resolve_to = null)
        {
            if (!$this->web_domain_exists($zone)) {
                return error("domain `%s' is not owned by this account", $zone);
            }

            if (!($creds = $this->_getCredentials())) {
                return error("cannot add cf zone `%s', no account registered",
                    $zone
                );
            }
            // full zone hosting
            if (!$subdomains && $resolve_to) {
                $recs = $this->dns_get_records_by_rr('A', $zone);
                $subdomains = array_column($recs, 'subdomain');
            }
            $myresolve_to = $resolve_to;
            if (!$resolve_to) {
                $myresolve_to = 'CF-' . $this->_generateRandom(32);
                if ($this->dns_record_exists($zone, $myresolve_to, 'A')) {
                    return error("random resolve_to generator failed, record `%s' already exists",
                        $myresolve_to);

                }
                $ip = $this->common_get_ip_address();
                if (!$this->dns_add_record($zone, $myresolve_to, 'A', $this->common_get_ip_address(), 43200)) {
                    return error("failed to set secure resolve_to from `%s' to `%s'",
                        $myresolve_to,
                        $ip
                    );
                }
            } else {
                if ($resolve_to === $zone) {
                    return error("filtered connections must resolve to a subdomain and " .
                        "may not not resolve to the zone name itself");
                } else {
                    if (!$this->dns_gethostbyname_t($resolve_to)) {
                        return error("failed to resolve target CNAME `%s' to IP address",
                            $resolve_to
                        );
                    }
                }
            }
            // leave subdomain suitability up to CF
            // subdomains may consist of just a subdomain or optional resolve_to
            // param delimited by :

            $resolved = array();
            foreach ($subdomains as $sub) {
                if (false === ($pos = strpos($sub, ':'))) {
                    continue;
                }
                $target = substr($sub, ++$pos);
                if (isset($resolved[$target])) {
                    continue;
                }
                if (!$this->dns_gethostbyname_t($target)) {
                    warn("subdomain `%s' cname `%s' is irresolvable", $sub, $target);
                }
                $resolved[$target] = 1;
            }

            $api = $this->_getProviderAPI();
            $resp = $api->zone_set($creds['user'], $zone, $resolve_to, $subdomains);
            if (!$this->_isSuccess($resp)) {
                if (!$resolve_to) {
                    $this->dns_remove_record($zone, $subdomains['target'], "CNAME");
                    $this->dns_remove_record($zone, $subdomains['source'], "A");
                }

                return error("failed to add zone `%s', error: (%s) %s",
                    $zone,
                    strtoupper($resp->err_code),
                    $this->_getFailureReason($resp)
                );
            }
            if ($this->email_transport_exists($zone)) {
                info("IMPORTANT: CloudFlare cannot be used to hide your domain name when email " .
                    "is active for this domain. You must disable email for this domain or use a " .
                    "third-party to host email to hide your server address. Visit Mail > Mail Routing " .
                    "to disable email on the domain.");
            }
            $ret = $this->_parse($resp);
            $matches = array();
            if ($resolve_to) {
                $len = strlen($zone) + 1;
                foreach ($ret['forward_tos'] as $key => $dest) {
                    $sub = substr($key, 0, -$len);
                    if ($this->dns_record_exists($zone, $sub, 'A')) {
                        $this->dns_remove_record($zone, $sub, 'A');
                    }

                    if ($this->dns_record_exists($zone, $sub, 'CNAME')) {
                        warn("clobbered existing CNAME record for subdomain `%s'", $sub);
                        $this->dns_remove_record($zone, $sub, 'CNAME');
                    }

                    if (!$this->dns_add_record($zone, $sub, 'CNAME', $dest)) {
                        $hostname = ltrim($sub . '.' . $zone, ".");
                        error("failed to forward `%s' to CF target `%s'",
                            $hostname,
                            $dest
                        );
                    }
                }
                return info("DNS records have been set for %s. Only these hostnames will forward to CF.",
                    join(", ", $subdomains)
                );
            }
            if (!preg_match_all(Regex::CLOUDFLARE_NAMESERVER_TARGET, $ret['msg'], $matches, PREG_PATTERN_ORDER)) {
                return info("zone succeeded, but could not find nameservers to set - login to cloudflare.com to complete setup");
            }
            $ns = join(", ", $matches[0]);
            info("zone setup complete - change the nameservers to %s to finalize your setup", $ns);
            return $matches[0];
        }

        private function _generateRandom($min = 16, $max = null)
        {
            if (!$max) {
                $max = $min;
            }
            if ($min > $max) {
                warn("min > max, set min = max (%d)", $min);
                $max = $min;
            }
            $chars = "0123456789abcdefghijklmnopqrstuvwxyz";
            $tmp = array();
            if ($min != $max) {
                $n = mt_rand(0, $max);
            } else {
                $n = $min;
            }

            for ($i = 0, $rng = strlen($chars) - 1; $i < $n; $i++) {
                $tmp[] = $chars[mt_rand(0, $rng)];
            }
            return join("", $tmp);
        }

        /**
         * Remove a hosted CF zone
         *
         * Removal will succeed whether a zone is properly hosted
         * or not, this is a CF API limitation
         *
         * @param $zone
         * @return bool
         */
        public function remove_zone($zone)
        {
            if (!$this->web_domain_exists($zone)) {
                return error("domain `%s' is not owned by this account", $zone);
            }

            $creds = $this->_getCredentials();
            $api = $this->_getProviderAPI();

            // before deleting the zone, take a peak at

            $info = $this->get_zone_info($zone);
            var_dump($info);
            $resp = $api->zone_delete($creds['user'], $zone);
            if (!$this->_isSuccess($resp)) {
                return error("failed to delete zone `%s': %s",
                    $zone,
                    $this->_getFailureReason($resp)
                );
            }

            $ret = $this->_parse($resp);
            if (!$ret['zone_deleted']) {
                return warn("CF reported zone removal failed");
            }

            // clean-up forwards and remap to A
            $map = array();
            $trim = strlen($zone) + 1;
            foreach ((array)$info['hosted_cnames'] as $src => $dest) {
                if (!isset($map[$dest])) {
                    $ip = $this->dns_gethostbyname_t($dest, 2500);
                    $map[$dest] = $ip;
                }
                $ip = $map[$dest];
                $subdomain = substr($src, 0, -$trim);
                if ($this->dns_record_exists($zone, $subdomain, 'CNAME')) {
                    $this->dns_remove_record($zone, $subdomain, 'CNAME');
                }
                if (!$this->dns_add_record($zone, $subdomain, 'A', $ip)) {
                    warn("failed to add subdomain A record `%s' with value `%s'",
                        $subdomain,
                        $ip);
                }
            }
            return info("CF no longer manages DNS for zone `%s', change nameservers for domain back to %s",
                $zone,
                join(", ", $this->dns_get_hosting_nameservers())
            );
        }

        public function get_zone_info($zone)
        {
            $creds = $this->_getCredentials();
            $api = $this->_getProviderAPI();
            $resp = $api->zone_lookup($creds['user'], $zone);
            if (!$this->_isSuccess($resp)) {
                return error("failed to retrieve zone info for `%s'",
                    $this->_getFailureReason($resp));
            }
            $ret = $this->_parse($resp);
            return $ret;
        }

        /**
         * Verify that zone is hosted through CF
         *
         * CF only returns an affirmative if nameservers are delegated
         *
         * @param $zone
         * @return bool
         */
        public function is_hosted($zone)
        {
            $info = $this->get_zone_info($zone);
            if (!$info) {
                return false;
            }
            return (bool)$info['zone_hosted'];
        }

        public function delete($key = null)
        {
            return error("cloudflare api lacks ability to delete users");
        }

        /**
         * Get CF client API implementation
         *
         * @return bool|\Cloudflare\Api
         */
        private function _getClientAPI()
        {
            $cred = $this->_getCredentials();
            if (!$cred) {
                return false;
            }
            $api = new Cloudflare\Api($cred['email'], $cred['key']);
            return $api;
        }
    }

?>
