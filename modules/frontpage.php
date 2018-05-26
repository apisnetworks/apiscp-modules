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
	 * Microsoft FrontPage Server Extensions 2002
	 *
	 * @author Matt Saladna <matt@apisnetworks.com>
	 */
	class Frontpage_Module extends Module_Skeleton
	{

		public $exportedFunctions = array(
			'*' => PRIVILEGE_SITE,
		);

		public function disable($domain = null)
		{
			if (!IS_CLI) {
				return $this->query('frontpage_disable', $domain);
			}
			$domain = $this->_canonicalizeDomain($domain);

			$path = $this->web_get_docroot($domain);

			if (!$path) {
				return error("unknown domain `$domain'");
			}

			$enabled = $this->enabled($domain);
			if (!$enabled) {
				return true;
			}

			$paths = (array)$this->get_config('frontpage', 'paths');
			$domains = (array)$this->get_config('frontpage', 'domains');

			Util_Process_Safe::exec('/usr/local/frontpage/currentversion/bin/owsadm.exe ' .
				'-o uninstall -p 80 -m www.%s',
				$domain);
			$status = Util_Process_Safe::exec('find %s -maxdepth 1  -type d -a -regex ' .
				'\'%s\' -exec rm -rf {} \\; ' .
				'-printf "Removed %%P\n"',
				$this->domain_fs_path() . '/' . $path,
				'.*/\\(_vti_\\(cnf\\|log\\|pvt\\|bin\\|txt\\)\\)\\|.*/_private'
			);
			// remove fp web
			$key = array_search($path, $paths);
			if ($key !== false) {
				unset($paths[$key]);
			}
			$key = array_search($domain, $domains);
			if ($key !== false) {
				unset($domains[$key]);
			}
			$link = '/usr/local/frontpage/' . $domain . ':80.cnf';
			if (file_exists($link)) {
				unlink($link);
			}

			$link = '/usr/local/frontpage/www.' . $domain . ':80.cnf';
			if (file_exists($link)) {
				unlink($link);
			}

			$this->set_config('frontpage', 'enabled', count($domains) > 0);
			$this->set_config('frontpage', 'paths', $paths);
			$this->set_config('frontpage', 'domains', $domains);
			return $status['success'];
		}

		/**
		 * bool get_frontpage_status()
		 *
		 * @return bool
		 */
		public function enabled($domain = null)
		{
			if (!$domain) {
				return $this->get_service_value('frontpage', 'enabled');
			}
			if (!$domain) {
				$domain = $this->domain;
			}
			return in_array($domain, (array)$this->get_service_value('frontpage', 'domains'));

		}

		/**
		 *  Toggle Microsoft FrontPage Server Extensions per domain
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function enable($domain = null)
		{
			if (!IS_CLI) {
				return $this->query('frontpage_enable', $domain);
			}
			$domain = $this->_canonicalizeDomain($domain);

			$path = $this->web_get_docroot($domain);

			if (!$path) {
				return error("unknown domain `$domain'");
			}

			$enabled = $this->enabled($domain);
			if ($enabled) {
				return true;
			}

			$paths = (array)$this->get_config('frontpage', 'paths');
			$domains = (array)$this->get_config('frontpage', 'domains');
			$status = Util_Process_Safe::exec('/usr/local/sbin/enable_fp.sh %s %s',
				$domain,
				$path
			);
			$link = '/usr/local/frontpage/' . $domain . ':80.cnf';
			symlink('/usr/local/frontpage/www.' . $domain . ':80.cnf', $link);
			$domains[] = $domain;
			$paths[] = $path;

			$this->set_config('frontpage', 'enabled', count($domains) > 0);
			$this->set_config('frontpage', 'paths', $paths);
			$this->set_config('frontpage', 'domains', $domains);
			return $status['success'];
		}

		public function get_active_domains()
		{
			return (array)$this->get_config('frontpage', 'domains');
		}

		public function _reset(Util_Account_Editor &$editor = null)
		{
			if (version_compare(platform_version(), '7', '>=')) {
				return [];
			}
			$module = 'frontpage';
			$params = array(
				'paths'   => array(),
				'enabled' => 0,
				'domains' => array()
			);
			if ($editor) {
				foreach ($params as $k => $v) {
					$editor->setConfig($module, $k, $v);
				}
			}
			return array($module => $params);
		}

		private function _canonicalizeDomain($domain)
		{
			$domain = strtolower($domain);
			if (substr($domain, 0, 4) == "www.") {
				$domain = substr($domain, 4);
			}
			return $domain;
		}
	}

?>
