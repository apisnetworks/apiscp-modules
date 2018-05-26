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
	 * Ruby, RoR features formerly under Web_Module
	 *
	 * @package core
	 */
	class Ruby_Module extends Module_Skeleton
	{
		const RUBY_DIR = '/usr/local/lib/ruby';
		const RUBY_VERSION_FULL = '1.9.1';
		const RUBY_VERSION = '1.9';

		public $exportedFunctions = array('*' => PRIVILEGE_SITE);

		/**
		 * bool ruby_on_rails_enabled (void)
		 * Checks to see if Ruby on Rails support is enabled for a domain
		 *
		 * @return bool
		 */
		public function rails_installed()
		{
			if (!$this->ssh_enabled()) {
				return false;
			}
			return $this->get_gem('rails', true);
		}

		public function get_gem($gem, $local = false)
		{
			if (!$local) {
				$gems = $this->list_remote_gems();
			} else {
				$gems = $this->list_installed_gems();
			}
			if (!isset($gems[$gem])) {
				return array();
			}
			return $gems[$gem];
		}

		public function list_remote_gems()
		{
			if (file_exists(TEMP_DIR . '/gems-cache') && (is_debug() ||
					(time() - filemtime(TEMP_DIR . '/gems-cache')) < 86400 * 5)
			) {
				$data = unserialize(file_get_contents(TEMP_DIR . '/gems-cache'));
				return $data;
			}
			$status = Util_Process::exec("unset GEM_HOME; env HOME='/tmp/' /usr/bin/gem list --remote -d");
			if ($status instanceof Exception) {
				return $status;
			}
			$gems = array();
			$gemCount = preg_match_all('!^([^(\n]+) \(([0-9,\. ]+)\)([\s\S]+?)^\s*$\n([\s\S]+?)^$$!m',
				$status['output'], $gemsTmp);

			for ($i = 1; $i < $gemCount; $i++) {
				$gems[$gemsTmp[1][$i]] = array(
					'versions'    => array_map('trim', explode(',', $gemsTmp[2][$i])),
					'description' => trim($gemsTmp[4][$i])
				);
			}
			file_put_contents('/tmp/gems-cache', serialize($gems));
			return $gems;
		}

		/**
		 * List all installed (local) gems
		 *
		 * @param string $rubyver MAJOR.MINOR
		 * @return array
		 */

		public function list_installed_gems($rubyver = null)
		{
			if (!$rubyver) {
				$rubyver = self::RUBY_VERSION;
			}
			if (!IS_CLI) {
				$cache = Cache_Account::spawn($this->getAuthContext())->get('web:gems:i:' . $rubyver);
				if (!empty($cache)) {
					return $cache;
				}
			}

			if (!IS_CLI) {
				return $this->query('ruby_list_installed_gems', $rubyver);
			}

			$gemhome = '/usr/local/lib/ruby/gems/' . $rubyver;
			if (!file_exists($this->domain_fs_path() . $gemhome . '/gems')) {
				return error("no gems found for $rubyver");
			}
			$status = Util_Process_Sudo::exec('env GEM_PATH=%s ' .
				'gem list',
				$gemhome,
				$this->username
			);
			$gems = array();
			if (!$status['success']) {
				return $gems;
			}
			$token = strtok($status['output'], " \n");

			while ($token !== false) {
				$name = $token;
				$version = substr(strtok("\n"), 1, -1);
				$versions = false;
				if (strpos($version, ",") !== false) {
					$versions = explode(",", $version);
					$version = $versions[0];
				}
				$token = strtok(" ");
				$gems[$name] = array(
					'name'     => $name,
					'version'  => $version,
					'versions' => $versions
				);
			}
			Cache_Account::spawn($this->getAuthContext())->add(
				'web:gems:i' . $rubyver, $gems, 3600
			);
			return $gems;
		}

		/**
		 * bool ruby_exists (void)
		 * Checks to see if /usr/bin/ruby exists for a given domain
		 *
		 * @return bool
		 */
		public function exists()
		{
			return file_exists($this->domain_fs_path() . '/usr/bin/ruby');
		}

		/**
		 * bool gem_exists (void)
		 * Checks to see if /usr/bin/gem exists for use with Ruby
		 *
		 * @return bool
		 */
		public function gem_exists()
		{
			return file_exists($this->domain_fs_path() . '/usr/local/bin/gem') ||
				file_exists($this->domain_fs_path() . '/usr/bin/gem');
		}

		/**
		 * Installs Ruby, RoR, rake, and rubygems
		 *
		 * @return bool
		 */
		public function install_rails($ver = null)
		{
			if (!IS_CLI) {
				return $this->query('web_enable_ruby_on_rails', $ver);
			}
			if (!$this->ssh_enabled()) {
				return error("Pre-requisite SSH not satisfied");
			}
			if (!is_null($ver)) {
				$rbconf = APNSCP_INSTALL_PATH . '/opt/ruby-extras/' . $ver . '/rbconfig.rb';
				if (floatval($ver) != $ver || !file_exists($rbconf)) {
					return error("unknown version `$ver'");
				}
			} else {
				$ver = self::RUBY_VERSION;
			}
			$proc = Util_Process_Tee::auto(new Util_Process);
			$resp = $this->_installRails($proc, $ver);
			$proc->close();
			// only old servers need this
			if (version_compare(platform_version(), '4', '<=')) {
				if (!$this->misc_is_mounted('fcgi')) {
					$this->misc_mount_service('fcgi');
				}
			}
			return $resp;

		}

		private function _installRails(Util_Process_Tee $proc, $rubyver = null)
		{
			$rpmver = $rubyver;
			$rubylib = '/usr/local/lib/ruby/site_ruby/' . $rubyver;
			$gemhome = '/usr/local/lib/ruby/gems/' . $rubyver;
			$rbconf = $rubylib . '/rbconfig.rb';
			$rubygems = 'rubygems-1.3.7';
			$prefix = $this->domain_fs_path();
			$newruby = $upgrade = 0;
			if (!$this->ruby_exists()) {
				$newruby = 1;
			} else {
				$oldver = substr($this->version(), 0, 3);
				if ($oldver != self::RUBY_VERSION) {
					$newruby = 1;
					$upgrade = 1;
					$this->_upgradeRails($proc);
					rename($prefix . '/usr/bin/ruby', $prefix . '/usr/bin/ruby' . $oldver);
				}
			}

			if (!file_exists($this->domain_fs_path() . $rubylib)) {
				mkdir($this->domain_fs_path() . $rubylib, 0755, true);
				chown($this->domain_fs_path() . $rubylib, $this->user_id);
				chgrp($this->domain_fs_path() . $rubylib, $this->group_id);
			}
			if (!file_exists($this->domain_fs_path() . $gemhome)) {
				mkdir($this->domain_fs_path() . $gemhome, 0755, true);
				chown($this->domain_fs_path() . $gemhome, $this->user_id);
				chgrp($this->domain_fs_path() . $gemhome, $this->group_id);
				chown($this->domain_fs_path() . dirname($gemhome), $this->user_id);
				chgrp($this->domain_fs_path() . dirname($gemhome), $this->group_id);
			}
			chown($this->domain_fs_path() . dirname($rubylib), $this->user_id);
			chgrp($this->domain_fs_path() . dirname($rubylib), $this->group_id);
			chown($this->domain_fs_path() . dirname(dirname($rubylib)), $this->user_id);
			chgrp($this->domain_fs_path() . dirname(dirname($rubylib)), $this->group_id);

			if ($newruby) {
				$proc->log("Installing Ruby");

				$rubyrpms = array(
					'ruby' . $rpmver,
					'ruby' . $rpmver . '-libs',
					'ruby' . $rpmver . '-ri',
					'ruby' . $rpmver . '-devel',
					'ruby' . $rpmver . '-irb',
					'ruby' . $rpmver . '-rdoc',
				);
				foreach ($rubyrpms as $rpm) {
					Util_Process::exec("sh /root/replicatedomain.sh " . $rpm . " " . $this->domain);
				}
			}

			if (!file_exists($this->domain_fs_path() . dirname($rbconf))) {
				$this->file_create_directory(dirname($rbconf), 0755, true);
			}

			// rbconfig.rb on Apollo is OK
			if (!file_exists($this->domain_fs_path() . $rbconf) && version_compare(platform_version(), '4.5', '<')) {
				copy(APNSCP_INSTALL_PATH . '/opt/ruby-extras/' . $rubyver . '/rbconfig.rb', $prefix . $rbconf);
				chown($prefix . $rbconf, $this->user_id);
				chgrp($prefix . $rbconf, $this->group_id);
			}

			if (!file_exists($this->domain_fs_path() . '/usr/bin/ruby')) {
				copy(APNSCP_INSTALL_PATH . '/opt/ruby-extras/' . $rubyver . '/ruby', $prefix . '/usr/bin/ruby');
				chown($prefix . '/usr/bin/ruby', $this->user_id);
				chgrp($prefix . '/usr/bin/ruby', $this->group_id);
				chmod($prefix . '/usr/bin/ruby', 0755);
			}
			if (!file_exists($this->domain_fs_path() . '/usr/local/bin/ruby')) {
				$this->file_symlink('/usr/bin/ruby', '/usr/local/bin/ruby');
			}
			$sudo = Util_Process_Tee::watch(new Util_Process_Sudo);
			// RubyGems is bundled into Ruby 1.9.2, apollo (4.5) is
			// the only server to have 1.9.2
			if (version_compare(platform_version(), '4.5', '<') ||
				version_compare(platform_version(), '4.5', '=') && version_compare($rubyver, '1.8', '=')
			) {
				$proc->log("Installing RubyGems");
				$status = $proc->exec('tar -xvzf %s/var/storehouse/%s.tgz -C %s/tmp/',
					APNSCP_INSTALL_PATH, $rubygems, $this->domain_fs_path());
				$sudo->exec('cd /tmp/' . $rubygems . ' ; ruby /tmp/' . $rubygems . '/setup.rb');
			}
			if (!$this->install_gem("rails")) {
				return error("installation of Rails failed");
			}
			// Rails 3.1 requires Rack 1.3.5, 1.4 is present
			$this->install_gem('rack', '1.3.5');

			$sqlitename = 'sqlite3-ruby';
			if (version_compare(platform_version(), '4.5', '>=')) {
				$sqlitename = 'sqlite3';
			}
			$this->install_gem($sqlitename);

			$this->install_gem('rake');

			$this->install_gem('mysql2');

			$this->install_gem('therubyracer');

			if ($this->sql_enabled('pgsql')) {
				foreach (array('postgresql-devel', 'postgresql-libs') as $rpm) {
					Util_Process::exec("sh /root/replicatedomain.sh " . $rpm . " " . $this->domain);
				}
				$this->install_gem('pg');
			}
			$sudo->exec("cd /usr/local/bin && ln -sf ../lib/ruby/gems/" . $rubyver . "/bin/* ./");
			$sudo->close();
			$proc->log("Cleaning Ruby install");
			$proc->exec("rm -rf " . $this->domain_fs_path() . "/tmp/" . $rubygems);
			file_exists($this->domain_fs_path() . '/.config') && unlink($this->domain_fs_path() . '/.config');
			file_exists($this->domain_fs_path() . '/InstalledFiles') && unlink($this->domain_fs_path() . '/InstalledFiles');

			if ($upgrade) {
				$this->_migrateGems($oldver, $rubyver);
			}
			$proc->log("Done");
			return true;
		}

		public function version($full = false)
		{
			if (!IS_CLI) {
				return $this->query('ruby_version', $full);
			}
			if (!$this->ruby_exists()) {
				return false;
			}
			$version = Util_Process_Sudo::exec('ruby -e "print RUBY_VERSION"');
			$version = $version['output'];
			if (!$full) {
				return substr($version, 0, strrpos($version, '.'));
			}
			return $version;
		}

		/**
		 * install Ruby gem
		 *
		 * @param  string $gem name to install
		 * @return bool
		 */
		public function install_gem($gem, $ver = null)
		{
			if (!IS_CLI) {
				return $this->query('ruby_install_gem', $gem, $ver);
			}
			if (!preg_match('!^[a-zA-Z0-9_-]+$!', $gem)) {
				return error($gem . ": invalid gem");
			}
			$flags = '--remote ';
			$proc = Util_Process_Tee::watch(new Util_Process_Sudo);
			if ($ver) {
				$flags .= ' -v ' . escapeshellarg($ver);
			}
			$proc->log('Installing ' . $gem);

			$status = $proc->exec('gem install '
				. '--no-ri --no-rdoc %s %s -- --prefix=/usr/local/',
				$flags,
				$gem,
				$this->username
			);
			return $status['success'];
		}

		private function _migrateGems($oldver, $newver)
		{
			$proc = Util_Process_Tee::auto(new Util_Process_Sudo);
			$oldgems = array_keys($this->list_installed_gems($oldver));
			$newgems = (array)$this->list_installed_gems($newver);
			$newgems = array_keys($newgems);
			$gems = array_diff($oldgems, $newgems);
			$gems_cnt = count($gems);
			if (!$gems_cnt) {
				return;
			}

			$proc->log("Migrating $gems_cnt gems");
			$i = 0;
			foreach ($gems as $gem) {
				$i++;
				$proc->log(sprintf("%3d/%d Migrating %s", $i, $gems_cnt, $gem));
				$this->install_gem($gem);
			}
		}

		public function gem_version($gem, $local = false)
		{
			$info = $this->get_gem($gem, $local);
			if (!empty($info['versions'])) {
				return array_shift($info['versions']);
			}
			return $info['version'];
		}

		/**
		 * string get_gem_description (string)
		 * Fetches the description for a gem
		 *
		 * @param  string $mGemName gem name
		 * @return string description of the gem
		 */

		public function gem_description($mGemName)
		{
			$gems = $this->list_remote_gems();
			if (!isset($gems[$mGemName])) {
				return false;
			}
			return str_replace('\n', '', trim($gems[$mGemName]['description']));
		}

		/**
		 * Get installed version of RubyGems
		 *
		 * @return string version number
		 */
		public function rubygems_version()
		{
			$file = glob($this->domain_fs_path() .
				self::RUBY_DIR . '/site_ruby/*/rubygems/version.rb');
			if (empty($file)) {
				return null;
			}
			$file = array_pop($file);
			$fp = fopen($file, 'r') or fatal("cannot open file!");
			$version = '';
			while (false !== ($line = fgets($fp))) {
				$tok = strtok(" ", $line);
				if ($tok != "RubyGemsVersion") {
					continue;
				}
				strtok(" "); // =
				$version = trim(strtok(" "), '"\'');
			}
			fclose($fp);
			if (!$version) {
				return error("version.rb is corrupted");
			}
			return $version;
		}

		public function uninstall_rails()
		{
			if (!$this->ssh_enabled()) {
				return error("Pre-requisite SSH not satisfied");
			}
			return $this->uninstall_gem("rails");
		}

		public function uninstall_gem($gem, $ver = null)
		{
			if (!IS_CLI) {
				return $this->query('ruby_uninstall_gem', $gem, $ver);
			}
			if (!preg_match('!^[a-zA-Z0-9_-]+$!', $gem)) {
				return error($gem . ": invalid gem");
			}
			$proc = Util_Process_Tee::watch(new Util_Process_Sudo);

			$proc->log('Uninstalling ' . $gem);
			if (!$ver) {
				$flags = '-a';
			} else {
				$flags = '-v ' . escapeshellarg($ver);
			}
			$status = $proc->exec('gem uninstall -I '
				. '--no-rdoc %s %s -x -- --prefix=/usr/local/',
				$flags,
				$gem,
				$this->username
			);
			return $status['success'];
		}

		public function _edit()
		{
			$conf_cur = Auth::profile()->conf->cur['ssh'];
			$conf_new = Auth::profile()->conf->new['ssh'];
			if (!version_compare(platform_version(), "6", ">=")) {
				return;
			}
			if ($conf_new['enabled'] && !$conf_cur['enabled']) {
				$this->initialize_gemset();
			}
		}

		public function initialize_gemset($user = null)
		{
			if (!IS_CLI) {
				return $this->query('ruby_initialize_gemset', $user);
			}
			if (!version_compare(platform_version(), "6", ">=")) {
				return info("gemset unsupported on platform v%d", platform_version());
			}
			if (!$user || !($this->permission_level & PRIVILEGE_SITE)) {
				$user = $this->username;
			}

			if (!$this->user_exists($user)) {
				return error("invalid user `%s'", $user);
			}
			if (!$this->misc_procfs_enabled()) {
				return -1;
			}
			$proc = new Util_Process_Sudo();
			$proc->setOption('user', $user);
			$ret = $proc->run("/bin/bash -i rvm user gemsets");
			if (!$ret['success']) {
				return error("error intiailizing gemset: `%s'", $ret['stderr']);
			}
			return $ret['success'];
		}

		public function _create()
		{
			$conf_new = Auth::profile()->conf->new['ssh'];
			if (!$conf_new['enabled']) {
				return true;
			}
			if (version_compare(platform_version(), "6", ">=")) {
				$this->initialize_gemset();
			}

		}
	}

?>
