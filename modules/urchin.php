<?php
	/**
	 * Urchin functions
	 * @package core
	 */

	class Urchin_Module extends Module_Skeleton {
		// maximum of permitted profiles without charge
		const MAX_FREE_PROFILES = 2;

		const URCHIN_BASE = '/usr/local/';
		// from http://www.google.com/support/urchin45/bin/answer.py?hl=en&answer=28623&ctx=cb
		const SREQUEST_HOSTNAME = 95;
		public function _init() {
			$this->exportedFunctions = array(
				'*' => PRIVILEGE_SITE,
				'create_profile_backend' => PRIVILEGE_SITE|PRIVILEGE_SERVER_EXEC
			);
		}
        
        public function enabled() {
            return version_compare(PLATFORM_VERSION, '4.5', '<');
        }
        
		public function create_user($mUser, $mPassword = "urchin") {
			if (!preg_match('/^[a-z]+[a-z0-9_\.]+$/', strtolower($mUser)))
				return error ("Invalid username `".$mUser."'");

			if (!$this->affiliation_exists())
				$this->create_affiliation();

			if ($this->user_exists($mUser))
				return false;

			return $this->_urchin_driver_bool('add',
				'user', 
				array('name' => $mUser,
					'ct_fullname' => $this->domain,
					'ct_password' => $mPassword,
					'ct_adminlevel' => 3,
					'cr_leveltype' => 1,
					'ct_affiliation'=> $this->site)
				);
		}

		private function _getProfileID($profile) {
			$profile = strtolower($profile);
			if (!$this->profile_exists($profile)) return error("invalid profile `$profile'");
			$profile = $this->_urchin_driver('get','profile',array('name' => $profile,'parameter' => 'recnum'));
			return intval($profile['recnum']);
		}


		private function _getUserID() {
			$cache = Cache_Account::spawn();
			$id = $cache->get('urchin-uid');
			if ($id) return $id;
			$drv = $this->_urchin_driver('get','user',array('name' => $this->username));
			if (!isset($drv['ct_affiliation']) ||
				$drv['ct_affiliation'] != $this->site) return 0;
			$id = $drv['recnum'];
			$cache->add('urchin-uid', $id);
			return $id;
		}

		/**
		 * Delete Urchin profile
		 *
		 * @param string $profile profile name
		 * @return bool
		 */
		public function delete_profile($profile) {
			if (!IS_CLI) return $this->query('urchin_delete_profile', $profile);
			
			$id = $this->_getProfileID($profile);
			if ($id < 1) return false;
			$profilemeta = $this->_urchin_driver('get','profile',array('name' => $profile));
			foreach ($profilemeta['cs_llist'] as $logid) {
				$this->_deleteLog($logid);
			}
			// delete task
			$this->_urchin_driver_bool('delete','task',array('recnum' => $profilemeta['cs_taskid']));
			// delete profile
			$ret = $this->_urchin_driver_bool('delete','profile',array('recnum' => $profilemeta['recnum']));
			if (isset($profilemeta['cs_flist'])) {
				foreach ($profilemeta['cs_flist'] as $filter)
					$this->_deleteFilter($filter, $id);
			}
			if ($ret) {
				$this->file_delete('/var/lib/urchin/'.$profile, true);
				unlink(self::URCHIN_BASE.'/urchin/data/reports/'.$profile);
			}
			foreach ($profilemeta['cs_ulist'] as $user) {
				$profiles = $this->_urchin_driver('get_parameter','profile',array('parameter' => 'cs_rlist', 'recnum' => $user));
				$key = array_search($id, $profiles);
				if ($key === false) { continue; }
				unset($profiles[$key]);
				$this->_urchin_driver('set_parameter','profile', array('recnum' => $user, 'cs_rlist' => '!'.join('!',$profiles).'!'));
			}
			$c = Cache_Account::spawn()->delete('urchin-profiles');
			return $ret;
			
		}

		private function _deleteLog($id)
		{
			$filtid = $this->_urchin_driver(
				'get_parameter',
				'logfile',
				array('parameter' => 'cs_flist', 'recnum' => $id));
			$status = $this->_urchin_driver('delete','logfile',array('recnum' => $id));
			if ($filtid < 1) return true;
			// clean up filters
			foreach ($filtid as $filter)
				$this->_deleteFilter($filter, $id);
			return true;
		}

		private function _deleteFilter($filterid, $ownerid) {
			$filtermeta = $this->_urchin_driver(
				'get',
				'filter',
				array('recnum' => $filterid)
			);
			if (!$filtermeta) return true;
			$inlog  = $inprof = false;
			if (isset($filtermeta['cs_llist'])) {
				$inlog = array_search($ownerid,$filtermeta['cs_llist']);
			}
			if (isset($filtermeta['cs_rlist'])) {
				$inprof = array_search($ownerid,$filtermeta['cs_rlist']);
			}

			if ($inlog !== false) {
				$index = 'cs_llist';
				$key = $inlog;
			} elseif ($inprof !== false) {
				$index = 'cs_rlist';
				$key = $inprof;
			} else {
				return warn("permission denied: cannot discard filter `$filterid'");
			}
			unset($filtermeta[$index][$key]);
			if (!count($filtermeta['cs_llist']) && !count($filtermeta['cs_rlist']))
				return $this->_urchin_driver('delete','filter',array('recnum' => $filterid));

			return $this->_urchin_driver(
				'set_parameter',
				'filter',
				array(
					'recnum' => $filterid,
					$index => '!'.join('!',$filtermeta[$index]).'!'
				)
			);
		}

		/**
		 * Delete log resource
		 *
		 * @param string $log_name  log source name
		 * @param string $profile   profile name
		 */
		public function delete_log($log_name, $profile = null) {
			if (!$profile) {
				$ids = $this->_urchin_driver('get_parameter','logfile',array('parameter' => 'cs_rlist', 'name' => $log_name));
				$ret = true;
				foreach ($ids as $id) {
					$profile = $this->_urchin_driver('get_parameter', 'profile',array('parameter' => 'ct_name', 'recnum' => $id));
					$ret = $this->delete_log($log_name, $profile);
				}
				return $ret;
			}
			$id = $this->_getProfileID($profile);
			if ($id < 1) return false;

			$logmeta = $this->_urchin_driver('get','logfile',array('name' => $log_name));
			if ($logmeta['ct_affiliation'] != $this->site) return error("permission denied: `$log_name' cannot remove");
			return $this->_deleteLog($logmeta['recnum']);
		}

		public function user_is_affiliated($mUser) {
				$ret = $this->_urchin_driver_bool('get_parameter','user', array('parameter' => 'ct_affiliation',
																			 'name'      => $mUser));
			return $ret == $this->site;

		}

		public function affiliation_exists() {
			$ret = $this->_urchin_driver_bool('get_parameter','affiliation',array('parameter' => 'ct_contact', 'name' => $this->site));
			return $ret;
		}
		public function get_max_allowed_profiles() {
			try {
				$profile_limit = $this->get_service_value('urchin','max_profiles');
			} catch (Exception $e) {
				$profile_limit = self::MAX_FREE_PROFILES;
			}

			return $profile_limit;
		}
		/**
		 * create_profile first checks for the affiliation necessary during
		 * the initial profile setup for an account.  Following the affiliation
		 * check a user check is performed on the primary username.  If the
		 * user is not found, then the user is created with the default
		 * password of "urchin".  To avoid the default password, either
		 * call {@link create_user} prior to invoking create_profile or
		 * call {@link change_password} following create_profile
		 */
		public function create_profile($domain = NULL) {
			$log = 'access_log';
			$domain = preg_replace('/[^[a-z0-9\.\*-]]/','',strtolower(is_null($domain) ? $this->get_service_value('siteinfo','domain') : $domain));

			$profile_limit = $this->get_service_value('urchin','max_profiles');
			if (!$profile_limit) $profile_limit = self::MAX_FREE_PROFILES;
			if (!file_exists($this->domain_fs_path().'/var/log/httpd/'.$log))
				return error("source log ".$log." does not exist in /var/log/httpd/");
			$domain = str_replace('*',
				$this->get_service_value('siteinfo','domain'),
				str_replace('*.', '', $domain));
			// default site affiliation doesn't exist
			if (!$this->affiliation_exists())
				$this->create_affiliation();
			if ($this->profile_exists($domain))
				return false;
			else if ($this->get_profile_count() > $profile_limit)
				return error("Profile creation exceeds ".self::MAX_FREE_PROFILES." profile account limit");

			if (!$this->user_exists($this->username)) {
				$ret = $this->create_user($this->username);
				if (!$ret)
					return $ret;
			}

			if (!$this->query('urchin_create_profile_backend',$domain, $log))
				return error("Unable to create profile directory for `" . $domain."'");
			$u_rec  = $this->_urchin_driver('seek','user',array('name'      => $this->username));
			if (!preg_match('/recnum=(\d+)/',$u_rec['output'],$u_rec))
				return error("fatal: cannot find recnum for ".$this->username);
			$u_rec  = $u_rec[1];
			$p_rec  = $this->_urchin_driver('add','profile',array('name'             => $domain,
				'ct_affiliation'   => $this->site,
				'ct_website'       => 'http://www.'.$domain,
				'ct_reportdomains' => 'www.'.$domain.','.$domain,
				'cs_llist'         => '"'.$domain.'-'.$log.'","'.$domain.'-'.$log.'.[1-4]"',
				'cs_vmethod'       => 0,
				'cr_logtracking'   => 'on',
				'cr_autorollback'  => 'off',
				'cr_createbackups' => 'off',
				'cs_ulist'         => $this->username,
				'cr_cleanbackups'  => 'off',
				'cs_keepnbackups'  => '0',
				'cr_archivedata'   => 'on',
				'cs_archivenmonths'=> '2'));
			$l1_rec = $this->_urchin_driver('add','logfile',array('name'             => '"'.$domain.'-'.$log.'"',
				'ct_affiliation'   => $this->site,
				'cs_logformat'     => 'auto',
				'ct_loglocation'   => '"'.$this->domain_fs_path().'/var/log/httpd/'.$log.'"',
				'cs_rlist'         => '!'.$p_rec.'!'));
			$l2_rec = $this->_urchin_driver('add','logfile',array('name'             => '"'.$domain.'-'.$log.'.[1-4]"',
				'ct_affiliation'   => $this->site,
				'cs_logformat'     => 'auto',
				'ct_loglocation'   => '"'.$this->domain_fs_path().'/var/log/httpd/'.$log.'.[1-4]"',
				'cs_rlist'         => '!'.$p_rec.'!'));
			$t_rec  = $this->_urchin_driver('add','task',   array('name'             => $domain,
				'ct_affiliation'   => $this->site,
				'cr_frequency'     => '5',
				'cr_minute'        => '0',
				'cr_runnow'        => '0',
				'ct_status'        => '2',
				'cs_rid'           => $p_rec));
			$f1_rec = $this->_urchin_driver('add','filter', array(
				'name' => '"' . $domain . '-' . $log.'-filter' . '"',
				'cr_filtertype'    => 'include',
				'cs_llist'         => '!'.$l1_rec.'!'.$l2_rec.'!',
				// 'cs_llist'         => '"' . $mDomain.'-'.$mLog.'","' . $mDomain.'-'.$mLog. '".[1-4]"',
				'cs_rlist'         => '!'.$p_rec.'!',
				'ct_filter'        => '^(www\.)?' . str_replace('*', '.*', $domain) . '$',
				'ct_filterfield'   => 'HTTP Host',
				'cs_filterfield'   => self::SREQUEST_HOSTNAME,
				'ct_affiliation'   => $this->site
			));
			$profiles = $this->_urchin_driver('get_parameter',
				'user', 
				array('name' => $this->username,
				'parameter'=> 'cs_rlist')
			);
			if (!$profiles)
				$profiles = array($p_rec);
			else if (!is_array($profiles))
				$profiles = array($profiles,$p_rec);
			else
				$profiles[] = $p_rec;
			$this->_urchin_driver('set_parameter', NULL, array('recnum'   => $p_rec,
				'cs_ulist' => '!'.$u_rec.'!'));
			$this->_urchin_driver('set_parameter', NULL, array('recnum'   => $p_rec,
				'cs_taskid'=> $t_rec));
			$this->_urchin_driver('set_parameter', NULL, array('recnum'   => $p_rec,
				'cs_llist' => '!'.$l1_rec.'!'.$l2_rec.'!'));
			$this->_urchin_driver('set_parameter', NULL, array('recnum'   => $u_rec,
				'cs_rlist' => '!'.join('!',$profiles).'!'));
			info("reporting profile created for `%s'! wait 24 hours for statistics to generate", $domain);
			return true;
		}

	
		public function profile_exists($mProfile) {
			$ret = $this->_urchin_driver('get_parameter','profile',array('parameter' => 'ct_affiliation',
				'name'      => $mProfile));
			return !strcmp($ret, $this->site);
		}

		public function create_profile_backend($mProfile, $mLogs) {
			chmod($this->domain_fs_path() . '/var/lib/urchin', 02751);
			chown($this->domain_fs_path() . '/var/lib/urchin', 'urchin');
			chgrp($this->domain_fs_path() . '/var/lib/urchin', $this->group_id);
			if (!file_exists($this->domain_fs_path().'/var/lib/urchin/'.$mProfile.'/'))
				mkdir($this->domain_fs_path().'/var/lib/urchin/'.$mProfile.'/');

			chown($this->domain_fs_path().'/var/lib/urchin/'.$mProfile.'/','urchin') &&
			chgrp($this->domain_fs_path().'/var/lib/urchin/'.$mProfile.'/',$this->group_id) &&
			chmod($this->domain_fs_path().'/var/lib/urchin/'.$mProfile.'/',02750) &&
			( file_exists(self::URCHIN_BASE . '/urchin/data/reports/' . $mProfile) ||
			symlink($this->domain_fs_path().'/var/lib/urchin/'.$mProfile, self::URCHIN_BASE.'/urchin/data/reports/'.$mProfile));

			return file_exists(self::URCHIN_BASE.'/urchin/data/reports/'.$mProfile) &&
				 (readlink(self::URCHIN_BASE.'/urchin/data/reports/'.$mProfile) == $this->domain_fs_path().'/var/lib/urchin/'.$mProfile);
		}

		public function get_profile_count() {
			$data = $this->_urchin_driver(
				'get_parameter','user', array(
					'name' => $this->username,
					'parameter' => 'cs_rlist'));
			return count($data);
		}

		/**
		 * mixed locate_urchin_profile (void)
		 * Determines the corresponding Urchin URL for the primary profile
		 * @return mixed string if just one path, array if more than one location
		 */
		public function locate_profile() {
			if (!IS_CLI) return $this->query('urchin_locate_profile');
			$installations = array();
			$files = str_replace('//','/',glob(self::URCHIN_BASE.'/urchin*/data/reports/'.$this->domain));
			foreach($files as $installation) {
				$installations[] = substr($installation,strlen(self::URCHIN_BASE),strpos(substr($installation,strlen(self::URCHIN_BASE)),'/'));
			}
			if (sizeof($installations) == 0)
				return array();

			return array_pop($installations);
		}

		/**
		 * int get_urchin_disk_usage()
		 * This method counts only those profiles whose gid equals that of
		 * the site and thus counted under the quota.
		 * @return int total size of all urchin profiles in KB
		 */
		public function get_urchin_disk_usage($profile = null) {
			if (!IS_CLI) return $this->query('urchin_get_urchin_disk_usage');
			$size = 0;
			if (!file_exists($this->domain_fs_path().'/var/lib/urchin/'.$profile))
				return $size;
			return $this->_urchin_tr($this->domain_fs_path().'/var/lib/urchin/'.$profile);
		}

		private function _urchin_tr($mPath) {
			$dh = opendir($mPath);
			$size = 0;
			while (($file = readdir($dh)) !== false) {
				if ($file == '.' || $file == '..')
					continue;
				$size += (filesize($mPath.'/'.$file)/1024);
				if (is_dir($mPath.'/'.$file.'/'))
					$size += $this->_urchin_tr($mPath.'/'.$file.'/');
			}
			closedir($dh);
			return $size;
		}

		public function get_profile_username() {
			return $this->username;

		}

		/**
		 * int get_prune_period()
		 * Returns the time, in months, to retain urchin logs
		 * @return int
		 */
		public function get_prune_period() {
			$prune = $this->get_service_value('urchin','prune');
			return $prune == 0 ? 6 : $prune;
		}

		/**
		 * bool set_prune_period(int)
		 * Set the time, in months, to retain Urchin profiles
		 * Profiles exceeding the threshold will be removed by a cronjob
		 * that runs once a month on the beginning of the month
		 * @param $mPeriod int time to retain, in months (default: 3)
		 * @return bool action succeeded
		 */
		public function set_prune_period($mPeriod) {
			$this->set_config('urchin','prune',intval($mPeriod));
			return true;
		}

		public function get_profiles() {
			$profiles = array();

			$id = $this->_getUserID();
			if ($id < 1) return $profiles;

			$cache = Cache_Account::spawn();
			$cacheprof = $cache->get('urchin-profiles');
			if (is_array($cacheprof)) return $cacheprof;
			$user = $this->_urchin_driver('get','user',array('recnum' => $id));
			if (!isset($user['cs_rlist'][0])) return $profiles;
			foreach ($user['cs_rlist'] as $profileid) {
				$drv = $this->_urchin_driver('get_parameter','profile',array('parameter' => 'ct_name','recnum' => $profileid));
				// orphan profile
				if ($drv == '-1') continue;
				$profiles[] = array('profile' => $drv, 'size' => $this->get_urchin_disk_usage($drv));
			}
			$cache->add('urchin-profiles', (array)$profiles);
			return (array)$profiles;
		}

		public function change_password($mValue, $mUser = NULL) {
			if (!preg_match(Regex::PASSWORD, $mValue))
				return error("Invalid password");
			if (is_null($mUser))
				$mUser = $this->username;

			if (!$this->user_exists($mUser) || !$this->user_is_affiliated($mUser))
				return false;
			return $this->_urchin_driver_bool('set_parameter','user',array('name' => $mUser, 'ct_password' => $mValue));
		}

		/**
		 *  create an initial Urchin profile affiliation
		 */
		private function create_affiliation() {
			return
				$this->_urchin_driver_bool('add','affiliation',array('name'       => $this->site,
																	'ct_contact' => $this->username,
																	'ct_email'   => $this->get_service_value('siteinfo','email'),
																	'ct_reportdirectory' => $this->domain_fs_path().'/var/lib/urchin/',
																	'ct_browselocation'  => $this->domain_fs_path()));

		}
		private function user_exists($mUser) {
			return
				$this->_urchin_driver_bool(
					'get_parameter', 
					'user', 
					array('parameter' => 'ct_affiliation',
						'name' => $mUser));
		}

		/**
		 * Low-level Urchin driver
		 */
		private function _urchin_driver($mAction, $mTable = NULL, array $mParams = array()) {
			$param_string = '';
			if ($mParams)
				foreach ($mParams as $k => $v) {
					$param_string .= ' '.$k."=".escapeshellarg($v);
				}
			$output = Util_Process::exec("cd / && " . self::URCHIN_BASE.'urchin/util/uconf-driver action=%s table=%s %s',
				$mAction,
				$mTable,
				$param_string,
				array(0),
				array('mute_stderr' => true)
			);
			if ($mAction == 'add') {
				if (!$output['success']) return false;
				return trim($output['output']);
			} else if ($mAction == 'get') {
				if (!$output['success']) return null;
				else return $this->_parse(trim($output['output']));
			} else if ($mAction == 'get_parameter') {
				if (!$output['success']) return null;
				$resp = rtrim($output['output']);
				if (isset($resp[0]) && $resp[0] == "!") { $resp = explode("!",substr($resp,1,-1)); }
				return $resp;
			} else if ($mAction == 'delete') {
				return trim($output['success']);
			}
			return $output;
		}

		private function _parse($output) {
			$tokens = array();
			$token = $tok = strtok($output," =");
			$len = 0;
			do {
				$last = strlen($tok)-1;
				if ($tok[$last] == '"') {
					$tokens[$token] .= " ".substr($tok,0,$last);
					continue;
				}
				if ($tok === "") continue;

				$token = $tok;
				$len += strlen($tok+1);
				$tok   = strtok('" ');
				$len += strlen($tok+1);
				if ($tok === false) break;
				// table=profile, n=5, etc
				if ($tok[0] == '!') {
					$tok = trim($tok,"!");
					if (!$tok) $tok = array();
					else $tok = explode("!",$tok);
				} else if ($tok === 'on') {
					$tok = true;
				} else if ($tok === 'off') {
					$tok = false;
				}
				$tokens[$token] = $tok;
			} while (false !== ($tok = strtok(" =")));
			return $tokens;
		}

		private function _urchin_driver_bool($mAction, $mTable = null, array $mParams = array()) {
			$output = $this->_urchin_driver($mAction,$mTable, $mParams);
			return (bool)trim($output['success']);

		}

		public function _delete() {
			$uid = $this->_getUserID();
			if ($uid < 1) return true;

			foreach ($this->get_profiles() as $profile) {
				$this->delete_profile($profile['profile']);
			}
			$this->_urchin_driver_bool('delete','user',array('recnum' => $uid));
			$this->_urchin_driver_bool('delete','affiliation',array('name' => $this->site));
		}
	}

?>
