<?php
	/**
	 * User-specific functions and user creation
	 * @package core
	 */
	class User_Module extends Module_Skeleton {
		private static $uid_mappings = array();

		// minimum non-system user id
	    const MIN_UID = 500;
	    
		/*
		 * number of dummy users present within /etc/passwd
		 * that possess the same uid/gid as the main user
		 * majordomo, ftp, and mail
		 */
		const  DUMMY_USER_CNT = 3;
		/**
		 * void __construct(void)
		 * @ignore
		 */

		public function _init() {
			$this->exportedFunctions = array(
				'*'                   => PRIVILEGE_SITE,
                'flush'               => PRIVILEGE_SITE|PRIVILEGE_USER,
				'get_user_home'       => PRIVILEGE_ALL,
				'get_home'            => PRIVILEGE_ALL,
				'get_users'           => PRIVILEGE_SITE|PRIVILEGE_USER,
				'change_gecos'        => PRIVILEGE_SITE|PRIVILEGE_USER,
				'get_uid_from_username' => PRIVILEGE_SITE|PRIVILEGE_USER,
				'get_username_from_uid' => PRIVILEGE_SITE|PRIVILEGE_USER,
				'exists'         => PRIVILEGE_SITE|PRIVILEGE_USER,
				'get_quota'           => PRIVILEGE_SITE|PRIVILEGE_USER,
				'getpwnam'            => PRIVILEGE_SITE|PRIVILEGE_USER
			);
		}
		// {{{ change_quota()

		/**
		 * Change disk and file count quotas for a given user
		 *
		 * @param string  $user
		 * @param integer $diskquota disk quota provided in megabytes
		 * @param integer $filequota file count limit
		 * @return bool
		 */
		public function change_quota($user, $diskquota, $filequota = 0) {
			if (!IS_CLI)
				return $this->query('user_change_quota', $user, $diskquota, $filequota);
			if ($user == $this->get_service_value('siteinfo','admin_user'))
				return error("cannot set quota for administrator");

			if (!$this->exists($user)) return false;
			if (floatval($diskquota) != $diskquota || $diskquota < 0)
				return error($diskquota.": invalid disk quota");
			if ($diskquota > ($lim_quota = $this->get_service_value('diskquota','quota'))) {
				warn($diskquota.": quota exceeds site limit (".$lim_quota."), defaulting to unlimited");
				$quota = 0;
			}

			if (intval($filequota) != $filequota || $filequota < 0)
				return error($filequota.": invalid file quota");

			$output = Util_Process::exec('/usr/sbin/setquota -u %d %1d %1d %1d %1d -a',
				$this->get_uid_from_username($user),
				max(0,round($diskquota*1024)-16),
				round($diskquota*1024),
				$filequota,
				$filequota, array('mute_stderr' => true));

			return $output['success'];
		}

		// }}}

		/**
		 * Add new user to account
		 *
		 * @link Ftp_Module::jail_user()
		 * @link Web_Module::create_subdomain()
		 * @link Email_Module::create_mailbox()
		 * @param array $options
		 *          password : 'crypted': password is encrypted via crypt()
		 *          ftp      : control ftp service [1,0]
		 *          imap     : imap access allowed [1,0]
		 *          smtp     : smtp access
		 *          cp       : CP access
		 *          ssh      : ssh access enabled
		 */
		public function add_user($user, $password, $gecos = '', $quota = 0, array $options = array()) {
			if (!IS_CLI) {
				if (!IS_SOAP && $user == 'test') {
					return error("insecure, commonly-exploited username");
				}
				return $this->query('user_add_user', $user, $password, $gecos, $quota, $options);
			}

			$userorig = $user;
			$user = strtolower($user);
			if ($user != $userorig) warn("user `$user' converted to lowercase");
			if (!$user) {
				return error("no username specified)");
			} else if (!preg_match(Regex::USERNAME, $user)) {
				return error("invalid user `%s'", $user);
			}

            if (!$this->auth_password_permitted($password, $user)) {
                 return error("weak password disallowed"); 
            }
			$quotamax = $this->get_service_value('diskquota','quota');
			$units = $this->get_service_value('diskquota','units');
			if (!isset($options['password']) || $options['password'] != 'crypted')
				$password = $this->auth_crypt($password);
			if ($quota != floatval($quota) || $quota < 0)
				return error("disk quota `%s' outside of range (min: 0, max: %d) %s", $quota, $quotamax, $units);
			else if ($quota > $quotamax) {
				warn("quota %.1f exceeds limit %.1f: defaulting to %.1f",
					$quota, $quotamax, $quotamax);
				$quota = $quotamax;
			}
			$users = $this->get_users();
			if (isset($users[$user]))
				return error("username ".$user." exists");

			$smtp_enable = isset($options['smtp']) && $options['smtp'] != 0;
			$imap_enable = isset($options['imap']) && $options['imap'] != 0;
			$ftp_enable  = isset($options['ftp'])  && $options['ftp']  != 0;
			$cp_enable   = !isset($options['cp'])  || $options['cp']   != 0;
			$ssh_enable  = $this->get_service_value('ssh','enabled') && isset($options['smtp']) && $options['ssh'] != 0;

			$svc_list = array();
			if ($ftp_enable) {
				$svc_list[] = 'proftpd=1';
			}
			if ($smtp_enable) {
				$svc_list[] = 'smtp=1';
			}
			if ($imap_enable) {
				$svc_list[] = 'imap=1';
			}
			if ($ssh_enable) {
				$svc_list[] = 'ssh=1';
			}

			if (!$ftp_enable) {
				warn("FTP service not enabled.  User will not be permitted FTP access");
            }
            if (!$smtp_enable && $imap_enable) {
                warn("SMTP service not enabled. User will be able to receive mail, but not send");
            } else if ($smtp_enable && !$imap_enable) {
                warn("IMAP service not enabled. User will be able to send mail, but not receive");
            } else if (!$smtp_enable && !$imap_enable) {
                info("E-mail not enabled for user");
            }
            $cmd = '/usr/local/bin/AddVirtUser cpasswd=%(password)s %(site)s %(user)s %(gecos)s %(quota)d';
            $cmd .= ' ' . join($svc_list,' ');
			$status = Util_Process_Safe::exec($cmd, 
                    array('password' => $password, 
                    'site' => $this->site, 
                    'user' => $user, 
                    'gecos' => $gecos, 
                    'quota' => $quota), 
                    array(0,1)
            );
            // exit code is 0 or 1 from AddVirtUser
			if ($status['success']) {
				
				Error_Reporter::clear_buffer();
			}
			// 1 signifies added with warnings
            //     ex: "user already permitted to use smtp_relay service"
            // Since this is benign, check prior severity to error out
			if (Error_Reporter::get_severity() >= Error_Reporter::E_ERROR) {
				return false;
			}			
            // Ensim unconditionally grants IMAP/SMTP access
			if (!$imap_enable)
				$this->email_deny_user($user,'imap');
			if (!$smtp_enable)
				$this->email_deny_user($user,'smtp');
			if (!$cp_enable)
				$this->auth_deny_user($user, 'cp');

			if (!$this->exists($user)) {
				return false;
			}

			Util_Account_Hooks::run('create_user', array($user));
			return true;
		}

		public function get_home($user = NULL) {
			if (!$user)
				$user = $this->username;

			$pwnam = $this->getpwnam($user);
			return !$pwnam ? false : $pwnam['home'];
		}

		public function get_user_home($user = NULL) {
			return $this->get_home($user);
		}

		/**
		 * Get users belonging to account
		 *
		 * Finds all applicable users created and returns an array consisting
		 * of their information from /etc/passwd.  Indexed by username.
		 *
		 * The following indexes are provided:
		 *  uid: user id
		 *  gid: group id (which will be the same as the uid of the site admin)
		 *  home: home directory of the user
		 *  shell: path to the shell used by the user
		 *
		 * @return array
		 */
		public function get_users() {
			if (!IS_CLI) {
	        	$cache = Cache_Account::spawn();
	        	$gen = $cache->get('users.gen');
	        	$mtime = filemtime($this->domain_fs_path().'/etc/passwd');
	        	if ($gen == $mtime) {
	        		$users = $cache->get('users');
	        		if (!empty($users)) return $users;
	        	}

	        	return $this->query('user_get_users');
			}
			$fp = fopen($this->domain_fs_path()."/etc/shadow",'r');
			flock($fp,LOCK_SH);
			$mtime = filemtime($this->domain_fs_path().'/etc/passwd');
			if (!$fp) return error($this->domain.": unable to open /etc/shadow");
			$users = array();
			while (($line = fgets($fp)) !== false) {
				if (!preg_match(Regex::SHADOW_PHY_ENTRY,$line))
					continue;
				$line = explode(":",$line);
				if ($line[1] !== "!!" && $line[1] !== "") {
					$users[$line[0]] = $this->getpwnam($line[0]);
				}
			}
			fclose($fp);
			ksort($users);
			$cache = Cache_Account::spawn();
			$cache->set('users.gen', $mtime, 43200);
			$cache->set('users', $users, 43200);
			return $users;
		}

        /**
          * Flush account user cache
		  *
          * @return bool
		  */
        public function flush() {
            $cache = Cache_Account::spawn();
            $keys = array('users:pwd.gen', 'users');
            foreach ($keys as $key) {
                // don't worry about Memcache::delete() response
                // response will return NOT FOUND if cache is not yet set
                $cache->delete($key);
            }
            $code = $cache->getResultCode();
            if ($code) {
                $msg = $cache->getResultMessage();
                return ($msg == 'NOT FOUND') || error($msg);
            }
            return true;
        }

        /**
         * Perform getpwnam() lookup on virtual account
         *
         * name:   username
         * uid:    uid
         * gid:    gid
         * gecos:  gecos field
         * home:   home directory
         * shell:  shell
         *
         * @param  string $user
         * @return array
         */
		public function getpwnam($user = null) {
		    if (!$user) $user = $this->username;
			if (!IS_CLI) {
	        	$cache = Cache_Account::spawn();

	        	$gen = $cache->get('users:pwd.gen');
                $file = $this->domain_fs_path().'/etc/passwd';
	        	if ($gen == filemtime($file)) {
	        		$users = $cache->get('users:pwd');
	        		if (!empty($users) && array_key_exists($user, $users))
	        			return $users[$user];
	        	}

	        	return $this->query('user_getpwnam',$user);
			}
			$pwd = array();
            $file = $this->domain_fs_path() . '/etc/passwd';
			$fp = fopen($file, 'r');
			if (!$fp) return error("unable to open /etc/passwd");			
            $found = false;		
            clearstatcache(true, $file);
            $mtime = filemtime($file);            
			while (!feof($fp)) {
				$line = explode(':',trim(fgets($fp)));
				if (sizeof($line) < 6) continue;
				$myuser = $line[0];
				if ($line[0] == $user) {
					$found = true;
				}
				$pwd[$myuser]   = array(
					'uid'   => (int)$line[2],
					'gid'   => (int)$line[3],
					'gecos' => $line[4],
					'home'  => $line[5],
					'shell' => $line[6]
				);
			}
			fclose($fp);
			Cache_Account::spawn()->setMulti(
				array(
					'users:pwd.gen' => $mtime,
					'users:pwd' => $pwd,
				)
			);
			if (!$found) return array();
			return $pwd[$user];
		}

		public function get_user_count() {
			$users = 0;
			$fp = fopen($this->domain_fs_path()."/etc/passwd",'r');
			if (!$fp)
				return error("Unable to open /etc/passwd");

			while (($line = fgets($fp)) !== false ) {
				if (!preg_match(Regex::PASSWD_USER_ENTRY,$line))
					continue;
				$line = explode(":",$line);
				if ($line[1] !== "!!" && $line[1] !== "") {
					$users++;
				}
			}
			fclose($fp);
			return array('users' => $users-self::DUMMY_USER_CNT ,
						 'max' => $this->get_service_value("users","maxusers"));
		}

		public function delete_user($user) {
			if (!IS_CLI) {
				return $this->query('user_delete_user',$user);
			}

			$users = $this->get_users();
			if (!isset($users[$user])) {
				return error("user `%s' not found", $user);
			}
			else if ($user == $this->get_service_value('siteinfo','admin_user'))
				return error("cannot delete primary user");

			$uid = $users[$user]['uid'];
			// check to make sure subdomains/domains aren't hosted by user
			$domains  = $this->aliases_list_shared_domains();
			$home = $this->get_home($user);
			$subdomains = array_keys(
				$this->web_list_subdomains('path', '!^' . $home . '/!')
			);

			$blocking = array();
			foreach ($domains as $domain => $path) {
				if (!$this->file_file_exists($path)) {
					continue;
				}
				$stat = $this->file_stat($path);
				if (!$stat) {
					continue;
				}
				if (!strncmp($home, $path, strlen($home)) || $stat['uid'] == $uid) {
					$blocking[] = $domain;
				}
			}
			$subcount = count($subdomains);
			$domaincount = count($blocking);
			if ($domaincount > 0 || $subcount > 0) {
				Util_Conf::sort_domains($blocking);
				if ($domaincount > 0) {
					error("one or more domains rely on user `%s', remove or relocate these domains first (DNS > Addon Domains): `%s'",
						$user, join($blocking, ", "));
				}

				if (count($subdomains) === 1 && ($subdomains[0] === $user || !strncmp($subdomains[0].'.', $user.'.', strlen($user)+1))) {
					$subcount--;
					info("removed user-specific subdomain, `%s'", $subdomains[0]);
					$this->web_remove_subdomain($subdomains[0]);
				} else if (count($subdomains) > 0) {
					error("one or more subdomains rely on user `%s', remove or relocate these subdomains first (Web > Subdomains): `%s'",
						$user, join($subdomains, ", "));
				}

				if ($domaincount || $subcount) {
					return false;
				}

			}


			$cmd = 'DeleteVirtUser '.$this->site.' '.$user;

			mute_warn();
				Util_Account_Hooks::run('delete_user', $user);
				$status = Util_Process::exec($cmd, array(-1,0,1,2));
			unmute_warn();

			if (isset(self::$uid_mappings[$this->site]) &&
				isset(self::$uid_mappings[$this->site][$user]))
				unset(self::$uid_mappings[$this->site][$user]);
			return $status['success'];

		}

        /**
         * Change username in the system
         *
         * @param string $user
         * @param string $newuser
         * @return bool
         */
        public function rename_user($user, $newuser)
        {
            if (!IS_CLI) { return $this->query('user_rename_user', $user, $newuser); }

            $user = strtolower($user);
            $newuser = strtolower($newuser);
            // flush getpwnam cache
            $this->flush();
            $admin = $this->get_service_value('siteinfo','admin_user');
            if (!$this->exists($user)) {
                return error("invalid user specified `%s'", $user);
            } else if ($this->exists($newuser)) {
                return error("target user `%s' already exists", $newuser);
            } else if (!preg_match(Regex::USERNAME, $newuser)) {
                return error("invalid target user `%s", $newuser);
            } else if ($user === $admin) {
                return error("use auth_change_username to change primary user");
            }

            $pwd = $this->getpwnam($user);
            $newhome = preg_replace('!' . DIRECTORY_SEPARATOR . $user . '!',
                DIRECTORY_SEPARATOR . $newuser,
                $pwd['home'],
                1
            );
            $prefix = $this->domain_fs_path();
            if (file_exists($prefix . $newhome)) {
                return error("proposed home directory `%s' already exists", $newhome);
            }
            $auth = Auth::profile();
            // make a symlink to the original home to workaround fs checks
            // during the rename process
            //rename($prefix . $pwd['home'], $prefix . $newhome);
            $this->file_symlink($pwd['home'], $newhome);
	        if (!Util_Account_Hooks::run('edit_user', array($user, $newuser))) {
		        return error("unable to fully rename user, hook failed");
	        }
            $this->file_delete($newhome);
            // rename user in gecos
            return $this->usermod_driver($user,
                array(
                    'username' => $newuser,
                    'home' => $newhome,
                    'move_home' => true
                )
            ) && $this->flush();
        }

		/**
		 * array get_quota_history(string[, int = 0[, int = 0]])
		 * @param string $mUser
		 * @param int    $mBegin
		 * @param int    $mEnd
		 * @return array
		 */
		public function get_quota_history($mUser, $mBegin = 0, $mEnd = NULL) {
			$key = "q." . base64_encode(pack("LLa*", $mBegin, $mEnd, $mUser));
			$cache = Cache_Account::spawn();
			$data = $cache->get($key);
			if ($data) {
				return unserialize(gzinflate($data));
			}
			$quotas = array();
			if (is_null($mEnd))
				$mEnd = time();
			if (!is_int($mBegin) || !is_int($mEnd))
				return error("Invalid start, end range");
			if ($mBegin < 1) $mBegin = 0;
			$uids = $this->user_get_users();

			if (!isset($uids[$mUser])) return error("Invalid user");
			$uid = $this->get_uid_from_username($mUser);
			$this->mysql->query("SELECT
									unix_timestamp(ts) as ts,
									quota
								 FROM
									quota_tracker
								 WHERE
										uid = '".$uid."'
									AND
										ts >= from_unixtime(".$mBegin.")
									AND
										ts < from_unixtime(".$mEnd.")");
			while ($row = $this->mysql->fetch_object()) {
				$quotas[] = array('ts' => $row->ts, 'quota' => $row->quota);
			}
			$cache->set($key, gzdeflate(serialize($quotas)), 43200);
			return $quotas;
		}

		/**
		 * Remove historical quota data
		 *
		 * @param  string $user
		 * @param  int    $until erase records until this timestamp
		 * @return bool
		 */
		public function erase_quota_history($user, $until = -1)
		{
			if (!$this->exists($user)) return error("user `$user' does not exist");
			$uid = $this->get_uid_from_username($user);
			$until = intval($until);
			if ($until < 0) $until = time()+86400*30;
			$q = $this->mysql->query("DELETE FROM quota_tracker WHERE uid = ".$uid." AND ts < FROM_UNIXTIME(".$until.");");
			return (bool)$q;

		}

		/**
		 * Fetch storage and file quotas from the underlying quota subsystem
		 *
		 * qused: disk space used in KB
		 * qsoft: soft limit on disk space in KB
		 * qhard: hard limit on disk space in KB
		 * fused: files used
		 * fsoft: soft limit on files
		 * fhard: hard limit on files
		 *
		 * Multi-user lookups returns a hash, while a
		 * single-user lookup returns a single quota record
		 * @see Site_Module::get_account_quota()
		 *
		 * @param mixed $username single user or array of users
		 * @return array
		 */
		public function get_quota($users = null) {
			if (!IS_CLI) {
				return $this->query('user_get_quota', $users);
			}
			$single = !is_array($users);
			if (!$users || ($this->permission_level & PRIVILEGE_USER))
				$users = array($this->username);
			else if (!is_array($users)) {
				$users = array($users);
			}
			$do_apache = $this->permission_level&PRIVILEGE_SITE &&
				in_array('apache',$users);

			if ($do_apache) {
				$quota_sum = array('qused' => 0, 'fused' => 0);
			}
			$uids = array();
			foreach ($users as $key => $user) {
				if ($do_apache && $user == 'apache') continue;
				if ( ! ($uid = $this->get_uid_from_username($user))) {
					warn($user.": user does not exist");
					unset($users[$key]);
				}
				$uids[$uid] = $user;
			 }

			$uid_list = join(" ", array_keys($uids));
			$quota_rep = Util_Process::exec('quota -w -v -u '.$uid_list, array('mute_stderr' => true));
			preg_match_all(Regex::QUOTA_USRGRP, $quota_rep['output'], $quotas, PREG_SET_ORDER);
			$quota_stat = array_combine($users, array_fill(0, sizeof($users), null));
			$max = round($this->get_config('diskquota','quota')*1024);
			foreach ($quotas as $quota) {
				$uid = $quota['uid'];
				$user = $uids[$uid];
				$qhard = $quota['qhard'] > 0  ? $quota['qhard']: $max;
				$quota_stat[$user] = array('qused' => (int)$quota['qused'],
					'qsoft' => (int)$quota['qsoft'],
					'qhard' => (int)$qhard,
					'fused' => (int)$quota['fileused'],
					'fsoft' => (int)$quota['filesoft'],
					'fhard' => (int)$quota['filehard']
				);
				if ($do_apache) {
					$quota_sum['qused'] += $quota['qused'];
					$quota_sum['fused'] += $quota['fileused'];
				}
			}
			
			if ($do_apache) {
				$grp = $this->site_get_account_quota();
				$mysql_qquota = 0;
				$tmpq = Util_Process::exec("du -s %s/var/lib/mysql",
					$this->domain_fs_path()
				);
				
				if ($tmpq['success']) {
                    $tmp = explode(" ", $tmpq['output']);
					$mysql_qquota = intval(array_shift($tmp));
				}
				
				$ap_qquota = max(-1,$grp['qused']-$quota_sum['qused']-$mysql_qquota);
				$ap_fquota = max(-1, $grp['qused']-$quota_sum['qused']);
				$quota_stat['apache'] = array('qused' => $ap_qquota,
					'qsoft' => $grp['qsoft'],
					'qhard' => $grp['qhard'],
					'fused' => $ap_fquota,
					'fsoft' => $grp['fsoft'],
					'fhard' => $grp['fsoft']
				);
			}
			return $single ? array_pop($quota_stat) : $quota_stat;
		}


		public function get_uid_from_username($username) {
			$user = $this->getpwnam($username);
			if (!$user) return false;
			return $user['uid'];
		}

		// {{{ change_gecos()

		/**
		 * Change a user's gecos field
		 *
		 * Updates the gecos field in /etc/passwd
		 * If called by admin, change_gecos() takes  two parameters:
		 * $user and $gecos.  Users only need to supply one parameter,
		 * the new gecos value.
		 *
		 * @param string $user  target user or gecos field if called by user
		 * @param string $gecos gecos field supplied
		 * @return bool
		 */
		public function change_gecos($user, $gecos = null) {
		 if (!IS_CLI)
			return $this->query('user_change_gecos',$user, $gecos);
		  if ($this->permission_level & PRIVILEGE_USER || !$gecos) {
			$gecos = $user;
			$user  = $this->username;
		 }

		 return $this->usermod_driver($user, array('gecos' => $gecos));
		}

		// }}}

		// {{{ usermod_driver()

		/**
		 * usermod driver
		 *
		 * Possible attribute keys
		 * gecos:      gecos/comment field
		 * home:       home directory
		 * username:   new username *DANGEROUS*
		 * passwd:     password encrypted via crypt()
		 * pw_expire:  number of days after which the password expires
		 * pw_disable: date on which the account will expire (YYYY-MM-DD)
		 * shell:      user shell
		 * pw_lock:    lock/unlock password
		 * pw_unlock
         * move_home:  move home directory
		 *
		 * @private
		 * @param string $user
		 * @param array  $attributes new attributes to set
		 * @return
		 */
		public function usermod_driver($user, $attributes) {
			if (!IS_CLI) {
				return $this->query('user_usermod_driver',$user, $attributes);
			}

			if (!$this->exists($user))
				return error($user . ": user does not exist");

			$attr2flag = array(
                'gecos'     => '-c',
				'home'      => '-d',
				'username'  => '-l',
				'passwd'    => '-p',
				'pw_expire' => '-e',
				'pw_disable'=> '-e',
				'shell'     => '-s',
				'pw_lock'   => '-L',
				'pw_unlock' => '-U',
                'move_home' => '-m'
            );
			$cmd_str = '/usr/sbin/chroot '.$this->domain_fs_path().' /usr/sbin/usermod';
			$newuser = null;
			foreach ($attributes as $attr => $attr_val) {
				if (!isset($attr2flag[$attr]))
					return error($attr.": unrecognized attribute");

				// error checking...
				switch ($attr) {
					case 'gecos':
						if (!$attr_val)
							$attr_val = "''";
					break;
					case 'home':
					case 'pw_lock':
					break;

					case 'username':
						$newuser = $attr_val;
					break;

					case 'pw_unlock':
					break;

                    case 'move_home':
                        if (!array_key_exists('username', $attributes)) {
                            return error("cannot move home without renaming user");
                        }
                        $attr_val = null;
                    break;

					default:
						if (!$attr_val) {
							return error($attr." missing value");
						}

				}
				$cmd_str .= ' '.$attr2flag[$attr].' '. ($attr_val ? escapeshellarg($attr_val) : '');
			}

			$cmd = Util_Process::exec($cmd_str.' '.$user);
			if ($cmd['success'] && $newuser) {
                $userpath = $this->domain_info_path().'/users/';
                if (file_exists($userpath . '/' . $user)) {
				    rename($userpath . '/' . $user, $userpath . '/' . $newuser);
                }
			}
			return $cmd['success'];
		}

		// }}}

		/**
		 * Checks for existence of user
		 *
		 * @param string username
		 * @return bool
		 */
		public function exists($user) {
			return $this->get_uid_from_username($user) !== false;
		}

		public function get_username_from_uid($uid) {
			$site = $this->site_id;
			if (!isset(self::$uid_mappings[$site])) {
				self::$uid_mappings[$site] = array();
			} else if (isset(self::$uid_mappings[$site][$uid]))
				return self::$uid_mappings[$site][$uid];
			if (!($fp = fopen($this->domain_fs_path().'/etc/passwd','r')))
				return error("/etc/passwd: cannot access file");
			while (!feof($fp)) {
				$line = fgets($fp);
				$line = explode(':',$line);
				if (!isset($line[2]) || !is_numeric($line[2]) || isset(self::$uid_mappings[$site][$line[2]]))
					continue;
				self::$uid_mappings[$site][$line[2]] = $line[0];
			}
			fclose($fp);
			if (!isset(self::$uid_mappings[$site][$uid])) return false;
		 	return self::$uid_mappings[$site][$uid];
		}


		/**
		 * Generate a list of files contributing towards the account quota
		 *
		 * Upon successful generation, the list is stored under ~/filelist-apis.txt
		 *
		 * @param  string $user  restrict search to user
		 * @param  string $base  glob-style directories to inspect
		 * @param  bool   $sort  sort by size
		 * @return bool
		 */
		public function find_quota_files($user = '',
			$base = '/{home,usr/local,var/www,var/lib,var/log}', $sort = true) {
			if (!IS_CLI)
				return $this->query('user_find_quota_files', $user, $base, $sort);
            $file = 'filelist-apis.txt';
			if (!$user)
				$user_args = '';
			else if (!$this->exists($user))
				return error('%s: does not exist', $user);
			else
				$user_args = '-user '.$user;
			// permit glob...
			if (false !== ($pos = strpos($base, "{")) && false !== ($end = strpos($base, "}"))) {
				$tmp = substr($base, 0, ++$pos);
				$tmp .= escapeshellarg(substr($base, $pos, $end-$pos));
				$tmp .= substr($base, $end);
				$base = $tmp;
			} else {
				$base = escapeshellarg($base);
			}
			$chroot_cmd = sprintf('find %s -type f -group %s %s -printf "%s"',
				$base,
				$this->group_id,
				$user_args,
				'%10k\t%16s\t%-16u\t%p\r\n'
			);
			if ($sort) {
				$chroot_cmd .= ' | sort -nr';
			}
			$list = '/home/'.$this->username.'/' . $file;

			$ret = Util_Process::exec("chroot %s /bin/sh -c '(printf %s ; %s) > %s'",
				$this->domain_fs_path(),
				'"%10s\t%16s\t%-16s\t%s\r\n" "szquota (KB)" "szdisk (B)" username path',
				$chroot_cmd,
				$list
			);
			$path = $this->domain_fs_path() . $list;
			chown($path, (int)$this->user_id);
			chgrp($path, (int)$this->group_id);
			if (!$ret['success']) {
                return false;
            }
            return $file;
		}
        
        /**
         * Remove a supplemental group
         * 
         * @param string $group
         * @return bool
         */
        public function sgroupdel($group) {
            if (!preg_match(Regex::GROUPNAME, $group)) {
                return error("invalid group `%s'", $group);
            }
            
            $groups = $this->sgroups();
            if (count($groups) == 1) {
                return error("cannot remove last group");
            } else if (!in_array($group, $groups)) {
                return error("cannot remove non-existent group `%s'", $group);
            }
            $file = $this->domain_fs_path() . '/etc/group';            
            $fp = fopen($file, 'r+');
            flock($fp, LOCK_EX);
            $lines = array();
            while (false !== ($line = fgets($fp))) {
                list($group_name, $password, $gid, $user_list) =
                        explode(':', $line);
                if ($group_name == $group) {
                    continue;
                }
                $lines[] = $line;
            }
            ftruncate($fp, 0);
            $lines = join("", $lines);
            fwrite($fp, $lines);
            fclose($fp);
            return true;
        }
        
        /**
         * Add a supplemental group
         * 
         * @param string $group
         * @return bool
         */
        public function sgroupadd($group) {
            if (!preg_match(Regex::GROUPNAME, $group)) {
                return error("invalid group `%s'", $group);
            }
            
            $groups = $this->sgroups();
            if (in_array($group, $groups)) {
                return error("duplicate group `%s'", $group);
            }
            // @XXX -o is a Redhat-specific param to override duplicate gid
            $cmd = 'chroot %(path)s groupadd -o -f -g %(groupid)d %(group)s';
            $args = array(
                'path' => $this->domain_fs_path(),
                'groupid' => $this->group_id,
                'group' => $group
            );
            $proc = Util_Process_Safe::exec($cmd, $args);
            return $proc['success'];
        }
        
        /**
         * List supplemental groups
         * 
         * @return array
         */
        public function sgroups() {
            $groups = array();
            $file = $this->domain_fs_path() . '/etc/group';
            $fp = fopen($file, 'r');
            while (false !== ($line = fgets($fp))) {
                list($group_name, $password, $gid, $user_list) =
                        explode(':', $line);
                if ($gid != $this->group_id) {
                    continue;
                }
                $groups[] = $group_name;
            }
            return $groups;
        }
        
		public function _delete() {
			foreach ($this->get_users() as $user => $pwd) {
				$this->erase_quota_history($user);
			}
		}

		public function _delete_user($user)
		{
			$this->erase_quota_history($user);
		}
	}
?>
