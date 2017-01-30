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
	 * Provides file interaction and ACL support
	 *
	 * @package core
	 */
	
	if (!defined('STDERR')) {
		$fp = fopen('/dev/null', 'w');
		define('STDERR', $fp);
	}

	class File_Module extends Module_Skeleton
	{
		const UPLOAD_UID = WS_UID;
		const STCACHE_ROOT = '6666cd76f96956469e7be39d750cc7d9';
		const ACL_MODE_RECURSIVE = 'R';
		const ACL_MODE_DEFAULT = 'd';
		const ACL_NO_RECALC_MASK = 'n';
		const ACL_FLAGS = '-PRbdkxn';
		// under apnscp root
		const DOWNLOAD_SKIP_LIST = '/etc/file_download_skiplist.txt';

		private static $registered_extensions = array(
			'zip'     => 'zip',
			'tgz'     => 'gzip',
			'tar'     => 'tar',
			'tar.gz'  => 'gzip',
			'gz'      => 'gzip',
			'bz'      => 'bzip',
			'bz2'     => 'bzip',
			'tar.bz'  => 'bzip',
			'tar.bz2' => 'bzip',
			'tbz'     => 'bzip',
			'tbz2'    => 'bzip'
			/*'rar'    => 'rar'*/
		);
		private static $uid_mappings;
		private static $stat_cache = array();
		// assume all operations exist on shadow/
		// if user is admin, bypass costly stat checks
		private static $acl_cache = array();
				private $quota_cache = array(
			'time' => null,
			'uids' => array()
		); // nobody from /etc/passwd
				private $compression_instances; // md5("/")

		// apply settings recursively
		private $trans_paths = array();
		// apply settings as default
		private $cached;
		// don't recalculate effective rights mask
		private $clearstat = false;
		// all valid ACL flags
		private $_optimizedShadowAssertion = false;

		/**
		 * {{{ void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();

			foreach (array_unique(array_values(self::$registered_extensions)) as $iface) {
				$this->compression_instances[$iface] = null;
			}
			$this->_optimizedShadowAssertion = (int)version_compare(platform_version(), '4.5', '>=');
			if ($this->_optimizedShadowAssertion && version_compare(platform_version(), '6', '>=')) {
				$this->_optimizedShadowAssertion = 2;
			}
			$this->exportedFunctions = array(
				'*'                               => PRIVILEGE_ALL,
				'lookup_chroot_pwnam'             => PRIVILEGE_SERVER_EXEC,
				'get_directory_contents_backend'  => PRIVILEGE_SERVER_EXEC|PRIVILEGE_ALL,
				'get_file_contents_backend'       => PRIVILEGE_ALL | PRIVILEGE_SERVER_EXEC,
				'report_quota'                    => PRIVILEGE_SITE,
				'report_quota_backend'            => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'change_file_permissions_backend' => PRIVILEGE_ALL | PRIVILEGE_SERVER_EXEC,
				'stat_backend'                    => PRIVILEGE_ALL | PRIVILEGE_SERVER_EXEC,
				'delete_backend'                  => PRIVILEGE_ALL | PRIVILEGE_SERVER_EXEC,
				'chmod_backend'                   => PRIVILEGE_ALL | PRIVILEGE_SERVER_EXEC,
				'put_file_contents_backend'       => PRIVILEGE_ALL | PRIVILEGE_SERVER_EXEC,
				'move_backend'                    => PRIVILEGE_ALL | PRIVILEGE_SERVER_EXEC,
				'fix_apache_perms_backend'        => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'chmod_backend'                   => PRIVILEGE_ALL | PRIVILEGE_SERVER_EXEC,
				'find_quota_files'                => PRIVILEGE_SITE,
				'canonicalize_site'               => PRIVILEGE_SITE | PRIVILEGE_USER);
			$this->__wakeup();
		}

		public function __wakeup()
		{
			$this->cached = Cache_User::spawn();
		}

		/**
		 * Transform relative path into an absolute path
		 *
		 * @param $file     absolute location of a path
		 * @param $referent relative path
		 * @return string
		 */
		public static function convert_relative_absolute($file, $referent)
		{
			if (false !== ($file_rel = strstr($file, '..'))) {
				$file = self::convert_relative_absolute(substr($file, 0, strpos($file, "..")), $file_rel);
			}

			// fetch the rest of the string
			$file_com = explode("/", dirname($file));
			$token = strtok($referent, '/');

			if ($token != "..") return $referent;

			array_pop($file_com);
			while (false !== ($token = strtok("/"))) {
				if ($token == '..') {
					array_pop($file_com);
				} else if (!$token)
					continue;
				else {
					$file_com[] = $token;
					break;
				}
			}

			$path = join("/", $file_com);

			while (false !== ($token = strtok("/"))) {
				if (!$token)               // path: /
					$path .= '/';
				else if ($token == '..') { // path: ..
					return self::convert_relative_absolute($path, strtok(""));
				} else
					$path .= '/' . $token;
			}

			return $path . strtok("");
		}

		/**
		 * array get_registered_extensions ()
		 * Keys from the return value correspond to the extension type,
		 * values are the classes all implementing the common interface
		 * Compression_Interface
		 *
		 * @return array list of known compression extensions and their corresponding
		 * interfaces.
		 */
		public function get_registered_extensions()
		{
			return self::$registered_extensions;
		}

		/**
		 * Extract files from archive
		 *
		 *
		 * @param  string $archive   archive file
		 * @param  string $dest      destination directory
		 * @param  bool   $overwrite overwrite destination files if source exists
		 * @return bool
		 */
		public function extract($archive, $dest, $overwrite = true)
		{
			if (!IS_CLI) {
				$ret = $this->query('file_extract', $archive, $dest);
				return $ret;
			}

			$class = $this->initialize_interface($archive);
			$archive_path = $this->make_path($archive);
			$destination_path = $this->make_path($dest);
			$tmp_path = $this->_mktmpdir('/tmp', 'ee');
			if ($archive_path instanceof Exception) return $archive_path;
			else if ($destination_path instanceof Exception) return $destination_path;

			$archive_stat = $this->stat_backend($archive);
			$destination_stat = $this->stat_backend($dest);
			if (!file_exists($destination_path)) {
				if (!$this->create_directory($dest, 0755, true))
					return false;
			} else if (!$this->can_descend($destination_path, true)) {
				return error($dest . ": unable to write to directory");
			}

			if ($archive_stat instanceof Exception)
				return $archive_stat;
			else if ($destination_stat instanceof Exception && !$destination_stat instanceof FileError)
				return $destination_stat;

			mkdir($tmp_path);
			chmod($tmp_path, 0700);

			$ret = $class->extract_files($archive_path, $tmp_path);
			if ($ret instanceof Exception) return $ret;

			/** now that we have the files extracted, chown */
			if (!strpos($tmp_path, '/', 1)) return error("path creation failure");
			$ret = 0;
			$flags = '-aHWxq';
			if (!$overwrite) $flags .= ' --ignore-existing';
			$proc = Util_Process_Safe::exec(
				'/bin/chown -R %s:%s %s && rsync ' . $flags . ' %s/ %s/ && rm -rf %s/',
				$this->user_id, $this->group_id, $tmp_path, $tmp_path, $destination_path, $tmp_path
			);

			chmod($destination_path, 0755);
			return $proc['success'];
		}

		/**
		 * Initialize compression driver for file
		 *
		 * @private
		 * @param  string $file
		 * @return object class instance
		 */
		private function initialize_interface($file)
		{
			if (!$this->is_compressed($file))
				return error($file . ": not a recognized compressed file");
			$ext = substr($this->compression_extension($file), 1);
			if (!$ext)
				return error($file . ": internal error determining archive extension");
			if (isset($this->compression_instances[$ext])) {
				return $this->compression_instances[$ext];
			}

			$base_dir = INCLUDE_PATH . '/lib/modules/compression/';
			$module = self::$registered_extensions[$ext];
			if (!file_exists($base_dir . '/' . $module . '.php'))
				return error($module . ": compression filter not found");

			if (!class_exists(ucwords($module) . '_Filter', 0)) {
				if (!interface_exists('IArchive', 0))
					include($base_dir . '/iarchive.php');
				if (!class_exists('Archive_Base', 0))
					include($base_dir . '/base.php');
				include($base_dir . '/' . $module . '.php');
			}

			$c = ucwords($module) . '_Filter';
			$class = new $c($this);

			$class->init($this);
			$this->compression_instances[$ext] = $class;

			return $this->compression_instances[$ext];
		}

		/**
		 * bool is_compressed (string)
		 * Checks to see if a file is a compressed archive through a
		 * bit of guestimation
		 *
		 * @param  string $mFile
		 * @return bool
		 */
		public function is_compressed($mFile)
		{
			$extTmp = explode(".", $mFile);
			$ext = array_pop($extTmp);
			/** may be .tar.gz for example */
			if (!isset(self::$registered_extensions[$ext])) {
				$ext2 = array_pop($extTmp);
				if (isset(self::$registered_extensions[join(array($ext2, $ext), '.')]))
					return true;
				else
					return false;
			} else
				return true;

		}

		/**
		 * Extract compression extension from file
		 *
		 * @param  $file
		 * @return string
		 */
		public function compression_extension($file)
		{
			if (!$this->is_compressed($file))
				return false;

			$extTmp = explode(".", $file);
			if (sizeof($extTmp) > 2)
				$ext = join(".", array_slice($extTmp, -2));

			if (sizeof($extTmp) <= 2 || !isset(self::$registered_extensions[$ext]))
				$ext = join("", array_slice($extTmp, -1));

			$this->compression_ext = $ext;
			return '.' . $ext;
		}

		/**
		 * Returns a path outside the chroot'd environment
		 *
		 * @TODO tokenize
		 * @param  string $path
		 * @param  string $link translated symbolic link path
		 * @throws FileError when an invalid path is detected
		 */
		public function make_path($path, &$link = '')
		{
			if (isset($this->trans_paths[$this->site_id][$path])) {
				$path = $this->trans_paths[$this->site_id][$path];
				$link = $path[1];
				return $path[0];
			}
			// we really don't know how to handle relative files

			if (!isset($path[0])) {
				return $this->domain_fs_path();
			} else if ($path[0] === "~") {
				$path = $this->user_get_home() . substr($path,1);
			} else if ($path[0] !== '/') {
				return error($path . ": path must be absolute");
			}
			$root = '';
			$newpath = str_replace('//', '/', $path);
			$link = '';

			if (($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER))) {
				$root = $this->domain_fs_path();
			}

			if (is_link($root . $newpath)) {
				$link = $root . $newpath;
				if (file_exists($link) && substr(readlink($link), 0, 1) == '/') {
					$newpath = realpath($link);
				} else {
					$po = $newpath;
					$newpath = substr(realpath($link), strlen($root));
					if (!$newpath) $newpath = $po;
				}
			}
			//print $mPath." ; ".var_export(explode('/',$mPath));
			for ($pathCom = explode('/', $newpath), $i = sizeof($pathCom); $i > 0; $i--) {
				$pathTest = $root . join(array_slice($pathCom, 0, $i), '/');
				if (file_exists($pathTest))
					break;
			}

			if (isset($root[1]) &&
				substr(realpath($pathTest), 0, strlen($root)) != $root
			) {
				// let's assume they made a symlink to /var/www/html/ instead of ../../var/www/
				//if (!file_exists($this->domain_fs_path().realpath($pathTest)))

				$newpath = $root . $pathTest;
				//return new FileError("Invalid path detected");
			}
			if (!self::sanitized($newpath))
				return error($newpath . ": Garbage characters in file ");
			$newpath = $root . str_replace('//', '/', $newpath);
			if (!isset($this->trans_paths[$this->site_id]))
				$this->trans_paths[$this->site_id] = array();
			$this->trans_paths[$this->site_id][$path] = array($newpath, $link);
			$this->trans_paths[$this->site_id][$newpath] = $path;
			return $newpath;

		}

		/**
		 * Verify file name is legal
		 *
		 *
		 * @param mixed $file file or directory name to check for malicious
		 *                    characters
		 * @return bool
		 */
		public static function sanitized($file)
		{
			return true;
		}

		protected function _mktmpdir($path, $prefix = '')
		{
			$dir = $path . '/' . uniqid($prefix);
			if (file_exists($dir))
				return $this->_mktmpdir($path, $prefix);
			return $dir;
		}

		/**
		 * Give information about a file
		 *
		 * @see stat()
		 * @param string $file
		 * @return array
		 */
		public function stat_backend($file, $shadow = false)
		{
			$link = '';
			$link_type = 0;
			$path = $shadow ? $this->make_shadow_path($file, $link) :
				$this->make_path($file, $link);
			if ($path instanceof Exception) {
				return $path;
			}

			$filemtime = -1;
			if (!$link && !file_exists($path)) return array();
			if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER))
				$prefix = $shadow ? $this->domain_shadow_path() : $this->domain_fs_path();
			else
				$prefix = '';
			// real path
			if ($link)
				$pathbase = dirname($link);
			else
				$pathbase = dirname($path);

			// virtual path
			$file = rtrim($file, "/");
			$vpathbase = dirname($file);
			$dirhash = md5($vpathbase);
			$filename = basename($file);

			// $file = "/"
			if (!isset($filename[0])) $filename = '.';
			$filehash = md5($filename);

			if ($this->clearstat) {
				clearstatcache(false);
				$this->clearstat = false;
			}

			$prefixlen = strlen($prefix);
			$siteid = $this->site_id;

			$dh = opendir($pathbase);
			if (!$dh) {
				return error("cannot open `%s'", dirname($file));
			}
			Error_Reporter::mute_warning(true);
			$stats = array();
			while (false !== ($dirent = readdir($dh))) {
				if ($dirent === '..') {
					continue;
				}
				$portable_link = true;
				$path = $pathbase . '/' . $dirent;
				$islink = is_link($prefix . $vpathbase . '/' . $dirent);
				$vfile = $vpathbase . '/' . $dirent;
				$enthash = md5($dirent);

				if ($islink === false) {
					$stat_details = stat($path);
				} else {
					$tmp = $vpathbase . '/' . $dirent;
					$referent = $shadow ? $this->make_shadow_path($tmp) : $this->make_path($tmp);
					$vreferent = substr($referent, $prefixlen);
					if (!file_exists($referent)) {
						$vreferent = null;
						$portable_link = 0;
					} else {
						$portable_link = substr(readlink($prefix . $vpathbase . '/' . $dirent), 0, 1) != '/';
					}
					$link_type = $referent && is_dir($referent) ? 2 : 1;
					$stat_details = lstat($path);
				}

				if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
					// fetch uid/gid from chroot'd filesystem
					$owner = $this->lookup_chroot_pwnam($stat_details['uid']);
					$group = $this->lookup_chroot_pwnam($stat_details['gid']);
				} else {
					// otherwise we can use normal posix functions to query /etc/passwd
					$owner = posix_getpwuid($stat_details['uid']);
					$owner = $owner['name'];
					$group = posix_getgrnam($stat_details['gid']);
					$group = $group['name'];
				}

				$acl = 0;
				// next gather the ACLs on the file
				// if file is a symbolic link, then skip it
				if (!$islink && $vpathbase !== '.') {
					$acls = $this->get_acls($vfile);
					if ($acls) {
						$pwusr = $this->lookup_chroot_pwnam($this->user_id);
						$pwgrp = $this->lookup_chroot_pwnam($this->group_id);
						foreach ($acls as $item) {
							if (isset($item['user']) && $item['user'] == $pwusr) {
								$acl = $item['permissions'];
								break;
							} else if (isset($item['group']) && $item['group'] == $pwgrp) {
								$acl = $item['permissions'];
							}
						}
					}
				}
				$vstat = array(
					'filename'    => $dirent,
					'owner'       => $owner ? $owner : $stat_details['uid'],
					'group'       => $group ? $group : $stat_details['gid'],
					'uid'         => $stat_details['uid'],
					'gid'         => $stat_details['gid'],
					'size'        => $stat_details['size'],
					'file_type'   => $islink ? 'link' : filetype($path),
					'referent'    => $islink ? $vreferent : null,
					'portable'    => $portable_link,
					'link'        => !$islink ? 0 : $link_type,
					'nlinks'      => $stat_details['nlink'],
					'permissions' => $islink ? 41471 : $stat_details['mode'],
					'site_quota'  => ($stat_details['gid'] == $this->group_id),
					'user_quota'  => ($stat_details['uid'] == $this->user_id),
					'ctime'       => $stat_details['ctime'],
					'mtime'       => $stat_details['mtime'],
					'atime'       => $stat_details['atime'],
					'inode'       => $stat_details['ino'],
					'sid'         => $this->site_id,
					'can_write'   => $acl & 2 || $islink ||
						($this->permission_level & PRIVILEGE_SITE) &&
						($stat_details['gid'] == $this->group_id || $stat_details['uid'] == APACHE_UID /* apache */) ||
						$stat_details['uid'] == $this->user_id && $stat_details['mode'] & 0x0080 ||
						($stat_details['gid'] == $this->group_id && $stat_details['mode'] & 0x0010) &&
						!($stat_details['mode'] & 0x0200) ||
						$stat_details['gid'] != $this->group_id && $stat_details['mode'] & 0x0002,

					'can_read' => $acl & 4 ||
						($this->permission_level & PRIVILEGE_SITE) &&
						($stat_details['gid'] == $this->group_id || $stat_details['uid'] == APACHE_UID) ||
						$stat_details['uid'] == $this->user_id && $stat_details['mode'] & 0x0100 ||
						$stat_details['gid'] == $this->group_id && $stat_details['mode'] & 0x0020 ||
						$stat_details['gid'] != $this->group_id && $stat_details['mode'] & 0x0004,

					'can_execute' => $acl & 1 ||
						($this->permission_level & PRIVILEGE_SITE) &&
						($stat_details['gid'] == $this->group_id || $stat_details['uid'] == APACHE_UID) ||
						$stat_details['uid'] == $this->user_id && $stat_details['mode'] & 0x0040 ||
						$stat_details['gid'] == $this->group_id && $stat_details['mode'] & 0x0008 ||
						$stat_details['gid'] != $this->group_id && $stat_details['mode'] & 0x0001,

					'can_chown' => ($this->permission_level & PRIVILEGE_SITE) && /** super user */
						($stat_details['gid'] == $this->group_id || $stat_details['uid'] == APACHE_UID ||
							($stat_details['gid'] == APACHE_UID)) ||
						$this->permission_level & PRIVILEGE_USER && $stat_details['uid'] == $this->user_id,

					'can_chgrp' => $this->permission_level & PRIVILEGE_ADMIN
				);
				$stats[$enthash] = $vstat;
			}
			closedir($dh);
			Error_Reporter::unmute_warning();
			self::$stat_cache[$siteid][$dirhash] = $stats;
			// special case root fs for accounts

			$cachekey = $this->_getCacheKey($file);
			if (!$this->cached->set($cachekey, $stats, 7200)) {
				Error_Reporter::report("FAIL ADD: $file ($cachekey) - msg " . $this->cached->getResultMessage());
			}
			//$this->cached->delete($cachekey);

			if (!isset($stats[$filehash])) {
				if (!$shadow) {
					return $this->stat_backend($file, true);
				}
				if (is_debug()) {
					$newpath = str_replace('/fst', '/shadow', $pathbase);
					var_dump(`ls -la $pathbase ; ls -la $newpath`);
					var_dump("EMER: Missed hash!?!!!@", $vpathbase, $filename, $dirhash, $filehash, self::$stat_cache[$siteid][$dirhash]);
					die();
				}
			}

			if (!isset($stats[$filehash])) {
				$data = "ASKED: $filehash ($filename)" . "\r\n\r\n" . var_export($stats, true);
				Error_Report::report("MISSED HASH: " . $data);
			}
			return $stats[$filehash];
		}

		/**
		 * mixed lookup_chroot_pwnam (integer)
		 *
		 * @param integer $uid user id to lookup
		 * @return string transformed name of the uid.
		 *                     Transforms the uid the username within a chroot'd environment
		 */
		private function lookup_chroot_pwnam($uid)
		{
			if (!$uid) return 'root';
			return $this->user_get_username_from_uid($uid);
		}

		/**
		 * Perform ACL lookup on files
		 *
		 * @param  string $file filename
		 * @return array
		 */
		public function get_acls($file)
		{
			if (!strncmp($file, "/proc", 5)) return array();
			if (!IS_CLI) {
				$ret = $this->query('file_get_acls', $file);
				return $ret;
			}

			if ($this->permission_level & PRIVILEGE_SITE) {
				$optimized = $this->_optimizedShadowAssertion;
			} else {
				$optimized = false;
			}

			if ($optimized) {
				// only copy off shadow, if in the future ro -> rw branch
				// propagation can setgid copy-ups, then maybe switch back to make_path()
				// do not use shadow path as dest if luna+ (OverlayFS)
				$path = $this->make_shadow_path($file);
				$prefixlen = strlen($this->domain_shadow_path());
			} else {
				$path = $this->make_path($file);
				$prefixlen = strlen($this->domain_fs_path());
			}

			if (!$path) return $path;

			$cache_key = $this->site_id . "|" . dirname($file);
			$apc_key = "acl:" . $cache_key;
			$acl_dir = $path;

			// check apc backend cache
			if (!isset(self::$acl_cache[$cache_key])) {
				$acl_dir = dirname($path);
				$cache = apc_fetch($apc_key, $success);
				if ($success) {
					$cache = unserialize($cache);
					self::$acl_cache = array_merge(self::$acl_cache,
						$cache);
					return $cache;

				}
			}

			// acl updates only happen through one command
			if (isset(self::$acl_cache[$cache_key])) {
				//print "Self cache hit on $cache_key\n";
				return self::$acl_cache[$cache_key]['aclinfo'];
			}

			if (!is_readable($path))
				return new FileError($file . ": unable to read");

			if (!is_dir($acl_dir)) $acl_dir = dirname($path);

			// conceal any warnings about missing files in the glob pattern
			$path_safe = escapeshellarg($acl_dir);
			$path_safe = str_replace('%', '%%', $path_safe);
			// ignore non-ACL entries
			$cmd = sprintf('getfacl --skip-base --absolute-names --omit-header --numeric --tabular ' .
				"--all-effective %s/ %s/'.[!.]*' %s/'..?*' %s/'*'",
				$path_safe,
				$path_safe,
				$path_safe,
				$path_safe);
			$data = Util_Process::exec($cmd, array(0, 1), array('mute_stderr' => true));
			/**
			 * @TODO: Cache expensive ACL lookups
			 */

			$isChroot = $this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER);
			$data['output'] = preg_replace_callback('/\\\\(\d{3})/', create_function('$match', 'return chr(octdec($match[1]));'), $data['output']);
			//if (!$data['output']) {
			//	warn($cmd.": no response");
			//}

			$acl_cache = array();

			foreach (explode("\n\n", $data['output']) as $entry) {
				if (strncmp($entry, '# file:', 7))
					continue;

				$entpath = substr($entry, 8, strpos($entry, "\n") - 8);
				if (strrchr($entpath, '/') == '/.' || strrchr($entpath, '/') == '/..')
					continue;
				/** skip .. and . entries */
				$acls = array();
				foreach (explode("\n", $entry) as $line) {
					if (preg_match(Regex::GETFACL_ACL, $line, $aclMatches)) {
						$perms = 0;
						if ($aclMatches[1] == "USER") {
							$type = "euser";
						} else if ($aclMatches[1] == "GROUP") {
							$type = "egroup";
						} else {
							$type = $aclMatches[1];
						}

						if (strtolower($aclMatches[3][0]) == 'r')
							$perms |= 4;
						if (strtolower($aclMatches[3][1]) == 'w')
							$perms |= 2;
						if (strtolower($aclMatches[3][2]) == 'x')
							$perms |= 1;
						$acls[] = array($type         => ($isChroot ?
							$this->lookup_chroot_pwnam($aclMatches[2]) : $aclMatches[2]),
						                'permissions' => $perms
						);
					}
				}
				$aclkey = $this->site_id . "|" . substr($entpath, $prefixlen);
				$acl_cache[$aclkey] = array(
					'ctime'   => filectime($entpath),
					'aclinfo' => $acls
				);
			}

			if (!isset($acl_cache[$cache_key])) {
				$acl_cache[$cache_key] = array(
					'aclinfo' => array(),
					'ctime'   => time()
				);
			}

			apc_add($apc_key, serialize($acl_cache), 1800);
			self::$acl_cache = array_merge(self::$acl_cache, $acl_cache);
			return self::$acl_cache[$cache_key]['aclinfo'];
		}

		/**
		 * Resolve path as shadow
		 *
		 * @param        $path
		 * @param string $link
		 * @return string
		 */
		public function make_shadow_path($path, &$link = '')
		{
			$path = $this->make_path($path, $link);
			$prefix = $this->domain_fs_path();
			return $this->domain_shadow_path() . substr($path, strlen($prefix));
		}

		private function _getCacheKey($file)
		{
			$cachebase = $this->_getCacheDir($file);
			return 's:' . md5($cachebase);
		}

		private function _getCacheDir($file)
		{
			return dirname($file);
		}

		/**
		 * bool create_directory (string[, int[, bool]])
		 * Creates a directory within the filesystem and will recursively
		 * create parent directories if need be
		 *
		 * @param string  $dir       directory name to create
		 * @param integer $mode      mode to create the file
		 * @param bool    $recursive recursively create directory
		 */
		public function create_directory($dir, $mode = 0755, $recursive = false)
		{
			if (!is_int($mode))
				return error($mode . ": invalid mode");
			if (!IS_CLI)
				return $this->query('file_create_directory', $dir, $mode, $recursive);

			$path = $this->make_path($dir);
			$dir2mk = array();
			if (!$recursive && !file_exists(dirname($path)))
				return error(dirname($dir) . ": no such file/directory");
			if (file_exists($path)) {
				if (is_dir($path)) return true;
				else               return warn($dir . ": file exists");
			}
			//

			$dir = $this->unmake_path($path);
			$curpath = '';
			$curdir = strtok($dir, "/");
			$pathpfx = $this->domain_fs_path();

			do {
				$curpath .= '/' . $curdir;
				$fullpath = $pathpfx . $curpath;
				if (!file_exists($fullpath))
					$dir2mk[] = $fullpath;
			} while (false !== ($curdir = (strtok("/"))));
			if (!$dir2mk) {
				// @XXX weird aufs bug, initial stat reports no
				// but incremental dir buildup reports file_exists()
				// possible delay in cache?
				// triggered in litmus basic test no 6,
				// "mkcol_over_plain" -> mkdir over file
				return is_dir($fullpath);
			}
			$parent = dirname($dir2mk[0]);
			$pstat = $this->stat($this->unmake_path($parent));

			if ($pstat instanceof Exception)
				return $pstat;

			// check to see if can access parent
			if (!$this->can_descend($parent) || !$pstat['can_write']) {
				return error($this->unmake_path($parent) . ': permission denied');
			}

			foreach ($dir2mk as $newdir) {
				$res = mkdir($newdir) &&
					chown($newdir, (int)$this->user_id) &&
					chgrp($newdir, (int)$this->group_id) &&
					chmod($newdir, (int)$mode);

				if (!$res) {
					return error($this->unmake_path($newdir) . ": cannot create directory");
				}
			}
			return true;
		}

		/**
		 * string unmake_path(string $mPath)
		 * Complimentary function to make_path
		 *
		 * @return string chroot'd path
		 */
		public function unmake_path($mPath)
		{
			// admin always has root access
			if ($this->permission_level & PRIVILEGE_ADMIN) {
				return $mPath;
			}
			if (isset($this->trans_paths[$mPath]))
				return $this->trans_paths[$mPath];
			$mPath = str_replace('//', '/', $mPath);
			$offset = 0;
			if (($this->permission_level & PRIVILEGE_SITE) == PRIVILEGE_SITE ||
				($this->permission_level & PRIVILEGE_USER) == PRIVILEGE_USER
			) {
				if (stristr($mPath, '/home/virtual/' . $this->domain))
					$offset = strlen('/home/virtual/' . $this->domain);
				else if (stristr($mPath, $this->domain_fs_path()))
					$offset = strlen($this->domain_fs_path());
			}
			return str_replace('//', '/', '/' . substr($mPath, $offset));
		}

		/**
		 * Gives information about a file
		 *
		 * Peforms a stat() request on named file
		 *
		 *    array(22) {
		 *    ["owner"]=> string(5) "debug"
		 *    ["group"]=> string(5) "group"
		 *    ["uid"]=> int(664)
		 *    ["gid"]=> int(664)
		 *    ["size"]=> int(4096)
		 *    ["file_type"]=> string(3) "dir"
		 *    ["referent"]=> NULL
		 *    ["portable"]=> bool(true)
		 *    ["link"]=> int(0)
		 *    ["nlinks"]=> int(4)
		 *    ["permissions"]=> int(16889)
		 *    ["site_quota"]=> bool(true)
		 *    ["user_quota"]=> bool(true)
		 *    ["ctime"]=> int(1242769316)
		 *    ["mtime"]=> int(1242769316)
		 *    ["atime"]=> int(1230433552)
		 *    ["inode"]=> int(2454742)
		 *    ["can_write"]=> bool(true)
		 *    ["can_read"]=> bool(true)
		 *    ["can_execute"]=> bool(true)
		 *    ["can_chown"]=> bool(true)
		 *    ["can_chgrp"]=> bool(true)
		 *  }
		 *
		 *  owner: resolved name of the uid
		 *  group: resolved name of the gid
		 *  uid:   numeric user id
		 *  gid:   numeric group id
		 *  size:  file size in bytes
		 *  file_type: file type, values [dir, file, link]
		 *  link: file is symbolic link, 2 if directory, 1 if file
		 *  nlinks: number of hardlinks to the file
		 *  permissions: file permissions encoded as integer
		 *  site_quota: whether the file counts towards the site's quota
		 *  user_quota: whether the file counts towards the user's quota
		 *  ctime: creation time
		 *  mtime: modification time
		 *  atime: last access time
		 *  inode: filesystem inode
		 *  can_write: file has write bit set
		 *  can_read:  file has read bit set
		 *  can_execute: file has execute bit set
		 *  can_chown: user privileged to chown()
		 *  can_chgrp: user privileged to chgrp()
		 *
		 * @param string $file
		 * @return array
		 */
		public function stat($file)
		{
			$stat = $this->_getCache($file);
			if (false !== $stat) return $stat;
			$shadow = version_compare(platform_version(), '4.5', '>=');
			return $this->query('file_stat_backend', $file, $shadow);
		}

		private function _getCache($file)
		{
			$dir = dirname($file);
			$filename = basename($file);
			if (!isset($filename[0])) $filename = '.';
			$dirhash = md5($dir);
			$filehash = md5($filename);
			$siteid = $this->site_id;
			if (isset(self::$stat_cache[$siteid][$dirhash][$filehash])) {
				return self::$stat_cache[$siteid][$dirhash][$filehash];
			}
			$cache = $this->cached;
			$cachekey = $this->_getCacheKey($file);
			$stat = $cache->get($cachekey);
			// direct file stat

			if ($stat) {
				self::$stat_cache[$siteid][$dirhash] = $stat;
				if (isset($stat[$filehash])) {
					return $stat[$filehash];
				}
			}
			return false;
		}

		/**
		 * bool can_descend (string)
		 *
		 * @param string $path      fully resolved path
		 * @param bool   $rw        require write permissions as well
		 * @param bool   $direxists require that directory exists
		 *                          break before encountered
		 */
		private function can_descend($path, $rw = false, $direxists = true)
		{
			$fspfx = $this->domain_fs_path();
			if (substr($path, 0, strlen($fspfx)) != $fspfx)
				return error($path . ": not fully qualified path");
			// directory components to examine, assume fs prefix is immutable
			$dirchk = substr($path, strlen($fspfx));
			$subdir = strtok($dirchk, "/");
			$curpath = '';
			do {
				$curpath .= '/' . $subdir;
				$fullpath = $fspfx . $curpath;
				if (!file_exists($fullpath)) {
					if ($direxists) return false;
					else break;
				}

				$stat = $this->stat_backend(substr($fullpath, strlen($fspfx)));
				if ($stat instanceof Exception)
					return error($stat->getMessage());
				if (!$stat['can_execute'] || !$stat['can_read']) {
					return false;
				}
			} while (false !== ($subdir = strtok("/")));

			if ($rw && !$stat['can_write']) {
				return false;
			}


			return true;
		}

		/**
		 * List contents of a compressed file
		 *
		 * @param  string $file file name
		 * @return array
		 */
		public function get_archive_contents($file)
		{
			if (!IS_CLI)
				return $this->query('file_get_archive_contents', $file);

			$path = $this->make_path($file);
			$stat = $this->stat_backend($file);

			if ($path instanceof Exception)
				return $path;
			if ($stat instanceof Exception)
				return $stat;

			$class = $this->initialize_interface($path);
			if ($class instanceof Exception || !$class)
				return $class;

			$files = $class->list_files($path);
			Util_Conf::sort_files($files, 'value', true);
			return $files;
		}

		/**
		 * Copy files
		 *
		 * @param  string|array $source    array of source files or directories to copy
		 * @param  string       $dest      destination directory or file
		 * @param  int          $force     overwrite destination with source if exists
		 * @param  int          $recursive recursively copy directory contents
		 * @param  int          $prune     remove target before copying
		 * @return bool
		 */
		public function copy($source, $dest, $force = true, $recursive = true, $prune = false)
		{
			if (!IS_CLI) {
				if (!$source || !$dest)
					return error("invalid source or destination");
				return $this->query('file_copy', $source, $dest, $force, $recursive, $prune);
			}
			if ($this->permission_level & PRIVILEGE_SITE) {
				$optimized = $this->_optimizedShadowAssertion;
			} else {
				$optimized = false;
			}

			if (!is_array($source)) $source = array($source);

			if ($optimized && $optimized !== 2) {
				// only copy off shadow, if in the future ro -> rw branch
				// propagation can setgid copy-ups, then maybe switch back to make_path()
				// do not use shadow path as dest if luna+ (OverlayFS)
				$dest_path = $this->make_shadow_path($dest);
			} else {
				$dest_path = $this->make_path($dest);
			}

			if (is_link($dest_path)) $dest_path = readlink($dest_path);
			$dest_parent = $dest_path;

			// destination is not a folder
			if (!file_exists($dest_path) || !is_dir($dest_path)) {
				if (count($source) > 1)
					return error("copying mulitple files, but " .
						"destination `$dest' is not a directory");
				$dest_parent = dirname($dest_path);
			}
			if (!file_exists($dest_parent)) return error("destination `$dest_parent' does not exist");

			if (!$optimized) {
				// ignore dir checks on optimized algo
				$parent_stat = $this->stat_backend($this->unmake_path($dest_parent));
				if ($parent_stat instanceof Exception) {
					print $source . " " . $dest . " - " . $parent_stat->getMessage();
					return $parent_stat;
				}
				if ($parent_stat['file_type'] == 'dir' && (!$parent_stat['can_write'] ||
						!$parent_stat['can_execute'] || !$parent_stat['can_read'])
				)
					return error("accessing `$dest': permission denied");
			}

			$files_copied = -1; // number of files copied
			for ($i = 0, $nsource = sizeof($source); $i < $nsource; $i++) {
				$link = '';

				$src_path = $optimized ? $this->make_shadow_path($source[$i], $link) :
					$this->make_path($source[$i], $link);

				if (strlen($source[$i]) <= 6)
					return error("aborting operation for your own good! " . var_export($source[$i]));

				if ($link) $files = (array)$link;
				else if ($src_path === $dest_path) {
					warn("source directory `" .
						$this->unmake_path($src_path) . "' and destination are same");
					continue;
				} else {
					$files = glob($src_path, GLOB_NOSORT);
				}
				for ($j = 0, $nfiles = sizeof($files); $j < $nfiles; $j++) {
					$file = $files[$j];
					if (!file_exists($file)) continue;

					if ($optimized) {
						$local_file = $this->unmake_shadow_path($file);
						// create a stat array with bare minimums
						$fstat = array(
							'file_type'   => filetype($file),
							'permissions' => fileperms($file)
						);
					} else {
						$local_file = $this->unmake_path($file);
						$fstat = $this->stat($local_file);
						#fwrite(STDERR, "F: (".$fstat['file_type'].")".$file."\n");
						if ($fstat instanceof Exception) return $fstat;

						if (!$fstat['can_read']) {
							$files_copied = 0;
							error("cannot read `$local_file'");
							continue;
						}
					}

					if ($fstat['file_type'] != 'dir') {
						// copy file to newfile
						$newfile = $dest_path;
						if ($dest_parent == $dest_path)
							$newfile .= '/' . basename($local_file);
						if (is_dir($newfile)) {
							//fwrite(STDERR, "WTF\n\n\n");
							$newfile .= basename($local_file);
						}
						if ($file === $newfile) {
							warn("source `" . basename($file) . "' destination same");
							continue;
						}
						if (file_exists($newfile)) {
							if (!$force) {
								warn("cannot overwrite `" . $this->unmake_path($newfile) . " " .
									$dest_parent . " " . $dest_path . " " . $local_file . "'");
								$files_copied = 0;
								continue;
							}
							// permissions are already asserted by checking dest
							unlink($newfile);
						}
						#fwrite(STDERR, "Copy $file to $newfile\n");
						copy($file, $newfile) && chown($newfile, $this->user_id) &&
						chgrp($newfile, $this->group_id) and $files_copied &= 1;
						continue;
					} else {
						if (!$recursive) {
							warn("skipping directory `$local_file");
							$files_copied = 0;
							continue;
						}
						// copy directory contents
						$mkdir = '';
						$newdest = $dest . '/' . basename($local_file);
						// directory rename
						if (!file_exists($dest_path)) {
							$mkdir = 1;
							$newdest = $dest;
							// directory parenting
						} else if (!file_exists($dest_path) . '/' . basename($local_file)) {
							$mkdir = 1;
						}
						//print "Dir - ".$dest_path." -- ".$newdest." -- ".$mkdir."\n";
						if ($mkdir && !$this->create_directory($newdest,
								$fstat['permissions'], false)
						) continue;
						//fwrite(STDERR, "Enumerating dir $local_file to $newdest\n");
						$subreq = $this->copy(
							array($local_file . '/*'),
							$newdest,
							$force,
							$recursive,
							$prune
						);
						if ($prune && !$subreq) {
							$this->delete($dest, true);
						}
						$files_copied &= $subreq;

					}
				}
			}
			return $files_copied;
		}

		/**
		 * Strip shadow prefix from path
		 *
		 * Because this is a wrapper to unmake_path,
		 *
		 * @param $path
		 * @return string
		 */
		public function unmake_shadow_path($path)
		{
			$shadow = $this->domain_shadow_path();

			if (!strncmp($path, $shadow, strlen($shadow))) {
				$fst = $this->domain_fs_path();
				$path = $fst . substr($path, strlen($shadow));
			}
			return $path = $this->unmake_path($path);
		}

		/**
		 * bool delete (mixed, [bool = FALSE])
		 * Deletes a file from within the filesystem and calls {@see can_delete()}
		 *
		 * @param mixed $file      accepts file or array of files to delete
		 * @param  bool $recursive recusrively delete files
		 * @return bool
		 */
		public function delete($file, $recursive = false)
		{
			if (!is_array($file))
				$file = array($file);
			foreach ($file as $locfile)
				if (!self::sanitized($locfile))
					return error("Junk path detected for %s", $locfile);
			$data = $this->query('file_delete_backend', $file, (bool)$recursive);
			$this->_purgeCache($file);
			return is_array($data) ? new FileError(join($data, "\n")) : true;
		}

		/**
		 * Remove files from cache
		 *
		 * @param array|string $files
		 * @return bool
		 */
		private function _purgeCache($files)
		{
			$it = new ArrayIterator($files);
			$purged = array();
			$siteid = $this->site_id;
			while ($it->valid()) {
				$f = $it->current();
				$dir = dirname($f);
				$hash = md5($dir);
				$key = $it->key();
				$it->offsetUnset($key);
				$it->next();
				if (isset($purged[$hash])) continue;
				self::$stat_cache[$siteid][$hash] = null;
				$this->cached->delete('s:' . $hash);
				$purged[$hash] = 1;
				// has not been previously removed
			}
			if ($it->count() >= 1) {
				$this->clearstat = true;
			}

			return;
		}

		/**
		 * bool delete_backend (mixed, [bool = FALSE])
		 *
		 * @see delete()
		 */
		public function delete_backend($files, $recurse, $depth = 1)
		{
			$link = '';
			$ret = $ok = 1;
			$truncate = 0;
			$optimized = $this->_optimizedShadowAssertion &&
				($this->permission_level & PRIVILEGE_SITE);

			if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
				if ($optimized) {
					$truncate = strlen($this->domain_shadow_path());
				} else {
					$truncate = strlen($this->domain_fs_path());
				}
			}

			foreach ($files as $wcfile) {
				if (!isset($wcfile[5]))
					throw new FileError("Something's wrong, aborting! " . var_export($wcfile));
				$link = '';
				$exdir = $optimized ? $this->make_shadow_path($wcfile, $link) :
					$this->make_path($wcfile, $link);

				if (!$exdir) continue;
				$globmatch = glob($exdir, GLOB_NOSORT);

				/**
				 * Dangling symlinks fail, manually construct
				 * the array
				 */
				if (!$globmatch && is_link($exdir))
					$globmatch = array($exdir);
				for ($i = 0, $n = sizeof($globmatch); $i < $n;
				     $i++, $ret &= $ok) {
					$ok = 0;
					$path = $globmatch[$i];
					// local file name
					if ($truncate) $file = substr($path, $truncate);
					else $file = $path;
					// recursive deletion is not enabled, delete
					// link instead
					if (!$path || !file_exists($path) && !is_link($path)) {
						$ok = 1;
						continue;
					}
					if (!$optimized) {
						// perform stat only on secondary users or old platforms
						$stat = $this->stat(dirname($file));

						if ($stat instanceof Exception) {
							Error_Reporter::handle_exception($stat);
							error($file . ": cannot delete- stat failed");
							continue;
						}
					}

					// remove a symlink, do not follow
					if (is_link($path)) { //&& (!$recurse || $depth > 1)) {
						unlink($path);
						$ok = 1;
						continue;
					}

					$is_dir = is_dir($path);
					// file is a directory, enumerate its children, delete,
					// and if successful (directory is non-empty), remove this
					// directory
					if ($is_dir) {
						if (!$recurse) {
							warn($file . ": cannot remove directory without " .
								"recursive option");
							continue;
						}
						$dh = opendir($path);
						if (!$dh) {
							error($file . ": cannot open directory");
							continue;
						}

						$dirfiles = array();
						while (false !== ($dirent = readdir($dh))) {
							if ($dirent != '.' && $dirent != '..')
								$dirfiles[] = $file . '/' . $this->_glob_escape($dirent);
						}
						closedir($dh);
						$ok = $this->delete_backend($dirfiles, $recurse, $depth + 1);
						// cannot remove directory if subdir has files
						if (!$ok) continue;
					}
					if (!$optimized && (!$stat['can_execute'] || !$stat['can_write'])) {
						warn($file . ": cannot remove directory- permission denied");
						continue;
					}
					if ($is_dir === true && !rmdir($path) ||
						$is_dir === false && !unlink($path)
					) {
						$errmsg = Error_Reporter::get_last_php_msg();
						if ($errmsg) warn($file . ": cannot remove- " . $errmsg);
						continue;
					}

					$ok = 1;
				}
			}
			return (bool)$ret & $ok;

		}

		/**
		 * mixed glob_escape(mixed)
		 * Escape glob-special characters:
		 * {, }, [, ], *, ?
		 */
		private function _glob_escape($str)
		{
			$search = array('*', '[', ']', '{', '}', '?');
			$replace = array('\*', '\[', '\]', '{', '\}', '\?',);
			if (!is_array($str))
				return substr($str, 0, strrpos($str, '/')) . str_replace($search,
					$replace, substr($str, strrpos($str, '/')));

			$safe = array();
			foreach ($str as $raw)
				$safe[] = substr($str, 0, strrpos($raw, '/')) . str_replace($search,
						$replace, substr($raw, strrpos($str, '/')));

			return $safe;
		}

		/**
		 * bool chown(string, string[, bool = false])
		 *
		 * @param mixed  $mFile      array of filenames or single filename
		 * @param string $mUser      target uid
		 * @param bool   $mRecursive recursively chown
		 * @return bool
		 */
		public function chown($mFile, $mUser, $mRecursive = false)
		{
			if (!IS_CLI)
				return $this->query('file_chown', $mFile, $mUser, $mRecursive);
			$validUsers = array_keys($this->user_get_users());
			$validUsers[] = 'apache';

			if ($this->tomcat_enabled())
				$validUsers[] = $this->tomcat_system_user();
			if (!in_array($mUser, $validUsers))
				return error("invalid user `" . $mUser . "'");
			else if (!is_array($mFile))
				$mFile = array($mFile);
			$errors = array();
			$tUID = $this->user_get_users();

			// RHEL constant UID
			$tUID['apache'] = array('uid' => APACHE_UID);
			if (!isset($tUID[$mUser]['uid']))
				return error("Eep, unable to find UID for " . $mUser);
			$tUID = (int)$tUID[$mUser]['uid'];
			if ($this->permission_level & PRIVILEGE_SITE) {
				$optimized = $this->_optimizedShadowAssertion;
			} else {
				$optimized = false;
			}
			foreach ($mFile as $file) {
				if ($optimized) {
					$path = $this->make_shadow_path($file);
				} else {
					$path = $this->make_path($file);
					$stat = $this->stat_backend($file);
					if ($path instanceof Exception) {
						$errors[$file] = $path->getMessage();
					} else if ($stat instanceof Exception) {
						$errors[$file] = $stat->getMessage();
					} else if (!$this->can_descend(dirname($path))) {
						$errors[$file] = "insufficient permissions to access";
					} else if (!$stat['can_chown']) {
						$errors[$file] = "Unable to change group ownership of " . $file;
					}
				}

				if (is_dir($path) && $mRecursive) {
					// Recursive chown
					$files = scandir($path);
					// . and ..
					unset($files[0]);
					unset($files[1]);
					array_walk($files, create_function('&$a', '$a="' . $file . '/" . $a;'));
					$status = $this->chown($files, $mUser, $mRecursive);
					if ($status instanceof Exception) {
						$errors[$file] = $status->getMessage();
					}
				}

				if (!chown($path, $tUID)) {
					$errors[$file] = Error_Reporter::get_last_php_msg();
				}
			}
			$this->_purgeCache($mFile);
			return (sizeof($errors) == 0 ? true : new FileError(join("\n", $errors)));
		}

		/**
		 * bool chgrp(string, string[, bool = false])
		 *
		 * @param string $mFile      filename
		 * @param string $mGroup     target gid, effectively just the admin's uid
		 * @param bool   $mRecursive recursively chown
		 * @return bool
		 */
		public function chgrp($mFile, $mGroup, $mRecursive = false)
		{
			// @XXX why is this even here?
			if (!IS_CLI)
				return $this->query('file_chgrp', $mFile, $mGroup, $mRecursive);
			$admin = $this->group_id;
			foreach ($this->common_get_users() as $user => $data) {
				if ($data['gid'] == $data['uid']) {
					$admin = $user;
				}
			}
			if ($mGroup != $admin)
				return error("invalid group `" . $mGroup . "'");
			else if (!is_array($mFile))
				$mFile = array($mFile);
			$errors = array();

			if ($this->permission_level & PRIVILEGE_SITE) {
				$optimized = $this->_optimizedShadowAssertion;
			} else {
				$optimized = false;
			}
			foreach ($mFile as $file) {
				if ($optimized) {
					$path = $this->make_shadow_path($file);
				} else {
					$path = $this->make_path($file);
					$stat = $this->stat_backend($file);
					if ($path instanceof Exception) {
						$errors[$file] = $path->getMessage();
					} else if ($stat instanceof Exception) {
						$errors[$file] = $stat->getMessage();
					} else if (!$this->can_descend(dirname($path))) {
						$errors[$file] = "insufficient permissions to access";
					} else if (!$stat['can_chgrp']) {
						$errors[$file] = "Unable to change group ownership of " . $file;
					}
				}

				if (is_dir($path) && $mRecursive) {
					// Recursive chown
					$files = scandir($path);
					// . and ..
					unset($files[0]);
					unset($files[1]);
					array_walk($files, create_function('&$a', '$a="' . $file . '/" . $a;'));
					$status = $this->chgrp($files, $mUser, $mRecursive);
					if ($status instanceof Exception) {
						$errors[$file] = $status->getMessage();
					}
				}

				if (!chgrp($path, $tUID)) {
					$errors[$file] = Error_Reporter::get_last_php_msg();
				}
			}

			return (sizeof($errors) == 0 ? true : $errors);
		}

		/**
		 * bool chmod (string, int)
		 *
		 * @param string $mFile file name
		 * @param int    $mMode mode in octal for the file
		 * @param bool   $mRecursive
		 */
		public function chmod($mFile, $mMode, $mRecursive = false)
		{
			if (!ctype_digit($mMode))
				return error("invalid mode");

			$qd = $this->query('file_chmod_backend', $mFile, $mMode, $mRecursive);
			return $qd;
		}

		/**
		 * bool chmod_backend (string, int[, bool = false])
		 * {@link chmod}
		 */
		public function chmod_backend($mFile, $mMode, $mRecursive)
		{
			if (!is_float($mMode) && (strlen($mMode) != 4)) {
				$mMode = (float)octdec('0' . (string)$mMode);
			} else if (!is_float($mMode)) {
				$mMode = (float)octdec($mMode);
			}
			/* 4095 dec -> 7777 oct
			 * 0140000 -> socket
			 * 0147777 -> socket + all perms
			 */
			if ($mMode > 0xCFFF) {
				// 0147777
				return error("invalid mode `%o'", $mMode);
			}
			$purge = (array)$mFile;
			$path = $this->make_path($mFile);
			if ($path instanceof Exception)
				return $path;
			if (is_dir($path) && $mRecursive) {

				$files = scandir($path);
				// . and ..
				unset($files[0]);
				unset($files[1]);

				foreach ($files as $file) {
					$file = $mFile . "/" . $file;
					$stat = $this->stat_backend($file);
					if ($stat['link'])
						continue;
					if ($stat instanceof Exception) {
						error($stat->getMessage());
						continue;
					}
					if (!$stat['can_chown']) {
						warn("cannot chmod perm denied: " . $file);
						continue;
					}
					$purge[] = $file;

					if ($stat['file_type'] == '\dir') {
						$this->chmod_backend($file, $mMode, $mRecursive);

					} else
						chmod($this->make_path($file), $mMode);
				}
			}
			$stat = $this->stat_backend($mFile);
			if ($stat instanceof Exception) return warn($stat->getMessage());
			if (!$stat['can_chown']) {
				return warn("cannot chmod perm denied: " . $mFile);
			}
			$ret = chmod($path, $mMode);
			$this->_purgeCache($purge);
			return $ret;
		}

		/**
		 * string get_mime_type (string)
		 * Determines the MIME type of a file through the file shell command
		 *
		 * @param string $mFile
		 *
		 */
		public function get_mime_type($mFile, $mFormat = 'normal')
		{
			if (!IS_CLI) {
				$path = $this->make_path($mFile);
				if (!$path || ($path instanceof Exception) || !file_exists($path) || !is_readable($path)) {
					$mimestatus = $this->query('file_get_mime_type', $mFile, $mFormat);
				} else {
					$mimestatus = Util_Process_Safe::exec('file %s %s',
						($mFormat == 'html' ? '-i' : '-b'),
						$path,
						array(0, -1));
				}
				if (!$mimestatus) {
					return false;
				}
				return ($mFormat == 'html') ? trim(substr(strstr($mimestatus['output'], ':'), 2)) : $mimestatus;
			}

			$path = $this->make_path($mFile);

			if ($path instanceof Exception)
				return $path;
			else if (!is_file($path)) {
				return new FileError($mFile . " is not a file");
			}
			if (!is_readable($path))
				return new FileError("Unable to read " . $mFile);

			$mimestatus = Util_Process_Safe::exec('file %s %s',
				($mFormat == 'html' ? '-i' : '-b'),
				$path,
				array(0, -1));
			return $mimestatus;
		}

		/**
		 * Get file contents
		 *
		 * @param string $mPath path to the filename
		 * @param  bool  $raw   base64 encode data
		 * @return string
		 *
		 * @throws FileError if the requested file is not a file (directory)
		 * @throws PermissionError if the user does not have access to read the file
		 */
		public function get_file_contents($mPath, $raw = true)
		{
			$path = $this->make_path($mPath);
			if ($path instanceof Exception)
				return $path;
			else if (!is_readable($path))
				return $this->query('file_get_file_contents_backend', $mPath, $raw);
			else if (!is_file($path))
				return new FileError($mPath . " is not a file");

			return !$raw ? base64_encode(file_get_contents($path)) : file_get_contents($path);


		}
		/* }}} */

		/**
		 * @see get_file_contents()
		 * @param  string $mPath file name
		 * @param  bool   $mRaw
		 * @return string base64-encoded file
		 */
		public function get_file_contents_backend($mPath, $mRaw = true)
		{
			$path = $this->make_path($mPath);
			if ($path instanceof Exception)
				return $path;
			else if (!is_file($path))
				return new FileError($mPath . " is not a file");
			if (!is_readable($path))
				return new FileError("Unable to read " . $mPath);
			if (!$this->_assert_permissions($mPath, 'read')) {
				return new PermissionError("Unable to read file");
			}
			$stat = $this->stat($mPath);
			if (!$stat['can_read'])
				return new PermissionError("Unable to read file " . $mPath);
			$str = file_get_contents($path);
			return ($mRaw ? $str : base64_encode($str));

		}

		/**
		 * Verify user is privileged for file
		 *
		 * @param string $mFile     file name
		 * @param string $mPermType perm type, may be either read write or execute
		 * @todo  update code for write, execute
		 */
		private function _assert_permissions($mFile, $mPermType)
		{
			$stats = $this->stat_backend($mFile);
			if ($stats instanceof Exception)
				return false;

			switch ($mPermType) {
				case 'read':
					if (($this->permission_level & PRIVILEGE_SITE)) {
						return true;
					}
				case 'write':
					return true;
				case 'execute':
					return true;
				default:
					return false;
			}
		}
		/* }}} */

		/**
		 * Write contents to file
		 *
		 * @param  string $path      path to the filename
		 * @param  string $data      file data
		 * @param  bool   $overwrite if the file exists, overwrite
		 * @param  bool   $binary    data is to be treated as binary data. Data must be base64 encoded
		 * @return bool
		 *
		 * @privilege PRIVILEGE_ALL
		 * @throws FileError the requested file exists and $mOverwrite is false
		 * @throws PermissionError the user does not have access to write to the parent directory/file
		 */
		public function put_file_contents($file, $data, $overwrite = true, $binary = false)
		{
			return $this->query('file_put_file_contents_backend', $file, $data, (bool)$overwrite, (bool)$binary);
		}

		/**
		 * @see put_file_contents()
		 */
		public function put_file_contents_backend($mFile, $mData, $mOverwrite, $binary)
		{
			$path = $this->make_path($mFile);
			if ($path instanceof Exception)
				return $path;
			$dir_stat = $this->stat_backend(dirname($mFile));

			if ($dir_stat instanceof Exception)
				return $dir_stat;

			if (file_exists($path)) {
				$file_stat = $this->stat_backend($mFile);
				if ($file_stat instanceof Exception)
					return $file_stat;
			}

			if (!file_exists($path) && (!$dir_stat['can_write'])) {
				return new PermissionError("Cannot write to destination directory " . dirname($mFile));
			} else if ($binary && !preg_match('/^[a-zA-Z0-9\+\/=]*$/', $mData)) {
				return new ArgumentError("File data not base64 encoded");
			}

			if (file_exists($path)) {
				if (!$mOverwrite) {
					return new FileError("Target " . $mFile . " already exists");
				} else if ($mOverwrite && !is_file($path)) {
					return new FileError("Target " . $mFile . " is not a file");
				} else if (!$file_stat['can_write']) {
					return new PermissionError("Cannot overwrite file");
				}
			}

			if (!file_exists($path) &&
				($status = $this->create_file($mFile, 0644)) instanceof Exception
			) {
				return $status;
			}

			$fp = fopen($path, 'w' . ($binary ? '' : 'b'));
			ftruncate($fp, 0);
			fwrite($fp, !$binary ? $mData : base64_decode($mData));
			fclose($fp);
			$this->_purgeCache((array)$mFile);
			return true;
		}

		/**
		 * Create an empty file
		 *
		 * @param string $file file name to create
		 * @param int    $mode mode for the file
		 */
		public function create_file($file, $mode = 0644)
		{
			if (!IS_CLI)
				return $this->query('file_create_file', $file, $mode);

			$path = $this->make_path($file);
			if ($path instanceof Exception)
				return $path;
			$stat = $this->stat(dirname($file));

			if ($stat instanceof Exception)
				return $stat;

			if (!$stat['can_write'])
				return new FileError(dirname($file) . ": cannot write to directory");
			if (file_exists($path))
				return new FileError($file . ": file exists");
			$fp = fopen($path, 'w');
			fclose($fp);
			chown($path, (int)$this->user_id);
			chgrp($path, (int)$this->group_id);
			chmod($path, $mode);
			return true;
		}

		/**
		 * array get_directory_contents (string)
		 *
		 * @param string $mPath the path to the directory
		 * @return array
		 */
		public function get_directory_contents($mPath, $sort = true)
		{
			if (!IS_CLI) {
				$shadow = version_compare(platform_version(), '4.5', '>=');
				return $this->query('file_get_directory_contents_backend', rtrim($mPath, '/'), $sort, $shadow);
			}
		}

		public function get_directory_contents_backend($mPath, $sort = true, $shadow = false) {
			$path = $shadow ? $this->make_shadow_path($mPath) : $this->make_path($mPath);
			if ($path instanceof Exception)
				return $path;
			if (!is_dir($path))
				return error("`%s'`: invalid directory", $mPath);
			// trust transformed path, e.g. get_directory_contents("~/")
			$mPath = rtrim($shadow ? $this->unmake_shadow_path($path) : $this->unmake_path($path), '/');
			$stat = $this->stat_backend($this->unmake_shadow_path($path));
			if ($stat instanceof Exception) throw $stat;
			if (!$stat['can_execute'] || !$stat['can_read']) {
				return error("cannot access directory `%s' permission denied",
					$mPath);
			}
			if ($stat['link'])
				$mPath = $stat['referent'];
			$dirHandle = dir($path);
			if (!$dirHandle)
				return error(__FUNCTION__ . "(): unable to access directory");
			$files = array();

			while (false !== ($entry = $dirHandle->read())) {
				/** chroot'd passwd file */
				if ($entry == '.' || $entry == '..')
					continue;
				$stat = $this->stat($mPath . '/' . $entry);
				if ($stat instanceof Exception) return $stat;
				if (!isset($stat['owner'])) {
					/**
					 * dir() suffers from a delayed cache response
					 * confirm stat finds the file on the fs
					 */
					continue;
				}
				$stat['file_name'] = $mPath . '/' . $entry;

				if ($sort)
					$files[] = $stat;
				else
					$files[$mPath . '/' . $entry] = $stat;
			}
			unset($dirHandle);

			if ($sort)
				Util_Conf::sort_files($files);
			else
				Util_Conf::sort_files($files, 'key');

			return $files;
		}

		/**
		 * Make directories writeable by Web server
		 *
		 * @param string|array $paths     paths
		 * @param bool         $recursive recursively change ownerhsip
		 *
		 * Calls setgid, fixes permissions for Apache-written directories
		 *
		 * @return bool
		 */
		public function fix_apache_perms_backend($paths, $recursive = false)
		{
			if (!is_array($paths))
				$paths = array($paths);
			$prefix = $this->domain_fs_path();
			if (version_compare(platform_version(), '4.5', '>=')) {
				$prefix = $this->domain_shadow_path();
			}
			foreach ($paths as $path) {
				$path_resolved = $prefix . '/' . $path;
				if (!file_exists($path_resolved)) {
					error("`$path': invalid path");
					continue;
				}
				$stat = $this->file_stat($path);
				$uid = $stat['uid'];

				chgrp($path_resolved, (int)$this->group_id);
				$safe_path = escapeshellarg($path_resolved);

				// chown path to apache:gid
				Util_Process::exec('chown %s %s:%s %s',
					($recursive ? '-R ' : ' '),
					'apache',
					$this->group_id,
					$safe_path
				);

				// set ACLs on existing files
				$limit = !$recursive ? '-maxdepth 0' : '';
				$def_cmd = ' -d -m user:apache:%2$s -d -m user:%4$s:%2$s';
				$cmd = 'chmod u=+%2$s,g=+%3$s "{}" ; ' .
					'setfacl -m user:%4$s:%2$s -m user:apache:%2$s';
				Util_Process::exec('find %1$s ' . $limit . ' -type d -print0 |  ' .
					'xargs -0 -i /bin/sh -c \'' . $cmd . $def_cmd . ' "{}"\'',
					$safe_path,
					'rwx',
					'rwxs',
					$uid

				);
				$status = Util_Process::exec('find %1$s ' . $limit . ' -type f -print0 | ' .
					'xargs -0 -i /bin/sh -c \'' . $cmd . ' "{}"\'',
					$safe_path,
					'rw',
					'rw',
					$uid

				);
			}
			return $status['success'];
		}

		/**
		 * array report_quota (mixed)
		 *
		 * @param $mUIDs array of uids
		 * @privilege PRIVILEGE_SITE
		 * @return array associative array of quotas for given users supplied by the
		 *               parameter $mUIDs.  The array is structured as follows:
		 *               -uid: user id of the user N.B.: the username is not used; instead
		 *               call {@link Site_Module::get_users} to retrieve the numeric values
		 *               - quota:
		 *               - soft:
		 *               - hard
		 *               - files:
		 *               - file_soft:
		 *               - file_hard
		 */
		public function report_quota($mUIDs)
		{
			deprecated_func("use user_get_quota()");
			return null;
		}

		/**
		 * Convert end-of-line characters
		 *
		 * @param  string $mFile filename
		 * @param  string $mEOL  target platform
		 * @return bool
		 */
		public function convert_eol($mFile, $mTarget)
		{
			if (!IS_CLI)
				return $this->query('file_convert_eol', $mFile, $mTarget);
			$mTarget = strtolower($mTarget);
			if (!in_array($mTarget, array('unix', 'windows', 'mac')))
				return error("unknown platform `" . $mTarget . "'");
			$stat = $this->stat($mFile);
			if (!$stat['can_read'] || !$stat['can_write'])
				return error("cannot access `" . $mFile . "'");
			$file = $this->make_path($mFile);

			if ($mTarget == 'unix')
				$cmd = 'dos2unix';
			else if ($mTarget == 'windows')
				$cmd = 'unix2dos';
			else if ($mTarget == 'mac')
				$cmd = 'dos2unix -c mac';
			return Util_Process_Safe::exec($cmd . ' %s',
				$file) && chown($file, $stat['uid'])
			&& chgrp($file, $stat['gid']);
		}

		/**
		 * Create a symbolic link
		 *
		 * @param unknown_type $mSrc
		 * @param unknown_type $mDest
		 * @return bool
		 * @see symlink()
		 * @deprecated
		 */
		public function create_symlink($mSrc, $mDest)
		{
			return $this->symlink($mSrc, $mDest);
		}

		/**
		 * Create a symbolic link
		 *
		 * @param string $mSrc  source file
		 * @param string $mDest destination link
		 * @return bool
		 */
		public function symlink($mSrc, $mDest)
		{
			if (!IS_CLI)
				return $this->query('file_create_symlink', $mSrc, $mDest);

			$link = '';
			if (substr($mSrc, 0, 2) == '..')
				$mSrc = dirname($mDest) . '/' . $mSrc;
			if (substr($mDest, -1, 1) == '/')
				$mDest = $mDest . basename($mSrc);

			$src_path = $this->make_path($mSrc);
			$dest_path = $this->make_path($mDest, $link);

			if (file_exists($dest_path))
				return error("destination `" . $this->unmake_path($dest_path) . "' exists");
			else if (!file_exists($src_path))
				return error("source `" . $this->unmake_path($src_path) . "' does not exist");
			$link = self::convert_absolute_relative($dest_path, $src_path);
			if (!file_exists(dirname($dest_path) . '/' . self::convert_absolute_relative($dest_path, $src_path)))
				warn("file $mSrc does not exist");

			//debug(self::convert_absolute_relative($dest_path, $src_path)." -> ".$dest_path);
			symlink($link, $dest_path);
			return lchown($dest_path, $this->user_id) && lchgrp($dest_path, $this->group_id);
		}

		/**
		 * Transform absolute path into relative path
		 *
		 * @param $cwd
		 * @param $dir
		 * @return string
		 */
		public static function convert_absolute_relative($pwd, $dir)
		{
			//
			if (dirname($pwd) == rtrim($dir, '/')) {
				return '../' . basename($dir);
			}

			$pwd = array_values(array_filter(explode("/", $pwd)));
			$dir = array_values(array_filter(explode("/", $dir)));
			// just in case PHP changes scoping rules in the future...
			$idx = 0;
			for (; $idx < sizeof($pwd); $idx++) {
				if (!isset($dir[$idx]) || ($dir[$idx] != $pwd[$idx]))
					break;
			}
			return str_repeat("../", sizeof($pwd) - ($idx + 1)) . join("/", array_slice($dir, $idx));
		}

		/**
		 * Rename a file
		 *
		 * @param string $file    filename
		 * @param string $newfile new filename
		 * @return bool
		 */
		public function rename($from, $to, $files = array())
		{
			if (!IS_CLI)
				return $this->query('file_rename', $from,
					$to, $files);
			if (!is_array($files) || !$files) return $this->move($from, $to);

			if (!is_array($from)) $file = array($from);
			if (!is_array($to)) $newfile = array($to);
			$nsrc = sizeof($file);
			$ndest = sizeof($newfile);
			if ($nsrc > 1 && $ndest != $nsrc) {
				if ($ndest != 1)
					return error("cannot move files- destination " .
						"must be directory for multiple files");

			}
			for ($i = 0, $n = sizeof($file); $i < $n; $i++) {
				if (sizeof($newfile) == 1)
					$newfile[$i] = $newfile[0];
				if (substr($newfile[$i], 0, 1) != '/')
					$newfile[$i] = dirname($file[$i]) . '/' . $newfile[$i];
			}

			$changed_ctr = 0;

			for ($i = 0; $i < sizeof($file); $i++) {
				$link = '';
				$src_path = $this->make_path($file[$i], $link);
				$src_stat = $this->stat_backend($file[$i]);

				$dest_path = $this->make_path($newfile[$i]);
				$dest_stat = $this->stat_backend(dirname($newfile[$i]));

				if ($dest_path instanceof Exception || $dest_stat instanceof Exception ||
					$src_path instanceof Exception || $src_stat instanceof Exception
				)


					if (file_exists($dest_path) || !$link && !file_exists($src_path)) {
						continue;
					}
				// no perms
				if (!$link || !$dest_stat['can_execute'] && !$dest_stat['can_write']) {
					continue;
				}

				if ($src_stat['link']) {
					// rename won't rename a symbolic link; delete and recreate the link
					$this->delete(array($this->unmake_path($link)), false);
					$this->create_symlink_backend($src_stat['referent'], $this->unmake_path($dest_path));
					$this->chown_symlink($this->unmake_path($dest_path), $src_stat['owner']) && $changed_ctr++;
				} else {
					rename($src_path, $dest_path) && $changed_ctr++;
				}

			}
			return $changed_ctr > 0;
		}

		/**
		 * Move files
		 *
		 * @param  mixed  $src       source file(s) or directories
		 * @param  string $dest      destination directory
		 * @param  string $overwrite overwrite destination if exists
		 * @return bool
		 */
		public function move($src, $dest, $overwrite = false)
		{
			// @TODO algorithm is sloppy
			if (!IS_CLI)
				return $this->query('file_move', $src, $dest, (bool)$overwrite);

			if (!$src || !$dest) return error("missing source/destination");
			if ($this->permission_level & PRIVILEGE_SITE) {
				$optimized = !!$this->_optimizedShadowAssertion;
			} else {
				$optimized = false;
			}
			$unmakeFn = $optimized ? 'unmake_shadow_path' : 'unmake_path';
			$dest_path = $this->make_path($dest);
			if ($optimized) {
				// OverlayFS doesn't like direct operations on r/w branch
				// perform move onto synthetic fs
				$dest_parent = $this->make_shadow_path(dirname($dest));
			} else {
				$dest_parent = dirname($dest_path);
			}

			if (!file_exists($dest_parent))
				return error("move: destination directory `" . dirname($dest) . "' does not exist");
			else if (!is_dir($dest_parent))
				return error("move: `" . dirname($dest) . "' is not a directory");
			else if (!$optimized && !$this->can_descend($dest_parent))
				return error("move: `" . dirname($dest) . "' cannot access - permission denied");

			if (!is_array($src)) $src = array($src);

			// straight file rename
			// mv /a.txt /b.txt
			if (!file_exists($dest_path)) {
				if (isset($src[1])) {
					return error("move: cannot rename multiple files to new file");
				}
				$parent = $this->{$unmakeFn}($dest_parent);
			} else {
				$parent = $this->unmake_path($dest_path);
			}
			if ($optimized) {
				$dest_pstat = [
					'file_type' => filetype($dest_parent)
				];
			} else {
				$dest_pstat = $this->stat($parent);
			}

			// verify that dest is writeable
			if (!$optimized && (!$dest_pstat['can_write'] || !$dest_pstat['can_execute'])) {
				return error("move: `" . $parent . "' cannot write - permission denied");
			}

			// move all files
			$nchanged = -1;
			$perm_cache = array();
			// single item
			$isRename = !isset($src[1]);
			$destIsDir = $dest_pstat['file_type'] == 'dir';

			for ($i = 0, $nsrc = sizeof($src); $i < $nsrc; $i++) {
				$lchanged = $nchanged;
				$nchanged = 0;
				$link = '';
				$file = $src[$i];
				$src_path = $this->make_path($file, $link);

				if (!file_exists($src_path)) {
					warn("move: `" . $file . "': No such file or directory");
					continue;
				} else if ($src_path === $dest_path) {
					warn("move: `" . $file . "': source and dest are the same");
					continue;
				}

				if ($optimized) {
					$src_stat = array(
						'file_type' => filetype($src_path),
						'uid'       => fileowner($src_path),
						'link'      => is_link($src_path)
					);
				} else {
					$src_stat = $this->stat($file);
				}


				if (!$src_stat || $src_stat instanceof Exception) {
					if ($src_stat instanceof Exception)
						warn("`" . $file . "': " . $src_stat->getMessage());
					continue;
				}

				// source directory must have -wx permission
				$src_parent = dirname($src_path);
				if (!isset($perm_cache[$src_parent])) {
					$src_pstat = $this->stat($this->unmake_path($src_parent));
					$perm_cache[$src_parent] = !$src_pstat instanceof Exception && $src_pstat &&
						$src_pstat['can_write'] && $src_pstat['can_execute'];
				}

				if (!$perm_cache[$src_parent]) {
					warn("cannot move `" . $file . "' - permission denied");
					continue;
				}

				$rename_dest = $dest_path;
				// add file/dirname onto destination if dest is exists/is dir
				if (!$isRename && $destIsDir) {
					// destination is directory
					$rename_dest = $dest_path . DIRECTORY_SEPARATOR . basename($file);
				} else if ($src_stat['file_type'] != 'dir' && file_exists($dest_path)) {
					$rename_dest = $dest_path;
				} else if ($src_stat['file_type'] == 'dir' && is_dir($dest_path)) {
					$rename_dest .= DIRECTORY_SEPARATOR . basename($file);
				}


				if (!$destIsDir && $src_stat['file_type'] == 'dir' &&
					$dest_pstat['file_type'] == 'file'
				) {
					warn("cannot move `" . $file . "' - $dest is a file");
					continue;
				}

				// need to do an extra round of lookups to
				// ensure files/directories are not clobbered
				if (file_exists($rename_dest)) {
					if (!$overwrite) {
						warn("cannot move `" . basename($file) . "' - destination `" . basename($rename_dest) . "' exists");
						continue;
					}
					$del = $this->delete($this->unmake_path($rename_dest), true);
					if (!$del || $del instanceof Exception) {
						if ($del instanceof Exception)
							warn("cannot remove file `$file' - " . $del->getMessage());
						continue;

					}
				}

				if ($src_stat['link']) {
					// rename won't rename a symbolic link; delete and recreate the link
					$this->delete(array($this->unmake_path($link)), false);
					$this->symlink($src_stat['referent'], $parent);
					if ($src_stat['uid'] >= User_Module::MIN_UID || $src_stat['uid'] === APACHE_UID) {
						// don't worry about changing
						// symlink if owner is root or apache
						$nchanged = $lchanged & $this->chown_symlink($parent, $src_stat['owner']);
					}

					continue;
				}

				// CP runs Dav, Dav uses UPLOAD_UID
				if ($src_stat['uid'] == self::UPLOAD_UID) {
					chown($src_path, $this->user_id);
					chgrp($src_path, $this->group_id);
				}
				$rename_dest = rtrim($rename_dest, DIRECTORY_SEPARATOR);
				$nchanged = rename($src_path, $rename_dest) & $lchanged;
			}
			return $nchanged > 0;
		}

		/**
		 * Change ownership of symbolic link
		 *
		 * @param string $mFile symbolic link
		 * @param string $mUser target username
		 * @return bool
		 */
		public function chown_symlink($mFile, $mUser)
		{
			if (!IS_CLI)
				return $this->query('file_chown_symlink', $mFile, $mUser);
			$validUsers = array_keys($this->user_get_users());
			$validUsers[] = 'apache';
			if (!in_array($mUser, $validUsers))
				return error("invalid chown user `%s'", $mUser);
			else if (!is_array($mFile))
				$mFile = array($mFile);

			$errors = array();
			$uid_cache = $this->user_get_users();

			// RHEL constant UID
			$uid_cache['apache'] = array('uid' => APACHE_UID);

			if (!isset($uid_cache[$mUser]['uid']))
				return new ArgumentError("Eep, unable to find UID for " . $mUser);

			$uid_cache = $uid_cache[$mUser]['uid'];
			foreach ($mFile as $file) {
				$link = '';
				$path = $this->make_path($file, $link);
				$stat = $this->stat($this->unmake_path(dirname($link)));
				if ($path instanceof Exception) {
					$errors[$file] = $path->getMessage();
				} else if (($ex = $this->can_descend(dirname($path))) instanceof Exception || !$ex) {
					$errors[$file] = $ex->getMessage();
				} else if ($stat['can_chown']) {
					if (!lchown($link, (int)$uid_cache)) {
						$errors[$file] = Error_Reporter::get_last_php_msg();
					}

				} else {
					$errors[$file] = "Unable to change user ownership of " . $file;
				}
			}
			$this->_purgeCache($mFile);
			return (sizeof($errors) == 0 ? true : new FileError(join("\n", $errors)));
		}

		/**
		 * Check existence of file
		 *
		 * @param string|array $file
		 * @param array        $missing files not found
		 * @return bool|array
		 */
		public function file_exists($file, array &$missing = null)
		{
			if (!IS_CLI && (is_array($file) || !file_exists($this->make_path($file))))
				return $this->query('file_file_exists', $file);

			/** CLI */
			if (!is_array($file)) $file = array($file);
			$exists = true;
			$do_missing = is_array($missing);
			for ($i = 0, $n = sizeof($file); $i < $n; $i++) {
				if (!$exists && $do_missing) $missing[] = $file[$i];
				$path = $this->make_path($file[$i]);
				clearstatcache(true, $path);
				$exists = file_exists($path);
			}

			return $exists;
		}

		/**
		 * @see User_Module::find_quota_files()
		 * @deprecated
		 * @param $file
		 * @return array
		 */
		public function find_quota_files($file = '')
		{
			deprecated("use user_find_quota_files");
			return $this->user_find_quota_files();
		}

		/**
		 * Canonicalize jailed filesystem path
		 *
		 * @param  string $path
		 * @return string
		 */
		public function canonicalize_site($path)
		{
			if ($this->permission_level & PRIVILEGE_ADMIN) {
				return $path;
			}
			$prefix = $this->domain_fs_path();
			$len = strlen($prefix);
			if (!strncmp($path, $prefix, $len)) {
				$path = substr($path, $len);
			}
			return !$path ? '/' : $path;
		}

		/**
		 * Canonicalize global path
		 *
		 * @param  string $path
		 * @return string
		 */
		public function canonicalize_abs($path)
		{

			if ($this->permission_level & PRIVILEGE_ADMIN) {
				return $path;
			}
			$prefix = $this->domain_fs_path();
			$len = strlen($prefix);
			if (strncmp($path, $prefix, $len))
				$path = $prefix . $path;
			return $path;
		}

		/**
		 * Assume ownership of uploaded files
		 *
		 * @param  mixed $files
		 * @return bool
		 */
		public function endow_upload($files)
		{
			if (!IS_CLI) return $this->query("file_endow_upload", $files);
			if (Error_Reporter::is_error()) {
				return error("cannot handle upload in inconsistent state");
			}

			if (!is_array($files)) {
				$files = array($files);
			}

			for ($i = 0, $n = sizeof($files); $i < $n; $i++) {
				$file = $files[$i];
				if ($file[0] === "." || $file[0] === "/") {
					warn("invalid file to endow upload `%s', skipping (must reside in `%s'", $file, TEMP_DIR);
				}
				$path = $this->make_path(TEMP_DIR . '/' . $file);
				$base = $this->make_path(TEMP_DIR);
				if (substr($path, 0, strlen($base)) != $base) {
					error("file `$file' contains invalid characters");
					report("Invalid chars? $path $base $file");
					continue;
				} else if (!file_exists($path)) {
					error("file `" . TEMP_DIR . "/$file' does not exist");
					continue;
				} else {
					$stat = $this->stat(TEMP_DIR . '/' . $file);
					if ($stat['uid'] != self::UPLOAD_UID || $stat['file_type'] != 'file'
						|| $stat['nlinks'] > 1 || $stat['link'] != 0
					) {
						error("file `$file' is not an uploaded file");
						continue;
					}
				}
				file_exists($path) && chown($path, $this->user_id) && chgrp($path, $this->group_id);
			}
			return !Error_Reporter::is_error();
		}

		/**
		 * Create or alter the timestamp of a file
		 *
		 * @param string $file filename
		 * @param int    $time optional unix timestamp
		 * @return bool
		 */
		public function touch($file, $time = null)
		{
			if (!IS_CLI) {
				return $this->query('file_touch', $file, $time);
			}
			if (!$file) {
				return error("no filename specified");
			}
			if (is_null($time)) {
				$time = time();
			} else if (intval($time) != $time || $time < 0) {
				return error("invalid time spec `%d'", $time);
			}
			$prefix = $this->domain_fs_path();
			$path = $this->make_path($file);
			if (!$path) {
				return error('invalid file path `%s', $file);
			}
			$exists = file_exists($path);
			if ($exists) {
				$stat = $this->stat($file);
				if (!$stat) {
					return error("stat failed on `%s'", $file);
				} else if (!$stat['can_write']) {
					return error("cannot modify file `%s'", $file);
				}
			}
			$ret = touch($path, $time);
			if (!$exists) {
				chown($path, (int)$this->user_id);
				chgrp($path, (int)$this->group_id);
			}
			return $ret;
		}

		/**
		 * Create a pipe destination to compress
		 *
		 * @param array $files
		 * @return string $path
		 */
		public function initialize_download(array $files)
		{
			if (!IS_CLI) {
				return $this->query('file_initialize_download', $files);
			}

			if (version_compare(platform_version(), '4.5', '<=')) {
				return error('platform version too old to support download feature');
			}
			// @XXX potential race condition
			$fifo = tempnam('/tmp', 'id-' . $this->site);
			unlink($fifo);
			if (!posix_mkfifo($fifo, 0600)) {
				return error("failed to ready pipe for archive");
			}

			$newfiles = array();
			// do a separate path for unprivileged users
			$isUser = $this->permission_level&PRIVILEGE_USER == PRIVILEGE_USER;
			$shadowpath = $this->domain_shadow_path();
			foreach ($files as $f) {
				if (false !== strpos($f, "..") || $f[0] !== '/') {
					// naughty naughty!
					continue;
				} else if (!isset($f[1])) {
					// evaluate out to . or root
					$f = "..";
					continue;
				}
				if ($isUser) {
					$stat = $this->stat($f);
					if ($stat['uid'] != $this->user_id) {
						warn("file `%s' not owned by %s, skipping", $f, $this->username);
						continue;
					}
				}
				$newfiles[] = substr($f, 1);
			}
			if (!$newfiles) {
				return error("nothing to download!");
			}
			$filelist = tempnam('/tmp', 'fl');
			chmod($filelist, 0600);
			chown($fifo, self::UPLOAD_UID);
			file_put_contents($filelist, join("\n", $newfiles));

			$proc = new Util_Process_Fork();

			/*$proc->addCallback(function() use ($fifo, $filelist) {
				unlink($fifo);
				unlink($filelist);
			}, 'close');*/
			// lowest priority
			$proc->setPriority(19);
			// need absolute path to pcntl_exec
			$xtrainclude = null;
			$ret = $proc->run('/bin/tar --directory %(shadow)s -cf %(fifo)s %(xtrainclude)s --exclude-from=%(skipfile)s '.
				'--one-file-system --files-from=%(list)s ',
				array(
					'xtrainclude' => $xtrainclude,
					'shadow' => $this->domain_shadow_path(),
					'fifo' =>  $fifo,
					'list' => $filelist,
					'skipfile' => INCLUDE_PATH . self::DOWNLOAD_SKIP_LIST
				)
			);
			return $ret['success'] ? $fifo : false;
		}

		/**
		 * Set file access control lists
		 *
		 * permissions may be of the form:
		 *  octal (1, 2, 4 and any combo thereof)
		 *  or
		 *  drwx, d sets default
		 *  setting permission null will remove all permissions
		 *
		 * @param string|array    $file
		 * @param string          $user
		 * @param int|string|null $permission
		 * @param array           $xtra map of default: bool, recursive: bool (not manageable by subuser)
		 * @return bool
		 */
		public function set_acls($file, $user, $permission = null, $xtra = array())
		{
			if (!IS_CLI) {
				return $this->query('file_set_acls', $file, $user, $permission, $xtra);
			}

			if (!version_compare(platform_version(), '4.5', '>=')) {
				return error("`%s': only available on platform 4.5+", __FUNCTION__);
			}
			// don't worry about caching, already done in user_get_users
			$uuidmap = $this->user_get_users();
			$uuidmap['apache'] = array('uid' => APACHE_UID);

			if ($this->tomcat_permitted()) {
				$tcuser = $this->tomcat_system_user();
				$tcuid = posix_getpwnam($tcuser);
				$uuidmap[$tcuser] = $tcuid['uid'];
			}

			$file = (array)$file;
			$sfiles = array();
			$prefix = $this->make_shadow_path("");
			$prefixlen = strlen($prefix);
			foreach ($file as $tmp) {
				$shadow = $this->make_shadow_path($tmp);
				$glob = glob($shadow, GLOB_NOSORT);
				foreach ($glob as $shadow) {
					if (strncmp($shadow, $prefix, $prefixlen)) {
						// malicious bastard
						continue;
					}
					if (!$shadow) {
						error("skipping invalid path `%s'", $tmp);
						continue;
					} else if (!file_exists($shadow)) {
						error("skipping missing path `%s'", $tmp);
						continue;
					}

					$f = substr($shadow, $prefixlen);
					if ($this->permission_level & ~(PRIVILEGE_SITE | PRIVILEGE_ADMIN)) {
						// do an extra expensive stat check to ensure ownership
						// this should be just occur for secondary users, trust account admin to
						// have all access under shadow/
						$stat = $this->stat($f);
						if (!$stat['can_chown']) {
							error("%s: cannot change ownership attributes", $f);
							continue;
						}

					}
					$sfiles[] = $shadow;
				}


			}
			if (!$sfiles) {
				return error("no files to adjust!");
			}

			// never follow symlinks
			$flags = '-P';
			if (!$user) {
				$flags .= 'b';
				if (is_array($permission)) {
					$xtra = $permission;
					$permission = array();
				}

			} else if (!is_array($user)) {
				$user = array($user => $permission);
			} else if (is_array($user) && is_array($permission)) {
				// arguments passed in map format
				$xtra = $permission;
				// arguments passed with implicit true assumption
				$permission = null;
			} else if (is_array($user)) {
				// todo
			}
			if (array_key_exists(0, $xtra)) {
				$xtra = array_fill_keys($xtra, true);
			}
			$xtra = array_merge(
				array(
					self::ACL_MODE_DEFAULT   => false,
					self::ACL_MODE_RECURSIVE => false,
					self::ACL_NO_RECALC_MASK => false,
				), $xtra
			);
			if ($xtra[self::ACL_MODE_DEFAULT]) {
				$flags .= 'd';
			}
			if ($xtra[self::ACL_NO_RECALC_MASK]) {
				$flags .= 'n';
			}
			if (!($this->permission_level & PRIVILEGE_USER) && $xtra[self::ACL_MODE_RECURSIVE]) {
				$flags .= 'R';
			}
			if (0 < ($pos = strspn($flags, self::ACL_FLAGS)) && isset($flags[$pos])) {
				return error("unrecognized acl flag: %s", $flags[$pos]);
			}
			$map = array();

			// just removing acls from all files?
			if (!$user) {
				return $this->_acl_driver($sfiles, $flags);
			}

			// build a permission map
			foreach ($user as $u => $perms) {
				// passed as [[apache: 7], [foo: 7], [apache: drwx]] ...
				if (is_array($perms)) {
					$u = key($perms);
					$perms = current($perms);
				}

				if (!isset($uuidmap[$u])) {
					return error("invalid user `%s',", $u);
				} else if (!isset($uuidmap[$u]['uid'])) {
					return error("eep, unable to find UID for `%s'", $u);
				}

				$default = false;

				if (!ctype_digit((string)$perms)) {
					if (0 < ($pos = strspn($perms, "drwx")) && isset($perms[$pos])) {
						// permissions provided as chars, verify it's sensible
						return error("unknown permission mode `%s' setting for user `%s'",
							$perms[$pos], $u
						);
					}
					$tmp = 0;
					for ($i = 0, $n = strlen($perms); $i < $n; $i++) {
						if ($perms[$i] === 'r') {
							$tmp |= 4;
						} else if ($perms[$i] === 'w') {
							$tmp |= 2;
						} else if ($perms[$i] === 'x') {
							$tmp |= 1;
						} else if ($perms[$i] === 'd' && !$xtra[self::ACL_MODE_DEFAULT]) {
							$default = true;
						}
					}
					$perms = $tmp;
				}
				$uid = $uuidmap[$u]['uid'];
				$map[] = '-m ' . ($default ? 'd:' : '') . 'u:' . $uid . (is_null($perms) ? '' : ':' . $perms);
			}
			return $this->_acl_driver($sfiles, $flags, $map);

		}

		private function _acl_driver(array $files, $flags, array $rights = array())
		{
			$shadow = $this->domain_shadow_path();
			if ($flags[0] !== "-") {
				return error("acl flags garbled");
			} else if (strncmp($files[0], $shadow, strlen($shadow))) {
				return error("crit: acl path error?!!");
			}

			$cmd = 'setfacl ' . $flags . ' ' . join(" ", $rights);
			$cmd .= str_repeat(" %s", count($files));
			$proc = Util_Process_Safe::exec($cmd, $files);

			if (!$proc['success']) {
				return error("setting ACLs failed: `%s'", $proc['stderr']);
			}

			return true;
		}

		public function _delete()
		{
			// make sure we dump overlayfs' page cache
			if (version_compare(platform_version(), '6.5', '>=')) {
				$this->purge();
			}
		}

		/**
		 * Dump OverlayFS cache
		 *
		 * @return bool
		 */
		public function purge()
		{
			if (!IS_CLI) {
				return $this->query('file_purge');
			}
			if (version_compare(platform_version(), '6', '<')) {
				return false;
			}
			if ($this->permission_level & !(PRIVILEGE_SITE | PRIVILEGE_USER)) {
				return true;
			}
			$proc = Util_Process::exec('/etc/init.d/fsmount reload_site %s', $this->site);
			return $proc['success'];
		}

		public function _resetID()
		{
			// reset cache to use new user id
			$this->__wakeup();
			self::$stat_cache = null;

		}

		/**
		 * Translate a relative symlink into its absolute path
		 *
		 * @param string $mPwd
		 * @param string $mLink
		 * @return string resolved path
		 */
		private function resolve_path($mPwd, $mLink)
		{
			$oldpwd = getcwd();
			chdir($this->domain_fs_path() . '/' . $mPwd);
			if (DEBUG)
				echo "$mPwd -- $mLink <> " . readlink($mLink) . "\n";

			chdir($mLink);
			if (!strstr(getcwd(), $this->domain_fs_path())) {
				// naughty, naughty, absolute link
				chdir($this->domain_fs_path() . getcwd());
			}
			$path = substr(getcwd(), strlen($this->domain_fs_path()));
			chdir($oldpwd);

			return file_exists($path) ? $path : null;
		}
	}

?>
