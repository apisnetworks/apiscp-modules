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
	 * Class Pman_Module
	 *
	 * Process management
	 * @package core
	 */
	class Pman_Module extends Module_Skeleton
	{
		const PROC_PATH = '/proc';
		const PROC_CACHE_KEY = 'pman.all';
		const MAX_WAIT_TIME = 300;
		/* biggest signal number + 1 taken from bits/signum.h */
		const _NSIG = 65;

		public $exportedFunctions = array(
			'*'                      => PRIVILEGE_ALL,
			'schedule_api_cmd_admin' => PRIVILEGE_ADMIN
		);

		public function __construct()
		{
			parent::__construct();
		}

		/**
		 * Terminal a process with SIGKILL
		 *
		 * @param int $pid process
		 * @return bool
		 */
		public function kill($pid)
		{
			// SIGKILL isn't defined in ISAPI?
			return $this->signal($pid, 9);
		}

		/**
		 * Send a POSIX signal a process
		 *
		 * @param int $pid
		 * @param int $signal
		 * @return bool
		 */
		public function signal($pid, $signal = 9)
		{
			if (!IS_CLI) {
				return $this->query('pman_signal', $pid, $signal);
			}

			if (!ctype_digit($pid)) {
				return error("invalid pid `%s'", $pid);
			}
			$signal = intval($signal);
			if ($signal < -1 || $signal > self::_NSIG) {
				return error("invalid signal %d", $signal);
			}
			$status = Util_Process_Sudo::exec('/bin/kill -%d %d ', $signal, (int)$pid);
			if (!$status['success']) {
				return error("kill failed: %s", $status['stderr']);
			}
			return $status['success'];
		}

		/**
		 * Stat a running process
		 *
		 * @param int $pid process id
		 * @return array stat or empty array
		 *
		 * Sample response:
		 * Array
		 * (
		 * [pid] => 8849
		 * [comm] => bash
		 * [stat] => S
		 * [ppid] => 8848
		 * [pgrp] => 8849
		 * [session] => 5185
		 * [tty_nr] => 34816
		 * [tpgid] => 27992
		 * [flags] => 4219136
		 * [minflt] => 47250071
		 * [cminflt] => 154934160
		 * [majflt] => 0
		 * [cmajflt] => 0
		 * [utime] => 101.48
		 * [stime] => 403.61
		 * [cutime] => 0
		 * [cstime] => 0
		 * [priority] => 39
		 * [nice] => 19
		 * [num_threads] => 1
		 * [itrealvalue] => 0
		 * [starttime] => 50639.3
		 * [vsize] => 4988
		 * [rss] => 2516
		 * [rsslim] => 524288
		 * [user] => 514
		 * [cwd] => /
		 * [startutime] => 1430844663
		 * [args] => Array
		 * (
		 * )
		 *
		 * pid: process id
		 * comm: raw command name
		 * args: command arguments
		 * stat: process state, one char of RSDZTW, R = running
		 * ppid: parent PID
		 * pgrp: process group ID
		 * session: process session ID
		 * tty_nr: controlling terminal in bitmap
		 * tpgid: ID of foreground process group of controlling terminal proc
		 * flags: task flags
		 * minflt: number of minor faults
		 * cminflt: number of minor faults in children
		 * majflt: number of major faults
		 * cmajflt: number of major faults in children
		 * utime: user time in seconds (NB: converted from jiffies)
		 * stime: system time in seconds (NB: converted from jiffies)
		 * cutime: user time of children in seconds (NB: converted from jiffies)
		 * cstime: system time of chldren in seconds (NB: converted from jiffies)
		 * priority: process priority level
		 * nice: nice level
		 * num_threads: number of threads
		 * itrealvalue: obsolete (always 0)
		 * starttime: time the process started after boot
		 * startutime: time the process started after boot in unixtime
		 * vsize: virtual memory size in KB (NB: converted from pages)
		 * rss: resident set memory size in KB (NB: converted from pages)
		 * rsslim: current limit in KB of the rss
		 * user: user id of the process (translate w/ user_get_username_from_uid)
		 *
		 */
		public function stat($pid)
		{
			if (!IS_CLI) {
				return $this->query('pman_stat', $pid);
			}
			$procs = $this->_processAccumulator();
			if (isset($procs[$pid])) {
				return $procs[$pid];
			}
			return array();
		}

		/**
		 * Collect all processes for a site
		 *
		 * @return array
		 */
		private function _processAccumulator()
		{
			$cache = Cache_Account::spawn();
			$all = $cache->get(self::PROC_CACHE_KEY);
			if ($all !== false) {
				return $all;
			}

			$that = $this;
			// @link http://linux.die.net/man/5/proc
			// ends on #25 - rsslim
			$scanspec = "%d %s %c %d %d" .
				"%d %d %d %u %lu" .
				"%lu %lu %lu %lu %lu" .
				"%ld %ld %ld %ld %ld" .
				"%ld %lu %lu %ld %lu";

			$stathash = array(
				'pid',
				'comm',
				'stat',
				'ppid',
				'pgrp',
				'session',
				'tty_nr',
				'tpgid',
				'flags',
				'minflt',
				'cminflt',
				'majflt',
				'cmajflt',
				'utime',
				'stime',
				'cutime',
				'cstime',
				'priority',
				'nice',
				'num_threads',
				'itrealvalue',
				'starttime',
				'vsize',
				'rss',
				'rsslim'
			);
			$pids = $this->_collectPids();
			$func = function () use ($that, $pids, $scanspec, $stathash) {
				$procs = array();
				$uptime = file_get_contents('/proc/uptime');
				$now = time();
				list($uptime) = explode(" ", $uptime, 1);
				foreach ($pids as $pid) {
					$path = '/proc/' . $pid;
					$user = fileowner($path);
					//$cmd = file_get_contents($path . '/cmdline');
					if (!file_exists($path)) {
						continue;
					}
					$cwd = readlink($path . '/cwd');
					$cmdline = file_get_contents($path . '/cmdline');
					$statraw = file_get_contents($path . '/stat');
					$cwd = $that->file_canonicalize_site($cwd);
					//$memraw = explode(" ", file_get_contents($path . '/statm'));
					$scanraw = sscanf($statraw, $scanspec); // read up to rsslim
					$stat = array_combine(
						$stathash,
						$scanraw
					);
					$stat['user'] = $user;
					$stat['cwd'] = $cwd;
					$stat['comm'] = substr($stat['comm'], 1, -1);

					$stat['utime'] /= CPU_CLK_TCK;
					$stat['stime'] /= CPU_CLK_TCK;
					$stat['cutime'] /= CPU_CLK_TCK;
					$stat['cstime'] /= CPU_CLK_TCK;
					$stat['starttime'] /= CPU_CLK_TCK;
					$stat['startutime'] = round($now - ($uptime - $stat['starttime']));
					// drop from bytes to KB
					$stat['vsize'] /= 1024;
					$stat['rss'] = $stat['rss'] * MEM_PAGESIZE;
					$stat['rsslim'] /= 1024;
					$stat['args'] = explode("\0", $cmdline, -1);
					unset($stat['args'][0]);


					$procs[$stat['pid']] = $stat;
				}
				return $procs;
			};
			$all = Error_Reporter::silence($func);
			$cache->set(self::PROC_CACHE_KEY, $all, 60);
			return $all;
		}

		/**
		 * Get active processes
		 *
		 * @return array
		 */
		private function _collectPids()
		{
			$controllers = $this->cgroup_get_controllers();
			// memory + cpu proc lists are balanced
			$cgroupprocs = Cgroup_Module::CGROUP_LOCATION . '/' .
				array_pop($controllers) . '/' . $this->cgroup_get_cgroup() . '/cgroup.procs';
			if (version_compare(platform_version(), '6', '>=') && file_exists($cgroupprocs)) {
				return file($cgroupprocs, FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES);
			}
			$procpath = self::PROC_PATH;
			$dir = opendir($procpath);
			$groupid = $this->group_id;
			$procs = array();
			while (false !== ($file = readdir($dir))) {
				$path = $procpath . '/' . $file;
				if (!is_dir($path) || $file === ".." || $file === ".") {
					continue;
				} else if (filegroup($path) !== $groupid) {
					continue;
				}
				$procs[] = $file;
			}
			closedir($dir);
			return $procs;
		}

		/**
		 * Get active process count
		 *
		 * Count is fetched from cache. {@see flush} may be necessary
		 *
		 * @return int
		 */
		public function pcount()
		{
			$count = count($this->_processAccumulator());
			return $count;
		}

		/**
		 * Flush process accumulator cache
		 *
		 * @return bool
		 */
		public function flush()
		{
			$cache = Cache_Account::spawn();
			return $cache->delete(self::PROC_CACHE_KEY);
		}

		/**
		 * Get all processes
		 *
		 * @return array {@see stat}
		 */
		public function get_processes()
		{
			if (!IS_CLI) {
				return $this->query('pman_get_processes');
			}
			return $this->_processAccumulator();
		}

		/**
		 * Run a process
		 *
		 * Sample response:
		 *
		 * Array
		 * (
		 * [stdin] =>
		 * [stdout] => Hello World!!!
		 * [0] => Hello World!!!
		 * [stderr] =>
		 * [1] =>
		 * [output] => Hello World!!!
		 * [errno] => 0
		 * [return] => 0
		 * [error] =>
		 * [success] => 1
		 * )
		 *
		 * @param string $proc    process name, format specifiers allowed
		 * @param array  $args    optional arguments to supply to format
		 * @param array  $env     optional environment vars to set
		 * @param array  $options optional options, tee: set tee output to file
		 * @return array
		 */
		public function run($cmd, $args = null, $env = null, $options = array())
		{
			if (!IS_CLI) {
				if ($this->auth_is_demo()) {
					return error("process execution forbidden in demo");
				}
				// store msg buffer in event app is killed for
				// exceeding max wait time
				$buffer = Error_Reporter::flush_buffer();
				$resp = $this->query('pman_run', $cmd, $args, $env, $options);
				if (is_null($resp)) {
					// restore old buffer, ignore crash or other nasty error detected! msg
					Error_Reporter::set_buffer($buffer);
					return error("process lingered for %d seconds, " .
						"automatically abandoning", self::MAX_WAIT_TIME);
				}
				Error_Reporter::merge_buffer($buffer);
				return $resp;
			}

			if (is_null($env)) {
				$env = $_ENV;
			}

			$proc = new Util_Process_Sudo();

			if ($env) {
				$proc->setEnvironment($env);
			}
			if (isset($options['tee'])) {
				if ($options['tee'][0] != '/') {
					// relative file listed, assume /tmp
					$options['tee'] = sys_get_temp_dir() . '/' . $options['tee'];
				}
				if (file_exists($options['tee']) || is_link($options['tee'])) {
					// verify not trying to stream something like /etc/shadow
					return error("tee file `%s' exists", $options['tee']);
				} else if (!touch($options['tee'])) {
					return error("cannot use tee file `%s'", $options['tee']);
				}
				$tee = new Util_Process_Tee();
				$tee->setTeeFile($options['tee']);
				$tee->setProcess($proc);
			}
			// capture & extract the safe command, then sudo
			$proc->setOption('umask', 0022)->
			setOption('timeout', self::MAX_WAIT_TIME)->
			setOption('user', $this->username);
			// temp fix, last arg is checked for user/domain substitution,
			// wordpress sets user for example
			$ret = $proc->run($cmd, $args);

			return $ret;
		}

		/**
		 * Background an apnscp function with an optional delay
		 *
		 * @param            $realcmd
		 * @param array|null $args
		 * @param string     $when
		 */
		public function schedule_api_cmd($cmd, $args = array(), $when = 'now')
		{
			if (!IS_CLI) {
				return $this->query('pman_schedule_api_cmd', $cmd, $args, $when);
			}
			return $this->schedule_api_cmd_admin($this->site, $this->username, $cmd, $args, $when);
		}

		/**
		 * Background an apnscp function as any user on any domain
		 * with an optional delay
		 *
		 * @param string     $site domain or site to runas
		 * @param string     $user username to run as
		 * @param            $realcmd
		 * @param array|null $args
		 * @param string     $when
		 */
		public function schedule_api_cmd_admin($site, $user = null, $cmd, $args = array(), $when = 'now')
		{
			if (!IS_CLI) {
				return $this->query('pman_schedule_api_cmd_admin', $site, $user, $cmd, $args, $when);
			}
			// @XXX changing the username following api_cmd can result in a failed command
			$realcmd = INCLUDE_PATH . '/bin/cmd ';
			if ($site) {
				$realcmd .= '-d ' . escapeshellarg($site) . ' ';
			}
			if ($user) {
				$realcmd .= '-u ' . escapeshellarg($user) . ' ';
			}
			// support multiple commands
			if (!is_array($cmd)) {
				$cmd = array(array($cmd, $args));
			} else if (is_scalar($args)) {
				// [site, user, [[cmd1, [args]], [cmd2, [args]]], when]
				$when = $args;
			}

			// avoid fatals
			$timespec = new DateTime($when);
			if (!$timespec) {
				return error("unparseable timespec `%s'", $when);
			}
			$proc = new Util_Process_Schedule($timespec);

			$components = array();
			for ($i = 0, $n = sizeof($cmd); $i < $n; $i++) {
				$tmp = $cmd[$i];
				$cmdcom = $tmp[0];
				if (isset($tmp[1])) {
					$argcom = $tmp[1];
				} else {
					$argcom = array();
				}
				$safeargs = array();
				foreach ($argcom as $a) {
					if (is_array($a)) {
						if (isset($a[0])) {
							// array
							$a = array_map('escapeshellarg', $a);
						} else {
							// hash
							array_walk($a, function (&$v, $k) {
								$v = escapeshellarg($k) . ':' . escapeshellarg($v);
							});
						}
						$a = '[' . join(",", $a) . ']';
					}
					$safeargs[] = escapeshellarg($a);
				}
				$safeargs = join(" ", $safeargs);

				$components[] = escapeshellarg($cmdcom) . ' ' . $safeargs;
			}
			$realcmd .= join(' \; ', $components);
			$ret = $proc->run($realcmd);
			if (!$ret['success']) {
				return error("failed to schedule task `%s': %s", $cmd, $ret['error']);
			}
			return true;
		}
	}
