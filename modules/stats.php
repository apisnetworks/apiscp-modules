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
	 * Statistics/hardware information
	 *
	 * @package core
	 */
	class Stats_Module extends Module_Skeleton
	{
		/**
		 * {{{ void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = array(
				'*' => PRIVILEGE_ALL
			);
		}

		/**
		 * array get_partition_information
		 *
		 * @return array
		 */
		public function get_partition_information()
		{
			$fstype = array();
			$fsoptions = array();

			$df = Util_Process::exec('df -kP');
			$mounts = explode("\n", $df['output']);

			$buffer = Util_Process::exec("mount");
			$buffer = explode("\n", $buffer['output']);

			$j = 0;
			$results = [];
			$seenMounts = [];
			foreach ($buffer as $line) {
				if (0 !== strpos($line, '/dev/')) {
					continue;
				}
				preg_match("/(.*) on (.*) type (.*) \((.*)\)/", $line, $result);
				if (count($result) == 5) {
					$dev = $result[1];
					$mpoint = $result[2];
					$type = $result[3];
					$options = $result[4];
					$fstype[$mpoint] = $type;
					$fsdev[$dev] = $type;
					$fsoptions[$mpoint] = $options;

					foreach ($mounts as $line2) {
						if (preg_match("!^" . preg_quote($result[1], '!') . "!", $line2)) {
							$line2 = preg_replace("!^" . preg_quote($result[1], '!') . "!", "", $line2);
							$ar_buf = preg_split("/(\s+)/", $line2, 6);
							if (sizeof($ar_buf) < 6) {
								continue;
							}
							$ar_buf[0] = $result[1];
							$mount = $ar_buf[5];
							if ($mount == "/dev/shm" || $ar_buf[0] == "" || isset($seenMounts[$mount]) ||
								!isset($fsoptions[$mount]) || false !== strpos($fsoptions[$mount], "bind")
							) {
								continue;
							}
							$seenMounts[$mount] = 1;
							$results[$j] = array();
							$results[$j]['disk'] = $ar_buf[0];
							$results[$j]['size'] = (int)$ar_buf[1];
							$results[$j]['used'] = (int)$ar_buf[2];
							$results[$j]['free'] = (int)$ar_buf[3];
							$results[$j]['percent'] = round(($results[$j]['used'] * 100) / $results[$j]['size']) . '%';
							$results[$j]['mount'] = $ar_buf[5];
							($fstype[$ar_buf[5]]) ? $results[$j]['fstype'] = $fstype[$ar_buf[5]] : $results[$j]['fstype'] = $fsdev[$ar_buf[0]];
							$results[$j]['options'] = $fsoptions[$ar_buf[5]];
							$j++;
						}
					}
				}
			}

			return $results;
		}

		public function get_spamassassin_stats()
		{
			$sastats = array();
			if (!file_exists('/tmp/sa-stats')) {
				return $sastats;
			}
			$fp = fopen('/tmp/sa-stats', 'r');
			while (false !== ($line = fgets($fp))) {
				$buffer = '  ';
				if (false !== strpos($line, 'Period Beginning')) {
					$data = explode(':', $line);
					$sastats['begin_date'] = trim(join(array_slice($data, 1), ':'));
				} else {
					if (false !== strpos($line, 'Period Ending')) {
						$data = explode(':', $line);
						$sastats['end_date'] = trim(join(array_slice($data, 1), ':'));
					} else {
						if (false !== strpos($line, 'Reporting Period')) {
							/** Get the whole section of reporting period... */
							$line = fgets($fp);
							fgets($fp); // remove --------- line
							while (false !== ($line = fgets($fp))) {
								if ($buffer[strlen($buffer) - 2] == "\n" && $buffer[strlen($buffer) - 1] == "\n" && $line == "\n") {
									break;
								}
								$buffer .= $line;
							}
							$sastats['reporting_information'] = trim($buffer);
						} else {
							if (false !== strpos($line, 'Statistics by Hour')) {
								$line = fgets($fp); // remove --------- line
								while (false !== ($line = fgets($fp))) {

									if ($buffer[strlen($buffer) - 2] == "\n" && $buffer[strlen($buffer) - 1] == "\n" && $line == "\n") {
										break;
									}
									$buffer .= $line;
								}
								$sastats['stats_by_hour'] = trim($buffer);
							} else {
								if (false !== strpos($line, 'Done. Report generated')) {
									while (false !== ($line = fgets($fp))) {
										/**
										 * nasty hack, we shouldn't assume TOP [SPAM, HAM]
										 * RULES FIRED is coming next
										 */
										if (false !== strpos($line, 'TOP')) {
											$bufftmp = $buffer;
											$buffer = $line;
											while (false !== ($line = fgets($fp))) {
												$buffer .= $line;
											}
											$sastats['rule_information'] = trim($buffer);
											$buffer = $bufftmp;
											break;
										}
										$buffer .= $line;
									}
									$sastats['reporting_information'] .= "\n\n" . trim($buffer);
								} else {
									if (false !== strpos($line, "TOP")) {

									}
								}
							}
						}
					}
				}
			}
			fclose($fp);

			return $sastats;
		}

		/**
		 * array get_memory_information()
		 *
		 * @return array
		 */
		public function get_memory_information()
		{
			if (false === ($fd = fopen('/proc/meminfo', 'r'))) {
				return new FileError("/proc/meminfo does not exist");
			}

			$results['ram'] = array();
			$results['swap'] = array(
				'total'   => 0,
				'used'    => 0,
				'percent' => 0
			);
			$results['devswap'] = array();

			while ($buf = fgets($fd)) {
				if (preg_match('/^MemTotal:\s+(.*)\s*kB/i', $buf, $ar_buf)) {
					$results['ram']['total'] = (int)$ar_buf[1];
				} else {
					if (preg_match('/^MemFree:\s+(.*)\s*kB/i', $buf, $ar_buf)) {
						$results['ram']['t_free'] = (int)$ar_buf[1];
					} else {
						if (preg_match('/^Cached:\s+(.*)\s*kB/i', $buf, $ar_buf)) {
							$results['ram']['cached'] = (int)$ar_buf[1];
						} else {
							if (preg_match('/^Buffers:\s+(.*)\s*kB/i', $buf, $ar_buf)) {
								$results['ram']['buffers'] = (int)$ar_buf[1];
							} else {
								if (preg_match('/^SwapTotal:\s+([1-9][0-9]*)\s*kB/i', $buf, $ar_buf)) {
									$results['swap']['total'] = (int)$ar_buf[1];
								} else {
									if (preg_match('/^SwapFree:\s+(.*)\s*kB/i', $buf, $ar_buf)) {
										$results['swap']['free'] = (int)$ar_buf[1];
									}
								}
							}
						}
					}
				}
			}
			fclose($fd);

			$results['ram']['t_used'] = $results['ram']['total'] - $results['ram']['t_free'];
			$results['ram']['percent'] = round(($results['ram']['t_used'] * 100) / $results['ram']['total']);
			$results['swap']['used'] = $results['swap']['total'] - $results['swap']['free'];
			if ($results['swap']['total'] > 0) {
				$results['swap']['percent'] = round(($results['swap']['used'] * 100) / $results['swap']['total']);
			}

			// values for splitting memory usage
			if (isset($results['ram']['cached']) && isset($results['ram']['buffers'])) {
				$results['ram']['app'] = $results['ram']['t_used'] - $results['ram']['cached'] - $results['ram']['buffers'];
				$results['ram']['app_percent'] = round(($results['ram']['app'] * 100) / $results['ram']['total']);
				$results['ram']['buffers_percent'] = round(($results['ram']['buffers'] * 100) / $results['ram']['total']);
				$results['ram']['cached_percent'] = round(($results['ram']['cached'] * 100) / $results['ram']['total']);
			}

			$swaps = file('/proc/swaps');
			for ($i = 1, $n = sizeof($swaps); $i < $n; $i++) {
				$ar_buf = preg_split('/\s+/', $swaps[$i], 6);
				$results['devswap'][$ar_buf[0]] = array();
				$results['devswap'][$ar_buf[0]]['total'] = $ar_buf[2];
				$results['devswap'][$ar_buf[0]]['used'] = $ar_buf[3];
				$results['devswap'][$ar_buf[0]]['free'] = ($results['devswap'][$ar_buf[0]]['total'] - $results['devswap'][$ar_buf[0]]['used']);
				$results['devswap'][$ar_buf[0]]['percent'] = round(($ar_buf[3] * 100) / $ar_buf[2]);
			}

			return $results;
		}

		/**
		 * array get_network_device_information
		 *
		 * @return array key, device name, values:
		 *              [tx,rx]_bytes, [tx,rx]_packets,
		 *              [tx,rx]_errs, [tx,rx]_drop
		 */
		public function get_network_device_information()
		{
			$results = array();

			if (false === ($fd = fopen('/proc/net/dev', 'r'))) {
				return new IOError("/proc/net/dev does not exist");
			}

			while ($buf = fgets($fd, 4096)) {
				if (preg_match('/:/', $buf)) {
					list($dev_name, $stats_list) = preg_split('/:/', $buf, 2);
					$stats = preg_split('/\s+/', trim($stats_list));
					$results[$dev_name] = array();

					$results[$dev_name]['rx_bytes'] = $stats[0];
					$results[$dev_name]['rx_packets'] = $stats[1];
					$results[$dev_name]['rx_errs'] = $stats[2];
					$results[$dev_name]['rx_drop'] = $stats[3];

					$results[$dev_name]['tx_bytes'] = $stats[8];
					$results[$dev_name]['tx_packets'] = $stats[9];
					$results[$dev_name]['tx_errs'] = $stats[10];
					$results[$dev_name]['tx_drop'] = $stats[11];

					$results[$dev_name]['errs'] = $stats[2] + $stats[10];
					$results[$dev_name]['drop'] = $stats[3] + $stats[11];
				}
			}

			return $results;

		}

	}

?>
