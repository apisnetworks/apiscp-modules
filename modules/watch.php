<?php

    /**
     *  File watch component
     *
     *  @package core
     */
    class Watch_Module extends Module_Skeleton {
        const CACHE_STORAGE_DURATION = 7200;
        const CACHE_PREFIX = 'watch.';

        public $exportedFunctions;

        public function __construct() {
            parent::__construct();
            if (version_compare(platform_version(), '4.5', '<')) {
                $this->exportedFunctions = array();
                return;
            }
            $this->exportedFunctions = array(
                '*' => PRIVILEGE_SITE|PRIVILEGE_USER
            );
        }

        /**
         * Make a filesystem checkpoint
         *
         * Note: this only works on publicly readable locations
         *
         * @param string $path path to checkpoint
         * @return string checkpoint id
         */
        public function checkpoint($path) {
            $fullpath = $this->file_make_shadow_path($path);
            if (!$fullpath) {
                return error("unknown or invalid path `%s' provided", $path);
            } else if (!is_dir($fullpath)) {
                return error("path `%s' is inaccessible", $path);
            }

            $ts = time();
            $inode = fileinode($fullpath);
            $struct = array(
                'ts' => $ts,
                'path' => $path,
                'inode' => $inode,
                'map' => $this->_watch_generate($fullpath)
            );
            $key = $this->_makeKeyFromResults($struct);
            $key = $this->_getWatchCachePrefix() . $key;
            $cache = Cache_Account::spawn();
            if (is_debug()) {
                $duration = null;
            } else {
                $duration = self::CACHE_STORAGE_DURATION;
            }
            if (!$cache->set($key, $struct, $duration)) {
                return error("failed to save watch data: (%d) %s",
                    $cache->getResultCode(),
                    $cache->getResultMessage()
                );
            }
            return substr($key, strlen($this->_getWatchCachePrefix()));
        }

        /**
         * Retrieve stored checkpoint from cache
         *
         * @param string $id
         * @return array
         */
        public function fetch($id) {
            $cache = Cache_Account::spawn();
            $map = $cache->get($this->_getWatchCachePrefix() . $id);
            if (!$map) {
                return array();
            }
            return $map;
        }

        private function _watch_generate($path) {
            $dh = opendir($path);
            if (!$dh) {
                return array();
            }
            while (false !== ($file = readdir($dh))) {
                if ($file === "..") {
                    continue;
                }
                $filepath = $path . '/' . $file;
                $size = filesize($filepath);
                $mtime = filemtime($filepath);
                $ctime = filectime($filepath);
                if ($file !== "." && is_dir($filepath)) {
                    $arr[$file] = $this->_watch_generate($filepath);
                } else {
                    $arr[$file] = array(
                        'size'  => $size,
                        'mtime' => $mtime,
                        'ctime' => $ctime
                    );
                }
            }
            closedir($dh);
            return $arr;

        }

        /**
         * Export a checkpoint
         *
         * @param string $id checkpoint ID to export @link checkpoint
         * @return bool|string
         */
        public function export($id) {
            $res = $this->fetch($id);
            if (!$id) {
                return error("export failed");
            }
            return base64_encode(serialize($res));
        }

        /**
         * Import a saved checkpoint
         *
         * @param string $data checkpoint data (@see export)
         * @return bool
         */
        public function import($data) {
            if (!preg_match('/^[a-zA-Z0-9\+\/=]*$/', $data)) {
                return error("data is not base64-encoded");
            }

            $data = unserialize(base64_decode($data));
            if (!$data) {
                return error("invalid data to import");
            }
            $hash = $this->_makeKeyFromResults($data);
            $key = $this->_getWatchCachePrefix() . $hash;
            $cache = Cache_Account::spawn();
            if (!$cache->set($key, $data, self::CACHE_STORAGE_DURATION)) {
                return error("failed to import checkpoint data: (%d) %s",
                    $cache->getResultCode(),
                    $cache->getResultMessage()
                );
            }
            return $hash;
        }

        /**
         * Compare checkpoints for changes
         *
         * @param string $id1 initial checkpoint
         * @param string $id2 comparison checkpoint
         * @return array|bool differences or false on failure
         */
        public function compare($id1, $id2) {
            $cache = Cache_Account::spawn();
            $res1 = $cache->get($this->_getWatchCachePrefix() . $id1);
            if (false === $res1) {
                return error("invalid or expired watch key, `%s'", $id1);
            }

            $res2 = $cache->get($this->_getWatchCachePrefix() . $id2);
            if (false === $res2) {
                return error("invalid or expired watch key, `%s'", $id2);
            }
            if ($res1['path'] != $res2['path']) {
                return error("path `%s' does not match path `%s'",
                    $res1['path'],
                    $res2['path']
                );
            } else if ($res1['inode'] != $res2['inode']) {
                warn("inode mismatch on `%s' but path same, irregular results possible", $res1['path']);
            }
            if ($res1['ts'] > $res2['ts']) {
                warn("tokens passed in reverse order - items shown are original values");
            }
            // files that have changed
            $changed = Util_PHP::array_diff_assoc_recursive($res2['map'], $res1['map']);
            return $changed;
        }

        private function _makeKeyFromResults($results) {
            return base_convert($results['ts'] + $results['inode'], 10, 36);
        }
        /**
         * Unattended file change calcuation
         *
         * @param $path
         * @param $token1 initial reference token (@see watch)
         * @param string $mode whether to lock or unlock changed files
         * @return bool
         *
         */
        public function batch($path, $id1, $mode = 'unlock') {
            $id2 = $this->checkpoint($path);
            $diff = $this->compare($id1, $id2);
            if (!$diff) {
                return error("watch batch operation failed");
            }
            $report = $this->_generateChangeReport($path, $diff);
            $resp = $this->lockdown($path, $diff, $mode);
            $report .= "\r\nEnforcement results (" . $mode . " changed files): \r\n";
            if (!$resp) {
                $report .= "\tPartially succeeded. Error messages: \r\n" .
                    var_export(Error_Reporter::flush_buffer(), true);
            } else {
                $report .= "\tSUCCESS!";
            }

            Mail::send(
                $this->common_get_admin_email(),
                'File Change Report (' . $this->domain . ')',
                $report
            );
            return $diff;
        }

        /**
         * Change ownership to active user + open up only to $diff files
         *
         * @param string $path
         * @param array $diff calculated diff @see compare()
         * @param string $mode lock or unlock, how to handle changed files
         * @return bool
         */
        public function lockdown($path, $diff, $mode = 'unlock') {
            if (!IS_CLI) {
                return $this->query('watch_lockdown', $path, $diff);
            }

            if (!$this->file_file_exists($path)) {
                return error("path `%s' does not exist", $path);
            }
            $stat = $this->file_stat($path);
            $uid = $stat['uid'];
            if ($stat['uid'] < User_Module::MIN_UID) {
                return error("uid of `%s' is a system uid `%d'", $path, $stat['uid']);
            } else if (($this->permission_level&PRIVILEGE_USER) && $uid != $this->user_id) {
                return error("cannot lockdown docroots unowned by this user");
            }
            $username = $this->user_get_username_from_uid($uid);
            $proposed = $this->_collapseChanges($path, $diff);
            // files and directories to adjust
            $adjfiles = array();
            $adjdirs = array();
            foreach ($proposed as $f => $meta) {
                if (isset($meta['size'])) {
                    // file grew
                    $adjfiles[$f] = true;
                } else if (isset($meta['ctime'])) {
                    // file created
                    $dir = dirname($f);
                    $adjdirs[$dir] = true;
                } else { // mtime
                    if (substr($f, -1) === ".") {
                        // file removed or added
                        $adjdirs[dirname($f)] = true;
                    }  else {
                        // file modified in place
                        $adjfiles[$f] = true;
                    }
                }
            }
            $filtered = array_filter(
                array_merge(array_keys($adjdirs), array_keys($adjfiles)),
                function ($d) use($path) { return !strncmp($d, $path, strlen($path)); }
            );

            if ($mode === 'lock') {
                $this->file_chown($filtered, $username);
                return $this->file_set_acls($filtered, null, array(File_Module::ACL_NO_RECALC_MASK));
            }

            // unlocked
            $this->file_chown($path, $username, true);
            if (!$this->file_set_acls($path, null, array(File_Module::ACL_NO_RECALC_MASK, File_Module::ACL_MODE_RECURSIVE))) {
                warn("failed to release apache acls on `%s'", $path);
            }
            // make sure apache-created files are turned over to the account
            $prefix = $this->domain_shadow_path();
            foreach ($filtered as $f) {
                $f = $prefix . $f;
                if (file_exists($f) && filegroup($f) === APACHE_GID) {
                    chgrp($f, $this->group_id);
                }
            }
            $users = array(
                array('apache' => 7),
                array('apache' => 'drwx'),
                array($username => 7),
                array($username => 'drwx')
            );
            return $this->file_set_acls($filtered, $users, array(File_Module::ACL_NO_RECALC_MASK));
        }

        private function _generateChangeReport($path, $files) {
            $files = $this->_collapseChanges($path, $files);
            $msg = "Hello, " . "\r\n" .
                "The following files were noted as changed: " . "\r\n\r\n";
            foreach ($files as $file => $modes) {
                $msg .= "\t" . $file . ": " . join(", ", array_keys($modes)) . "\r\n";
            }
            return $msg;

        }

        private function _collapseChanges($path, $files) {
            $p = $path;
            $changed = array();
            foreach ($files as $f => $l) {
                if (is_array($l)) {
                    $changed = array_merge($changed, $this->_collapseChanges($p . DIRECTORY_SEPARATOR . $f, $l));
                } else {
                    $changed[$p][$f] = $l;
                }

            }
            return $changed;
        }

        private function _getWatchCachePrefix() {
            return self::CACHE_PREFIX;
        }
    }