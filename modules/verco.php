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
     * Version control, CVS and subversion
     *
     * @package core
     */
    class Verco_Module extends Module_Skeleton
    {
        const TRAC_VERSION = '0.12.1';
        private $cvs_rpms = array('cvs');
        private $mercurial_rpms = array();
        private $git_rpms = array();
        private $svn_rpms = array('neon', 'neon-devel', 'subversion-devel', 'subversion', 'apr', 'apr-util', 'gnutls');

        /**
         * void __construct(void)
         *
         * @ignore
         */
        public function __construct()
        {
            parent::__construct();
            $this->user_srvc_cache = array();

            $this->exportedFunctions = array(
                'enable_svn'                      => PRIVILEGE_SITE,
                'enable_svn_backend'              => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
                'enable_cvs'                      => PRIVILEGE_SITE,
                'enable_cvs_backend'              => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
                'create_svn_repository'           => PRIVILEGE_SITE,
                'create_svn_repository_backend'   => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
                'create_cvs_repository'           => PRIVILEGE_SITE,
                'create_cvs_repository_backend'   => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
                'is_cvs_repository'               => PRIVILEGE_SITE,
                'is_svn_repository'               => PRIVILEGE_SITE,
                'delete_svn_repository'           => PRIVILEGE_SITE,
                'delete_svn_repository_backend'   => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
                'delete_cvs_repository'           => PRIVILEGE_SITE,
                'delete_cvs_repository_backend'   => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
                'cvs_enabled'                     => PRIVILEGE_SITE,
                'svn_enabled'                     => PRIVILEGE_SITE,
                'list_known_svn_repositories'     => PRIVILEGE_SITE,
                'list_known_cvs_repositories'     => PRIVILEGE_SITE,
                'get_local_installed_svn_version' => PRIVILEGE_SITE,
                'get_current_system_svn_version'  => PRIVILEGE_SITE,
                'get_current_system_cvs_version'  => PRIVILEGE_SITE,
                'get_local_installed_cvs_version' => PRIVILEGE_SITE,
                'get_trac_version'                => PRIVILEGE_ALL,
                'install_trac'                    => PRIVILEGE_SITE,
                'install_fcgi_bindings_backend'   => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
                'trac_installed'                  => PRIVILEGE_SITE,
            );
        }

        /**
         * bool enable_svn (void)
         *
         * @throws PermissionError if pre-req SSH is not satisfied
         * @return bool
         */
        public function enable_svn()
        {
            if (!$this->check_for_shell()) {
                return new PermissionError("Pre-req SSH not satisfied");
            }
            return $this->query('verco_enable_svn_backend');
        }

        /**
         * bool enable_svn_backend (void)
         * {@link enable_svn}
         *
         * @return bool
         */
        public function enable_svn_backend()
        {
            // subversion is part of apollo platform
            if (version_compare(PLATFORM_VERSION, '4.5', '>=')) {
                return true;
            }
            foreach ($this->svn_rpms as $rpm) {
                $status = Util_Process::exec('/root/replicatedomain.sh ' . $rpm . ' ' . $this->domain);
            }

            return $status;
        }

        public function create_svn_repository($mPath)
        {
            $data = $this->query('verco_create_svn_repository_backend', $mPath);
            if ($data instanceof Exception) {
                return $data;
            }

            $this->mysql->query("INSERT INTO `repository_paths`
													(`id`,
													 `domain`,
													 `type`,
													 `date_installed`,
													 `path`)
											 VALUES
													(NULL,
													 '" . $this->domain . "',
													 'svn',
													 " . time() . ",
													 '" . $mPath . "');");

            return $data;

        }

        public function create_svn_repository_backend($mPath)
        {
            $status = Util_Process_Sudo::exec("svnadmin create %s", $mPath);
            return $status;


        }

        public function delete_svn_repository($mPath)
        {
            $data = $this->query('verco_delete_svn_repository_backend', $mPath);
            if ($data instanceof Exception) {
                return $data;
            }

            $this->mysql->query("DELETE FROM repository_paths WHERE `domain` = '" . $this->domain . "' AND `type` = 'svn' AND path = '" . $mPath . "';");

            return true;

        }

        public function delete_svn_repository_backend($mPath)
        {
            $status = Util_Process_Sudo::exec('rm -rf %s',
                $mPath);
            return $status;

        }

        public function get_local_installed_svn_version()
        {
            if (!file_exists($this->domain_fs_path() . '/usr/bin/svn')) {
                return false;
            }

            $status = Util_Process::exec($this->domain_fs_path() . '/usr/bin/svn --version --quiet');
            return trim($status['output']);
        }

        public function get_current_system_svn_version()
        {
            $status = Util_Process::exec('env HOME="/" svn --version');
            preg_match('/version (.*)/', $status['output'], $info);
            return $info[1];
        }

        public function get_current_system_cvs_version()
        {
            $status = Util_Process::exec('cvs --version');
            preg_match('/\(CVS\) ([0-9\.]+)/', $status['output'], $info);
            return $info[1];
        }

        public function get_local_installed_cvs_version()
        {
            $status = Util_Process::exec($this->domain_fs_path() . '/usr/bin/cvs --version');
            preg_match('/\(CVS\) ([0-9\.]+)/', $status['output'], $info);
            return isset($info[1]) ? $info[1] : false;
        }

        /**
         * bool svn_enabled
         * Checks to see if Subversion is enabled for an account
         *
         * @return bool
         */
        public function svn_enabled()
        {
            return $this->check_for_shell() && file_exists('/home/virtual/' . $this->domain . '/usr/bin/svn');
        }

        public function is_svn_repository($mPath)
        {
            return false;

        }

        /**
         * array list_known_svn_repositories (void)
         *
         * @return array all known repositories, each index has an array with the values
         *               path and date (integer unix time)
         */
        public function list_known_svn_repositories()
        {
            $q = $this->mysql->query("SELECT path, date_installed FROM `repository_paths` WHERE domain = '" . $this->domain . "' AND type = 'svn'");
            $repos = array();
            while ($row = $q->fetch_object()) {
                $repos[] = array('path' => $row->path, 'date' => $row->date_installed);
            }
            return $repos;
        }

        public function create_cvs_repository($mPath)
        {
            $status = $this->query('verco_create_cvs_repository_backend', $mPath);
            if ($status['output'] instanceof Exception) {
                return $status['output'];
            }

            $stat = $this->mysql->query("INSERT INTO `repository_paths`
													(`id`,
													 `domain`,
													 `type`,
													 `date_installed`,
													 `path`)
											 VALUES
													(NULL,
													 '" . $this->domain . "',
													 'cvs',
													 " . time() . ",
													 '" . $mPath . "');");
            return $status;
        }

        public function create_cvs_repository_backend($mPath)
        {
            $status = Util_Process_Sudo::exec('cvs -d %s init',
                $mPath);
            return $status;

        }

        public function delete_cvs_repository($mPath)
        {
            $data = $this->query('verco_delete_cvs_repository_backend', $mPath);
            if ($data instanceof Exception) {
                return $data;
            }

            $this->mysql->query("DELETE FROM repository_paths WHERE `domain` = '" . $this->domain . "' AND `type` = 'cvs' AND path = '" . $mPath . "';");

            return true;

        }

        public function delete_cvs_repository_backend($mPath)
        {
            $status = Util_Process_Sudo::exec('rm -rf %s',
                $mPath);
            return $status;
        }

        /**
         * bool cvs_enabled (void)
         *
         * Checks to see if CVS is enabled
         *
         * @return bool
         */
        public function cvs_enabled()
        {
            return $this->check_for_shell() && file_exists('/home/virtual/' . $this->domain . '/usr/bin/cvs');
        }

        /**
         * bool enable_cvs (void)
         * Enables CVS support for an account
         *
         * @throw PermissionError pre-req SSH is not satisfied
         * @return bool
         */
        public function enable_cvs()
        {
            if (!$this->check_for_shell()) {
                return new PermissionError("Pre-req SSH not satisfied");
            }
            return $this->query('verco_enable_cvs_backend');
        }

        /**
         * bool enable_cvs_backend (void)
         * {@link enable_cvs_backend}
         *
         * @return bool
         */
        public function enable_cvs_backend()
        {
            // cvs is part of apollo platform
            if (version_compare(PLATFORM_VERSION, '4.5', '<')) {
                return true;
            }
            foreach ($this->cvs_rpms as $rpm) {
                $status = Util_Process::exec('/root/replicatedomain.sh ' . $rpm . ' ' . $this->domain);
            }

            return $status;
        }

        public function is_cvs_repository($mPath)
        {
            return false;
        }

        /**
         * array list_known_cvs_repositories (void)
         *
         * @return array all known repositories, each index has an array with the values
         *               path and date (integer unix time)
         */
        public function list_known_cvs_repositories()
        {
            $q = $this->mysql->query("SELECT path, date_installed FROM `repository_paths` WHERE domain = '" . $this->domain . "' AND type = 'cvs'");
            $repos = array();
            while ($row = $q->fetch_object()) {
                $repos[] = array('path' => $row->path, 'date' => $row->date_installed);
            }

            return $repos;
        }

        public function install_trac()
        {
            if (!$this->check_for_shell()) {
                return new PermissionError("Pre-requisite SSH not satisfied");
            }
            if (!IS_CLI) {
                return $this->query('verco_install_trac');
            }

            // Prep filesystem
            Util_Process_Sudo::exec('[[ ! -z "$PYTHONPATH" && -d $PYTHONPATH ]] || mkdir -p $PYTHONPATH');

            $tmp = $this->domain_fs_path() . "/tmp";
            $trac = APNSCP_INSTALL_PATH . "/var/storehouse/trac/Trac-" . self::TRAC_VERSION . ".tar.gz ";
            if (version_compare(PLATFORM_VERSION, '4.5', '<')) {
                Util_Process::exec("sh /root/replicatedomain.sh subversion-python " . $this->domain);

                Util_Process::exec("tar -xvz --overwrite -C %s -f %s && chown -R %d:%d %s",
                    $tmp,
                    APNSCP_INSTALL_PATH . "/var/storehouse/trac/setuptools-0.6c9.tar.gz",
                    $this->user_id,
                    $this->group_id,
                    $tmp . '/setuptools-0.6c9'
                );
                Util_Process_Sudo::exec('cd /tmp/setuptools-0.6c9/ && python setup.py install --prefix=/usr/local');

                Util_Process::exec("tar -xvz --overwrite -C %s -f %s && chown -R %d:%d %s",
                    $tmp,
                    APNSCP_INSTALL_PATH . "/var/storehouse/trac/pysqlite-2.3.3.tar.gz",
                    $this->user_id,
                    $this->group_id,
                    $tmp . '/pysqlite-2.3.3'
                );
                Util_Process_Sudo::exec('cd /tmp/pysqlite-2.3.3/ && python setup.py install --prefix=/usr/local');

            }

            Util_Process::exec("tar -xvz --overwrite -C %s -f %s && chown -R %d:%d %s",
                $tmp,
                APNSCP_INSTALL_PATH . "/var/storehouse/trac/clearsilver-0.10.4.tar.gz",
                $this->user_id,
                $this->group_id,
                $tmp . '/clearsilver-0.10.4'
            );

            Util_Process_Sudo::exec('cd /tmp/clearsilver-0.10.4/ && ./configure --prefix=/usr/local --disable-ruby && make && make install');

            Util_Process::exec("tar -xvz --overwrite -C %s -f %s && chown -R %d:%d %s",
                $tmp,
                $trac,
                $this->user_id,
                $this->group_id,
                $tmp . '/Trac-' . self::TRAC_VERSION

            );

            Util_Process_Sudo::exec('cd %s && python setup.py install --prefix=/usr/local',
                '/tmp/Trac-' . self::TRAC_VERSION);
            Util_Process::exec("rm -rf %s/{pysqlite-2.3.3,clearsilver-0.10.4,setuptools-0.6c9,Trac-" . self::TRAC_VERSION . "}/",
                $tmp);
            return $this->trac_installed();

        }

        public function trac_installed()
        {
            return file_exists($this->domain_fs_path() . '/usr/local/bin/trac-admin');
        }

        public function get_trac_version()
        {
            return self::TRAC_VERSION;
        }

        private function check_for_shell()
        {
            return $this->get_service_value('ssh', 'enabled');
        }


    }

?>
