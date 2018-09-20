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
	 * PostgreSQL operations
	 *
	 * @package core
	 */
	class Pgsql_Module extends Module_Support_Sql
	{
		const DEPENDENCY_MAP = [
			'siteinfo'
		];
		const PG_TEMP_PASSWORD = '23f!eoj3';
		const PGSQL_DATADIR = '/var/lib/pgsql';

		/* @ignore */
		const MASTER_USER = 'root';

		protected const PGSQL_PERMITTED_EXTENSIONS = ['pg_trgm', 'hstore'];

		/**
		 * {{{ void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = array(
				'*'                             => PRIVILEGE_SITE,
				'version'                       => PRIVILEGE_ALL,
				'get_elevated_password_backend' => PRIVILEGE_ALL | PRIVILEGE_SERVER_EXEC,
				'prep_tablespace_backend' => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'vacuum_backend'    => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'get_uptime'        => PRIVILEGE_ALL,
				'get_username'      => PRIVILEGE_ALL,
				'get_password'      => PRIVILEGE_ALL,
				'set_password'      => PRIVILEGE_ALL,
				'enabled'                 => PRIVILEGE_SITE | PRIVILEGE_USER,
				'get_prefix'        => PRIVILEGE_SITE | PRIVILEGE_USER,

				// necessary for DB backup routines
				'get_database_size'       => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'database_exists'   => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'site_from_tablespace' => PRIVILEGE_ADMIN
			);
		}

		public function __destruct()
		{
			foreach ($this->_tempUsers as $user) {
				if (!$this->user_exists($user)) {
					continue;
				}
				$this->_delete_temp_user($user);
			}
		}


		public function get_prefix()
		{
			// for now
			return $this->getServiceValue('mysql', 'dbaseprefix');
		}



		public function user_exists($user)
		{
			$db = \PostgreSQL::initialize();
			$prefix = $this->get_prefix();
			if ($user != $this->getServiceValue('mysql', 'dbaseadmin') &&
				0 !== strpos($user, $prefix)
			) {
				$user = $prefix . $user;
			}
			$q = $db->query_params("SELECT 1 FROM pg_authid WHERE rolname = $1", array($db->escape_string($user)));
			return !$q || $db->num_rows() > 0;
		}

		private function _delete_temp_user($user)
		{
			if (!$this->delete_user($user)) {
				return false;
			}

			$idx = array_search($user, $this->_tempUsers);
			if ($idx !== false) {
				unset($this->_tempUsers[$idx]);
			}
			return true;
		}

		// {{{ connect_mysql_root()

		/**
		 * bool delete_user(string[, bool = false])
		 * Delete a PostgreSQL user
		 *
		 * @param string $user    username
		 * @param bool   $cascade casecade delete
		 * @return bool
		 */
		public function delete_user($user, $cascade = false)
		{
			if ($user == $this->username && !Util_Account_Hooks::is_mode('delete')) {
				return error("Cannot remove main user");
			} else {
				if (!$this->user_exists($user)) {
					return error("db user `$user' not found");
				}
			}
			$prefix = $this->get_prefix();
			if ($user != $this->getConfig('mysql', 'dbaseadmin') && strncmp($user, $prefix, strlen($prefix))) {
				$user = $prefix . $user;
			}
			$tblspace = $this->get_tablespace();
			if (function_exists('pg_escape_literal')) {
				$usersafe = pg_escape_identifier($user);
			} else {
				$usersafe = '"' . pg_escape_string($user) . '"';
			}
			$pghandler = \PostgreSQL::initialize();
			$pghandler->query('REVOKE ALL ON TABLESPACE ' . $tblspace . ' FROM ' . $usersafe . '');
			$pghandler->query("DROP ROLE " . $usersafe);

			if ($pghandler->error) {
				return new PostgreSQLError("Invalid query, " . $pghandler->error);
			}

			return true;

		}

		// }}}

		/**
		 * Get tablespace name for domain
		 *
		 * @return null|string
		 */
		public function get_tablespace(): ?string
		{
			return $this->getServiceValue(
				'pgsql',
				'tablespace',
				\Opcenter\Database\PostgreSQL::getTablespaceFromUser($this->username)
			);
		}

		/**
		 * Get site from tablespace
		 *
		 * @param string $tblspace
		 * @return null|string
		 */
		public function site_from_tablespace(string $tblspace): ?string
		{
			$db = \PostgreSQL::pdo();
			$query = "SELECT rolname FROM pg_authid JOIN pg_tablespace ON (pg_authid.oid = pg_tablespace.spcowner) WHERE spcname = '" . pg_escape_string($tblspace) . "'";
			$rs = $db->query($query);
			if (!$rs) {
				return null;
			}
			$user = $rs->fetchObject()->rolname;
			if ($siteid = \Auth::get_site_id_from_admin($user)) {
				return 'site' . $siteid;
			}
			// not strictly enforced yet...
			$map = \Opcenter\Map::load('pgsql.usermap');
			return $map->fetch($user) ?: null;
		}

		public function set_password($password)
		{
			if (!IS_CLI) {
				return $this->query('pgsql_set_password', $password);
			}

			return $this->_set_pg_param('password', $password);

		}

		private function _set_pg_param($param, $val)
		{
			$pwd = $this->user_getpwnam();
			$file = $this->domain_fs_path() . $pwd['home'] . '/.pgpass';

			if (!file_exists($file)) {
				\Opcenter\Filesystem::touch($file, $this->user_id, $this->group_id, 0600);
			}

			return \Opcenter\Database\PostgreSQL::setUserConfigurationField($file, $param, $val);

		}

		public function set_username($user)
		{
			if (!IS_CLI) {
				return $this->query('pgsql_set_username', $user);
			}
			return $this->_set_pg_param('username', $user);

		}

		public function get_password($user = null)
		{
			if (!IS_CLI) {
				return $this->query('pgsql_get_password', $user);
			}
			if (!$user) {
				$user = $this->username;
			}
			$pwd = $this->user_getpwnam($user);
			if (!$pwd) {
				return error('unknown system user `%s\'', $user);
			}
			$file = $this->domain_fs_path() . $pwd['home'] . '/.pgpass';
			if (!file_exists($file)) {
				return false;
			}
			return \Opcenter\Database\PostgreSQL::getUserConfiguration($file)['password'];
		}

		public function get_elevated_password_backend()
		{
			return Opcenter\Database\MySQL::rootPassword();
		}

		/**
		 * Change account database prefix
		 *
		 * @param string $prefix
		 * @return bool
		 */
		public function change_prefix($prefix)
		{
			return error("use sql_change_prefix");
		}

		public function get_sql_prefix()
		{
			deprecated("use pgsql_get_prefix");
			return $this->get_prefix();
		}

		/**
		 * bool service_enabled (string)
		 *
		 * Checks to see if a service is enabled
		 *
		 * @deprecated @see enabled()
		 * @return bool
		 */
		public function service_enabled()
		{
			deprecated("use enabled()");
			return $this->enabled();
		}

		/**
		 * MySQL/PostgreSQL service enabled on account
		 *
		 * Checks to see if either MySQL or PostgreSQL is enabled on an account
		 *
		 * @return bool
		 */
		public function enabled()
		{
			return parent::svc_enabled('pgsql');
		}

		/**
		 * bool add_user(string, string[, int])
		 */
		public function add_user($user, $password, $maxconn = self::DEFAULT_CONCURRENCY_LIMIT)
		{
			if (!$user) {
				return error("no username specified");
			}
			$prefix = str_replace('-', '', $this->get_prefix());
			if ($user != $this->getServiceValue('mysql', 'dbaseadmin') &&
				0 !== strpos($user, $prefix))
			{
				$user = $prefix . $user;
			}
			if (!$this->enabled()) {
				return error("PostgreSQL service not enabled for account.");
			} else if ($this->user_exists($user)) {
				return error("pg user `$user' exists");
			}

			if ($maxconn < 0) {
				$maxconn = self::PER_DATABASE_CONNECTION_LIMIT;
			}
			if (strlen($password) < self::MIN_PASSWORD_LENGTH) {
				return error("Password must be at least %d characters", self::MIN_PASSWORD_LENGTH);
			} else if ($maxconn < 0) {
				return error("Max connections, queries, and updates must be greater than -1");
			}
			if (!\Opcenter\Database\PostgreSQL::createUser($user, $password)) {
				return false;
			}
			\Opcenter\Database\PostgreSQL::setRole($user, $this->username);
			$vendor = \Opcenter\Database\PostgreSQL::vendor();
			return (bool)\PostgreSQL::initialize()->query($vendor->setMaxConnections($user, $maxconn));
		}

		/**
		 * bool create_database (string)
		 *
		 * @param  string $db
		 * @return bool  creation succeeded
		 */
		public function create_database($db)
		{
			if (!$this->enabled()) {
				return error("PostgreSQL service not enabled for account.");
			}
			if (!preg_match('/^[a-zA-Z_0-9-]+$/', $db)) {
				return error("invalid database name `%s'", $db);
			}
			if ($this->database_exists($db)) {
				return error("database `$db' exists");
			}
			$prefix = $this->get_prefix();

			// db name passed without prefix
			if (strncmp($db, $prefix, strlen($prefix))) {
				$db = $prefix . $db;
			}
			if (!$this->prep_tablespace()) {
				return false;
			}
			// optional template
			$template = '';
			if (version_compare(platform_version(), '6', '>=')) {
				$template = "TEMPLATE = template1";
			}
			$pghandler = \PostgreSQL::initialize();
			$pghandler->query("CREATE DATABASE \"" . $db . "\" WITH OWNER = " . $this->username . " $template TABLESPACE = \"" . $this->get_tablespace() . "\" CONNECTION LIMIT = " . static::PER_DATABASE_CONNECTION_LIMIT);
			if ($pghandler->error) {
				return error("error while creating database: %s", $pghandler->error);
			}
			return info("created database `%s'", $db);
		}

		/**
		 * Query PostgreSQL system table for existence of database
		 *
		 * @param string $db database name
		 * @return bool
		 */
		public function database_exists($db)
		{
			if (!$this->permission_level & PRIVILEGE_ADMIN) {
				$prefix = $this->get_prefix();
				if (0 !== strpos($db, $prefix)) {
					$db = $prefix . $db;
				}
			}
			$pgdb = \PostgreSQL::initialize();
			$q = $pgdb->query_params("SELECT 1 FROM pg_database WHERE datname = $1", array($pgdb->escape_string($db)));
			return !$q || $pgdb->num_rows() > 0;
		}

		/**
		 * void prep_tablespace ()
		 * Checks to see if tablespace exists, if not, creates it
		 *
		 * @private
		 */
		public function prep_tablespace()
		{
			if (\Opcenter\Database\PostgreSQL::getTablespaceFromUser($this->username)) {
				return true;
			}
			$path = $this->domain_fs_path() . self::PGSQL_DATADIR;
			if (!file_exists($path)) {
				$this->query("pgsql_prep_tablespace_backend", $path);
			}
			return \Opcenter\Database\PostgreSQL::initializeTablespace($this->domain, $path, $this->username);
		}

		public function add_extension($db, $extension)
		{
			if (!IS_CLI) {
				return $this->query('pgsql_add_extension', $db, $extension);
			}

			if (!platform_is('6')) {
				return error("%s only available on v6+ platforms", __FUNCTION__);
			}

			$extensions = $this->_getPermittedExtensions();
			if (!in_array($extension, $extensions, true)) {
				return error("extension `%s' unrecognized or disallowed usage", $extension);
			}

			$dbs = $this->list_databases();
			if (!in_array($db, $dbs)) {
				return error("database `%s' unknown", $db);
			}

			$cmd = "CREATE EXTENSION IF NOT EXISTS " . $extension;
			$proc = Util_Process_Safe::exec('psql -c %s %s', $cmd, $db);
			if (!$proc['success']) {
				return error("extension creation failed - %s", $proc['stderr']);
			}
			return $proc['success'];
		}

		private function _getPermittedExtensions()
		{
			return static::PGSQL_PERMITTED_EXTENSIONS;
		}

		/**
		 * array list_databases ()
		 * Queries the db table in the pgsql database for applicable grants
		 *
		 * @return array list of databases
		 */
		public function list_databases()
		{
			$prefix = $this->get_prefix();
			$pgdb = \PostgreSQL::initialize();
			$pgdb->query("SELECT datname FROM pg_database WHERE datname LIKE '"
				. str_replace(array("-", '_'), array("", '\_'), $prefix) . "%' OR datdba = "
				. "(SELECT oid FROM pg_roles WHERE rolname = '" . $this->username . "')");
			$dbs = array();
			while ($row = $pgdb->fetch_object()) {
				$dbs[] = $row->datname;
			}
			return $dbs;
		}

		/**
		 * void prep_tablespace_backend ()
		 * {@link prep_tablespace}
		 *
		 * @param string $path tablespace path
		 * @return bool
		 */
		public function prep_tablespace_backend($location)
		{
			if (!is_dir($location)) {
				mkdir($location) || fatal("failed to create pgsql data directory `%s'", $location);
			}
			chown($location, "postgres");
			chgrp($location, (int)\Session::get('group_id', posix_getgrgid('postgres')));
			chmod($location, 02750);
		}

		/**
		 * bool add_user_permissions (string, string, string, array)
		 * Add/removes privileges for a user to a table, any value listed as
		 * false or not supplied as an array key will revoke the privilege
		 *
		 * @param string $user
		 * @param string $db
		 * @param array  $opts
		 */
		public function add_user_permissions($user, $db, array $opts)
		{
			return error("Function not implemented in PostgreSQL");
		}

		public function delete_user_permissions($user, $db)
		{
			return error("Function not implemented in PostgreSQL");
		}

		/**
		 * void get_user_permissions(string, string)
		 * Function not implemented in PostgreSQL
		 *
		 * @return void
		 */
		public function get_user_permissions($user, $db)
		{
			return error("Function not implemented in PostgreSQL");
		}

		/**
		 * bool delete_database(string)
		 * Drops the database and revokes all permssions
		 *
		 * @param  string $db
		 * @return bool   drop succeeded
		 */
		public function delete_database($db)
		{
			$pgdb = \PostgreSQL::initialize();
			$db = $pgdb->escape_string($db);
			$prefix = $this->get_prefix();
			if (0 !== strpos($db, $prefix)) {
				$db = $prefix . $db;
			}
			if (!\Opcenter\Database\PostgreSQL::databaseExists($db, $this->username)) {
				return error("Unknown database `%s'", $db);
			}
			$resp = \Opcenter\Database\PostgreSQL::dropDatabase($db);
			$this->delete_backup($db);
			if (!$resp) {
				return error("Error while dropping database, " . $pgdb->error);
			}
			return true;
		}

		/**
		 * Remove PostgreSQL Backup
		 *
		 * @param string $db
		 * @return bool
		 */
		public function delete_backup($db)
		{
			return parent::delete_backup_real('pgsql', $db);
		}

		/**
		 * Modify use password and connection limit
		 *
		 * NOTE: Not implemented with PostgreSQL, owner of database automatically
		 * receives grants.  Varying degrees of grants impact the usability of
		 * this function, i.e. common grants [SELECT, INSERT, UPDATE, DELETE] exist
		 * solely on the table level, while [CREATE, TEMP] exist on the database
		 * level
		 *
		 * @param string $user    user
		 * @param string $password
		 * @param int    $maxconn connection limit
		 * @return bool query succeeded
		 */
		public function edit_user($user, $password, $maxconn = null)
		{
			$prefix = str_replace('-', '', $this->get_prefix());
			if ($user != $this->getServiceValue('mysql', 'dbaseadmin') &&
				strncmp($user, $prefix, strlen($prefix))
			) {
				$user = $prefix . $user;
			}
			if (is_int($maxconn) && ($maxconn < 1)) {
				$maxconn = self::DEFAULT_CONCURRENCY_LIMIT;
			}
			if (!$password && !$maxconn) {
				return warn("no action taken for `$user'");
			}
			if ($password && strlen($password) < self::MIN_PASSWORD_LENGTH) {
				return error("pgsql password must be at least %d characters long", 3);
			}
			$pgdb = \PostgreSQL::pdo();
			$params = [
				':name' => $user,
				':password' => $password,
				':connlimit' => $maxconn
			];

			if (!$password && is_int($maxconn)) {
				$query = 'UPDATE pg_authid SET rolconnlimit = :connlimit WHERE rolname = :name';
			} else if ($password && is_int($maxconn)) {
				$query = 'UPDATE pg_authid SET rolpassword = :password, rolconnlimit = :connlimit WHERE rolname = :name';
			} else if ($password && !is_int($maxconn)) {
				$query = 'UPDATE pg_authid SET rolpassword = :password WHERE rolname = :name';
				unset($params[':connlimit']);
			}

			$stmt = $pgdb->prepare($query);

			if (!$stmt->execute($params)) {
				return error("Failed to edit user `%s': %s",
					$user,
					array_get($stmt->errorInfo(), 2, 'UNKNOWN')
				);
			}

			// @TODO v7.5
			if (platform_is('7.5')) {
				$pgdb->setAttribute(PDO::ATTR_EMULATE_PREPARES, true);
				$stmt = $pgdb->prepare('UPDATE pg_authid SET rolpassword = CONCAT(\'md5\', md5(CONCAT(:password, :name))) WHERE rolname = :name;');
				$ret = $stmt->execute(array_except($params, [':connlimit']));
				if (!$ret) {
					return error("failed to update postgresql password for user `%s'", $user);
				}

			}
			if ($user == $this->get_username()) {
				$this->set_password($password);
			}
			return true;
		}

		public function get_username()
		{
			if (!IS_CLI) {
				return $this->query('pgsql_get_username');
			}

			$user = $this->username;
			$pwd = $this->user_getpwnam($user);
			if (!$pwd) {
				return error('unknown system user `%s\'', $user);
			}
			$file = $this->domain_fs_path() . $pwd['home'] . '/.pgpass';
			if (!file_exists($file)) {
				return $this->username;
			}
			$contents = file_get_contents($file);
			if (!preg_match(Regex::SQL_PGPASS, $contents, $matches)) {
				return $user;
			}

			return $matches['username'] ?: $this->username;
		}

		/**
		 * array list_users ()
		 * Lists all created users for PostgreSQL
		 *
		 * @return array
		 */
		public function list_users()
		{
			if (!$this->enabled()) {
				return error("PostgreSQL service not enabled for account.");
			}
			$prefix = $this->get_prefix();
			$pgdb = \PostgreSQL::initialize();
			$q = $pgdb->query("SELECT rolname, rolpassword, rolconnlimit FROM pg_authid WHERE rolname = '"
				. $this->username . "' OR rolname LIKE '" . str_replace(array("-", "_"), array("", '\_'),
					$prefix) . "%' ORDER BY rolname");
			$users = array();
			while ($row = $pgdb->fetch_object()) {
				$users[$row->rolname] = array(
					'max_connections' => $row->rolconnlimit,
					'password'        => $row->rolpassword
				);
			}
			return $users;
		}

		/**
		 * string pg_vacuum_db (string)
		 * Vacuums a database
		 *
		 * @return string vacuum output
		 */
		public function vacuum($db)
		{
			$pgdb = \PostgreSQL::initialize();
			$db = $pgdb->escape_string($db);
			$prefix = $this->get_prefix();

			// db name passed without prefix
			if (0 !== strpos($db, $prefix)) {
				$db = $prefix . $db;
			}
			$q = "SELECT 1 FROM pg_database WHERE datname = $1 " .
				"AND datdba = (SELECT oid FROM pg_roles WHERE rolname = '" . $this->username . "')";
			$pgdb->query_params($q, array($db));
			if ($pgdb->num_rows() < 1) {
				return error("Database `$db' not owned by main user");
			}

			return $this->query('pgsql_vacuum_backend', $db);
		}

		public function vacuum_backend($db)
		{
			$status = Util_Process::exec("vacuumdb -zfq --dbname=" . escapeshellarg($db));
			if ($status['error'] instanceof Exception) {
				return error($status['error']);
			}
			return $status['success'];
		}

		public function truncate_database($db)
		{

			return $this->_empty_truncate_wrapper($db, "truncate");
		}

		private function _empty_truncate_wrapper($db, $mode)
		{
			if ($mode != "truncate" && $mode != "empty") {
				return error("unknown mode `%s'", $mode);
			}
			if ($mode == "empty") {
				// semantically more correct
				$mode = 'drop';
			}

			$prefix = $this->get_prefix();
			if (strncmp($db, $prefix, strlen($prefix))) {
				$db = $prefix . $db;
			}

			if (!$this->database_exists($db)) {
				return error("unknown database, `%s'", $db);
			}

			$user = $this->_create_temp_user($db);
			if (!$user) {
				return error("failed to %s db `%s'", $mode, $db);
			}
			$dsn = 'host=localhost dbname=' . $db . ' user=' . $user . ' password=' . self::PG_TEMP_PASSWORD;
			$sqldb = pg_connect($dsn);
			if (!$sqldb) {
				$this->_delete_temp_user($user);
				return error("failed to %s db `%s', db connection failed", $mode, $db);
			}
			// via psql -E, unlikely to
			$q = "SELECT n.nspname as \"schema\", " .
				"c.relname as \"name\", " .
				"r.rolname as \"owner\"" .
				"FROM pg_catalog.pg_class c " .
				"JOIN pg_catalog.pg_roles r ON r.oid = c.relowner " .
				"LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace " .
				"WHERE c.relkind IN ('r','') " .
				"AND n.nspname <> 'pg_catalog' " .
				"AND n.nspname !~ '^pg_toast' " .
				"AND pg_catalog.pg_table_is_visible(c.oid) " .
				"ORDER BY 1,2;";
			$rs = pg_query($sqldb, $q);
			$pgver = $this->version();
			// available in 8.4
			$identity = $mode !== "empty" && $pgver >= 80400 ? "RESTART IDENTITIY" : "";
			while (false !== ($res = pg_fetch_object($rs))) {
				if (function_exists('pg_escape_identifier')) {
					$tablesafe = pg_escape_identifier($res->name);
				} else {
					$tablesafe = '"' . pg_escape_string($res->name) . '"';
				}
				$q = strtoupper($mode) . " TABLE " . $tablesafe . " " . $identity . " CASCADE";
				if (!($res = pg_query($sqldb, $q))) {
					warn("failed to %s table `%s': %s", $mode, $res->name, pg_errormessage($sqldb));
				}
			}
			$this->_delete_temp_user($user);
			return true;
		}


		/***************** STATISTICS *******************/

		private function _create_temp_user($db)
		{

			$prefix = $this->get_prefix();
			$maxlen = \Mysql_Module::MYSQL_USER_FIELD_SIZE - strlen($prefix);
			if ($maxlen < 1) {
				return error("temp pgsql user exceeds field length");
			}
			$chars = array(
				'a',
				'b',
				'c',
				'd',
				'e',
				'f',
				'0',
				'1',
				'2',
				'3',
				'4',
				'5',
				'6',
				'7',
				'8',
				'9'
			);
			$maxlen = min(6, $maxlen);

			$user = $prefix;
			for ($i = 0; $i < $maxlen; $i++) {
				$n = mt_rand(0, 15);
				$user .= $chars[$n];
			}

			if ($this->user_exists($user)) {
				return error("cannot create temp pgsql user");
			}

			if (!$this->add_user($user, self::PG_TEMP_PASSWORD, 1)) {
				return error("unable to create role on pgsql database %s", $db);
			}

			$sqldb = \PostgreSQL::initialize();
			$q = "SELECT 'GRANT SELECT ON ' || relname || ' TO \"$user\";'
				FROM pg_class JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace
				WHERE nspname = 'public' AND relkind IN ('r', 'v');";
			$rs = $sqldb->query($q);
			if (!$rs->fetch_object()) {
				return error("cannot create temp pgsql user `%s'", $user);
			}
			$sqldb->query("GRANT \"" . $this->username . "\" TO \"" . $user . "\"");
			$this->_register_temp_user($user);
			return $user;

		}

		public function version($pretty = false)
		{
			$version = \Opcenter\Database\PostgreSQL::version();
			if (!$pretty) {
				return $version;
			}
			$pgver = array();
			foreach (array('patch', 'minor', 'major') as $v) {
				$pgver[$v] = $version % 100;
				$version /= 100;
			}
			return $pgver['major'] . '.' . $pgver['minor'] . '.' .
				$pgver['patch'];
		}

		public function empty_database($db)
		{
			return $this->_empty_truncate_wrapper($db, "empty");
		}

		/**
		 * bool pgsql_import(string, string, string, strin)
		 */
		public function import($db, $file)
		{
			if (!IS_CLI) {
				return $this->query('pgsql_import', $db, $file);
			}

			$prefix = $this->get_prefix();
			// db name passed without prefix
			if (strncmp($db, $prefix, strlen($prefix))) {
				$db = $prefix . $db;
			}

			$dbs = $this->list_databases();
			if (false === array_search($db, $dbs, true)) {
				return error("database `%s' does not exist", $db);
			}
			$unlink = null;
			if (false === ($realfile = $this->_preImport($file, $unlink))) {
				return false;
			}
			$user = $this->_create_temp_user($db);
			if (!$user) {
				return error("import failed - cannot create temp user");
			}
			$proc = new Util_Process_Safe();
			$proc->setEnvironment("PGPASSWORD", self::PG_TEMP_PASSWORD);
			$cmd = "psql -q -h 127.0.0.1 -f %(file)s -U %(user)s %(db)s";
			$args = array(
				'password' => self::PG_TEMP_PASSWORD,
				'file'     => $realfile,
				'user'     => $user,
				'db'       => $db
			);
			$status = $proc->run($cmd, $args);
			$this->_delete_temp_user($user);
			$this->_postImport($unlink);

			if (!$status['success']) {
				return error("import failed: %s", $status['error']);
			}
			return $status['success'];
		}

		/**
		 * Get disk space occupied by database
		 *
		 * @param string $db   database name
		 * @return int storage in bytes
		 */
		public function get_database_size($db)
		{
			$size = \PostgreSQL::initialize()->query("SELECT pg_database_size(" . pg_escape_literal($db) . ") as size")->fetch_object();
			return (int)$size->size;
		}
		// }}}

		public function export($db, $file = null)
		{
			if (!IS_CLI) {
				return $this->query('pgsql_export', $db, $file);
			}
			if (is_null($file)) {
				$file = $db . '.sql';
			}

			if ($file[0] !== '/' && $file[0] !== '.' && $file[0] !== '~') {
				$path = $this->domain_fs_path() . '/tmp/' . $file;
			} else {
				$path = $this->file_make_path($file);
			}
			if (!$path) {
				return error("invalid file `%s'", $file);
			}

			$pdir = dirname($file);
			if (!$this->file_exists($pdir) && !$this->file_create_directory($pdir, 0755, true)) {
				return error("failed to create parent directory, `%s'", $pdir);
			}

			if (!in_array($db, $this->list_databases())) {
				return error("invalid database `%s'", $db);
			}

			$user = $this->_create_temp_user($db);
			if (!$user) {
				return error("pgsql export failed - unable to create user");
			}

			$fsizelimit = Util_Ulimit::get('fsize');
			if ($this->get_database_size('pgsql', $db) > $fsizelimit / self::DB_BIN2TXT_MULT) {
				// make sure ulimit accommodates the db dump
				Util_Ulimit::set('fsize', 'unlimited');
			} else {
				$fsizelimit = null;
			}
			$status = Util_Process_Safe::exec("env PGPASSWORD=%s pg_dump -h 127.0.0.1 -U %s -x --file=%s %s",
				self::PG_TEMP_PASSWORD,
				$user,
				$path,
				$db);
			if ($user != self::MASTER_USER) {
				$this->_delete_temp_user($user);
			}
			if (!is_null($fsizelimit)) {
				Util_Ulimit::set('fsize', $fsizelimit);
			}
			if (!file_exists($path)) {
				return error("export failed: %s", $status['stderr']);
			}
			chown($path, $this->user_id) && chgrp($path, $this->group_id) && chmod($path, 0600);
			if (!$status['success']) {
				return error("export failed: %s", $status['stderr']);
			}
			return $this->file_unmake_path($path);
		}

		/**
		 * Export a PGSQL db to a named pipe for immediate download
		 *
		 * @param $db
		 * @return bool|void
		 */
		public function export_pipe($db)
		{
			if (version_compare(platform_version(), '4.5', '<=')) {
				return error('platform version too old to support download feature');
			}

			if (!in_array($db, $this->list_databases())) {
				return error("Invalid database " . $db);
			}

			$user = $this->_create_temp_user($db);

			return $this->query('pgsql_export_pipe_real', $db, $user);
		}

		/**
		 * Export a PGSQL database to a named pipe
		 *
		 * Differs from export_pipe in that it may only be called internally
		 * or from backend, no API access
		 *
		 * @param $db
		 * @param $user if empty use superuser
		 * @return bool|string|void
		 */
		public function export_pipe_real($db, $user)
		{
			if (!IS_CLI) {
				return $this->query('pgsql_export_pipe_real', $db, $user);
			}
			// automatically cleaned up on exit()/destruct

			$cmd = "/usr/bin/pg_dump -h 127.0.0.1 -U %s -x --file=%s %s";

			// @XXX potential race condition
			$fifo = tempnam('/tmp', 'id-' . $this->site);
			unlink($fifo);
			if (!posix_mkfifo($fifo, 0600)) {
				return error("failed to ready pipe for export");
			}
			chown($fifo, File_Module::UPLOAD_UID);
			$proc = new Util_Process_Fork();

			// lowest priority
			$proc->setPriority(19);
			$proc->setEnvironment('PGPASSWORD', self::PG_TEMP_PASSWORD);
			$status = $proc->run($cmd,
				$user,
				$fifo,
				$db
			);

			if (!$status['success'] || !file_exists($fifo)) {
				return error("export failed: %s", $status['stderr']);
			}
			register_shutdown_function(function () use ($fifo) {
				if (file_exists($fifo)) {
					unlink($fifo);
				}

			});

			return $fifo;
		}

		/**
		 * int get_uptime
		 *
		 * @return int time in seconds
		 */
		public function get_uptime()
		{
			$q = $this->psql->query("SELECT pg_postmaster_start_time() as st")->fetch_object();
			return $q->st;
		}


		public function add_backup($db, $extension = "zip", $span = 5, $preserve = '0', $email = '')
		{
			return parent::add_backup_real('pgsql', $db, $extension, $span, $preserve, $email);
		}

		public function edit_backup($db, $extension, $span = '0', $preserve = '0', $email = '')
		{
			return parent::edit_backup_real('pgsql', $db, $extension, $span, $preserve, $email);
		}

		public function list_backups()
		{
			return parent::list_backups_real('pgsql');
		}

		/**
		 * Fetch MySQL backup task information
		 *
		 * span   => (integer) days between backups
		 * hold   => (integer) number of backups to preserve
		 * next   => (integer) unix timestamp of next backup
		 * ext    => (string)  extension of backup
		 * email  => (string)  notify address after backup
		 *
		 * @param string $db database name
		 * @return array
		 */
		public function get_backup_config($db)
		{
			return parent::get_backup_config_real('pgsql', $db);
		}

		public function _delete()
		{
			$conf = $this->getAuthContext()->getAccount()->new;
			if ($this->enabled() && !parent::uninstallDatabaseService('pgsql')) {
				warn("failed to delete pgsql service from `%s'", $conf['siteinfo']['domain']);
			}
		}

		public function _create()
		{
			if (version_compare(platform_version(), '7.5', '>=')) {
				return true;
			}
			$conf = $this->getAuthContext()->getAccount()->new;

			if (!$conf['pgsql']['enabled']) {
				return;
			}
			$this->installDatabaseService('pgsql');
		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			if ($userold === $usernew) {
				return;
			}
		}

		public function _edit()
		{
			if (platform_is('7.5')) {
				return true;
			}

			$conf = $this->getAuthContext()->getAccount();

			if ($conf->new['pgsql']['enabled'] && !$conf->old['pgsql']['enabled']) {
				parent::installDatabaseService('pgsql');
			}
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}

		public function _create_user(string $user)
		{
			// TODO: Implement _create_user() method.
		}

		public function _delete_user(string $user)
		{
			// TODO: Implement _delete_user() method.
		}

	}
