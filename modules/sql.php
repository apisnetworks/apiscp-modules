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
	 * MySQL and PostgreSQL operations
	 *
	 * @package core
	 */
	class Sql_Module extends Module_Skeleton
	{
		private static $mysql_admin_pass;

		// maximum length of users - mysql compile-time constant
		const MYSQL_USER_FIELD_SIZE = 16;
		const PG_TEMP_PASSWORD = '23f!eoj3';
		const MYSQL_PATH = '/var/lib/mysql';
		const MIN_PASSWORD_LENGTH = 3;
		/* @ignore */
		const MASTER_USER = 'root';
		/**
		 * a bullshit constant to decide whether to
		 * up the ulimit fsize or not before exporting a db
		 */
		const DB_BIN2TXT_MULT = 1.5;

		private $_tempUsers = array('mysql' => array(), 'pgsql' => array());
		private $_permittedPgsqlExtensions = array('pg_trgm', 'hstore');

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
				'pgsql_version'                 => PRIVILEGE_ALL,
				'mysql_version'                 => PRIVILEGE_ALL,
				'version'                       => PRIVILEGE_ALL,
				'get_elevated_password_backend' => PRIVILEGE_ALL | PRIVILEGE_SERVER_EXEC,
				'create_mysql_database_backend' => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,

				'delete_mysql_database_backend' => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'get_mysql_uptime'              => PRIVILEGE_ALL,
				'assert_mysql_permissions'      => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,

				'prep_tablespace_backend' => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'pg_vacuum_db_backend'    => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'get_pgsql_uptime'        => PRIVILEGE_ALL,
				'set_mysql_option'        => PRIVILEGE_ALL,
				'get_mysql_option'        => PRIVILEGE_ALL,
				'get_pgsql_username'      => PRIVILEGE_ALL,
				'get_pgsql_password'      => PRIVILEGE_ALL,
				'set_pgsql_password'      => PRIVILEGE_ALL,
				'export_mysql_pipe_real'  => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'export_pgsql_pipe_real'  => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'enabled'                 => PRIVILEGE_SITE | PRIVILEGE_USER,
				'repair_mysql_database'   => PRIVILEGE_SITE | PRIVILEGE_ADMIN,

				// necessary for DB backup routines
				'get_database_size'       => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'mysql_database_exists'   => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'pgsql_database_exists'   => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'_export_mysql_old'       => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
			);
		}

		public function __destruct()
		{
			foreach ($this->_tempUsers['mysql'] as $user) {
				if (!$this->mysql_user_exists($user)) {
					continue;
				}
				$this->_delete_temp_mysql_user($user);
			}
			foreach ($this->_tempUsers['pgsql'] as $user) {
				if (!$this->pgsql_user_exists($user)) {
					continue;
				}
				$this->_delete_temp_pgsql_user($user);
			}
		}

		/**
		 * bool store_sql_password (string, string)
		 *
		 * @param string $sqlpasswd base64 encoded and encrypted password @{see encrypt_sql_password}
		 * @param string $type      password type, where type is either "mysql" or "pgsql"
		 */
		public function store_sql_password($sqlpasswd, $type)
		{
			if ($type != "mysql" && $type != "postgresql" && $type != "pgsql")
				return error($type . ": unrecognized type");
			if ($type == "mysql") {
				deprecated("use set_mysql_option");
				$this->set_mysql_option("password", $sqlpasswd, 'client');
				return true;
			} else if ($type == "pgsql") {
				deprecated("use set_pgsql_password()");
				$this->set_pgsql_password($sqlpasswd);
				return true;
			}
		}

		public function set_pgsql_password($password)
		{
			if (!IS_CLI) {
				return $this->query('sql_set_pgsql_password', $password);
			}

			return $this->_set_pg_param('password', $password);

		}

		public function set_pgsql_username($user)
		{
			if (!IS_CLI) {
				return $this->query('sql_set_pgsql_username', $user);
			}
			return $this->_set_pg_param('username', $user);

		}

		private function _set_pg_param($param, $val)
		{
			$pwd = $this->user_getpwnam();
			$file = $this->domain_fs_path() . $pwd['home'] . '/.pgpass';

			if (!file_exists($file)) {
				touch($file);
				chown($file, $this->user_id);
				chgrp($file, $this->group_id);
				chmod($file, 0600);
			}
			$pgpass = file_get_contents($file);
			$struct = array(
				'hostname' => '*',
				'port'     => '*',
				'database' => '*',
				'username' => $this->username,
				'password' => null
			);
			/**
			 * @link http://wiki.postgresql.org/wiki/Pgpass
			 */
			if (preg_match(Regex::SQL_PGPASS, $pgpass, $matches)) {
				$struct = array_merge($struct, $matches);
			} else {
				// old format, single token (password)
				$struct['password'] = $pgpass;
			}
			$struct[$param] = $val;
			return file_put_contents($file,
				$struct['hostname'] . ":" .
				$struct['port'] . ":" .
				$struct['database'] . ":" .
				$struct['username'] . ":" .
				$struct['password']
			);
		}


		public function get_pgsql_password($user = null)
		{
			if (!IS_CLI) {
				return $this->query('sql_get_pgsql_password', $user);
			}
			if (!$user) {
				$user = $this->username;
			}
			$pwd = $this->user_getpwnam($user);
			if (!$pwd) return error('unknown system user `%s\'', $user);
			$file = $this->domain_fs_path() . $pwd['home'] . '/.pgpass';
			if (!file_exists($file)) return false;
			$contents = explode(':', file_get_contents($file));
			return isset($contents[4]) ? $contents[4] : false;
		}

		public function get_pgsql_username()
		{
			if (!IS_CLI) {
				return $this->query('sql_get_pgsql_username');
			}

			$user = $this->username;
			$pwd = $this->user_getpwnam($user);
			if (!$pwd) return error('unknown system user `%s\'', $user);
			$file = $this->domain_fs_path() . $pwd['home'] . '/.pgpass';
			if (!file_exists($file)) return $this->username;
			$contents = file_get_contents($file);
			if (!preg_match(Regex::SQL_PGPASS, $contents, $matches)) {
				return $user;
			}

			return $matches['username'];
		}

		/**
		 * string retrieve_sql_password (string)
		 *
		 * @param string $type SQL type, either "pgsql" or "mysql"
		 * @return string base64-encoded and encrypted password on record
		 */
		public function retrieve_sql_password($type)
		{
			if ($type != "mysql" && $type != "postgresql" && $type != "pgsql")
				return error("Invalid database backend `$type'");
			if ($type == 'mysql') return $this->get_mysql_option('password');
			// deprecated
			else if ($type == 'pgsql') {
				$pass = $this->_getPGPass();
				if ($pass) return $pass;
			}

			// deprecated
			$q = $this->mysql->query("SELECT
				`value`
				FROM
				`stored_passwords`
				WHERE
				`type` = '" . $type . "'
				AND
				`username` = '" . $this->username . "'
				AND
				`domain` = '" . $this->domain . "'");
			if ($q->num_rows < 1) return null;
			$passwd = $q->fetch_object();
			$passwd = rtrim($passwd->value);
			if ($type == 'mysql') {
				$this->set_mysql_option('password', $passwd);
			} else if ($type == 'pgsql') {
				$this->set_pgsql_password($passwd);
			}

			return $passwd;
		}

		private function _get_elevated_password()
		{
			if (!isset(self::$mysql_admin_pass))
				self::$mysql_admin_pass = $this->query('sql_get_elevated_password_backend');
			return self::$mysql_admin_pass;
		}

		// {{{ connect_mysql_root()

		/**
		 * Establish privileged connection to MySQL server
		 *
		 * @return object
		 */
		private function _connect_root()
		{
			$conn = new mysqli('localhost', self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			return $conn;
		}

		// }}}

		public function get_elevated_password_backend()
		{
			// there may be situations that Ensim fails to retrieve
			// the password due to sloppy in-place edits (oops)
			// and there should *always* be a password set for root
			if (self::$mysql_admin_pass)
				return self::$mysql_admin_pass;
			$cmd = '';
			if (platform_version() < 4.5) {
				$cmd .= "cd /usr/lib/opcenter/mysql;";
			}
			$cmd .= "ensim-python -c 'from mysqlbe import *; print read_mysqlpass();'";

			$proc = Util_Process::exec($cmd);
			$pw = trim($proc['output']);
			self::$mysql_admin_pass = $pw;
			return $pw;
		}

		/**
		 * array list_mysql_databases ()
		 * Queries the db table in the mysql database for applicable grants
		 *
		 * @return array list of databases
		 */
		public function list_mysql_databases()
		{
			$prefix = $this->_escape($this->get_prefix());
			$conn = new mysqli("localhost", self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			$q = $conn->query("SELECT DISTINCT(REPLACE(db,'\\_','_')) as db from db WHERE db LIKE '" . $prefix . "%' OR user = '" . $this->username . "'");
			$dbs = array();
			while (false != ($row = $q->fetch_object()))
				$dbs[] = $row->db;

			$conn->close();
			return $dbs;
		}

		/**
		 * bool mysql_import(string, string, string, strin)
		 */
		public function import_mysql($db, $file)
		{
			if (!IS_CLI) {
				return $this->query('sql_import_mysql', $db, $file);
			}

			$prefix = $this->get_prefix();
			// db name passed without prefix
			if (strncmp($db, $prefix, strlen($prefix))) {
				$db = $prefix . $db;
			}

			$dbs = $this->list_mysql_databases();
			if (false === array_search($db, $dbs)) {
				return error("database `%s' does not exist", $db);
			}
			$unlink = null;
			if (false === ($realfile = $this->_preImport($file, $unlink))) {
				return false;
			}

			$fp = fopen($realfile, 'r+');
			while (false !== ($line = fgets($fp))) {
				for ($i = 0, $n = strlen($line); $i < $n; $i++) {
					$c = $line[$i];
					if ($c == ' ' || $c == '') continue;
					else if ($c == '/' || $c == '-') break;
					if (!strncmp($line, "CREATE DATABASE", strlen("CREATE DATABASE")) ||
						!strncmp($line, "USE DATABASE", strlen("USE DATABASE"))
					) {
						$pos = ftell($fp) - strlen($line);
						fseek($fp, $pos);
						warn("`%s' statement redacted", trim($line));
						fwrite($fp, '-- ');
						fgets($fp);
					}
					break;
				}
			}
			$user = $this->_create_temp_mysql_user($db);
			if (!$user) {
				$this->_postImport($unlink);
				return error("unable to import database");
			}
			$status = Util_Process_Safe::exec("mysql -u %s %s < %s",
				$user, $db, $realfile
			);
			$this->_delete_temp_user('mysql', $user);
			$this->_postImport($unlink);

			return $status['success'];
		}

		private function _preImport($file, &$unlink) {
			$realfile = $this->file_make_path($file);
			if (!file_exists($realfile)) {
				return error("file `%s' does not exist", $file);
			}

			if (!$this->file_is_compressed($file)) {
				return $realfile;
			}
			$fname = tempnam($this->domain_fs_path() . '/tmp', 'db');
			unlink($fname);
			$ret = $this->file_extract($file, $this->file_unmake_path($fname), true);
			if (!$ret) {
				return error("failed to extract archive `%s'", $file);
			}
			$files = glob($fname . '/*');
			if (!$files) {
				return error("empty archive");
			}
			$unlink = $this->file_unmake_path($fname);
			$tmp = array_pop($files);
			return $tmp;

		}

		private function _postImport($file) {
			if (!is_null($file)) {
				return $this->file_delete($file, true);
			}
			return true;
		}

		public function get_prefix()
		{
			return $this->get_service_value('mysql', 'dbaseprefix');
		}

		public function get_sql_prefix()
		{
			deprecated("use sql_get_prefix");
			return $this->get_prefix();
		}

		private function _escape($str)
		{
			return str_replace('_', '\_', $str);
		}

		public function get_supported_mysql_charsets()
		{
			$cache = Cache_Global::spawn();
			$key = 's:mysql.char';
			$charsets = $cache->get($key);
			if ($charsets) {
				return $charsets;
			}
			$db = MySQL::initialize();
			$rs = $db->query("SELECT CHARACTER_SET_NAME AS charset, DESCRIPTION AS `desc` FROM INFORMATION_SCHEMA.character_sets");
			$charsets = array();
			while (null !== ($row = $rs->fetch_object())) {
				$charsets[$row->charset] = $row->desc;
			}
			$cache->set($key, $charsets);
			return $charsets;
		}

		public function mysql_charset_valid($charset)
		{
			$charset = strtolower($charset);
			$charsets = $this->get_supported_mysql_charsets();
			return array_key_exists($charset, $charsets);
		}

		public function get_supported_mysql_collations()
		{
			$cache = Cache_Global::spawn();
			$key = 's:mysql.coll';
			$collations = $cache->get($key);
			if ($collations) {
				return $collations;
			}
			$collations = array();
			$db = MySQL::initialize();
			$q = "SELECT collation_name, character_set_name FROM " .
				"INFORMATION_SCHEMA.collations WHERE is_compiled = 'Yes'";
			$rs = $db->query($q);
			if (!$rs) {
				return $collations;
			}
			while (false != ($row = $rs->fetch_object())) {
				$collations[] = array(
					'collation' => $row->collation_name,
					'charset'   => $row->character_set_name
				);
			}
			$cache->set($key, $collations);
			return $collations;
		}

		/**
		 * Verify collation + charset combination are compatible
		 *
		 * @param string $collation
		 * @param string $charset
		 *
		 * @return bool
		 */
		public function mysql_collation_compatible($collation, $charset)
		{
			$db = MySQL::initialize();
			$q = "SELECT 1 FROM INFORMATION_SCHEMA.COLLATION_CHARACTER_SET_APPLICABILITY " .
				"WHERE collation_name = '" . $db->escape($collation) . "' AND " .
				"character_set_name = '" . $db->escape($charset) . "'";
			$rs = $db->query($q);
			if (!$rs) {
				return false;
			}
			return $rs->num_rows > 0;
		}

		/**
		 * Validate collation name
		 *
		 * @param string $collation
		 * @return bool
		 */
		public function mysql_collation_valid($collation)
		{
			$collations = $this->get_supported_mysql_collations();
			$collation = strtolower($collation);
			foreach ($collations as $c) {
				if ($c['collation'] == $collation) {
					return true;
				}
			}
			return false;
		}

		/**
		 * array list_mysql_users ()
		 * Lists all created users for MySQL
		 */
		public function list_mysql_users()
		{
			$prefix = str_replace('_', '\_', $this->get_service_value('mysql', 'dbaseprefix'));
			$conn = new mysqli("localhost", self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			$q = $conn->query("SELECT host,
									 user,
									 password,
									 ssl_type,
									 ssl_cipher,
									 x509_issuer,
									 x509_subject,
									 max_questions,
									 max_updates,
									 max_connections,
									 max_user_connections FROM user WHERE user = '" . $this->username . "' OR user LIKE '" . $prefix . "%'");
			$users = array();
			while (false != ($row = $q->fetch_object())) {
				$users[$row->user][$row->host] = array(
					'ssl_type'             => $row->ssl_type,
					'ssl_cipher'           => $row->ssl_cipher,
					'x509_issuer'          => $row->x509_issuer,
					'x509_subject'         => $row->x509_subject,
					'max_questions'        => $row->max_questions,
					'max_updates'          => $row->max_updates,
					'max_user_connections' => $row->max_user_connections,
					'max_connections'      => $row->max_connections,
					'password'             => $row->password,
				);
			}
			return $users;
		}

		/**
		 * bool
		 */

		/**
		 * Get disk space occupied by database
		 *
		 * @param string $type database type, "mysql" or "pgsql"
		 * @param string $db   database name
		 * @return int storage in bytes
		 */
		public function get_database_size($type, $db)
		{
			$type = strtolower($type);
			if ($type != "mysql" && $type != "postgresql" && $type != "pgsql")
				return error($type . ": invalid database type");

			if ($type == "pgsql" || $type == "postgresql") {
				$size = $this->pgsql->query("SELECT pg_database_size('" . $db . "') as size")->fetch_object();
				return $size->size;
			} else if (!IS_CLI) {
				return $this->query('sql_get_database_size', $type, $db);
			}

			// mysql type
			$dir = self::MYSQL_PATH . '/' . $this->_canonicalize_mysql_database($db);
			// database created as directory in /var/lib/mysql
			// instead of under fst
			if (($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) && !is_link($dir)) {
				$this->_move_mysql_db($db);
			}
			if (!file_exists($dir) || (is_link($dir) && !readlink($dir))) {
				return warn($db . ": database does not exist");
			}

			$space = 0;
			$dh = opendir($dir);
			while (($file = readdir($dh)) !== false) {
				if ($file == "." || $file == "..")
					continue;
				$space += filesize($dir . '/' . $file);
			}
			closedir($dh);
			return $space;
		}

		private function _move_mysql_db($db)
		{

			/**
			 * make sure the DB is accessed by the correct user
			 * otherwise the DB will be relocated under the caller's fs
			 */
			$prefix = $this->get_service_value('mysql', 'dbaseadmin');
			if (strncmp($db, $prefix, strlen($prefix))) {
				return true;
			}
			$src = self::MYSQL_PATH . '/' . $db;
			$dest = $this->domain_fs_path() . self::MYSQL_PATH . '/' . $db;
			if (is_dir($dest)) {
				report("dest db exists - %s", $dest);
				return false;
			}
			mkdir($dest);

			chown($dest, 'mysql');
			chgrp($dest, $this->group_id);
			chmod($dest, 02750);
			/* a read lock should be used in this situation to ensure
			 * absolutely no data is lost in the process
			 * only a global flush tables would work, but this can
			 * cause a 15+ second hang while tables are flushed
			 * as a consequence, forgo the read lock and just move the files
			 *
			 * this process is also quicker than an export/import routine
			 */

			$dh = opendir($src);
			if (!$dh) return error("could not relocate database `%s'", $db);

			while (false !== ($file = readdir($dh))) {
				if ($file == '.' || $file == '..') {
					continue;
				}
				rename($src . '/' . $file, $dest . '/' . $file);
				chown($dest . '/' . $file, 'mysql');
				chgrp($dest . '/' . $file, $this->group_id);
			}

			rmdir($src);
			symlink($dest, $src);
			warn("database `%s' relocated under account filesystem root", $db);
			$db = $this->_connect_root();
			$db->query("FLUSH TABLES");
			return true;
		}

		/**
		 * bool add_mysql_user(string, string, string[, int[, int[, int[, string[, string[, string[, string]]]]]]])
		 */
		public function add_mysql_user($user, $host, $password, $maxconn = 5, $maxupdates = 0, $maxquery = 0, $ssl = '', $cipher = '', $issuer = '', $subject = '')
		{
			if (!$user) {
				return error("no username specified");
			}
			$dbaseadmin = $this->get_config('mysql', 'dbaseadmin');
			/*if ($user === $dbaseadmin) {
				return error("cannot name user after primary account user, `%s'", $dbaseadmin);
			}*/

			$ssl = strtoupper($ssl);
			if ($maxconn == 0)
				$maxconn = 5;
			$host = trim($host);
			if ($host != 'localhost') {
				if (!ip2long($host) && !preg_match(Regex::SQL_MYSQL_IP_WILDCARD, $host)) {
					return error("rejected host `%s': only numeric IP addresses are permitted, not hostnames", $host);
				}
			}
			if (strlen($password) < self::MIN_PASSWORD_LENGTH)
				return error("Password must be at least %d characters", self::MIN_PASSWORD_LENGTH);
			else if ($ssl != '' && $ssl != 'ANY' && $ssl != 'X509' && $ssl != 'SPECIFIED')
				return error("Invalid SSL type");
			else if ($maxconn < 1 || $maxquery < 0 || $maxupdates < 0)
				return error("Max connections, queries, and updates must be greater than 0");
			else if ($maxconn > 10)
				return error("Max concurrent connections cannot exceed 10.  Please file a ticket with explanation if you need more than 10.");
			else if ($this->mysql_user_exists($user, $host))
				return error("mysql user `$user' on `$host' exists");
			$conn = $this->_connect_root();
			$prefix = $this->get_prefix();
			if ($user != $this->get_config('mysql', 'dbaseadmin') && strncmp($user, $prefix, strlen($prefix))) {
				// add the prefix if prefix is not provided, this is to workaround cases where user
				// is equal to prefixprefixuser
				$user = $prefix . $user;
			}
			$pwclause = 'password(?)';
			// password is encrypted in new pw form or old
			if ($password[0] == '*' && strlen($password) == 41
				&& ctype_xdigit(substr($password, 1)) ||
				strlen($password) == 16 && ctype_xdigit($password)
			) {
				$pwclause = '?';
			}
			$stmt = $conn->prepare("INSERT INTO user
				(host,
				 user,
				 password,
				 ssl_type,
				 ssl_cipher,
				 x509_issuer,
				 x509_subject,
				 max_questions,
				 max_updates,
				 max_user_connections)
			VALUES
				(?,
				 ?,
				 " . $pwclause . ",
				 ?,
				 ?,
				 ?,
				 ?,
				 ?,
				 ?,
				 ?);");

			$ssl = $cipher = $issuer = $subject = "";
			$maxquery = $maxupdates = $maxconn = 0;
			$stmt->bind_param("sssssssiii", $host, $user, $password, $ssl, $cipher,
				$issuer, $subject, $maxquery, $maxupdates, $maxconn);
			$stmt->execute();
			if (!$stmt->error)
				$conn->query("FLUSH PRIVILEGES;");
			else
				return new MySQLError("Invalid query, " . $stmt->error);

			if ($stmt->affected_rows < 1)
				return error("user creation `%s@%s' failed", $user, $host);
			return true;
		}

		public function get_mysql_database_charset($db)
		{
			if (!preg_match('/^[a-zA-Z_0-9-]+$/', $db)) {
				return error("invalid database name `%s'", $db);
			}

			$prefix = $this->get_prefix();
		}

		/**
		 * Create a new mysql database
		 *
		 * @param  string $db
		 * @param  string $charset   optional default charset
		 * @param  string $collation optional default collation
		 * @return bool  creation succeeded
		 */

		public function create_mysql_database($db, $charset = 'latin1', $collation = 'latin1_general_ci')
		{
			$charset = strtolower($charset);
			$collation = strtolower($collation);

			if (!preg_match('/^[a-zA-Z_0-9-]+$/', $db))
				return error("invalid database name `%s'", $db);
			if (!$this->mysql_charset_valid($charset)) {
				return error("unrecognized mysql charset `%s'", $charset);
			}
			if (!$this->mysql_collation_valid($collation)) {
				return error("invalid mysql collation `%s'", $collation);
			} else if (!$this->mysql_collation_compatible($collation, $charset)) {
				warn("collation `%s' for charset `%s' not sensible", $collation, $charset);
			}

			$prefix = $this->get_prefix();

			// db name passed without prefix
			if (strncmp($db, $prefix, strlen($prefix)))
				$db = $prefix . $db;

			if ($this->mysql_database_exists($db)) {
				return error("database `$db' exists");
			}
			$status = $this->query('sql_create_mysql_database_backend', $db, $charset, $collation);
			if (!$status)
				return $status;

			$conn = new mysqli('localhost', self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			$conn->query("GRANT ALL ON `" . $db . "`.* to " . $this->username . "@localhost;");
			if ($conn->error)
				return error("error while applying grants: `%s'", $conn->error);
			return info("created database `%s'", $db);

		}

		/**
		 * bool create_mysql_database_backend (string)
		 * {@link create_mysql_database}
		 */
		public function create_mysql_database_backend($db, $charset, $collation)
		{
			$dboptData = "default-character-set=" . $charset . "\n" .
				"default-collation=" . $collation;
			$path = $this->domain_fs_path();
			if (version_compare(platform_version(), '4.5', '>=') && version_compare(platform_version(), '6.5', '<')) {
				$path = $this->domain_shadow_path();
			}
			$dbcan = $this->_canonicalize_mysql_database($db);

			if (file_exists(self::MYSQL_PATH . '/' . $dbcan))
				return error("database `%s' exists", $db);
			if (!file_exists($path . self::MYSQL_PATH))
				return error("base directory for MySQL doesn't exist");
			$path .= self::MYSQL_PATH . '/' . $dbcan;

			if (!file_exists($path)) mkdir($path);
			chown($path, 'mysql');
			chown($path, 'mysql');
			chgrp($path, (int)$this->group_id);
			symlink($path, self::MYSQL_PATH . '/' . $dbcan);
			chmod($path, 02750);

			$fp = fopen($path . '/db.opt', 'w');
			fwrite($fp, $dboptData);
			fclose($fp);
			chown($path . '/db.opt', 'mysql');
			chgrp($path . '/db.opt', (int)$this->group_id);
			return file_exists(self::MYSQL_PATH . '/' . $dbcan) && file_exists($path);
		}

		/**
		 * Set grants for a MySQL user
		 *
		 * @param string $user
		 * @param string $host
		 * @param string $db
		 * @param array  $privileges
		 * @return bool
		 */
		public function set_mysql_privileges($user, $host, $db, array $privileges)
		{
			if (!$host)
				return error("invalid host name `$host'");

			$privileges = array_change_key_case($privileges);
			$prefix = $this->get_prefix();
			if ($user != $this->get_service_value('mysql', 'dbaseadmin') &&
				strncmp($user, $prefix, strlen($prefix))
			) {
				$user = $prefix . $user;
			}
			if ($user != $this->username && !preg_match('/^' . $prefix . '/', $user))
				return error("invalid user `%s'", $user);
			$conn = new mysqli('localhost', self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			/** ignore prefixed dbs as they should have ownership rights */
			if (!preg_match('!/^' . $prefix . '!', $db)) {
				$rs = $conn->query("SELECT 1 FROM db WHERE user = '" . $this->username . "' AND db = '" . $db . "'");
				if ($rs->num_rows < 1)
					return error("No grants found in database on `%s' for user `%s'", $db, $user);
			}

			$valid_opts = array(
				'select'         => false, 'insert' => false, 'update' => false,
				'delete'         => false, 'create' => false, 'drop' => false,
				'grant'          => false, 'references' => false, 'index' => false,
				'alter'          => false, 'create_tmp_table' => false,
				'show_view'      => false, 'create_view' => false,
				'create_routine' => false, 'alter_routine' => false,
				'lock_tables'    => false, 'execute' => false,
			);

			// MySQL 5.1 supports triggers, available on platform 4.5+
			if (version_compare(PLATFORM_VERSION, 4.5, '>=')) {
				$valid_opts['event'] = false;
				$valid_opts['trigger'] = false;
			}

			if (count($privileges) <= 2 && isset($privileges['read']) || isset($privileges['write'])) {
				// simplified mode
				$tmp = array();
				if ($privileges['read']) {
					$tmp['select'] = $tmp['show_view'] = $tmp['execute'] = true;
				}

				if ($privileges['write']) {
					$write = array_diff(array_keys($valid_opts), array('select', 'show_view', 'execute'));
					$tmp2 = array_fill_keys($write, true);
					$tmp = array_merge($tmp, $tmp2);
				}
				$privileges = $tmp;
			}

			$opts_copy = $valid_opts;
			foreach ($valid_opts as $opt => $enabled) {
				if (isset($privileges[($opt)]) && $privileges[$opt])
					$valid_opts[$opt] = $opt . '_priv';
				else
					unset($valid_opts[$opt]);
			}

			$revoke_opts = array_diff_key($opts_copy, $valid_opts);
			foreach (array_keys($opts_copy) as $name) {
				$opts[] = (isset($valid_opts[$name])) ? 'Y' : 'N';
			}
			array_walk($opts_copy, create_function('&$key, &$val', '$key = $val."_priv";'));
			$conn->query("REPLACE INTO db (" . join($opts_copy, ", ") . ", `host`, `db`, `user`) VALUES ('" . join($opts, "', '") . "', '" . $host . "', '" . $db . "', '" . $user . "');");

			$ar = $conn->affected_rows;

			if ($conn->error)
				return new MySQLError("Error when applying grants, " . $conn->error);

			$conn->query("FLUSH PRIVILEGES;");
			return $ar > 0;
		}

		/**
		 * bool add_mysql_user_permissions (string, string, string, array)
		 *
		 * @deprecated
		 * @see set_mysql_privileges()
		 *
		 * @param string $user
		 * @param string $host
		 * @param string $db
		 * @param array  $opts
		 */
		public function add_mysql_user_permissions($user, $host, $db, array $opts)
		{
			deprecated_func("use set_mysql_privileges()");
			return $this->set_mysql_privileges($user, $host, $db, $opts);
		}

		/**
		 * Revoke all privileges on a database from a MySQL user
		 *
		 * @param string $user
		 * @param string $host
		 * @param string $db
		 * @return bool
		 */
		public function revoke_from_mysql_db($user, $host, $db)
		{
			$prefix = $this->get_prefix();
			if ($user != $this->get_service_value('mysql', 'dbaseadmin') &&
				strncmp($user, $prefix, strlen($prefix))
			) {
				$user = $prefix . $user;
			}
			if ($user != $this->username && !preg_match('/^' . $prefix . '/', $user))
				return error("invalid user `$user'");
			$conn = new mysqli('localhost', self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			$stmt = $conn->prepare("DELETE FROM db WHERE user = ? AND host = ? AND db = ?");
			$stmt->bind_param("sss", $user, $host, $db);
			$res = $stmt->execute();
			if (!$res) return error("Query error while dropping permissions, " . $stmt->error);

			$conn->query("FLUSH PRIVILEGES;");
			return $stmt->affected_rows > 0;
		}

		/**
		 *
		 * @deprecated
		 * @see revoke_from_mysql_db()
		 */
		public function delete_mysql_user_permissions($user, $host, $db)
		{
			deprecated_func("use revoke_from_mysql_db()");
			return $this->revoke_from_mysql_db($user, $host, $db);
		}

		/**
		 * Get MySQL grants for a user on a database
		 *
		 * @param string $user
		 * @param string $host
		 * @param string $db
		 * @return array
		 */
		public function get_mysql_privileges($user, $host, $db)
		{
			$prefix = $this->get_prefix();
			if ($user != $this->get_service_value('mysql', 'dbaseadmin') &&
				strncmp($user, $prefix, strlen($prefix))
			) {
				$user = $prefix . $user;
			}
			$conn = new mysqli('localhost', self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			$extra = ', NULL, NULL';
			if ($this->mysql_version() >= 50100) {
				$extra = ', EVENT_PRIV, TRIGGER_PRIV';
			}

			$stmt = $conn->prepare("SELECT Select_priv, Insert_priv, Update_priv, DELETE_PRIV,
									 CREATE_PRIV, DROP_PRIV, GRANT_PRIV, REFERENCES_PRIV,
									 INDEX_PRIV, ALTER_PRIV, CREATE_TMP_TABLE_PRIV,
									 LOCK_TABLES_PRIV, CREATE_VIEW_PRIV, SHOW_VIEW_PRIV,
									 CREATE_ROUTINE_PRIV, ALTER_ROUTINE_PRIV, EXECUTE_PRIV
									 $extra FROM db WHERE user = ? AND db = ? AND host = ?");
			$stmt->bind_param("sss", $user, $db, $host);
			$stmt->execute();
			$select = $insert = $update = $delete = $create = $drop = $domain =
			$grant = $references = $index = $alter = $create_tmp_table =
			$lock_tables = $create_view = $show_view = $create_routine =
			$alter_routine = $execute = $event = $trigger = null;
			$stmt->bind_result($select, $insert, $update, $delete, $create, $drop, $grant,
				$references, $index, $alter, $create_tmp_table, $lock_tables,
				$create_view, $show_view, $create_routine, $alter_routine,
				$execute, $event, $trigger);

			if ($stmt->fetch()) {
				$priv = array(
					'select'           => $select,
					'insert'           => $insert,
					'update'           => $update,
					'delete'           => $delete,
					'create'           => $create,
					'drop'             => $drop,
					'grant'            => $grant,
					'references'       => $references,
					'index'            => $index,
					'alter'            => $alter,
					'create_tmp_table' => $create_tmp_table,
					'lock_tables'      => $lock_tables,
					'create_view'      => $create_view,
					'show_view'        => $show_view,
					'create_routine'   => $create_routine,
					'alter_routine'    => $alter_routine,
					'execute'          => $execute,
					'trigger'          => $trigger,
					'event'            => $event
				);
				array_walk($priv, create_function('&$key, &$val', '$key = ($key == "Y");'));
				$stmt->close();
			} else {
				$priv = array(
					'select'           => false,
					'insert'           => false,
					'update'           => false,
					'delete'           => false,
					'create'           => false,
					'drop'             => false,
					'grant'            => false,
					'references'       => false,
					'index'            => false,
					'alter'            => false,
					'create_tmp_table' => false,
					'lock_tables'      => false,
					'create_view'      => false,
					'show_view'        => false,
					'create_routine'   => false,
					'alter_routine'    => false,
					'execute'          => false,
				);
			}
			if (version_compare(PLATFORM_VERSION, 4.5, '<')) {
				unset($priv['event']);
				unset($priv['trigger']);
			}
			return $priv;
		}

		public function get_mysql_user_permissions($user, $host, $db)
		{
			deprecated_func("use get_mysql_privileges()");
			return $this->get_mysql_privileges($user, $host, $db);
		}


		/**
		 * Delete MySQL database from system
		 *
		 * @param  string $db database
		 * @return bool
		 */
		public function delete_mysql_database($db)
		{
			$db = str_replace('\\\\', '\\', $db);
			$prefix = $this->get_prefix();
			$prefixwc = str_replace('_', '\_', $prefix) . '%';
			$conn = new mysqli('localhost', self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			$stmt = $conn->prepare("SELECT user FROM db WHERE (user = ? OR db LIKE ?) AND db = ?");
			$stmt->bind_param("sss", $this->username, $prefixwc, $db);
			$stmt->execute();
			$stmt->store_result();
			if ($stmt->num_rows < 1) {
				$stmt->free_result();
				// db name passed without prefix, db not found,
				// don't coerce db to prefix + db unless db deletion failed
				if (strncmp($db, $prefix, strlen($prefix))) {
					$db = $prefix . $db;
					return $this->delete_mysql_database($db);
				}
				return error("Unknown database `%s'", $db);
			}
			$stmt->free_result();
			$this->query('sql_assert_mysql_permissions');

			$stmt = $conn->prepare("DELETE FROM db WHERE db = ?");
			$stmt->bind_param("s", $db);
			$stmt->execute();

			// FLUSH is necessary, because MySQL will permit a separate CREATE DATABASE
			// query by the former owner bypassing this requirement
			// (it also bypasses filesystem namespacing + quota attribution)
			$conn->query("FLUSH PRIVILEGES");

			$q = $conn->query("DROP DATABASE IF EXISTS `" . $db . "`");
			if (!$q) return error("unable to drop database `$db': %s", $conn->error);
			$this->query('sql_delete_mysql_database_backend', $db);

			$this->delete_mysql_backup($db);


			if ($conn->error) return error("error while removing database `$db' - " . $conn->error);
			return true;
		}

		/**
		 * Ensure that /var/lib/mysql/ has mysql:<group id> ownership
		 */
		public function assert_mysql_permissions()
		{
			if (!file_exists($this->domain_fs_path() . self::MYSQL_PATH))
				return false;

			chown($this->domain_fs_path() . self::MYSQL_PATH, 'mysql');
			chgrp($this->domain_fs_path() . self::MYSQL_PATH, $this->group_id);
			return true;
		}

		public function delete_mysql_database_backend($db)
		{
			$db = $this->_canonicalize_mysql_database($db);
			if (is_link(self::MYSQL_PATH . '/' . $db))
				unlink(self::MYSQL_PATH . '/' . $db);

			return true;

		}

		/**
		 * bool edit_mysql_user(string, string, array)
		 * Note when calling through SOAP, all options must be given, otherwise
		 * the will default to server preferences.
		 *
		 * @param string $user user
		 * @param string $host hostname
		 * @param array  $opts array of options, valid indexes:
		 *                     host
		 *                     password
		 *                     max_user_connections
		 *                     max_updates
		 *                     max_questions
		 *                     use_ssl
		 *                     cipher_type
		 *                     ssl_cipher
		 *                     x509_subject
		 *                     x509_issuer
		 * @return bool query succeeded
		 */
		public function edit_mysql_user($user, $host, $opts)
		{
			$prefix = $this->get_prefix();
			if ($user != $this->get_service_value('mysql', 'dbaseadmin') &&
				strncmp($user, $prefix, strlen($prefix))
			) {
				$user = $prefix . $user;
			}
			if (!is_array($opts))
				return error("Options must be an array");
			if (isset($opts['cipher_type'])) {
				$opts['cipher_type'] = strtoupper($opts['cipher_type']);
				if ($opts['cipher_type'] != '' && $opts['cipher_type'] != 'ANY' &&
					$opts['cipher_type'] != 'SPECIFIED' && $opts['cipher_type'] != 'X509'
				)
					return error("Invalid cipher type");
			}
			if (isset($opts['host']) && $opts['host'] != 'localhost') {
				if (!ip2long($opts['host']) && !preg_match(Regex::SQL_MYSQL_IP_WILDCARD, $opts['host'])) {
					return error("rejected host `%s': only numeric IP addresses are permitted, not hostnames", $opts['host']);
				}
			}

			$defaults = array('host'                 => $host,
			                  'password'             => null,
			                  'max_user_connections' => 5,
			                  'max_updates'          => 0,
			                  'max_questions'        => 0,
			                  'use_ssl'              => false,
			                  'cipher_type'          => '',
			                  'ssl_cipher'           => '',
			                  'x509_subject'         => '',
			                  'x509_issuer'          => '');

			// make copy to check for max_user_connections change
			// later in event of password update
			$mergeopts = $opts;
			foreach ($defaults as $def_nam => $def_val) {
				if (!isset($mergeopts[$def_nam]))
					$mergeopts[$def_nam] = $def_val;
			}
			/** if we're not using SSL, blank it out */
			if (!$mergeopts['use_ssl']) {
				$mergeopts['x509_subject'] = $mergeopts['x509_issuer'] = $mergeopts['ssl_cipher'] = $mergeopts['cipher_type'] = '';
			} else {
				$mergeopts['cipher_type'] = 'ANY';
			}

			if (isset($mergeopts['max_user_connections']) && ($mergeopts['max_user_connections'] < 1))
				$mergeopts['max_user_connections'] = 5;

			if ($mergeopts['max_user_connections'] < 0 || $mergeopts['max_questions'] < 0 || $mergeopts['max_updates'] < 0)
				return error("Max connections, queries, and updates must be greater than 0");
			else if (isset($opts['max_user_connections']) && $opts['max_user_connections'] > 10)
				return error("Must file a ticket justifying need.  Check index placements first.");
			else if (!is_null($mergeopts['password']) && strlen($mergeopts['password']) < self::MIN_PASSWORD_LENGTH) {
				return error("password must be at least %d characters long", self::MIN_PASSWORD_LENGTH);
			}
			$conn = $this->_connect_root();

			$stmt = $conn->prepare("SELECT user FROM user where user = ? AND host = ?");
			$stmt->bind_param("ss", $user, $host);
			$stmt->execute();
			$stmt->store_result();
			if ($stmt->num_rows < 1) {
				return error("invalid user@host specified: %s@%s", $user, $host);
			}

			$stmt = $conn->prepare("UPDATE user
											SET
												host            = ?,
												ssl_type        = ?,
												ssl_cipher      = ?,
												x509_issuer     = ? ,
												x509_subject    = ?,
												max_questions   = ?,
												max_updates     = ?,
												max_user_connections = ?
											WHERE
													user = ?
												AND
													host = ?");

			$stmt->bind_param("sssssiiiss", $mergeopts['host'],
				$mergeopts['cipher_type'],
				$mergeopts['ssl_cipher'],
				$mergeopts['x509_issuer'],
				$mergeopts['x509_subject'],
				$mergeopts['max_questions'],
				$mergeopts['max_updates'],
				$mergeopts['max_user_connections'],
				$user,
				$host
			);
			$stmt->execute();
			if ($stmt->error)
				return new MySQLError("Invalid query, " . $stmt->error);
			if ($host != $defaults['host']) {
				$stmt = $conn->prepare("UPDATE db SET host = ? WHERE user = ? AND host = ?");
				$stmt->bind_param("sss", $mergeopts['host'], $user, $host);
				$stmt->execute();
				if ($stmt->error) {
					return error("error while updating DB grants, %s", $stmt->error);
				}
			}
			/** finally update the password if changed */
			if ($mergeopts['password']) {
				$pwclause = 'password(?)';
				$password = $mergeopts['password'];
				// password is encrypted in new pw form or old
				if ($password[0] == '*' && strlen($password) == 41
					&& ctype_xdigit(substr($password, 1)) ||
					/** only accept old-style passwords on platforms <v6 */
					strlen($password) == 16 && ctype_xdigit($password) && version_compare(platform_version(), 6, '<')
				) {
					$pwclause = '?';
				}
				$stmt2 = $conn->prepare("UPDATE user SET password = " . $pwclause . " WHERE user = ? AND host = ?;");

				$stmt2->bind_param("sss", $password, $user, $mergeopts['host']);
				$stmt2->execute();
				if ($stmt2->error)
					return new MySQLError("Query error while updating password, " . $stmt2->error);
				if ($user == $this->username) {
					$this->set_mysql_option('user', $this->username, 'client');
					$this->set_mysql_option('password',
						str_replace(array('"'), array('\"'), $password),
						'client'
					);
				}
			}
			$conn->query("FLUSH PRIVILEGES");
			return true;
		}

		/**
		 * Get option from MySQL client/server configuration
		 *
		 * @param  string $option option name
		 * @param  string $group  option group
		 * @return mixed option value, false on failure, null on empty value
		 */
		public function get_mysql_option($option, $group = 'client')
		{
			$home = $this->user_get_user_home();
			$regex = Regex::compile(Regex::MISC_INI_DIRECTIVE_C, $option);
			$optval = array();
			$confs = array();
			if ($this->file_file_exists($home . '/.my.cnf')) {
				$confs[] = $this->file_get_file_contents($home . '/.my.cnf');
			}
			$confs[] = file_get_contents('/etc/my.cnf');

			foreach ($confs as $config) {
				if ($group) {
					$startpos = strpos($config, '[' . $group . ']');
					if ($startpos !== false) {
						$endpos = strpos($config, '[', $startpos + 1);
						if (!$endpos) $endpos = strlen($config);
						$config = substr($config, $startpos, $endpos - $startpos);
					}
				}
				if (preg_match_all($regex, $config, $optval, PREG_SET_ORDER)) {
					$optval = array_pop($optval);
					return trim($optval[1], '"');
				}
			}
			return false;
		}

		/**
		 * Set MySQL client option
		 *
		 * Reads from ~/.my.cnf and creates if necessary.
		 * Specify a value of null to remove an option.
		 *
		 * @param string $option
		 * @param string $value
		 * @param string $group
		 * @return bool
		 */
		public function set_mysql_option($option, $value = null, $group = 'client')
		{
			$home = $this->user_get_user_home();
			if (!$this->file_file_exists($home . '/.my.cnf')) {
				$this->file_create_file($home . '/.my.cnf', 0600);
			}
			$lines = explode("\n", $this->file_get_file_contents($home . '/.my.cnf'));
			$group_set = $group && false;
			$config = array();
			$found = false;
			$dlen = strlen($option);
			$cgroup = '';
			if ($value && !ctype_alnum($value))
				$value = '"' . str_replace('"', '\"', $value) . '"';

			// I should rewrite this on more than 0 hours of sleep
			for ($i = 0, $n = sizeof($lines); $i < $n; $i++) {
				$line = trim($lines[$i]);
				if (!$line) continue;
				if ($line[0] == '[' && substr($line, -1) == ']') {
					$cgroup = substr($line, 1, -1);
					if (!isset($config[$cgroup])) $config[$cgroup] = array();
					if ($cgroup == $group) $group_set = true;
					else if ($group) $group_set = false;
					continue;
				} else if ($group_set) {
					if (substr($line, 0, $dlen) == $option) {
						$found = 1;
						if ($value === false) continue;
						$line = $option . ($value ? '=' . $value : '');
					}
				}
				$config[$cgroup][] = $line;
			}

			if (!$found) {
				if ($group && !isset($config[$cgroup]))
					$config[$group] = array();
				$config[$group][] = $option . ($value ? '=' . $value : '');
			}

			$formatted = '';
			foreach ($config as $group => $opts) {
				$formatted .= '[' . $group . ']' . "\n";
				$formatted .= join("\n", $opts) . "\n\n";
			}
			$this->file_put_file_contents($home . '/.my.cnf', $formatted, true);
			return true;
		}


		/**
		 * bool delete_mysql_user(string, string[, bool = false])
		 * Delete a MySQL user
		 *
		 * @param string $user    username
		 * @param string $host    hostname
		 * @param string $cascade revoke all privileges from databases
		 */
		public function delete_mysql_user($user, $host, $cascade = true)
		{
			if ($user == $this->username && !Util_Account_Hooks::is_mode('delete'))
				return error("Cannot remove main user");
			else if (!$this->mysql_user_exists($user, $host))
				return error("user `%s' on `%s' does not exist", $user, $host);
			$prefix = $this->get_prefix();
			if ($user != $this->get_config('mysql', 'dbaseadmin') &&
				substr($user, 0, strlen($prefix)) != $prefix
			) {
				$user = $prefix . $user;
			}
			$conn = new mysqli('localhost', self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			$stmt = $conn->prepare("DELETE FROM user WHERE user = ? AND host = ?");
			$stmt->bind_param("ss", $user, $host);
			$stmt->execute();
			if ($stmt->error)
				return new MySQLError("Invalid query, " . $stmt->error);
			if ($cascade) {
				$stmt2 = $conn->prepare("DELETE FROM db WHERE user = ? AND host = ?");
				$stmt2->bind_param("ss", $user, $host);
				$stmt2->execute();
				if (!$stmt2->error)
					$conn->query("FLUSH PRIVILEGES");
				else
					return new MySQLError("Invalid query, " . $stmt2->error);


			}
			return ($stmt->affected_rows > 0);

		}

		/**
		 * bool service_enabled (string)
		 *
		 * Checks to see if a service is enabled
		 *
		 * @deprecated @see enabled()
		 * @param  string $service service name, either "pgsql" or "mysql"
		 * @return bool
		 */
		public function service_enabled($service)
		{
			deprecated("use enabled()");
			return $this->enabled($service);
		}

		// {{{ enabled()
		/**
		 * MySQL/PostgreSQL service enabled on account
		 *
		 * Checks to see if either MySQL or PostgreSQL is enabled on an account
		 *
		 * @param string $svc_name service name to check (mysql, pgsql)
		 * @return bool
		 */
		public function enabled($svc_name)
		{
			if ($svc_name != "mysql" && $svc_name != "postgresql" && $svc_name != "pgsql")
				return error("Invalid service");

			if ($svc_name == "mysql")
				return $this->get_service_value('mysql', 'enabled');
			else if ($svc_name == "postgresql" || $svc_name == "pgsql")
				return (platform_version() >= 4.5 && $this->get_service_value('pgsql', 'enabled')) ||
				file_exists($this->domain_fs_path() . "/usr/bin/psql");
		}

		// }}}

		/**
		 * bool add_pgsql_user(string, string[, int])
		 */
		public function add_pgsql_user($user, $password, $maxconn = 5)
		{
			if (!$user) {
				return error("no username specified");
			}
			$prefix = str_replace('-', '', $this->get_prefix());
			if ($user != $this->get_service_value('mysql', 'dbaseadmin') &&
				strncmp($user, $prefix, strlen($prefix))
			) {
				$user = $prefix . $user;
			}
			if (!$this->enabled('pgsql'))
				return error("PostgreSQL service not enabled for account.");
			else if ($this->pgsql_user_exists($user))
				return error("pg user `$user' exists");
			if ($maxconn < 0)
				$maxconn = 5;
			if (strlen($password) < self::MIN_PASSWORD_LENGTH)
				return error("Password must be at least %d characters", self::MIN_PASSWORD_LENGTH);
			else if ($maxconn < 0)
				return error("Max connections, queries, and updates must be greater than -1");

			$rs = $this->pgsql->query("CREATE ROLE \"" . $user . "\" WITH NOCREATEDB NOCREATEROLE NOCREATEUSER LOGIN NOINHERIT CONNECTION LIMIT " . $maxconn . " UNENCRYPTED PASSWORD '" . $password . "';");

			if ($rs->error) {
				return error("user creation for `%s' failed", $user);
			}
			return true;
		}

		/**
		 * bool create_pgsql_database (string)
		 *
		 * @param  string $db
		 * @return bool  creation succeeded
		 */
		public function create_pgsql_database($db)
		{
			if (!$this->enabled('pgsql'))
				return error("PostgreSQL service not enabled for account.");
			if (!preg_match('/^[a-zA-Z_0-9-]+$/', $db))
				return error("invalid database name `%s'", $db);
			if ($this->pgsql_database_exists($db)) return error("database `$db' exists");
			$prefix = $this->get_prefix();

			// db name passed without prefix
			if (strncmp($db, $prefix, strlen($prefix)))
				$db = $prefix . $db;

			$this->prep_tablespace();
			// optional template
			$template = '';
			if (version_compare(platform_version(), '6', '>=')) {
				$template = "TEMPLATE = template1";
			}
			$this->pgsql->query("CREATE DATABASE \"" . $db . "\" WITH OWNER = " . $this->username . " $template TABLESPACE = \"" . $this->_get_tablespace() . "\" CONNECTION LIMIT = 5");
			if ($this->pgsql->error) {
				return error("error while creating database: %s", $this->pgsql->error);
			}
			return info("created database `%s'", $db);
		}

		public function add_pgsql_extension($db, $extension)
		{
			if (!IS_CLI) {
				return $this->query('sql_add_pgsql_extension', $db, $extension);
			}

			if (version_compare(platform_version(), '6', '<')) {
				return error("%s only available on v6+ platforms", __FUNCTION__);
			}
			$extensions = $this->_getPermittedPgsqlExtensions();
			if (!in_array($extension, $extensions)) {
				return error("extension `%s' unrecognized or disallowed usage", $extension);
			}

			$dbs = $this->list_pgsql_databases();
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

		private function _getPermittedPgsqlExtensions()
		{
			return $this->_permittedPgsqlExtensions;
		}

		/**
		 * void prep_tablespace ()
		 * Checks to see if tablespace exists, if not, creates it
		 *
		 * @private
		 */
		private function prep_tablespace()
		{
			if (!file_exists($this->domain_fs_path() . "/var/lib/pgsql/")) {
				$this->query("sql_prep_tablespace_backend");
			}
			$rs = $this->pgsql->query("SELECT 1 FROM pg_tablespace WHERE spcowner = (SELECT oid FROM pg_roles WHERE rolname = '" . $this->username . "')");
			if ($this->pgsql->num_rows() < 1)
				$this->pgsql->query("CREATE TABLESPACE \"" . str_replace(".", "_", $this->domain) . "\" OWNER " . $this->username . " LOCATION '/home/virtual/site" . $this->site_id . "/fst/var/lib/pgsql/'");
			return true;
		}

		/**
		 * void prep_tablespace_backend ()
		 * {@link prep_tablespace}
		 */
		public function prep_tablespace_backend()
		{
			mkdir($this->domain_fs_path() . "/var/lib/pgsql/");
			chown($this->domain_fs_path() . "/var/lib/pgsql/", "postgres");
			chgrp($this->domain_fs_path() . "/var/lib/pgsql/", (int)$this->user_id);
			chmod($this->domain_fs_path() . "/var/lib/pgsql/", 02750);
			return true;
		}

		/**
		 * Get tablespace name for domain
		 */
		private function _get_tablespace()
		{
			$db = $this->pgsql;
			$db->query("SELECT spcname FROM pg_tablespace WHERE spcowner = (SELECT oid FROM pg_roles WHERE rolname = '" . $this->username . "')");
			if ($db->num_rows() < 1) return null;
			return $db->fetch_object()->spcname;
		}

		/**
		 * bool add_pgsql_user_permissions (string, string, string, array)
		 * Add/removes privileges for a user to a table, any value listed as
		 * false or not supplied as an array key will revoke the privilege
		 *
		 * @param string $user
		 * @param string $db
		 * @param array  $opts
		 */
		public function add_pgsql_user_permissions($user, $db, array $opts)
		{
			return new apnscpException("Function not implemented in PostgreSQL");
		}

		public function delete_pgsql_user_permissions($user, $db)
		{
			return new apnscpException("Function not implemented in PostgreSQL");
		}

		/**
		 * void get_pgsql_user_permissions(string, string)
		 * Function not implemented in PostgreSQL
		 *
		 * @return void
		 */
		public function get_pgsql_user_permissions($user, $db)
		{
			return new apnscpException("Function not implemented in PostgreSQL");
		}

		/**
		 * bool delete_pgsql_database(string)
		 * Drops the database and revokes all permssions
		 *
		 * @param  string $db
		 * @return bool   drop succeeded
		 */
		public function delete_pgsql_database($db)
		{
			$db = $this->pgsql->escape_string($db);
			$prefix = $this->get_prefix();
			if (strncmp($db, $prefix, strlen($prefix)))
				$db = $prefix . $db;
			$stmt = $this->pgsql->query_params("SELECT 1 FROM pg_database WHERE datname = $1 AND datdba = (SELECT oid FROM pg_roles WHERE rolname = '" . $this->username . "')", array($db));
			if ($this->pgsql->num_rows() < 1)
				return error("Unknown database `%s'", $db);

			$this->pgsql->query("DROP DATABASE \"" . $db . "\"");
			$this->delete_pgsql_backup($db);
			return !$this->pgsql->error ? true : new PostgreSQLError("Error while dropping database, " . $this->pgsql->error);

		}

		/**
		 * array list_mysql_databases ()
		 * Queries the db table in the mysql database for applicable grants
		 *
		 * @return array list of databases
		 */
		public function list_pgsql_databases()
		{
			$prefix = $this->get_service_value('mysql', 'dbaseprefix');
			$this->pgsql->query("SELECT datname FROM pg_database WHERE datname LIKE '"
				. str_replace(array("-", '_'), array("", '\_'), $prefix) . "%' OR datdba = "
				. "(SELECT oid FROM pg_roles WHERE rolname = '" . $this->username . "')");
			$dbs = array();
			while ($row = $this->pgsql->fetch_object())
				$dbs[] = $row->datname;
			return $dbs;
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
		public function edit_pgsql_user($user, $password, $maxconn = null)
		{
			$prefix = str_replace('-', '', $this->get_prefix());
			if ($user != $this->get_service_value('mysql', 'dbaseadmin') &&
				strncmp($user, $prefix, strlen($prefix))
			) {
				$user = $prefix . $user;
			}
			if (is_int($maxconn) && ($maxconn < 1))
				$maxconn = 5;
			if (!$password && !$maxconn) {
				return warn("no action taken for `$user'");
			}
			if ($password && strlen($password) < self::MIN_PASSWORD_LENGTH) {
				return error("pgsql password must be at least %d characters long", 3);
			}
			$user = $this->pgsql->escape_string($user);
			$password = $this->pgsql->escape_string($password);

			if (!$password && is_int($maxconn)) {
				$this->pgsql->query_params('UPDATE pg_authid SET rolconnlimit = $1 WHERE rolname = $2;',
					array(intval($maxconn), $user)
				);
			} else if ($password && is_int($maxconn)) {
				$this->pgsql->query_params('UPDATE pg_authid SET rolpassword = $1, rolconnlimit = $2 WHERE rolname = $3;', array($password, intval($maxconn), $user));
			} else if ($password && !is_int($maxconn)) {
				$this->pgsql->query_params('UPDATE pg_authid SET rolpassword = $1 WHERE rolname = $2;', array($password, $user));
			}
			if ($this->pgsql->error)
				return new PostgreSQLError("Invalid query while editing user, " . $this->pgsql->error);
			if ($user == $this->get_pgsql_username()) {
				$this->set_pgsql_password($password);
			}
			return true;
		}

		/**
		 * array list_pgsql_users ()
		 * Lists all created users for PostgreSQL
		 *
		 * @return array
		 */
		public function list_pgsql_users()
		{
			if (!$this->enabled('pgsql'))
				return new PermissionError("PostgreSQL service not enabled for account.");
			$prefix = $this->get_service_value('mysql', 'dbaseprefix');

			$q = $this->pgsql->query("SELECT rolname, rolpassword, rolconnlimit FROM pg_authid WHERE rolname = '"
				. $this->username . "' OR rolname LIKE '" . str_replace(array("-", "_"), array("", '\_'), $prefix) . "%' ORDER BY rolname");
			$users = array();
			while ($row = $this->pgsql->fetch_object()) {
				$users[$row->rolname] = array(
					'max_connections' => $row->rolconnlimit,
					'password'        => $row->rolpassword
				);
			}
			return $users;
		}

		/**
		 * bool delete_pgsql_user(string[, bool = false])
		 * Delete a PostgreSQL user
		 *
		 * @param string $user username
		 */
		public function delete_pgsql_user($user, $cascade = false)
		{
			if ($user == $this->username && !Util_Account_Hooks::is_mode('delete'))
				return error("Cannot remove main user");
			else if (!$this->pgsql_user_exists($user))
				return error("db user `$user' not found");
			$prefix = $this->get_prefix();
			if ($user != $this->get_config('mysql', 'dbaseadmin') && strncmp($user, $prefix, strlen($prefix)))
				$user = $prefix . $user;
			$tblspace = $this->_get_tablespace();
			if (function_exists('pg_escape_literal')) {
				$usersafe = pg_escape_identifier($user);
			} else {
				$usersafe = '"' . pg_escape_string($user) . '"';
			}
			$this->pgsql->query('REVOKE ALL ON TABLESPACE ' . $tblspace . ' FROM ' . $usersafe . '');
			$this->pgsql->query("DROP ROLE " . $usersafe);

			if ($this->pgsql->error)
				return new PostgreSQLError("Invalid query, " . $this->pgsql->error);

			return true;

		}

		/**
		 * string pg_vacuum_db (string)
		 * Vacuums a database
		 *
		 * @return string vacuum output
		 */
		public function pg_vacuum_db($db)
		{
			$db = $this->pgsql->escape_string($db);
			$prefix = $this->get_prefix();

			// db name passed without prefix
			if (strncmp($db, $prefix, strlen($prefix)))
				$db = $prefix . $db;
			$q = "SELECT 1 FROM pg_database WHERE datname = $1 " .
				"AND datdba = (SELECT oid FROM pg_roles WHERE rolname = '" . $this->username . "')";
			$this->pgsql->query_params($q, array($db));
			if ($this->pgsql->num_rows() < 1)
				return error("Database `$db' not owned by main user");

			return $this->query('sql_pg_vacuum_db_backend', $db);
		}

		public function pg_vacuum_db_backend($db)
		{
			$status = Util_Process::exec("vacuumdb -zfq --dbname=" . escapeshellarg($db));
			if ($status['error'] instanceof Exception)
				return error($status['error']);
			return $status['success'];
		}

		public function truncate_pgsql_database($db)
		{

			return $this->_pgsql_empty_truncate_wrapper($db, "truncate");
		}

		private function _pgsql_empty_truncate_wrapper($db, $mode) {
			if ($mode != "truncate" && $mode != "empty") {
				return error("unknown mode `%s'", $mode);
			}
			if ($mode == "empty") {
				// semantically more correct
				$mode = 'drop';
			}

			$prefix = $this->get_service_value('mysql', 'dbaseprefix');
			if (strncmp($db, $prefix, strlen($prefix))) {
				$db = $prefix . $db;
			}

			if (!$this->pgsql_database_exists($db)) {
				return error("unknown database, `%s'", $db);
			}

			$user = $this->_create_temp_pgsql_user($db);
			if (!$user) {
				return error("failed to %s db `%s'", $mode, $db);
			}
			$dsn = 'host=localhost dbname=' . $db . ' user=' . $user . ' password=' . self::PG_TEMP_PASSWORD;
			$sqldb = pg_connect($dsn);
			if (!$sqldb) {
				$this->_delete_temp_pgsql_user($user);
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
			$pgver = $this->pgsql_version();
			// available in 8.4
			$identity = $mode !== "empty" && $pgver >= 80400 ? "RESTART IDENTITIY" : "";
			while (false !== ($res = pg_fetch_object($rs))) {
				if (function_exists('pg_escape_identifier')) {
					$tablesafe = pg_escape_identifier($res->name);
				} else {
					$tablesafe = '"' . pg_escape_string($res->name) . '"';
				}
				$q = strtoupper($mode) . " TABLE " . $tablesafe . " " . $identity . " CASCADE";
				if (!($res = pg_query($sqldb,$q))) {
					warn("failed to %s table `%s': %s", $mode, $res->name, pg_errormessage($sqldb));
				}
			}
			$this->_delete_temp_pgsql_user($user);
			return true;
		}

		public function empty_pgsql_database($db)
		{
			return $this->_pgsql_empty_truncate_wrapper($db, "empty");
		}

		/**
		 * bool pgsql_import(string, string, string, strin)
		 */
		public function import_pgsql($db, $file)
		{
			if (!IS_CLI) {
				return $this->query('sql_import_pgsql', $db, $file);
			}

			$prefix = $this->get_prefix();
			// db name passed without prefix
			if (strncmp($db, $prefix, strlen($prefix))) {
				$db = $prefix . $db;
			}
			
			$dbs = $this->list_pgsql_databases();
			if (false === array_search($db, $dbs)) {
				return error("database `%s' does not exist", $db);
			}
			$unlink = null;
			if (false === ($realfile = $this->_preImport($file, $unlink))) {
				return false;
			}
			$user = $this->_create_temp_pgsql_user($db);
			if (!$user) return error("import failed - cannot create temp user");
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
			$this->_delete_temp_pgsql_user($user);
			$this->_postImport($unlink);

			if (!$status['success']) {
				return error("import failed: %s", $status['error']);
			}
			return $status['success'];
		}

		public function truncate_mysql_database($db)
		{

			return $this->_mysql_empty_truncate_wrapper($db, "truncate");
		}

		private function _mysql_empty_truncate_wrapper($db, $mode) {
			if ($mode != "truncate" && $mode != "empty") {
				return error("unknown mode `%s'", $mode);
			}
			if ($mode == "empty") {
				// semantically more correct
				$mode = 'drop';
			}

			$prefix = $this->get_service_value('mysql', 'dbaseprefix');
			if (strncmp($db, $prefix, strlen($prefix))) {
				$db = $prefix . $db;
			}

			if (!$this->mysql_database_exists($db)) {
				return error("unknown database, `%s'", $db);
			}

			$user = $this->_create_temp_mysql_user($db);
			if (!$user) {
				return error("failed to %s db `%s'", $mode, $db);
			}
			$conn = new mysqli("localhost", $user);
			if (!$conn->select_db($db)) {
				return error("unable to establish db connection for user `%s' on db `%s'", $user, $db);
			}

			$conn->query("SET FOREIGN_KEY_CHECKS=0");

			$q = "SELECT CONCAT('" . strtoupper($mode) . " TABLE ','`', table_schema,'`','.','`',TABLE_NAME,'`', ';') 
					  FROM INFORMATION_SCHEMA.TABLES where  table_schema in ('" . $conn->escape_string($db) . "');";
			$res = $conn->query($q);
			while (null !== ($rs = $res->fetch_row())) {
				if (!$conn->query($rs[0])) {
					warn("failed to %s table `%s'", $mode, $rs[0]);
				}
			}

			$conn->query("SET @@FOREIGN_KEY_CHECKS=1;");
			if (!$res) {
				return error("%s failed on database `%s': `%s'", $mode, $db, $conn->error);
			}
			$this->_delete_temp_mysql_user($user);
			return true;
		}

		public function empty_mysql_database($db)
		{
			return $this->_mysql_empty_truncate_wrapper($db, "empty");
		}

		/**
		 * Export a MySQL database
		 *
		 * @param string      $db
		 * @param string|null $file optional filename
		 * @return mixed path of export or false on failure
		 */
		public function export_mysql($db, $file = null)
		{
			if (!IS_CLI)
				return $this->query('sql_export_mysql', $db, $file);

			if (is_null($file))
				$file = $db . '.sql';
			if (!in_array($db, $this->list_mysql_databases()))
				return error("Invalid database " . $db);
			if ($file[0] !== '/' && $file[0] !== '.' && $file[0] !== '~') {
				$file = '/tmp/' . $file;
			}
			$path = $this->file_make_path($file);
			if (!$path) {
				return error("invalid file `%s'", $file);
			}
			$user = $this->_create_temp_mysql_user($db);
			$cmd = "mysqldump -u %s %s > %s";
			if (!$user) {
				$user = self::MASTER_USER;
				$rootpw = escapeshellarg($this->_get_elevated_password());
				$cmd = str_replace("-u %s", "-u %s -p" . $rootpw, $cmd);
			}

			$fsizelimit = Util_Ulimit::get('fsize');
			if ($this->get_database_size('mysql', $db) > $fsizelimit / self::DB_BIN2TXT_MULT) {
				// make sure ulimit accommodates the db dump
				Util_Ulimit::set('fsize', 'unlimited');
			} else {
				// no need to change this then
				$fsizelimit = null;
			}

			$status = Util_Process_Safe::exec($cmd,
				$user,
				$db,
				$path
			);

			if ($user != self::MASTER_USER) {
				$this->_delete_temp_user('mysql', $user);
			}

			if (!is_null($fsizelimit)) {
				Util_Ulimit::set('fsize', $fsizelimit);
			}

			if (!$status['success'] || !file_exists($path))
				return error("export failed: %s", $status['stderr']);
			chown($path, $this->user_id) && chgrp($path, $this->group_id) && chmod($path, 0600);
			if (!$status['success'])
				return error("export failed: %s", $status['stderr']);

			return $this->file_unmake_path($path);
		}

		/**
		 * Export a db to a named pipe for immediate download
		 *
		 * @param $db
		 * @return bool|void
		 */
		public function export_mysql_pipe($db)
		{
			if (version_compare(platform_version(), '4.5', '<=')) {
				return error('platform version too old to support download feature');
			}

			if (!in_array($db, $this->list_mysql_databases())) {
				return error("Invalid database " . $db);
			}

			$user = $this->_create_temp_mysql_user($db);

			return $this->query('sql_export_mysql_pipe_real', $db, $user);
		}

		/**
		 * Export a database to a named pipe
		 *
		 * Differs from export_mysql_pipe in that it may only be called internally
		 * or from backend, no API access
		 *
		 * @param $db
		 * @param $user if empty use superuser
		 * @return bool|string|void
		 */
		public function export_mysql_pipe_real($db, $user)
		{
			if (!IS_CLI) {
				return $this->query('sql_export_mysql_pipe_real', $db, $user);
			}


			// automatically cleaned up on exit()/destruct

			$cmd = "/usr/bin/mysqldump -q -u %s %s -r%s";
			if (!$user) {
				$user = self::MASTER_USER;
				$rootpw = escapeshellarg($this->_get_elevated_password());
				$cmd = str_replace("-u %s", "-u %s --password=" . $rootpw, $cmd);
			}

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

			$status = $proc->run($cmd,
				$user,
				$db,
				$fifo
			);

			if (!$status['success'] || !file_exists($fifo))
				return error("export failed: %s", $status['stderr']);
			register_shutdown_function(function () use ($fifo) {
				if (file_exists($fifo)) {
					unlink($fifo);
				}

			});

			return $fifo;
		}

		public function export_pgsql($db, $file = null)
		{
			if (!IS_CLI)
				return $this->query('sql_export_pgsql', $db, $file);
			if (is_null($file))
				$file = $db . '.sql';

			if ($file[0] !== '/' && $file[0] !== '.' && $file[0] !== '~') {
				$path = $this->domain_fs_path() . '/tmp/' . $file;
			} else {
				$path = $this->file_make_path($file);
			}
			if (!$path) {
				return error("invalid file `%s'", $file);
			}

			if (!in_array($db, $this->list_pgsql_databases()))
				return error("invalid database `%s'", $db);

			$user = $this->_create_temp_pgsql_user($db);
			if (!$user) return error("pgsql export failed - unable to create user");

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
				$this->_delete_temp_user('pgsql', $user);
			}
			if (!is_null($fsizelimit)) {
				Util_Ulimit::set('fsize', $fsizelimit);
			}
			if (!file_exists($path))
				return error("export failed: %s", $status['stderr']);
			chown($path, $this->user_id) && chgrp($path, $this->group_id) && chmod($path, 0600);
			if (!$status['success'])
				return error("export failed: %s", $status['stderr']);
			return $this->file_unmake_path($path);
		}

		/**
		 * Export a PGSQL db to a named pipe for immediate download
		 *
		 * @param $db
		 * @return bool|void
		 */
		public function export_pgsql_pipe($db)
		{
			if (version_compare(platform_version(), '4.5', '<=')) {
				return error('platform version too old to support download feature');
			}

			if (!in_array($db, $this->list_pgsql_databases())) {
				return error("Invalid database " . $db);
			}

			$user = $this->_create_temp_pgsql_user($db);

			return $this->query('sql_export_pgsql_pipe_real', $db, $user);
		}

		/**
		 * Export a PGSQL database to a named pipe
		 *
		 * Differs from export_mysql_pipe in that it may only be called internally
		 * or from backend, no API access
		 *
		 * @param $db
		 * @param $user if empty use superuser
		 * @return bool|string|void
		 */
		public function export_pgsql_pipe_real($db, $user)
		{
			if (!IS_CLI) {
				return $this->query('sql_export_pgsql_pipe_real', $db, $user);
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

			if (!$status['success'] || !file_exists($fifo))
				return error("export failed: %s", $status['stderr']);
			register_shutdown_function(function () use ($fifo) {
				if (file_exists($fifo)) {
					unlink($fifo);
				}

			});

			return $fifo;
		}



		/***************** STATISTICS *******************/

		/**
		 * int get_pgsql_uptime
		 *
		 * @return int time in seconds
		 */
		public function get_pgsql_uptime()
		{
			$q = $this->psql->query("SELECT pg_postmaster_start_time() as st")->fetch_object();
			return $q->st;
		}

		/**
		 * int get_mysql_uptime
		 *
		 * @return int time in seconds
		 */
		public function get_mysql_uptime()
		{
			return $this->mysql->query("SHOW status LIKE 'uptime'")->fetch_object()->value;

		}

		public function add_mysql_backup($db, $extension = "zip", $span = 5, $preserve = '0', $email = '')
		{
			return $this->add_sql_backup('mysql', $db, $extension, $span, $preserve, $email);
		}

		public function add_pgsql_backup($db, $extension = "zip", $span = 5, $preserve = '0', $email = '')
		{
			return $this->add_sql_backup('pgsql', $db, $extension, $span, $preserve, $email);
		}

		public function edit_mysql_backup($db, $extension, $span = '0', $preserve = '0', $email = '')
		{
			return $this->edit_sql_backup('mysql', $db, $extension, $span, $preserve, $email);
		}

		public function edit_pgsql_backup($db, $extension, $span = '0', $preserve = '0', $email = '')
		{
			return $this->edit_sql_backup('mysql', $db, $extension, $span, $preserve, $email);
		}

		public function list_mysql_backups()
		{
			return $this->list_sql_backups('mysql');
		}

		public function list_pgsql_backups()
		{
			return $this->list_sql_backups('pgsql');
		}

		// {{{ delete_mysql_backup()

		/**
		 * Remove MySQL Backup
		 *
		 * @param string $db
		 * @return bool
		 */
		public function delete_mysql_backup($db)
		{
			return $this->delete_sql_backup('mysql', $db);
		}
		// }}}

		// {{{ delete_pgsql_backup()

		/**
		 * Remove PostgreSQL Backup
		 *
		 * @param string $db
		 * @return bool
		 */
		public function delete_pgsql_backup($db)
		{
			return $this->delete_sql_backup('pgsql', $db);
		}
		// }}}

		// {{{ get_mysql_backup_config()

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
		public function get_mysql_backup_config($db)
		{
			return $this->get_backup_config('mysql', $db);
		}

		// }}}

		// {{{ get_mysql_backup_config()

		/**
		 * Fetch backup information
		 *
		 * @see get_mysql_backup_config()
		 *
		 * @param string $db
		 * @return array
		 */
		public function get_pgsql_backup_config($db)
		{
			return $this->get_backup_config('pgsql', $db);
		}

		// }}}

		private function get_backup_config($type, $db)
		{
			if ($type != 'mysql' && $type != 'pgsql')
				return error($type . ": unknown type");

			$q = $this->mysql->query("SELECT day_span,
											 preserve,
											 UNIX_TIMESTAMP(next_date) as next_date,
											 extension,
											 email
									 FROM sql_dumps
									 WHERE db_type = '" . $type . "'
									 AND site_id = " . $this->site_id . "
									 AND db_name = '" . $db . "'");

			if ($q->num_rows < 1)
				return false;

			$row = $q->fetch_object();

			return array('span'      => $row->day_span,
			             'hold'      => $row->preserve,
			             'next'      => $row->next_date,
			             'extension' => $row->extension,
			             'email'     => $row->email);


		}


		private function add_sql_backup($type, $db, $extension, $span, $preserve, $email)
		{
			if (!$preserve)
				$preserve = '0';
			if ($type != 'mysql' && $type != 'pgsql')
				return error("invalid datanase type `%s'", $type);
			if ($type == 'mysql') {
				$dbs = $this->list_mysql_databases();
			} else {
				$dbs = $this->list_pgsql_databases();
			}

			if (!in_array($db, $dbs))
				return error("invalid database " . $db);
			else if (!in_array($extension, array('gz', 'bz', 'zip', 'none')))
				return error("Invalid extension");
			else if (intval($span) != $span || intval($preserve) != $preserve) {
				return error("Non-numeric type for day span/preservation amount");
			} else if ($span < 1) {
				return error("Day span value must be > 0");
			} else if (intval($email) != $email && !preg_match(Regex::EMAIL, $email)) {
				return error("Invalid e-mail address");
			}
			$q = "INSERT INTO
					sql_dumps
						(site_id,
						 db_type,
						 db_name,
						 day_span,
						 extension,
						 preserve,
						 next_date,

						 email)
				 VALUES
						(" . $this->site_id . ",
						 '" . $type . "',
						 '" . str_replace('\\', '', $db) . "',
						 " . $span . ",
						 '" . $extension . "',
						 " . $preserve . ",
						 NOW(),
						 '" . $email . "')
				 ON DUPLICATE KEY UPDATE
					day_span  = " . $span . ",
					extension = '" . $extension . "',
					preserve  =  " . $preserve . ",
					email     =  '" . $email . "';";
			try {
				$q = $this->mysql->query($q);
			} catch (Exception $e) {
				return error("general error setting backup routine");
			}
			return true;
		}

		private function edit_sql_backup($type, $db, $extension, $span, $preserve, $email)
		{
			if (!$preserve)
				$preserve = '0';
			if ($type != 'mysql' && $type != 'pgsql')
				return new ArgumentError("Invalid type " . $type);
			if ($type == 'mysql') {
				$dbs = $this->list_mysql_databases();
			} else {
				$dbs = $this->list_pgsql_databases();
			}
			if (!in_array($db, $dbs))
				return error("invalid database `%s'", $db);
			else if (!in_array($extension, array('gz', 'bz', 'zip', 'none')))
				return error("unrecognized extension `%s'", $extension);
			else if (!ctype_digit($span) || !ctype_digit($preserve))
				return error("non-numeric type for day span/preservation amount");
			else if ($email && !preg_match(Regex::EMAIL, $email))
				return error("invalid e-mail address");
			$q = $this->mysql->query("UPDATE
									sql_backups
								SET
									extension = '" . $extension . "',
									email = '" . $email . "',
									day_span = " . (!$span ? 'NULL' : $span) . ",
									preserve = " . $preserve . ",
									next_date = " . ($span > 1 ? 'DATE_ADD(NOW(), INTERVAL ".$span." DAY)' : null) . "
								WHERE
										db_type = '" . $type . "'
									AND
										db_name = '" . $db . "'
									AND
										site_id = " . $this->site_id . ";");
			return $this->mysql->affected_rows() > 0;

		}

		/**
		 *
		 * @return array
		 */
		private function list_sql_backups($type)
		{
			if ($type != 'pgsql' && $type != 'mysql')
				return new ArgumentError("Invalid database type " . $type);

			$backups = array();
			$fn = 'list_' . $type . '_databases';
			foreach ($this->$fn() as $db) {
				$task = $this->get_backup_config($type, $db);
				if (!$task)
					continue;
				$backups[$db] = $task;

			}
			return $backups;
		}

		private function delete_sql_backup($type, $db)
		{
			if ($type != 'mysql' && $type != 'pgsql')
				return new ArgumentError("Invalid type " . $type);
			$q = $this->mysql->query("DELETE FROM sql_dumps WHERE site_id = " . $this->site_id
				. " AND db_type = '" . $type . "' AND db_name = '"
				. $this->mysql->escape_string($db) . "';"
			);
			return $this->mysql->affected_rows() > 0;
		}

		// {{{ mysql_database_exists()

		/**
		 * Query information_schema for existence of MySQL database
		 *
		 * @param  string $db database name
		 * @return bool
		 */
		public function mysql_database_exists($db)
		{
			if (!IS_CLI) {
				return $this->query('sql_mysql_database_exists', $db);
			}
			$sqlroot = $this->domain_fs_path() . self::MYSQL_PATH;
			$normal = $this->_canonicalize_mysql_database($db);
			$prefix = $this->get_prefix();
			if (!file_exists($sqlroot . '/' . $normal)) {
				// tut-tut. Resolve db with prefix in mind
				$db = $prefix . $db;
			}

			$conn = $this->_connect_root();
			$dbsafe = $conn->escape_string($db);
			$q = $conn->query("SELECT db FROM db WHERE db = '" . $conn->escape_string($db) . "'");
			if ($q && $q->num_rows > 0) {
				return true;
			}
			$usersafe = $conn->escape_string($this->get_config('mysql', 'dbaseadmin'));
			$len = strlen($prefix . $prefix);
			// double prefix, remove first prefix, then check one last time
			if (!strncmp($db, $prefix . $prefix, $len)) {
				$db = substr($db, strlen($prefix));
				$dbsafe = $conn->escape_string($db);
			}
			$q = $conn->query("SELECT db FROM db WHERE db = '" . $dbsafe . "' AND user = '" . $usersafe . "'");
			return $q && $q->num_rows > 0;
		}

		// }}}

		public function mysql_user_exists($user, $host = 'localhost')
		{
			$conn = $this->_connect_root();
			$prefix = $this->get_prefix();
			if ($user != $this->get_service_value('mysql', 'dbaseadmin') &&
				strncmp($user, $prefix, strlen($prefix))
			) {
				$user = $prefix . $user;
			}

			$q = $conn->query("SELECT user FROM user WHERE user = '" .
				$conn->escape_string($user) . "' AND host = '" . $conn->escape_string($host) . "'");
			return !$q || $q->num_rows > 0;
		}

		/**
		 * Query PostgreSQL system table for existence of database
		 *
		 * @param string $db database name
		 * @return bool
		 */
		public function pgsql_database_exists($db)
		{
			$prefix = $this->get_prefix();
			if (strncmp($db, $prefix, strlen($prefix)))
				$db = $prefix . $db;
			$pgdb = $this->pgsql;
			$q = $pgdb->query_params("SELECT 1 FROM pg_database WHERE datname = $1", array($pgdb->escape_string($db)));
			return !$q || $pgdb->num_rows() > 0;
		}

		public function pgsql_user_exists($user)
		{
			$db = $this->pgsql;
			$prefix = $this->get_prefix();
			if ($user != $this->get_service_value('mysql', 'dbaseadmin') &&
				strncmp($user, $prefix, strlen($prefix))
			) {
				$user = $prefix . $user;
			}
			$q = $db->query_params("SELECT 1 FROM pg_authid WHERE rolname = $1", array($db->escape_string($user)));
			return !$q || $db->num_rows() > 0;
		}

		/**
		 * Returns the version of the MySQL server as an integer
		 *
		 * The form of this version number is
		 * main_version * 10000 + minor_version * 100 + sub_version
		 * (i.e. version 4.1.0 is 40100)
		 *
		 * @param $pretty bool pretty-print version
		 *
		 * @return int|string integer representing the server version or string
		 */
		public function mysql_version($pretty = false)
		{
			$db = $this->mysql;
			$version = $db->server_version;
			if (!$pretty) {
				return $version;
			}

			$mysqlver = array();
			foreach (array('patch', 'minor', 'major') as $v) {
				$mysqlver[$v] = $version % 100;
				$version /= 100;
			}
			return $mysqlver['major'] . '.' . $mysqlver['minor'] . '.' .
			$mysqlver['patch'];

		}

		public function pgsql_version()
		{
			$db = PostgreSQL::initialize();
			$handle = $db->getHandler();
			if (!is_resource($handle)) {
				// weird bug in PHP, $handle becomes unreferenced
				return null;
			}

			$version = pg_version($handle);
			if (!isset($version['server']))
				return null;
			$varr = explode(".", $version['server']);
			$version = $varr[0] * 10000;
			if (isset($varr[1])) {
				$version += $varr[1] * 100;
			}
			if (isset($varr[2])) {
				$version += $varr[2];
			}
			return $version;
		}

		/**
		 * Get active mysql connections
		 *
		 *  Array
		 *   (
		 *      [0] => Array
		 *      (
		 *          [id] => 11024
		 *          [user] => debug
		 *          [host] => localhost
		 *          [db] => debug
		 *          [command] => Query
		 *          [state] => User sleep
		 *          [info] => select sleep(1000)
		 *      )
		 *   )
		 *
		 * @return array
		 */
		public function mysql_processlist()
		{
			$conns = array();
			$db = $this->_connect_root();
			$user = $this->username;
			$prefix = $this->get_prefix();
			$q = "SELECT id, user, host, db, command, time, state, info FROM " .
				"information_schema.processlist WHERE user = '" .
				$db->real_escape_string($user) . "' OR user LIKE '" . $db->real_escape_string($prefix) . "%'";
			$rs = $db->query($q);
			while (false != ($row = $rs->fetch_object())) {
				$conns[] = array(
					'id'      => $row->id,
					'user'    => $row->user,
					'host'    => $row->host,
					'db'      => $row->db,
					'command' => $row->command,
					'state'   => $row->state,
					'info'    => $row->info
				);
			}
			return $conns;
		}

		public function repair_mysql_database($db)
		{
			if (!IS_CLI) {
				return $this->query('sql_repair_mysql_database', $db);
			}

			if (!$this->mysql_database_exists($db)) {
				return error("unknown database `%s'", $db);
			}

			$sqlroot = $this->domain_fs_path() . self::MYSQL_PATH;
			if (!file_exists($sqlroot . '/' . $db)) {
				// tut-tut. Resolve db with prefix in mind
				$prefix = $this->get_prefix();
				$db = $prefix . $db;
			}
			// make sure there are tables in this database to actually check...
			$files = glob($sqlroot . '/' . $db . '/*');
			if (count($files) < 2) {
				return true;
			}

			// negotiate to use mysqlcheck or myisamchk
			$quota = $this->site_get_account_quota();
			$db = $this->_connect_root();
			$q = "SELECT MAX(Data_length) AS max FROM " .
				"information_schema.tables WHERE table_schema = '" .
				$db->real_escape_string($db) . "'";
			$rs = $db->query($q);
			$tblsz = $rs->max/1024*1.25; //working room

			$qfree = $quota['qhard'] - $quota['qused'];
			$cmd = 'env HOME=/root mysqlcheck --auto-repair %s';
			if ($tblsz > $qfree) {
				warn("not enough storage to safely use mysqlcheck (need %d KB have %d KB free): reverting to myisamchk",
					$tblsz, $qfree
				);
				$cmd = 'myisamchk -r -c ' . $sqlroot . '/%s/*.MYI';
			}
			$ret = Util_Process_Safe::exec($cmd, $db);
			if (!$ret['success'] && !strstr($ret['stderr'], "doesn't exist")) {
				return error("`%s' repair failed:\n%s", $db, $ret['error']);
			}
			return info("`%s' repair succeeded:\n%s", $db, $ret['output']);
		}


		/**
		 * Kill a mysql connection
		 *
		 * @link mysql_processlist
		 * @param integer $id
		 * @return bool
		 */
		public function mysql_kill($id)
		{
			$db = $this->_connect_root();
			$id = intval($id);
			$procs = $this->mysql_processlist();
			$found = 0;
			foreach ($procs as $p) {
				if ($p['id'] == $id) {
					$found = 1;
					break;
				}
			}
			if (!$found) {
				return error("`%d': invalid query id specified", $id);
			}
			$q = "KILL $id";
			$rs = $db->query($q);
			return (bool)$rs;
		}

		/**
		 * Get max length of a column in mysql schema
		 *
		 * @param string $field
		 * @return int
		 */
		public function mysql_schema_column_maxlen($field)
		{
			static $cache = array();
			if (isset($cache[$field])) {
				return $cache[$field];
			}
			$db = $this->_connect_root();
			if ($field !== "user" && $field !== "db") {
				return error("unsupported field `%s' requested", $field);
			}

			$q = "SELECT CHARACTER_MAXIMUM_LENGTH AS maxlen " .
				"FROM INFORMATION_SCHEMA.COLUMNS WHERE " .
				"TABLE_SCHEMA = 'mysql' AND " .
				"TABLE_NAME = 'db' AND " .
				"COLUMN_NAME = '" . $field . "'";
			$res = $db->query($q);
			if (!$res) {
				return error("schema inquiry failed, `%s'", $db->error);
			}

			$rs = $res->fetch_object();
			$cache[$field] = (int)$rs->maxlen;
			return (int)$rs->maxlen;
		}

		private function _canonicalize_mysql_database($db)
		{
			if ($this->mysql_version() >= 50100) {
				$db = str_replace("-", "@002d", $db);
			}

			return $db;
		}

		private function _create_temp_pgsql_user($db)
		{

			$prefix = $this->get_prefix();
			$maxlen = self::MYSQL_USER_FIELD_SIZE - strlen($prefix);
			if ($maxlen < 1) return error("temp mysql user exceeds field length");
			$chars = array('a', 'b', 'c', 'd', 'e', 'f',
				'0', '1', '2', '3', '4', '5', '6', '7', '8', '9');
			$maxlen = min(6, $maxlen);

			$user = $prefix;
			for ($i = 0; $i < $maxlen; $i++) {
				$n = mt_rand(0, 15);
				$user .= $chars[$n];
			}

			$sqldb = $this->pgsql;
			$q = "SELECT rolname FROM pg_authid WHERE rolname = '" . $user . "'";
			$rs = $sqldb->query($q);
			if ($sqldb->num_rows() > 0) return error("cannot create temp pgsql user");

			$q = "CREATE ROLE \"" . $user . "\" WITH UNENCRYPTED PASSWORD '" . self::PG_TEMP_PASSWORD . "' INHERIT LOGIN " .
				"IN ROLE \"" . $this->get_pgsql_username() . "\"";
			$rs = $sqldb->query($q);

			if (!$rs || pg_last_error()) {
				return error("unable to create role on pgsql database %s", $db);
			}

			$q = "SELECT 'GRANT SELECT ON ' || relname || ' TO \"$user\";'
				FROM pg_class JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace
				WHERE nspname = 'public' AND relkind IN ('r', 'v');";
			$rs = $sqldb->query($q);
			if (!$rs->fetch_object()) {
				return error("cannot create temp pgsql user `%s'", $user);
			}
			$sqldb->query("GRANT \"" . $this->username . "\" TO \"" . $user . "\"");
			$this->_register_temp_user('pgsql', $user);
			return $user;

		}

		/**
		 * Create a temporary mysql user
		 *
		 * @param string $db
		 * @param bool   $return_connection
		 * @return string|object
		 */
		private function _create_temp_mysql_user($db)
		{
			$prefix = $this->get_prefix();
			$maxlen = self::MYSQL_USER_FIELD_SIZE - strlen($prefix);
			if ($maxlen < 1) return warn("temp mysql user exceeds field length, cannot create user");
			$chars = array('a', 'b', 'c', 'd', 'e', 'f',
				'0', '1', '2', '3', '4', '5', '6', '7', '8', '9');
			$maxlen = min(6, $maxlen);

			$user = $prefix;
			for ($i = 0; $i < $maxlen; $i++) {
				$n = mt_rand(0, 15);
				$user .= $chars[$n];
			}

			// could be handled via add_mysql_user()
			$sqldb = self::_connect_root();
			$q = "SELECT user FROM user WHERE user = '" . $user . "'";
			$rs = $sqldb->query($q);
			if ($rs->num_rows > 0) return error("cannot create temp mysql user");
			$q = "CREATE USER '" . $user . "'@'localhost' IDENTIFIED BY ''";
			$rs = $sqldb->query($q);
			if (!$rs) {
				return error("failed to create temp mysql user");
			}
			$q = "GRANT ALL ON `" . $db . "`.* to '" . $user . "'@localhost";
			$rs = $sqldb->query($q);
			if (!$rs) {
				return error("failed to create temp mysql user");
			}
			$this->_register_temp_user('mysql', $user);
			return $user;
		}

		private function _register_temp_user($sql, $user)
		{
			if ($sql != 'mysql' && $sql != 'pgsql') {
				return error("unknown database `$sql' while creating temp user");
			}

			$this->_tempUsers[$sql][] = $user;
			return true;
		}

		public function _delete_temp_user($dbtype, $user)
		{
			if ($dbtype == 'mysql') {
				return $this->_delete_temp_mysql_user($user);
			} else if ($dbtype == 'pgsql') {
				return $this->_delete_temp_pgsql_user($user);
			} else {
				fatal("unsupported database `%s'", $dbtype);
			}
		}

		/**
		 * Delete a temporary MySQL user
		 *
		 * @see  _delete_temp_user()
		 * @warn do not invoke directly, use wrapper _delete_temp_user()
		 * @param string $user
		 */
		private function _delete_temp_mysql_user($user)
		{
			if (!$this->delete_mysql_user($user, 'localhost', true)) {
				return false;
			}


			$idx = array_search($user, $this->_tempUsers['mysql']);
			if ($idx !== false) unset($this->_tempUsers['mysql'][$idx]);
			return true;
		}

		private function _delete_temp_pgsql_user($user)
		{
			if (!$this->delete_pgsql_user($user)) {
				return false;
			}

			$idx = array_search($user, $this->_tempUsers['pgsql']);
			if ($idx !== false) unset($this->_tempUsers['pgsql'][$idx]);
			return true;
		}

		public function _delete()
		{
			$dblang = array();
			if ($this->sql_enabled('mysql')) {
				$dblang = array_merge($dblang, array('mysql'));
			}
			if ($this->sql_enabled('pgsql')) {
				$dblang = array_merge($dblang, array('pgsql'));
			}
			foreach ($dblang as $lang) {
				$dbs = call_user_func(array($this, 'list_' . $lang . '_databases'));
				foreach ($dbs as $db) {
					call_user_func(
						array($this, 'delete_' . $lang . '_database'),
						$db
					);
				}
				$users = call_user_func(array($this, 'list_' . $lang . '_users'));
				foreach ($users as $user => $tmp) {
					foreach (array_keys($tmp) as $host) {
						call_user_func(
							array($this, 'delete_' . $lang . '_user'),
							$user, $host
						);
					}
				}
			}
		}

		public function _create()
		{
			if (!version_compare(platform_version(), '6.5', '>=')) {
				return;
			}

			$conf = Auth::profile()->conf->new;
			if ($conf['mysql']['enabled']) {
				$this->_createDatabase('mysql');
			}

			if ($conf['pgsql']['enabled']) {
				$this->_createDatabase('pgsql');
			}

		}

		private function _createDatabase($svc)
		{
			if ($svc != "pgsql" && $svc != "mysql") {
				return error("unknown database service `%s'", $svc);
			}

			$conf = Auth::profile()->conf->new;
			if (!$conf[$svc]['enabled']) {
				return;
			}
			if (isset($conf['mysql']['passwd'])) {
				$passwd = $conf['mysql']['passwd'];
			} else if (false !== ($tmp = $this->get_mysql_option('password', 'client'))) {
				$passwd = $tmp;
			} else {
				$passwd = sha1(mt_rand(0, time()) . SERVER_NAME_SHORT);
			}
			$proc = new Util_Process_Safe();
			$proc->setEnvironment('HOME', '/root');
			$ret = $proc->run('/usr/local/sbin/add%s-nodb.sh %s %s',
				$svc, $conf['siteinfo']['domain'], $passwd);

			if (!$ret['success']) {
				return error("failed to add %s for site `%s'",
					$svc, $conf['siteinfo']['domain']);
			}
			return true;
		}

		public function _edit()
		{
			$conf = Auth::profile()->conf;
			$conf_cur = $conf->cur['mysql'];
			$conf_new = $conf->new['mysql'];
			if ($conf_new == $conf_cur) return;

			$prefixold = $conf_cur['dbaseprefix'];
			$prefixnew = $conf_new['dbaseprefix'];
			$db = MySQL::initialize();
			if (!preg_match(Regex::SQL_PREFIX, $prefixnew)) {
				return error("invalid database prefix `%s'", $prefixnew);
			}
			if ($prefixold != $prefixnew) {
				if (strlen($prefixnew) > self::MYSQL_USER_FIELD_SIZE - 3 /* prefix + _xy */) {
					return error("database prefix max length is %d", (self::MYSQL_USER_FIELD_SIZE - 3));
				}
				$len = strlen($prefixold);
				$q = "UPDATE sql_dumps SET db_name = CONCAT('" .
					$db->escape_string($prefixnew) . "', SUBSTR(db_name, " . ($len + 1) . ")) WHERE " .
					"SUBSTR(db_name, 1, " . $len . ") = '" . $db->escape_string($prefixold) . "';";
				if (!$db->query($q)) {
					$this->add_error("sql backup rename failed");
				}
			}
			if (version_compare(platform_version(), '6.5', '<')) {
				return;
			}
			if ($conf->new['mysql']['enabled'] && !$conf->cur['mysql']['enabled']) {
				$this->_createDatabase('mysql');
			}

			if ($conf->new['pgsql']['enabled'] && !$conf->cur['pgsql']['enabled']) {
				$this->_createDatabase('pgsql');
			}
		}

	}

?>
