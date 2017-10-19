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
	 * MySQL and PostgreSQL operations
	 *
	 * @package core
	 */
	class Mysql_Module extends Module_Support_Sql
	{
		const MYSQL_USER_FIELD_SIZE = 16;

		const MYSQL_DATADIR = '/var/lib/mysql';

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
				'create_database_backend' => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'delete_database_backend' => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'get_uptime'              => PRIVILEGE_ALL,
				'assert_permissions'      => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'set_option'        => PRIVILEGE_ALL,
				'get_option'        => PRIVILEGE_ALL,
				'export_pipe_real'  => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'enabled'                 => PRIVILEGE_SITE | PRIVILEGE_USER,
				'repair_mysql_database'   => PRIVILEGE_SITE | PRIVILEGE_ADMIN,

				// necessary for DB backup routines
				'get_database_size'       => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'database_exists'   => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
				'_export_old'       => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
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

		public function user_exists($user, $host = 'localhost')
		{
			if (!$user) {
				return false;
			}
			$conn = $this->_connect_root();
			$prefix = $this->get_prefix();
			if ($user !== $this->get_service_value('mysql', 'dbaseadmin') &&
				0 !== strpos($user, $prefix)
			) {
				$user = $prefix . $user;
			}

			$q = $conn->query("SELECT user FROM user WHERE user = '" .
				$conn->escape_string($user) . "' AND host = '" . $conn->escape_string($host) . "'");
			return !$q || $q->num_rows > 0;
		}

		public function get_prefix()
		{
			return $this->get_service_value('mysql', 'dbaseprefix');
		}

		/**
		 * Delete a temporary MySQL user
		 *
		 * @warn do not invoke directly, use wrapper _delete_temp_user()
		 * @param string $user
		 * @return bool
		 */
		private function _delete_temp_user($user)
		{
			if (!$this->delete_user($user, 'localhost', true)) {
				return false;
			}


			$idx = array_search($user, $this->_tempUsers);
			if ($idx !== false) {
				unset($this->_tempUsers[$idx]);
			}
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
		public function delete_user($user, $host, $cascade = true)
		{
			if ($user == $this->username && !Util_Account_Hooks::is_mode('delete')) {
				return error("Cannot remove main user");
			} else {
				if (!$this->user_exists($user, $host)) {
					return error("user `%s' on `%s' does not exist", $user, $host);
				}
			}
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
			if ($stmt->error) {
				return new MySQLError("Invalid query, " . $stmt->error);
			}
			if ($cascade) {
				$stmt2 = $conn->prepare("DELETE FROM db WHERE user = ? AND host = ?");
				$stmt2->bind_param("ss", $user, $host);
				$stmt2->execute();
				if (!$stmt2->error) {
					$conn->query("FLUSH PRIVILEGES");
				} else {
					return new MySQLError("Invalid query, " . $stmt2->error);
				}


			}
			return ($stmt->affected_rows > 0);

		}

		/**
		 * bool store_sql_password (string, string)
		 *
		 * @param string $sqlpasswd plaintext password
		 * @return bool
		 */
		public function store_password($sqlpasswd)
		{
			return $this->set_option("password", $sqlpasswd, 'client');
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
		public function set_option($option, $value = null, $group = 'client')
		{
			$home = $this->user_get_user_home();
			if (!$this->file_file_exists($home . '/.my.cnf')) {
				$this->file_create_file($home . '/.my.cnf', 0600);
			}
			$lines = explode("\n", $this->file_get_file_contents($home . '/.my.cnf'));
			$group_set = $group && false;
			$config = array();
			$found = false;
			$cgroup = '';
			if ($value && !ctype_alnum($value)) {
				$value = '"' . str_replace('"', '\"', $value) . '"';
			}

			// I should rewrite this on more than 0 hours of sleep
			for ($i = 0, $n = sizeof($lines); $i < $n; $i++) {
				$line = trim($lines[$i]);
				if (!$line) {
					continue;
				}
				if ($line[0] == '[' && substr($line, -1) == ']') {
					$cgroup = substr($line, 1, -1);
					if (!isset($config[$cgroup])) {
						$config[$cgroup] = array();
					}
					if ($cgroup == $group) {
						$group_set = true;
					} else {
						if ($group) {
							$group_set = false;
						}
					}
					continue;
				}

				if ($group_set) {
					if (0 === strpos($line, $option)) {
						$found = true;
						if ($value === false) {
							continue;
						}
						$line = $option . ($value ? '=' . $value : '');
					}
				}
				$config[$cgroup][] = $line;
			}

			if (!$found) {
				if ($group && !isset($config[$cgroup])) {
					$config[$group] = array();
				}
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
		 * string retrieve_sql_password (string)
		 *
		 * @return string
		 */
		public function get_password()
		{
			return $this->get_option('password');
		}

		/**
		 * Get option from MySQL client/server configuration
		 *
		 * @param  string $option option name
		 * @param  string $group  option group
		 * @return mixed option value, false on failure, null on empty value
		 */
		public function get_option($option, $group = 'client')
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
						if (!$endpos) {
							$endpos = strlen($config);
						}
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

		public function get_elevated_password_backend()
		{
			if (!IS_CLI) {
				fatal("needs execution from backend");
			}
			return Opcenter\Database\MySQL::rootPassword();
		}

		/**
		 * Import a database from a dump
		 *
		 * @see Mysql_Module::export()
		 *
		 * @param string $db database name
		 * @param string $file filename
		 * @return bool
		 */
		public function import($db, $file)
		{
			if (!IS_CLI) {
				return $this->query('mysql_import', $db, $file);
			}

			$prefix = $this->get_prefix();
			// db name passed without prefix
			if (strncmp($db, $prefix, strlen($prefix))) {
				$db = $prefix . $db;
			}

			$dbs = $this->list_databases();
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
					if ($c == ' ' || $c === '') {
						continue;
					} else {
						if ($c == '/' || $c === '-') {
							break;
						}
					}
					if (0 === strpos($line, "CREATE DATABASE") ||
						0 === strpos($line, "USE DATABASE"))
					{
						$pos = ftell($fp) - strlen($line);
						fseek($fp, $pos);
						warn("`%s' statement redacted", trim($line));
						fwrite($fp, '-- ');
						fgets($fp);
					}
					break;
				}
			}
			$user = $this->_create_temp_user($db);
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

		/**
		 * array list_mysql_databases ()
		 * Queries the db table in the mysql database for applicable grants
		 *
		 * @return array list of databases
		 */
		public function list_databases()
		{
			$prefix = $this->_escape($this->get_prefix());
			$conn = new mysqli("localhost", self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			$q = $conn->query("SELECT DISTINCT(REPLACE(db,'\\_','_')) AS db FROM db WHERE db LIKE '" . $prefix . "%' OR user = '" . $this->username . "'");
			$dbs = array();
			while (null != ($row = $q->fetch_object())) {
				$dbs[] = $row->db;
			}

			$conn->close();
			return $dbs;
		}

		/**
		 * Create a temporary mysql user
		 *
		 * @param string $db
		 * @param bool   $return_connection
		 * @return string|object
		 */
		private function _create_temp_user($db)
		{
			$prefix = $this->get_prefix();
			$maxlen = self::MYSQL_USER_FIELD_SIZE - strlen($prefix);
			if ($maxlen < 1) {
				return warn("temp mysql user exceeds field length, cannot create user");
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

			// could be handled via add_mysql_user()
			$sqldb = self::_connect_root();
			$q = "SELECT user FROM user WHERE user = '" . $user . "'";
			$rs = $sqldb->query($q);
			if ($rs->num_rows > 0) {
				return error("cannot create temp mysql user");
			}
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
			$this->_register_temp_user($user);
			return $user;
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
			deprecated("use sql_get_prefix");
			return $this->get_prefix();
		}

		/**
		 * array list_mysql_users ()
		 * Lists all created users for MySQL
		 */
		public function list_users()
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
			while (null !== ($row = $q->fetch_object())) {
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
		 * bool add_mysql_user(string, string, string[, int[, int[, int[, string[, string[, string[, string]]]]]]])
		 */
		public function add_user(
			$user,
			$host,
			$password,
			$maxconn = 5,
			$maxupdates = 0,
			$maxquery = 0,
			$ssl = '',
			$cipher = '',
			$issuer = '',
			$subject = ''
		) {
			if (!$user) {
				return error("no username specified");
			}
			$dbaseadmin = $this->get_config('mysql', 'dbaseadmin');
			if ($user === $dbaseadmin && !IS_SOAP) {
				return error("cannot name user after primary account user, `%s'", $dbaseadmin);
			}

			$ssl = strtoupper($ssl);
			if (!$maxconn) {
				$maxconn = 5;
			}
			$host = trim($host);
			if ($host != 'localhost') {
				if (!ip2long($host) && !preg_match(Regex::SQL_MYSQL_IP_WILDCARD, $host)) {
					return error("rejected host `%s': only numeric IP addresses are permitted, not hostnames", $host);
				}
			}
			if (strlen($password) < self::MIN_PASSWORD_LENGTH) {
				return error("Password must be at least %d characters", self::MIN_PASSWORD_LENGTH);
			} else if ($ssl != '' && $ssl != 'ANY' && $ssl != 'X509' && $ssl != 'SPECIFIED') {
				return error("Invalid SSL type");
			} else if ($maxconn < 1 || $maxquery < 0 || $maxupdates < 0) {
				return error("Max connections, queries, and updates must be greater than 0");
			} else if ($maxconn > \Sql_Module::PER_DATABASE_CONNECTION_LIMIT) {
				return error("Max concurrent connections cannot exceed %d. " .
					"Open a ticket with explanation if you need more than %d.",
					\Sql_Module::PER_DATABASE_CONNECTION_LIMIT, \Sql_Module::PER_DATABASE_CONNECTION_LIMIT);
			} else if ($this->user_exists($user, $host)) {
				return error("mysql user `$user' on `$host' exists");
			}
			$conn = $this->_connect_root();
			$prefix = $this->get_prefix();
			if ($user != $this->get_config('mysql', 'dbaseadmin') && 0 !== strpos($user, $prefix)) {
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
			$needAuth = $conn->columnExists('authentication_string', 'user');
			$query = "INSERT INTO user
				(host,
				 user,
				 password,
				 ssl_type,
				 ssl_cipher,
				 x509_issuer,
				 x509_subject,
				 max_questions,
				 max_updates,			  
				 max_user_connections" . ($needAuth ? ', authentication_string' : '') . ')
			VALUES
				(?,
				 ?,
				 ' . $pwclause . ',
				 ?,
				 ?,
				 ?,
				 ?,
				 ?,
				 ?,
				 ?' . ($needAuth ? ',""' : '') . ');';
			$stmt = $conn->prepare($query);
			$stmt->bind_param("sssssssiii", $host, $user, $password, $ssl, $cipher,
				$issuer, $subject, $maxquery, $maxupdates, $maxconn);
			$stmt->execute();
			if ($stmt->error) {
				return new MySQLError("Invalid query, " . $stmt->error);
			}
			$conn->query("FLUSH PRIVILEGES;");

			if ($stmt->affected_rows < 1) {
				return error("user creation `%s@%s' failed", $user, $host);
			}
			return true;
		}

		public function get_database_charset($db)
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

		public function create_database($db, $charset = 'latin1', $collation = 'latin1_general_ci')
		{
			if (!IS_CLI) {
				return $this->query('mysql_create_database', $db, $charset, $collation);
			}

			$charset = strtolower($charset);
			$collation = strtolower($collation);

			if (!preg_match('/^[a-zA-Z_0-9-]+$/', $db)) {
				return error("invalid database name `%s'", $db);
			}
			if (!$this->charset_valid($charset)) {
				return error("unrecognized mysql charset `%s'", $charset);
			}
			if (!$this->collation_valid($collation)) {
				return error("invalid mysql collation `%s'", $collation);
			} else if (!$this->collation_compatible($collation, $charset)) {
				warn("collation `%s' for charset `%s' not sensible", $collation, $charset);
			}

			$prefix = $this->get_prefix();

			// db name passed without prefix
			if (0 !== strpos($db, $prefix)) {
				$db = $prefix . $db;
			}

			if ($this->database_exists($db)) {
				return error("database `$db' exists");
			}
			$status = $this->query('mysql_create_database_backend', $db, $charset, $collation);
			if (!$status) {
				return $status;
			}

			$conn = new mysqli('localhost', self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			$conn->query("GRANT ALL ON `" . $db . "`.* to " . $this->username . "@localhost;");
			if ($conn->error) {
				echo "DROPPING";
				\Opcenter\Database\MySQL::dropDatabase($db);
				return error("failed to create db `%s'. Error while applying grants: `%s' ".
					"- is control user `%s' missing?",
					$db,
					$conn->error,
					$this->username
				);
			}
			return info("created database `%s'", $db);

		}

		public function charset_valid($charset)
		{
			$charset = strtolower($charset);
			$charsets = $this->get_supported_charsets();
			return array_key_exists($charset, $charsets);
		}

		public function get_supported_charsets()
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

		/**
		 * Validate collation name
		 *
		 * @param string $collation
		 * @return bool
		 */
		public function collation_valid($collation)
		{
			$collations = $this->get_supported_collations();
			$collation = strtolower($collation);
			foreach ($collations as $c) {
				if ($c['collation'] === $collation) {
					return true;
				}
			}
			return false;
		}

		public function get_supported_collations()
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

			while (null !== ($row = $rs->fetch_object())) {
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
		public function collation_compatible($collation, $charset)
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
		 * Query information_schema for existence of MySQL database
		 *
		 * @param  string $db database name
		 * @return bool
		 */
		public function database_exists($db): bool
		{
			if (!IS_CLI) {
				return $this->query('mysql_database_exists', $db);
			}
			if (!$db) {
				return false;
			}
			$sqlroot = $this->domain_fs_path() . self::MYSQL_DATADIR;
			$normal = \Opcenter\Database\MySQL::canonicalize($db);
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
			} else if ($this->permission_level & PRIVILEGE_ADMIN) {
				// used by db backup routine, in future the task should be
				// removed from backup, but leave this as it is for now
				return false;
			}
			$usersafe = $conn->escape_string($this->get_config('mysql', 'dbaseadmin'));
			// double prefix, remove first prefix, then check one last time
			if (0 === strpos($db, $prefix.$prefix)) {
				$db = (string)substr($db, strlen($prefix));
				$dbsafe = $conn->escape_string($db);
			}
			$q = $conn->query("SELECT db FROM db WHERE db = '" . $dbsafe . "' AND user = '" . $usersafe . "'");
			return $q && $q->num_rows > 0;
		}

		/**
		 * bool create_mysql_database_backend (string)
		 * {@link create_mysql_database}
		 */
		public function create_database_backend($db, $charset, $collation)
		{
			$dboptData = "default-character-set=" . $charset . "\n" .
				"default-collation=" . $collation;
			$path = $this->domain_fs_path();
			if (version_compare(platform_version(), '4.5', '>=')) {
				/**
				 * use shadow/ on OverlayFS platforms too. mysqldump
				 * communicates with mysqld to dump tables, so there's
				 * no risk of ghosting as seen if we write directly to shadow/
				 * and query from the composite path fst/
				 */
				$path = $this->domain_shadow_path();
			}
			$dbcan = \Opcenter\Database\MySQL::canonicalize($db);

			if (file_exists(self::MYSQL_DATADIR . '/' . $dbcan)) {
				return error("database `%s' exists", $db);
			}
			if (!file_exists($path . self::MYSQL_DATADIR)) {
				return error("base directory for MySQL doesn't exist");
			}
			$path .= self::MYSQL_DATADIR . '/' . $dbcan;

			if (!file_exists($path)) {
				\Opcenter\Filesystem::mkdir($path, 'mysql', $this->group_id, 02750);
			}
			clearstatcache(true, self::MYSQL_DATADIR . '/' . $dbcan);
			symlink($path, self::MYSQL_DATADIR . '/' . $dbcan);

			$fp = fopen($path . '/db.opt', 'w');
			fwrite($fp, $dboptData);
			fclose($fp);
			chown($path . '/db.opt', 'mysql');
			chgrp($path . '/db.opt', (int)$this->group_id);
			return file_exists(self::MYSQL_DATADIR . '/' . $dbcan) && file_exists($path);
		}

		/**
		 * bool add_mysql_user_permissions (string, string, string, array)
		 *
		 * @deprecated
		 * @see Mysql_Module::set_privileges()
		 *
		 * @param string $user
		 * @param string $host
		 * @param string $db
		 * @param array  $opts
		 * @return bool
		 */
		public function add_user_permissions($user, $host, $db, array $opts)
		{
			deprecated_func("use set_mysql_privileges()");
			return $this->set_privileges($user, $host, $db, $opts);
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
		public function set_privileges($user, $host, $db, array $privileges)
		{
			if (!$host) {
				return error("invalid host name `$host'");
			}

			$privileges = array_change_key_case($privileges);
			$prefix = $this->get_prefix();
			if ($user != $this->get_service_value('mysql', 'dbaseadmin') &&
				strncmp($user, $prefix, strlen($prefix))
			) {
				$user = $prefix . $user;
			}
			if ($user != $this->username && !preg_match('/^' . $prefix . '/', $user)) {
				return error("invalid user `%s'", $user);
			}
			$conn = new mysqli('localhost', self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			/** ignore prefixed dbs as they should have ownership rights */
			if (!preg_match('!/^' . preg_quote($prefix, '!') . '!', $db)) {
				$rs = $conn->query("SELECT 1 FROM db WHERE user = '" . $this->username . "' AND db = '" . $db . "'");
				if ($rs->num_rows < 1) {
					return error("No grants found in database on `%s' for user `%s'", $db, $this->username);
				}
			}

			$valid_opts = array(
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
				'show_view'        => false,
				'create_view'      => false,
				'create_routine'   => false,
				'alter_routine'    => false,
				'lock_tables'      => false,
				'execute'          => false,
			);

			// MySQL 5.1 supports triggers, available on platform 4.5+
			if (version_compare(platform_version(), '4.5', '>=')) {
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
				if (isset($privileges[($opt)]) && $privileges[$opt]) {
					$valid_opts[$opt] = $opt . '_priv';
				} else {
					unset($valid_opts[$opt]);
				}
			}

			$revoke_opts = array_diff_key($opts_copy, $valid_opts);
			foreach (array_keys($opts_copy) as $name) {
				$opts[] = (isset($valid_opts[$name])) ? 'Y' : 'N';
			}
			array_walk($opts_copy, function (&$key, $val) {
				$key = $val . "_priv";
			});
			$conn->query("REPLACE INTO db (" . join($opts_copy,
					", ") . ", `host`, `db`, `user`) VALUES ('" . join($opts,
					"', '") . "', '" . $host . "', '" . $db . "', '" . $user . "');");

			$ar = $conn->affected_rows;

			if ($conn->error) {
				return new MySQLError("Error when applying grants, " . $conn->error);
			}

			$conn->query("FLUSH PRIVILEGES;");
			return $ar > 0;
		}

		/**
		 *
		 * @deprecated
		 * @see Mysql_Module::revoke_privileges()
		 */
		public function delete_user_permissions($user, $host, $db)
		{
			deprecated_func("use revoke_from_mysql_db()");
			return $this->revoke_privileges($user, $host, $db);
		}

		/**
		 * Revoke all privileges on a database from a MySQL user
		 *
		 * @param string $user
		 * @param string $host
		 * @param string $db
		 * @return bool
		 */
		public function revoke_privileges($user, $host, $db)
		{
			$prefix = $this->get_prefix();
			if ($user != $this->get_service_value('mysql', 'dbaseadmin') &&
				strncmp($user, $prefix, strlen($prefix))
			) {
				$user = $prefix . $user;
			}
			if ($user != $this->username && !preg_match('/^' . $prefix . '/', $user)) {
				return error("invalid user `$user'");
			}
			$conn = new mysqli('localhost', self::MASTER_USER, $this->_get_elevated_password());
			$conn->select_db("mysql");
			$stmt = $conn->prepare("DELETE FROM db WHERE user = ? AND host = ? AND db = ?");
			$stmt->bind_param("sss", $user, $host, $db);
			$res = $stmt->execute();
			if (!$res) {
				return error("Query error while dropping permissions, " . $stmt->error);
			}

			$conn->query("FLUSH PRIVILEGES;");
			return $stmt->affected_rows > 0;
		}

		// {{{ enabled()

		public function get_user_permissions($user, $host, $db)
		{
			deprecated_func("use get_privileges()");
			return $this->get_privileges($user, $host, $db);
		}

		// }}}

		/**
		 * Get MySQL grants for a user on a database
		 *
		 * @param string $user
		 * @param string $host
		 * @param string $db
		 * @return array
		 */
		public function get_privileges($user, $host, $db)
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
			if ($this->version() >= 50100) {
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
				array_walk($priv, function (&$key, &$val) { $key = $key == "Y"; });
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
			if (version_compare(platform_version(), '4.5', '<')) {
				unset($priv['event']);
				unset($priv['trigger']);
			}
			return $priv;
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
		public function version($pretty = false)
		{
			$version = \Opcenter\Database\MySQL::version();
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

		/**
		 * Delete MySQL database from system
		 *
		 * @param  string $db database
		 * @return bool
		 */
		public function delete_database($db)
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
					return $this->delete_database($db);
				}
				return error("Unknown database `%s'", $db);
			}
			$stmt->free_result();
			$this->query('mysql_assert_permissions');

			$stmt = $conn->prepare("DELETE FROM db WHERE db = ?");
			$stmt->bind_param("s", $db);
			$stmt->execute();

			// FLUSH is necessary, because MySQL will permit a separate CREATE DATABASE
			// query by the former owner bypassing this requirement
			// (it also bypasses filesystem namespacing + quota attribution)
			$conn->query("FLUSH PRIVILEGES");

			$q = $conn->query("DROP DATABASE IF EXISTS `" . $db . "`");
			if (!$q) {
				return error("unable to drop database `$db': %s", $conn->error);
			}
			$this->query('mysql_delete_database_backend', $db);

			$this->delete_backup($db);


			if ($conn->error) {
				return error("error while removing database `$db' - " . $conn->error);
			}
			return true;
		}

		/**
		 * Remove MySQL Backup
		 *
		 * @param string $db
		 * @return bool
		 */
		public function delete_backup($db)
		{
			return parent::delete_backup_real('mysql', $db);
		}

		/**
		 * Ensure that /var/lib/mysql/ has mysql:<group id> ownership
		 */
		public function assert_permissions()
		{
			if (!file_exists($this->domain_fs_path() . self::MYSQL_DATADIR)) {
				return false;
			}

			chown($this->domain_fs_path() . self::MYSQL_DATADIR, 'mysql');
			chgrp($this->domain_fs_path() . self::MYSQL_DATADIR, $this->group_id);
			return true;
		}

		public function delete_database_backend($db)
		{
			$db = \Opcenter\Database\MySQL::canonicalize($db);
			if (is_link(self::MYSQL_DATADIR . '/' . $db)) {
				unlink(self::MYSQL_DATADIR . '/' . $db);
			}

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
		public function edit_user($user, $host, $opts)
		{
			$prefix = $this->get_prefix();
			if ($user != $this->get_service_value('mysql', 'dbaseadmin') &&
				0 !== strpos($user, $prefix))
			{
				$user = $prefix . $user;
			}
			if (!is_array($opts)) {
				return error("Options must be an array");
			}
			if (isset($opts['cipher_type'])) {
				$opts['cipher_type'] = strtoupper($opts['cipher_type']);
				if ($opts['cipher_type'] != '' && $opts['cipher_type'] != 'ANY' &&
					$opts['cipher_type'] != 'SPECIFIED' && $opts['cipher_type'] != 'X509'
				) {
					return error("Invalid cipher type");
				}
			}
			if (isset($opts['host']) && $opts['host'] != 'localhost') {
				if (!ip2long($opts['host']) && !preg_match(Regex::SQL_MYSQL_IP_WILDCARD, $opts['host'])) {
					return error("rejected host `%s': only numeric IP addresses are permitted, not hostnames",
						$opts['host']);
				}
			}

			$defaults = array(
				'host'                 => $host,
				'password'             => null,
				'max_user_connections' => 5,
				'max_updates'          => 0,
				'max_questions'        => 0,
				'use_ssl'              => false,
				'cipher_type'          => '',
				'ssl_cipher'           => '',
				'x509_subject'         => '',
				'x509_issuer'          => ''
			);

			// make copy to check for max_user_connections change
			// later in event of password update
			$mergeopts = $opts;
			foreach ($defaults as $def_nam => $def_val) {
				if (!isset($mergeopts[$def_nam])) {
					$mergeopts[$def_nam] = $def_val;
				}
			}
			/** if we're not using SSL, blank it out */
			if (!$mergeopts['use_ssl']) {
				$mergeopts['x509_subject'] = $mergeopts['x509_issuer'] = $mergeopts['ssl_cipher'] = $mergeopts['cipher_type'] = '';
			} else {
				$mergeopts['cipher_type'] = 'ANY';
			}

			if ($mergeopts['max_user_connections'] < 1) {
				$mergeopts['max_user_connections'] = 5;
			}

			if ($mergeopts['max_questions'] < 0 || $mergeopts['max_updates'] < 0) {
				return error("Max queries and updates must be greater than 0");
			} else {
				if (isset($opts['max_user_connections']) && $opts['max_user_connections'] > \Sql_Module::PER_DATABASE_CONNECTION_LIMIT) {
					return error("Max connection limit %d. Must file a ticket justifying need. " .
						"Check index placements first.", \Sql_Module::PER_DATABASE_CONNECTION_LIMIT);
				} else {
					if (!is_null($mergeopts['password']) && strlen($mergeopts['password']) < self::MIN_PASSWORD_LENGTH) {
						return error("password must be at least %d characters long", self::MIN_PASSWORD_LENGTH);
					}
				}
			}
			$conn = $this->_connect_root();

			$stmt = $conn->prepare("SELECT user FROM user WHERE user = ? AND host = ?");
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
			if ($stmt->error) {
				return new MySQLError("Invalid query, " . $stmt->error);
			}
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
					strlen($password) == 16 && ctype_xdigit($password) && version_compare(platform_version(), "6", '<')
				) {
					$pwclause = '?';
				}
				$stmt2 = $conn->prepare("UPDATE user SET password = " . $pwclause . " WHERE user = ? AND host = ?;");

				$stmt2->bind_param("sss", $password, $user, $mergeopts['host']);
				$stmt2->execute();
				if ($stmt2->error) {
					return new MySQLError("Query error while updating password, " . $stmt2->error);
				}
				if ($user == $this->username) {
					$this->set_option('user', $this->username, 'client');
					$this->set_option('password',
						str_replace(array('"'), array('\"'), $password),
						'client'
					);
				}
			}
			$conn->query("FLUSH PRIVILEGES");
			return true;
		}

		/**
		 * bool service_enabled (string)
		 *
		 * Checks to see if a service is enabled
		 *
		 * @deprecated
		 * @see Mysql_Module::enabled()
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
			return parent::svc_enabled('mysql');
		}

		public function truncate_database($db)
		{

			return $this->_mysql_empty_truncate_wrapper($db, "truncate");
		}

		private function _mysql_empty_truncate_wrapper($db, $mode)
		{
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

			if (!$this->database_exists($db)) {
				return error("unknown database, `%s'", $db);
			}

			$user = $this->_create_temp_user($db);
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
			$this->_delete_temp_user($user);
			return true;
		}

		public function empty_database($db)
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
		public function export($db, $file = null)
		{
			if (!IS_CLI) {
				return $this->query('mysql_export', $db, $file);
			}

			if (is_null($file)) {
				$file = $db . '.sql';
			}
			if (!in_array($db, $this->list_databases())) {
				return error("Invalid database " . $db);
			}
			if ($file[0] !== '/' && $file[0] !== '.' && $file[0] !== '~') {
				$file = '/tmp/' . $file;
			}
			$pdir = dirname($file);
			if (!$this->file_file_exists($pdir) && !$this->file_create_directory($pdir, 0755, true)) {
				return error("failed to create parent directory, `%s'", $pdir);
			}
			$path = $this->file_make_path($file);
			if (!$path) {
				return error("invalid file `%s'", $file);
			}
			$user = $this->_create_temp_user($db);
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

			if (!$status['success'] || !file_exists($path)) {
				return error("export failed: %s", $status['stderr']);
			}
			chown($path, $this->user_id) && chgrp($path, $this->group_id) && chmod($path, 0600);
			if (!$status['success']) {
				return error("export failed: %s", $status['stderr']);
			}

			return $this->file_unmake_path($path);
		}

		// {{{ delete_mysql_backup()

		/**
		 * Get disk space occupied by database
		 *
		 * @param string $db   database name
		 * @return int storage in bytes
		 */
		public function get_database_size($db)
		{
			if (!IS_CLI) {
				$resp = $this->query('mysql_get_database_size', $db);
				return (int)$resp;
			}

			// mysql type
			$dir = self::MYSQL_DATADIR . '/' . \Opcenter\Database\MySQL::canonicalize($db);
			// database created as directory in /var/lib/mysql
			// instead of under fst
			if (($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) && !is_link($dir)) {
				$this->_move_db($db);
			}
			if (!file_exists($dir) || (is_link($dir) && !readlink($dir))) {
				warn($db . ": database does not exist");
				return 0;
			}

			$space = 0;
			$dh = opendir($dir);
			if (!$dh) {
				error("failed to open database directory `%s'", $dir);
				return 0;
			}
			while (($file = readdir($dh)) !== false) {
				if ($file == "." || $file == "..") {
					continue;
				}
				$space += filesize($dir . '/' . $file);
			}
			closedir($dh);
			return $space;
		}
		// }}}

		private function _move_db($db)
		{

			/**
			 * make sure the DB is accessed by the correct user
			 * otherwise the DB will be relocated under the caller's fs
			 */
			$prefix = $this->get_service_value('mysql', 'dbaseadmin');
			if (strncmp($db, $prefix, strlen($prefix))) {
				return true;
			}
			$dbfs = \Opcenter\Database\MySQL::canonicalize($db);
			$src = self::MYSQL_DATADIR . '/' . $dbfs;
			$dest = $this->domain_fs_path() . self::MYSQL_DATADIR . '/' . $dbfs;
			if (is_dir($dest)) {
				report("dest db exists - %s", $dest);
				return false;
			}
			\Opcenter\Filesystem::mkdir($dest, 'mysql', $this->group_id, 02750);
			/* a read lock should be used in this situation to ensure
			 * absolutely no data is lost in the process
			 * only a global flush tables would work, but this can
			 * cause a 15+ second hang while tables are flushed
			 * as a consequence, forgo the read lock and just move the files
			 *
			 * this process is also quicker than an export/import routine
			 */

			$dh = opendir($src);
			if (!$dh) {
				return error("could not relocate database `%s'", $db);
			}

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
		// }}}

		// {{{ get_mysql_backup_config()

		/**
		 * Export a db to a named pipe for immediate download
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

			return $this->query('mysql_export_pipe_real', $db, $user);
		}

		// }}}

		// {{{ get_mysql_backup_config()

		/**
		 * Export a database to a named pipe
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
				return $this->query('mysql_export_pipe_real', $db, $user);
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

		// }}}

		/**
		 * int get_mysql_uptime
		 *
		 * @return int time in seconds
		 */
		public function get_uptime()
		{
			$db = MySQL::initialize();
			return $db->query("SHOW status LIKE 'uptime'")->fetch_object()->value;

		}

		// {{{ mysql_database_exists()

		public function add_backup($db, $extension = "zip", $span = 5, $preserve = '0', $email = '')
		{
			return parent::add_backup_real('mysql', $db, $extension, $span, $preserve, $email);
		}

		public function edit_backup($db, $extension, $span = '0', $preserve = '0', $email = '')
		{
			return $this->edit_backup_real('mysql', $db, $extension, $span, $preserve, $email);
		}

		public function list_backups()
		{
			return parent::list_backups_real('mysql');
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
			return parent::get_backup_config_real('mysql', $db);
		}

		public function repair_database($db)
		{
			if (!IS_CLI) {
				return $this->query('mysql_repair_database', $db);
			}

			if (!$this->database_exists($db)) {
				return error("unknown database `%s'", $db);
			}

			$sqlroot = $this->domain_fs_path() . self::MYSQL_DATADIR;
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
			$conn = $this->_connect_root();
			$q = "SELECT MAX(Data_length) AS max FROM " .
				"information_schema.tables WHERE table_schema = '" .
				$conn->real_escape_string($db) . "'";
			$rs = $conn->query($q);
			$row = $rs->fetch_object();
			$tblsz = $row->max / 1024 * 1.25; //working room

			$qfree = $quota['qhard'] - $quota['qused'];
			$cmd = 'env HOME=/root mysqlcheck --auto-repair %s';
			if ($tblsz > $qfree) {
				warn("not enough storage to safely use mysqlcheck (need %d KB have %d KB free): reverting to myisamchk",
					$tblsz, $qfree
				);
				$cmd = 'myisamchk -r -c ' . $sqlroot . '/%s/*.MYI';
			}
			$ret = Util_Process_Safe::exec($cmd, array($db));
			if (!$ret['success'] && !strstr($ret['stderr'], "doesn't exist")) {
				return error("`%s' repair failed:\n%s", $db, $ret['stderr']);
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
		public function kill($id)
		{
			$db = $this->_connect_root();
			$id = intval($id);
			$procs = $this->get_processlist();
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
		public function get_processlist()
		{
			$conns = array();
			$db = $this->_connect_root();
			$user = $this->username;
			$prefix = $this->get_prefix();
			$q = "SELECT id, user, host, db, command, time, state, info FROM " .
				"information_schema.processlist WHERE user = '" .
				$db->real_escape_string($user) . "' OR user LIKE '" . $db->real_escape_string($prefix) . "%'";
			$rs = $db->query($q);
			while (null != ($row = $rs->fetch_object())) {
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

		/**
		 * Get max length of a column in mysql schema
		 *
		 * @param string $field
		 * @return int
		 */
		public function schema_column_maxlen($field)
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

		public function _delete()
		{
			if (!$this->enabled()) {
				return;
			}
			$conf = Auth::profile()->conf->new;
			if (!parent::uninstallDatabaseService('mysql')) {
				warn("failed to delete mysql service from `%s'", $conf['siteinfo']['domain']);
			}
		}

		public function _create()
		{
			$conf = Auth::profile()->conf->new;
			if ($conf['mysql']['enabled']) {
				parent::installDatabaseService('mysql');
			}
		}

		public function _edit()
		{
			$conf = Auth::profile()->conf;
			if ($conf->new['mysql']['enabled'] && !$conf->cur['mysql']['enabled']) {
				$this->installDatabaseService('mysql');
			}

			$conf_cur = $conf->cur['mysql'];
			$conf_new = $conf->new['mysql'];
			if ($conf_new == $conf_cur) {
				return;
			}

			$prefixold = $conf_cur['dbaseprefix'];
			$prefixnew = $conf_new['dbaseprefix'];
			$db = MySQL::initialize();
			if (!preg_match(Regex::SQL_PREFIX, $prefixnew)) {
				return error("invalid database prefix `%s'", $prefixnew);
			}
			if ($prefixold !== $prefixnew) {
				$maxlen = self::MYSQL_USER_FIELD_SIZE - 3;
				if (strlen($prefixnew) > $maxlen /* prefix + _xy */) {
					return error("database prefix max length is %d", $maxlen);
				}
				$len = strlen($prefixold);
				$q = "UPDATE sql_dumps SET db_name = CONCAT('" .
					$db->escape_string($prefixnew) . "', SUBSTR(db_name, " . ($len + 1) . ")) WHERE " .
					"SUBSTR(db_name, 1, " . $len . ") = '" . $db->escape_string($prefixold) . "';";
				if (!$db->query($q)) {
					$this->add_error("sql backup rename failed");
				}
				$this->renameDatabase($prefixold, $prefixnew);
				$this->renameUser($prefixold, $prefixnew);
				// update grants and db table
			}
			if ($conf_cur['dbaseadmin'] != $conf_new['dbaseadmin']) {

			}

		}
	}
