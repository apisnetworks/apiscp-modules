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
	 * @xxx MODULE IS DEPRECATED. SEE MYSQL/PGSQL MODULES
	 *
	 * @package core
	 */
	class Sql_Module extends Module_Support_Sql
	{
		const MYSQL_USER_FIELD_SIZE = 16;

		// maximum length of users - mysql compile-time constant
		const PG_TEMP_PASSWORD = '23f!eoj3';
		const MYSQL_DATADIR = '/var/lib/mysql';
		const PGSQL_DATADIR = '/var/lib/pgsql';
		const MIN_PASSWORD_LENGTH = 3;

		// maximum number of simultaneous connections to a given DB
		// higher increases the risk of monopolization
		const PER_DATABASE_CONNECTION_LIMIT = 20;
		/**
		 * @var int minimum db prefix length, to reduce collisions on server xfers
		 */
		const MIN_PREFIX_LENGTH = 3;
		/* @ignore */
		const MASTER_USER = 'root';
		/**
		 * a bullshit constant to decide whether to
		 * up the ulimit fsize or not before exporting a db
		 */
		const DB_BIN2TXT_MULT = 1.5;
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
				'get_prefix'                    => PRIVILEGE_SITE | PRIVILEGE_USER,
				'pgsql_version'                 => PRIVILEGE_ALL,
				'mysql_version'                 => PRIVILEGE_ALL,
				'version'                       => PRIVILEGE_ALL,
				'get_mysql_uptime'              => PRIVILEGE_ALL,
				'assert_mysql_permissions'      => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,

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

		public function mysql_user_exists($user, $host = 'localhost')
		{
			return parent::__call('mysql_user_exists', [$user, $host]);
		}

		public function get_prefix()
		{
			return $this->get_service_value('mysql', 'dbaseprefix');
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
			return $this->mysql_delete_user($user, $host, $cascade);
		}

		public function pgsql_user_exists($user)
		{
			// tricky
			return parent::__call('pgsql_user_exists', [$user]);
		}

		// {{{ connect_mysql_root()

		/**
		 * bool delete_pgsql_user(string[, bool = false])
		 * Delete a PostgreSQL user
		 *
		 * @param string $user    username
		 * @param bool   $cascade casecade delete
		 * @return bool
		 */
		public function delete_pgsql_user($user, $cascade = false)
		{
			return $this->pgsql_delete_user($user, $cascade);

		}

		/**
		 * bool store_sql_password (string, string)
		 *
		 * @param string $sqlpasswd base64 encoded and encrypted password @{see encrypt_sql_password}
		 * @param string $type      password type, where type is either "mysql" or "pgsql"
		 * @return bool
		 */
		public function store_sql_password($sqlpasswd, $type)
		{
			if ($type != "mysql" && $type != "postgresql" && $type != "pgsql") {
				return error($type . ": unrecognized type");
			}
			if ($type === "postgresql") {
				$type = "pgsql";
			}
			$fn = "${type}_store_password";
			return $this->$fn($sqlpasswd);
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
			return $this->mysql_set_option($option, $value, $group);

		}

		public function set_pgsql_password($password)
		{
			return $this->pgsql_set_password($password);

		}

		public function set_pgsql_username($user)
		{
			return $this->pgsql_set_username($user);

		}

		public function get_pgsql_password($user = null)
		{
			return $this->pgsql_get_password($user);
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
			return $this->mysql_get_option($option, $group);
		}

		public function get_elevated_password_backend()
		{
			return Opcenter\Database\MySQL::rootPassword();
		}

		/**
		 * bool mysql_import(string, string, string, strin)
		 */
		public function import_mysql($db, $file)
		{
			return $this->mysql_import($db, $file);
		}

		/**
		 * array list_mysql_databases ()
		 * Queries the db table in the mysql database for applicable grants
		 *
		 * @return array list of databases
		 */
		public function list_mysql_databases()
		{
			return $this->mysql_list_databases();
		}

		/**
		 * Change account database prefix
		 *
		 * @todo convert to module-specific
		 *
		 * @param string $prefix
		 * @return bool
		 */
		public function change_prefix($prefix)
		{
			if (!IS_CLI) {
				return $this->query('sql_change_prefix', $prefix);
			}
			$prefix = strtolower(rtrim($prefix, '_'));
			$normalizedPrefix = $prefix . '_';
			if (strlen($prefix) < static::MIN_PREFIX_LENGTH) {
				return error("minimum acceptable db prefix length is `%d'", static::MIN_PREFIX_LENGTH);
			} else {
				if (!preg_match(Regex::SQL_PREFIX, $normalizedPrefix)) {
					return error("invalid db prefix `%s'", $prefix);
				}
			}
			$map = \Opcenter\Map::load('mysql.prefixmap', 'r');
			if (array_key_exists($normalizedPrefix, $map)) {
				return error("prefix `%s' already in use", $prefix);
			}
			$editor = new \Util_Account_Editor($this->getAuthContext()->getAccount());
			$editor->setConfig('mysql', 'dbaseprefix', $normalizedPrefix);
			$status = $editor->edit();
			if (!$status) {
				return error("failed to change database prefix");
			}
			return $status;
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
		public function list_mysql_users()
		{
			return $this->mysql_list_users();
		}

		/**
		 * bool add_mysql_user(string, string, string[, int[, int[, int[, string[, string[, string[, string]]]]]]])
		 */
		public function add_mysql_user(
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
			return $this->mysql_add_user($user, $host, $password,
				$maxconn, $maxupdates, $maxquery, $ssl, $cipher, $issuer, $subject);
		}

		public function get_mysql_database_charset($db)
		{
			return $this->mysql_get_database_charset($db);
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
			return $this->mysql_create_database($db);
		}

		public function mysql_charset_valid($charset)
		{
			return parent::__call('mysql_charset_valid', [$charset]);
		}

		public function get_supported_mysql_charsets()
		{
			return $this->mysql_get_supported_charsets();
		}

		/**
		 * Validate collation name
		 *
		 * @param string $collation
		 * @return bool
		 */
		public function mysql_collation_valid($collation)
		{
			return parent::__call('mysql_collation_valid', [$collation]);
		}

		public function get_supported_mysql_collations()
		{
			return $this->mysql_get_supported_collations();
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
			return parent::__call('mysql_collation_compatible', [$collation, $charset]);
		}

		/**
		 * Query information_schema for existence of MySQL database
		 *
		 * @param  string $db database name
		 * @return bool
		 */
		public function mysql_database_exists($db)
		{
			return parent::__call('mysql_database_exists', [$db]);
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
		 * @return bool
		 */
		public function add_mysql_user_permissions($user, $host, $db, array $opts)
		{
			deprecated_func("use set_mysql_privileges()");
			return $this->set_mysql_privileges($user, $host, $db, $opts);
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
			return $this->mysql_set_privileges($user, $host, $db, $privileges);
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
		 * Revoke all privileges on a database from a MySQL user
		 *
		 * @param string $user
		 * @param string $host
		 * @param string $db
		 * @return bool
		 */
		public function revoke_from_mysql_db($user, $host, $db)
		{
			return $this->mysql_revoke_privileges($user, $host,$db);
		}

		// {{{ enabled()

		public function get_mysql_user_permissions($user, $host, $db)
		{
			deprecated_func("use get_mysql_privileges()");
			return $this->get_mysql_privileges($user, $host, $db);
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
		public function get_mysql_privileges($user, $host, $db)
		{
			return $this->mysql_get_privileges($user, $host, $db);
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
			return parent::__call('mysql_version', [$pretty]);

		}

		/**
		 * Delete MySQL database from system
		 *
		 * @param  string $db database
		 * @return bool
		 */
		public function delete_mysql_database($db)
		{
			return $this->mysql_delete_database($db);
		}

		/**
		 * Remove MySQL Backup
		 *
		 * @param string $db
		 * @return bool
		 */
		public function delete_mysql_backup($db)
		{
			return $this->mysql_delete_backup($db);
		}

		/**
		 * Ensure that /var/lib/mysql/ has mysql:<group id> ownership
		 */
		public function assert_mysql_permissions()
		{
			return $this->mysql_assert_permissions();
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
			return $this->mysql_edit_user($user, $host, $opts);
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
			if ($svc_name != "mysql" && $svc_name != "postgresql" && $svc_name != "pgsql") {
				return error("Invalid service");
			}

			if ($svc_name == "postgresql") {
				$svc_name = 'pgsql';
			}
			$fn = "${svc_name}_enabled";
			return $this->$fn();
		}

		/**
		 * bool add_pgsql_user(string, string[, int])
		 */
		public function add_pgsql_user($user, $password, $maxconn = 5)
		{
			return $this->pgsql_add_user($user, $password, $maxconn);
		}

		/**
		 * bool create_pgsql_database (string)
		 *
		 * @param  string $db
		 * @return bool  creation succeeded
		 */
		public function create_pgsql_database($db)
		{
			return $this->pgsql_create_database($db);
		}

		/**
		 * Query PostgreSQL system table for existence of database
		 *
		 * @param string $db database name
		 * @return bool
		 */
		public function pgsql_database_exists($db)
		{
			return parent::__call('pgsql_database_exists', [$db]);
		}

		/**
		 * void prep_tablespace ()
		 * Checks to see if tablespace exists, if not, creates it
		 *
		 * @private
		 */
		public function prep_tablespace()
		{
			return $this->pgsql_prep_tablespace();
		}

		public function add_pgsql_extension($db, $extension)
		{
			return $this->pgsql_add_extension($db, $extension);
		}

		/**
		 * array list_mysql_databases ()
		 * Queries the db table in the mysql database for applicable grants
		 *
		 * @return array list of databases
		 */
		public function list_pgsql_databases()
		{
			return $this->pgsql_list_databases();
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
			return error("Function not implemented in PostgreSQL");
		}

		public function delete_pgsql_user_permissions($user, $db)
		{
			return error("Function not implemented in PostgreSQL");
		}

		/**
		 * void get_pgsql_user_permissions(string, string)
		 * Function not implemented in PostgreSQL
		 *
		 * @return void
		 */
		public function get_pgsql_user_permissions($user, $db)
		{
			return error("Function not implemented in PostgreSQL");
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
			return $this->pgsql_delete_database($db);
		}

		/**
		 * Remove PostgreSQL Backup
		 *
		 * @param string $db
		 * @return bool
		 */
		public function delete_pgsql_backup($db)
		{
			return $this->pgsql_delete_backup($db);
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
			return $this->pgsql_edit_user($user, $password, $maxconn);
		}

		public function get_pgsql_username()
		{
			return $this->pgsql_get_username();
		}

		/**
		 * array list_pgsql_users ()
		 * Lists all created users for PostgreSQL
		 *
		 * @return array
		 */
		public function list_pgsql_users()
		{
			return $this->pgsql_list_users();
		}

		/**
		 * string pg_vacuum_db (string)
		 * Vacuums a database
		 *
		 * @return string vacuum output
		 */
		public function pg_vacuum_db($db)
		{
			return $this->pgsql_vacuum($db);
		}

		public function truncate_pgsql_database($db)
		{
			return $this->pgsql_truncate_database($db);
		}

		public function pgsql_version($pretty = false)
		{
			return parent::__call('pgsql_version', [$pretty]);
		}

		public function empty_pgsql_database($db)
		{
			return $this->pgsql_empty_database($db);
		}

		/**
		 * bool pgsql_import(string, string, string, strin)
		 */
		public function import_pgsql($db, $file)
		{
			return $this->pgsql_import($db, $file);
		}

		public function truncate_mysql_database($db)
		{
			return $this->mysql_truncate_database($db);
		}

		public function empty_mysql_database($db)
		{
			return $this->mysql_empty_database($db);
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
			return $this->mysql_export($db, $file);
		}

		// {{{ delete_mysql_backup()

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
			if ($type != "mysql" && $type != "postgresql" && $type != "pgsql") {
				return error($type . ": invalid database type");
			}
			if ($type === "postgresql") {
				$type = "pgsql";
			}
			$fn = "${type}_get_database_size";
			return $this->$fn($db);
		}
		// }}}

		// {{{ get_mysql_backup_config()

		/**
		 * Export a db to a named pipe for immediate download
		 *
		 * @param $db
		 * @return bool|void
		 */
		public function export_mysql_pipe($db)
		{
			return $this->mysql_export_pipe($db);
		}

		// }}}

		// {{{ get_mysql_backup_config()

		/**
		 * Export a database to a named pipe
		 *
		 * Differs from export_mysql_pipe in that it may only be called internally
		 * or from backend, no API access
		 *
		 * @param $db
		 * @param $user if empty use superuser
		 * @return bool|string
		 */
		public function export_mysql_pipe_real($db, $user)
		{
			return $this->mysql_export_pipe_real($db, $user);
		}

		// }}}

		public function export_pgsql($db, $file = null)
		{
			return $this->pgsql_export($db, $file);
		}

		/**
		 * Export a PGSQL db to a named pipe for immediate download
		 *
		 * @param $db
		 * @return bool|void
		 */
		public function export_pgsql_pipe($db)
		{
			return $this->pgsql_export_pipe($db);
		}

		/**
		 * int get_pgsql_uptime
		 *
		 * @return int time in seconds
		 */
		public function get_pgsql_uptime()
		{
			return $this->pgsql_get_uptime();
		}

		/**
		 * int get_mysql_uptime
		 *
		 * @return int time in seconds
		 */
		public function get_mysql_uptime()
		{
			return $this->mysql_get_uptime();

		}

		// {{{ mysql_database_exists()

		public function add_mysql_backup($db, $extension = "zip", $span = 5, $preserve = '0', $email = '')
		{
			return $this->mysql_add_backup($db, $extension, $span, $preserve, $email);

		}

		public function add_pgsql_backup($db, $extension = "zip", $span = 5, $preserve = '0', $email = '')
		{
			return $this->pgsql_add_backup($db, $extension, $span, $preserve, $email);
		}

		public function edit_mysql_backup($db, $extension, $span = '0', $preserve = '0', $email = '')
		{
			return $this->mysql_edit_backup($db, $extension, $span, $preserve, $email);
		}

		public function edit_pgsql_backup($db, $extension, $span = '0', $preserve = '0', $email = '')
		{
			return $this->pgsql_edit_backup($db, $extension, $span, $preserve, $email);
		}

		public function list_mysql_backups()
		{
			return $this->mysql_list_backups();
		}

		public function list_pgsql_backups()
		{
			return $this->pgsql_list_backups();
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
		public function get_mysql_backup_config($db)
		{
			return $this->mysql_get_backup_config($db);
		}

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
			return $this->pgsql_get_backup_config($db);
		}

		public function repair_mysql_database($db)
		{
			return $this->mysql_repair_database($db);
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
			return parent::__call('mysql_kill', [$id]);
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
			return parent::__call('mysql_processlist');
		}

		/**
		 * Get max length of a column in mysql schema
		 *
		 * @param string $field
		 * @return int
		 */
		public function mysql_schema_column_maxlen($field)
		{
			return parent::__call('mysql_schema_column_maxlen', [$field]);
		}

		public function _delete()
		{
			// migrated to mysql/pgsql modules
		}

		public function _create()
		{
		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			if ($userold === $usernew) {
				return;
			}
		}

		public function _edit()
		{
			$conf = Auth::profile()->conf;

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
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}

		public function _create_user(string $user)
		{
		}

		public function _delete_user(string $user)
		{
		}


	}
