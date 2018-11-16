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
	 * E-mail functions (aliases, virtual mailboxes)
	 *
	 * @package core
	 */
	class Email_Module extends Module_Skeleton implements \Opcenter\Contracts\Hookable, \Module\Skeleton\Contracts\Proxied
	{
		const DEPENDENCY_MAP = [
			'siteinfo', 'ipinfo', 'ipinfo6', 'users', 'aliases', 'dns'
		];
		const MAILDIR_HOME = \Opcenter\Mail\Storage::MAILDIR_HOME;
		const MAILBOX_SPECIAL = 's';
		const MAILBOX_FORWARD = 'a';
		const MAILBOX_USER = 'v';
		const MAILBOX_DISABLED = 'd';
		const MAILBOX_ENABLED = 'e';
		const MAILBOX_SINGLE = '1';
		const MAILBOX_DESTINATION = 'destination';

		const VACATION_PREFKEY = 'mail.vacapref';
		// webmail installations
		const POSTFIX_CMD = '/usr/sbin/postfix';
		const DOVECOT_SSL_CONFIG_DIR = '/etc/dovecot/conf.d/ssl';
		private $_webmail = array(
			'sqmail'    => array(
				'subdomain' => 'mail',
				'path'      => '/var/www/html/mail'
			),
			'horde'     => array(
				'subdomain' => 'horde',
				'path'      => '/var/www/html/horde'
			),
			'roundcube' => array(
				'subdomain' => 'roundcube',
				'path'      => '/var/www/html/roundcube'
			)
		);

		/**
		 * {{{ void __construct(void)
		 *
		 * @ignore
		 */
		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = array(
				'address_exists'                  => PRIVILEGE_SITE | PRIVILEGE_USER,
				'add_vacation'                    => PRIVILEGE_SITE | PRIVILEGE_USER,
				'add_vacation_backend'            => PRIVILEGE_SITE | PRIVILEGE_USER,
				'create_maildir_backend'          => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				'get_spool_size_backend'          => PRIVILEGE_SITE | PRIVILEGE_SERVER_EXEC,
				/** Vacation methods */
				'add_vacation'                    => PRIVILEGE_SITE | PRIVILEGE_USER,
				'set_vacation'                    => PRIVILEGE_SITE | PRIVILEGE_USER,
				'set_vacation_options'            => PRIVILEGE_SITE | PRIVILEGE_USER,
				'get_vacation_options'            => PRIVILEGE_SITE | PRIVILEGE_USER,
				'vacation_exists'                 => PRIVILEGE_SITE | PRIVILEGE_USER,
				'enable_vacation'                 => PRIVILEGE_SITE | PRIVILEGE_USER,
				'remove_vacation'                 => PRIVILEGE_SITE | PRIVILEGE_USER,
				'get_vacation_message'            => PRIVILEGE_SITE | PRIVILEGE_USER,
				'change_vacation_message'         => PRIVILEGE_SITE | PRIVILEGE_USER,
				'get_webmail_location'            => PRIVILEGE_SITE | PRIVILEGE_USER,
				'webmail_apps'                    => PRIVILEGE_SITE | PRIVILEGE_USER,
				'create_maildir'                  => PRIVILEGE_SITE | PRIVILEGE_USER,
				'remove_maildir'                  => PRIVILEGE_SITE | PRIVILEGE_USER,
				'get_records'                     => PRIVILEGE_SITE,
				'*'                               => PRIVILEGE_SITE,
				'get_provider'                    => PRIVILEGE_ALL
			);
		}

		public function _proxy(): \Module_Skeleton
		{
			$provider = $this->get_provider();
			if ($provider === 'builtin') {
				return $this;
			}

			return \Module\Provider::get('mail', $provider, $this->getAuthContext());
		}

		/**
		 * Get DNS provider
		 *
		 * @return string
		 */
		public function get_provider(): string
		{
			return $this->getServiceValue('mail', 'provider', 'builtin');
		}


		public function list_aliases()
		{
			return $this->list_mailboxes('forward');
		}

		/**
		 * Retrieve mailbox delivery maps from system
		 *
		 * @param $filter  string optional filter, possible values: forward, local, special, single, enabled, disabled, destination
		 * @param $address string supplementary argument to 'single', restrict address to %expr%. Mandatory for destination filter type
		 * @param $domain  string optionally restrict to all addresses matching domain
		 *
		 * @return array
		 *
		 */
		public function list_mailboxes($filter = null, $address = null, $domain = null)
		{
			$filter_clause = '1=1';


			if ($filter == 'forward') {
				$filter = self::MAILBOX_FORWARD;
			} else if ($filter == 'local') {
				$filter = self::MAILBOX_USER;
			} else if ($filter == 'special') {
				$filter = self::MAILBOX_SPECIAL;
			} else if ($filter == 'disabled') {
				$filter = self::MAILBOX_DISABLED;
			} else if ($filter == 'enabled') {
				$filter = self::MAILBOX_ENABLED;
			}

			if ($filter && !in_array($filter, array(
					self::MAILBOX_FORWARD,
					self::MAILBOX_USER,
					self::MAILBOX_SPECIAL,
					self::MAILBOX_DISABLED,
					self::MAILBOX_ENABLED,
					self::MAILBOX_SINGLE,
					self::MAILBOX_DESTINATION
				))
			) {
				return error("invalid filter specification `%s'", $filter);
			}

			if ($filter == self::MAILBOX_FORWARD) {
				$filter_clause = 'type = \'' . self::MAILBOX_FORWARD . '\'';
			} else if ($filter == self::MAILBOX_USER) {
				$filter_clause = 'type = \'' . self::MAILBOX_USER . '\'';
			} else if ($filter == self::MAILBOX_SPECIAL) {

			} else if ($filter == self::MAILBOX_SINGLE) {
				$filter_clause = 'email_lookup."user" ' . (false !== strpos($address, '%') ? 'LIKE' : '=') . ' \'' . pg_escape_string($address) . '\'';
			} else if ($filter == self::MAILBOX_ENABLED) {
				$filter_clause = 'enabled = 1::bit';
			} else if ($filter == self::MAILBOX_DISABLED) {
				$filter_clause = 'enabled = 0::bit';
			} else if ($filter == self::MAILBOX_DESTINATION) {
				$filter_clause = 'COALESCE(uids."user",alias_destination) = ' . pg_escape_literal($address);
			}

			if (null !== $address && $filter !== self::MAILBOX_DESTINATION) {
				// @TODO nasty
				$filter_clause .= ' AND email_lookup.user = \'' . pg_escape_string(strtolower($address)) . '\'';
			}
			if ($domain) {
				$filter_clause .= ' AND email_lookup.domain = \'' . pg_escape_string(strtolower($domain)) . '\'';
			}
			$mailboxes = array();
			$query = "
			SELECT
				email_lookup.\"user\",
				email_lookup.domain as domain,
				type,
				enabled,
				fs_destination AS target,
				uid,
				COALESCE(uids.\"user\",alias_destination) as destination
			FROM
				email_lookup
			JOIN
				domain_lookup
			ON
				(email_lookup.domain = domain_lookup.domain)
			LEFT JOIN
				uids
			USING(uid)
			WHERE
				(domain_lookup.site_id = " . $this->site_id . ") AND " . $filter_clause . " ORDER BY \"user\", domain;";
			$pgdb = \PostgreSQL::initialize();
			$pgdb->query($query);
			while (null !== ($row = $pgdb->fetch_object())) {
				$mailboxes[] = array(
					'user'        => trim($row->user),
					'domain'      => trim($row->domain),
					'type'        => $row->type,
					'enabled'     => (int)$row->enabled,
					'mailbox'     => $row->destination,
					'uid'         => (int)$row->uid,
					'custom'      => ($filter === 'local' ? $row->target : null),
					'destination' => $row->destination
				);
			}
			return $mailboxes;
		}

		public function enable_address($account, $domain = null)
		{
			$where = 'AND email_lookup.domain = domain_lookup.domain AND domain_lookup.site_id = ' . $this->site_id;
			if ($domain) {
				$where .= 'AND domain_lookup.domain = \'' . pg_escape_string($domain) . '\'';
			}
			$pgdb = \PostgreSQL::initialize();
			$pgdb->query('UPDATE email_lookup SET enabled = 1::bit FROM domain_lookup WHERE "user" = \'' . pg_escape_string($account) . '\' ' . $where . ';');
			return $pgdb->affected_rows() > 0;
		}

		/**
		 * Verify service is enabled
		 * @param null|string $which
		 * @return bool
		 */
		public function enabled(string $which = null): bool {
			// @TODO rename sendmail to smtp service
			if (platform_is('7.5')) {
				$which = $which === 'smtp_relay' ? 'smtp' : $which;
			} else {
				$which = $which === 'smtp' ? 'smtp_relay' : $which;
			}
			if ($which && $which !== 'smtp' && $which !== 'smtp_relay' && $which !== 'imap' && $which !== 'pop3') {
				return error("unknown service `%s'", $which);
			}
			if ($which) {
				$which = platform_is('7.5') ? 'mail' : 'sendmail';
				return (bool)$this->getServiceValue($which, 'enabled');
			}
			return $this->enabled('smtp') && $this->enabled('imap');
		}

		/**
		 * @deprecated @link modify_mailbox
		 */
		public function rename_mailbox($olduser, $olddomain, $newuser, $newdomain, $newmailbox, $newtype = null)
		{
			return $this->modify_mailbox($olduser, $olddomain, $newuser, $newdomain, $newmailbox, $newtype);
		}

		/**
		 * Rename a mailbox
		 *
		 * IMPORTANT: a mailbox may not be remapped into a catchall here
		 *
		 * @param string $olduser
		 * @param string $olddomain
		 * @param string $newuser
		 * @param string $newdomain
		 * @param string $newdestination
		 * @param string|null $newtype
		 * @return bool
		 */
		public function modify_mailbox(
			string $olduser,
			string $olddomain,
			string $newuser = '',
			string $newdomain = '',
			string $newdestination = '',
			string $newtype = null
		): bool {
			$args = array(
				'olduser',
				'olddomain',
				'newuser',
				'newdomain',
				'newtype'
			);
			foreach ($args as $var) {
				${$var} = strtolower(${$var});
			}
			if (!$newuser && !$newdomain) {
				$newuser = $olduser;
				$newdomain = $olddomain;
			}

			if ($olduser === "majordomo" && $this->majordomo_list_mailing_lists()) {
				return error("cannot remove majordomo email address while mailing lists exist");
			}

			if (($olduser . '@' . $olddomain != $newuser . '@' . $newdomain) && $this->address_exists($newuser,
					$newdomain)
			) {
				return error("Email address %s@%s already exists. Can't rename!",
					$newuser, $newdomain);
			}

			if (!$newtype) {
				$newtype = $this->mailbox_type($olduser, $olddomain);
			}

			$pgdb = \PostgreSQL::initialize();
			if ($newtype == self::MAILBOX_USER) {
				if (false != ($uid = intval($newdestination))) {
					$uid = intval($newdestination);
					$local_user = $this->user_get_username_from_uid($uid);
					$newdestination = '/home/' . $local_user . '/' . self::MAILDIR_HOME;
					if (!$local_user) {
						return error("Invalid mailbox destination, invalid uid `%d'", $uid);
					}
				} else if ($newdestination) {
					if (preg_match('!^/home/([^/]+)/' . self::MAILDIR_HOME . '([/.]*)$!', $newdestination,
						$match)) {
						$local_user = $match[1];
						$newdestination = ltrim(str_replace(array('/', '..'), '.', $match[2]), '.');
					} else {
						$local_user = $newdestination;
						$newdestination = null;
					}
				} else {
					// user rename
					$local_user = $newuser;
				}

				$local_user = strtolower($local_user);
				$users = $this->user_get_users();
				if (!isset($users[$local_user])) {
					return error("User account `%s' does not exist", $local_user);
				}

				$uid = intval($users[$local_user]['uid']);
				if ($newdestination == '') {
					$newdestination = null;
				} else {
					$this->query('email_create_maildir_backend', $local_user, $newdestination);
				}
				$pgdb->query("UPDATE email_lookup SET \"user\" = '" . $newuser . "', domain = '" . $newdomain . "', " .
					"fs_destination = " . (($newdestination != null) ? "'" . pg_escape_string(rtrim($newdestination,
								' /') . '/') . "'" : "NULL") . ", " .
					"alias_destination = NULL, uid = " . $uid . ", type = '" . self::MAILBOX_USER . "' WHERE \"user\" = '" . pg_escape_string($olduser) . "' " .
					"AND domain = '" . pg_escape_string($olddomain) . "';");
			} else {
				if (!$newuser) {
					return error("cannot forward catch-alls to external e-mail accounts");
				}
				$newdestination = preg_replace('/\s+/m', ",", trim($newdestination, ' ,'));
				if (!$newdestination) {
					return error("no forwarding destination set for `%s@%s`", $newuser, $newdomain);
				}
				$pgdb->query("UPDATE email_lookup SET \"user\" = '" . pg_escape_string($newuser) . "', domain = '" . pg_escape_string($newdomain) . "', " .
					"alias_destination = '" . pg_escape_string($newdestination) . "', uid = NULL, type = '" .
					self::MAILBOX_FORWARD . "', fs_destination = NULL WHERE \"user\" = '" .
					pg_escape_string($olduser) . "' AND domain = '" . pg_escape_string($olddomain) . "';");

			}
			$rows = $pgdb->affected_rows();
			$this->_shutdown_save_mailboxes();

			return $rows > 0;
		}

		public function address_exists($user, $domain)
		{
			$user = strtolower($user);
			$domain = strtolower($domain);
			if (!preg_match('/^[a-z0-9\._@\+-]+$/', $user . '@' . $domain)) {
				return error("invalid address `" . $user . '@' . $domain . "'");
			}
			$pgdb = \PostgreSQL::initialize();
			$pgdb->query("SELECT 1 FROM email_lookup WHERE \"user\" = '" . pg_escape_string($user) . "' AND domain = '" . pg_escape_string($domain) . "'");

			return $pgdb->num_rows() > 0;
		}

		/**
		 * Get mailbox type
		 *
		 * @param $user
		 * @param $domain
		 * @return bool|null|string
		 * @throws PostgreSQLError
		 */
		public function mailbox_type($user, $domain)
		{
			$user = strtolower($user);
			$domain = strtolower($domain);
			if (!preg_match(Regex::EMAIL, $user . '@' . $domain)) {
				return error("invalid address `" . $user . '@' . $domain . "'");
			}
			$pgdb = \PostgreSQL::initialize();
			$pgdb->query("SELECT type FROM email_lookup WHERE \"user\" = '" . $user . "' AND domain = '" . $domain . "'");

			if ($pgdb->num_rows() < 1) {
				return null;
			}
			return $pgdb->fetch_object()->type;
		}

		/**
		 * Save all mailboxes to a serialized file
		 *
		 * @see restore_mailboxes()
		 *
		 * @return boolean
		 */
		public function save_mailboxes()
		{
			if (!IS_CLI) {
				return $this->query('email_save_mailboxes');
			}
			$path = $this->domain_info_path();
			if (!is_dir($path)) {
				// site deleted, ignore save
				return true;
			}
			$q = 'SELECT * FROM email_lookup WHERE domain IN
                (select domain FROM domain_lookup WHERE site_id = ' . $this->site_id . ')';
			$db = \PostgreSQL::initialize();
			$email = array();
			$db->query($q);
			while ($row = $db->fetch_assoc()) {
				$email[] = array_map('trim', $row);
			}
			$path .= '/email_addr';
			return (bool)file_put_contents($path, serialize($email), LOCK_EX);
		}

		/**
		 * Remove an e-mail alias
		 *
		 * @param string $user
		 * @param string $domain
		 */
		public function remove_alias($user, $domain)
		{
			return $this->delete_mailbox($user, $domain, self::MAILBOX_FORWARD);
		}

		public function delete_mailbox($user, $domain, $type = '')
		{
			$type = strtolower($type);
			if ($type == 'l' || $type == self::MAILBOX_USER) {
				$type = self::MAILBOX_USER;
			} else {
				if ($type == 'f' || $type == self::MAILBOX_FORWARD) {
					$type = self::MAILBOX_FORWARD;
				} else {
					if ($type != '') {
						return error("unknown address type `%s'", $type);
					}
				}
			}
			/**
			 * otherwise we can clog up an mqueue pretty fast
			 */
			if ($user === "majordomo" && $this->majordomo_list_mailing_lists()) {
				return error("cannot remove majordomo email address while mailing lists exist");
			}

			$clause = '';
			if ($type) {
				$clause = "AND type = '$type' ";
			}
			$pgdb = \PostgreSQL::initialize();
			$pgdb->query('DELETE FROM
				email_lookup
				WHERE
				"user" = \'' . pg_escape_string($user) . "'
				AND
				domain = '" . pg_escape_string($domain) . "'
				$clause
				AND '" . pg_escape_string($domain) . "' IN
					(SELECT domain from domain_lookup WHERE site_id = " . $this->site_id . ");");
			$rows = $pgdb->affected_rows();
			$this->_shutdown_save_mailboxes();

			return $rows > 0;
		}

		public function get_mailbox($user, $domain)
		{
			$address = $this->list_mailboxes(self::MAILBOX_SINGLE, $user, $domain);
			return $address ? array_pop($address) : array();
		}

		public function remove_maildir($mailbox)
		{
			// assume remove_maildir() is only called by the owner
			if (!IS_CLI) {
				return $this->query('email_remove_maildir', $mailbox);
			}
			$mailbox = trim($mailbox);
			if ($mailbox[0] != ".") {
				$mailbox = '.' . $mailbox;
			}
			if (!preg_match(Regex::EMAIL_MAILDIR_FOLDER, $mailbox)) {
				return error("invalid maildir folder name `%s'", $mailbox);
			}
			$home = $this->user_get_user_home();
			$path = join(DIRECTORY_SEPARATOR, array($home, self::MAILDIR_HOME, $mailbox));
			if (!$this->file_delete($path, true)) {
				return error("failed to remove maildir `%s'", $mailbox);
			}

			$subscriptions = join(DIRECTORY_SEPARATOR,
				array(
					$this->domain_fs_path(),
					$home,
					self::MAILDIR_HOME,
					'subscriptions'
				)
			);
			$sname = trim($mailbox, '.');
			if (!file_exists($subscriptions)) {
				$contents = array();
			} else {
				$contents = file($subscriptions, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			}
			if (false === ($key = array_search($sname, $contents))) {
				return true;
			}
			unset($contents[$key]);
			file_put_contents($subscriptions, join("\n", $contents) . "\n");
			return \Opcenter\Filesystem::chogp($subscriptions, $this->user_id, $this->group_id, 0600);

		}

		/**
		 * Restore a saved copy of mailboxes
		 *
		 * @return boolean
		 */
		public function restore_mailboxes($file = 'email_addr')
		{
			if (!IS_CLI) {
				return $this->query('email_restore_mailboxes', $file);
			}
			if (!strspn($file[0], "abcdefghijklmnopqrstuvwxyz")) {
				return error("invalid mailbox backup `%s'", $file);
			}
			$file = $this->domain_info_path() . '/' . $file;
			if (!file_exists($file)) {
				warn("mailbox backup `%s' not found", basename($file));
				return -1;
			}
			$db = \PostgreSQL::initialize();
			$recs = unserialize(file_get_contents($file));
			$escapef = function ($rec) {
				return '"' . $rec . '"';
			};

			$escapev = function ($rec) {
				// empty values inserted as NULL
				if ($rec === "") {
					return "NULL";
				} else {
					if (ctype_digit($rec)) {
						if ($rec == 0 || $rec == 1) {
							/*
							 * assume this is the "enabled" column,
							 * which mandates a bit
							 */
							$rec .= '::bit';
						}
						return $rec;
					}
				}
				return "'" . pg_escape_string($rec) . "'";
			};
			$db = \PostgreSQL::initialize()->getHandler();
			foreach ($recs as $r) {
				$fields = array_map($escapef, array_keys($r));
				$values = array_map($escapev, array_values($r));
				$q = "INSERT INTO email_lookup (" . join($fields, ",") .
					") VALUES(" . join($values, ",") . ")";
				pg_send_query($db, $q);
				while (pg_connection_busy($db)) {
					usleep(50);
				}
				$res = pg_get_result($db);

				if (false !== ($err = pg_result_error($res))) {
					$errid = pg_result_error_field($res, PGSQL_DIAG_SQLSTATE);
					/**
					 * 23505 (unique_violation) Query violates unique key
					 *
					 * @link http://www.postgresql.org/docs/8.2/static/errcodes-appendix.html
					 */
					if ($errid == 23505) {
						warn("skipped duplicate entry `%s@%s'",
							$r['user'], $r['domain']);
					} else {
						if ($errid == 23514) {
							warn("skipped entry `%s@%s': domain for `%s' not " .
								"assigned to handle mail", $r['user'],
								$r['domain'], $r['domain']);
						} else {
							error("skipped `%s@%s': unknown query error",
								$r['user'], $r['domain']);
						}
					}
				}
			}
			return true;
		}

		public function remove_mailbox($user, $domain)
		{
			return $this->delete_mailbox($user, $domain);
		}

		/**
		 * Domain is designated to receive e-mail on hosting server
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function transport_exists($domain)
		{
			$q = \PostgreSQL::initialize()->query("SELECT site_id FROM domain_lookup WHERE domain = '" . pg_escape_string($domain) . "'");
			return $q->num_rows() > 0 && $q->fetch_object()->site_id == $this->site_id;
		}

		/***
		 * int get_spool_size (string)
		 *
		 * @privilege PRIVILEGE_SITE
		 * @return int size of the spool in bytes
		 * @param $username username of the spool; note well this differs from
		 *                  {@link File_Module::report_quota} in that the username is used instead of the uid.
		 *                  This may change in the future.  There is a limitation in this process
		 *                  in that it solely scans the main spool file for a user and excludes
		 *                  all other inboxes created from IMAP applications (such as SquirrelMail).
		 */
		public function get_spool_size($username)
		{

			if (!array_key_exists($username, $this->user_get_users())) {
				return error("Invalid user `%s'", $username);
			}
			return $this->query(
				'email_get_spool_size_backend',
				$this->domain_fs_path() . '/home/' . $username . '/' . self::MAILDIR_HOME
			);

		}

		/**
		 * Get mail folder size
		 *
		 * @param string $path
		 * @return bool|int
		 */
		public function get_spool_size_backend($path)
		{
			if (!file_exists($path)) {
				return 0;
			}
			$proc = Util_Process_Safe::exec('du -s %s', $path);
			if (!$proc['success']) {
				return false;
			}
			return intval($proc['output']) * 1024;
		}

		/**
		 * Set vacation options
		 *
		 * @param array $options
		 * @return bool
		 */
		public function set_vacation_options(array $options): bool {
			$driver = \Opcenter\Mail\Vacation::get($this->getAuthContext());
			foreach ($driver->getDefaults() as $k => $v) {
				if (isset($options[$k]) && !$driver->setOption($k, $options[$k])) {
					unset($options[$k]);
				}
			}
			$pref = \Preferences::factory($this->getAuthContext());
			$pref->unlock(\apnscpFunctionInterceptor::factory($this->getAuthContext()));
			$pref->offsetSet(self::VACATION_PREFKEY, $options);
			if (!$this->inContext()) {
				\Preferences::reload();
			}
			return true;
		}

		/**
		 * Get vacation options
		 * @return array
		 */
		public function get_vacation_options(): array {
			$prefs = array_get(\Preferences::factory($this->getAuthContext()), self::VACATION_PREFKEY, []);
			$mb = \Opcenter\Mail\Vacation::get($this->getAuthContext());
			$defaults = $mb->getDefaults();
			return array_merge($defaults, array_intersect_key($prefs, $defaults));
		}

		public function get_vacation_message($user = null)
		{
			if (!IS_CLI) {
				return $this->query('email_get_vacation_message', $user);
			}
			if (null !== $user && !($this->permission_level & PRIVILEGE_SITE)) {
				return error("unprivileged user may not setup vacation responder for other users");
			}

			if (null === $user) {
				$user = $this->username;
			} else if (!$this->user_exists($user)) {
				return error("unknown user `%s'", $user);
			}
			$svc = \Opcenter\Mail\Vacation::getActiveService();
			$class = 'Vacation\\Providers\\' . $svc . '\\Options\\Message';
			$fqns = \Opcenter\Mail\Vacation::appendNamespace($class);
			return (new $fqns)->getFromUser($user);
		}

		/**
		 * Wrapper to set_vacation
		 *
		 * @deprecated
		 * @param            $response
		 * @param null       $user
		 * @param array|null $flags
		 * @return bool|mixed|void
		 */
		public function add_vacation($response, $user = null, array $flags = null) {
			deprecated_func('use set_vacation()');
			return $this->enable_vacation($response, $user, $flags);
		}

		/**
		 * Enable vacation auto-responder
		 *
		 * @param null|string $user
		 * @param array|null $flags optional flags
		 * @return bool|mixed|void
		 */
		public function enable_vacation($user = null, array $flags = null)
		{
			if (!IS_CLI) {
				return $this->query('email_enable_vacation', $user, $flags);
			}
			if (null !== $user && !($this->permission_level & PRIVILEGE_SITE)) {
				return error("Non-privileged user may not setup vacation responder for other users");
			}

			if (null === $user) {
				$user = $this->getAuthContext();
			} else if (!$this->user_exists($user)) {
				return error("user `%s' does not exist", $user);
			} else if ($user && $flags) {
				return error("changing flags of secondary users not implemented");
			} else {
				$user = \Auth::context($user, $this->site);
			}

			$driver = \Opcenter\Mail\Vacation::get($user);
			if ($flags) {
				$this->set_vacation_options($flags);
			}
			return $driver->enable();
		}

		public function vacation_exists($user = null)
		{
			if (!IS_CLI) {
				return $this->query('email_vacation_exists', $user);
			}

			if (null !== $user && (($this->permission_level & PRIVILEGE_SITE) !== PRIVILEGE_SITE)) {
				return error("Unable to check vacation for non-admin account");
			} else if (null === $user) {
				$user = $this->getAuthContext();
			} else {
				if (!$this->user_exists($user)) {
					return false;
				}
				$user = \Auth::context($user, $this->site);
			}

			if (!$this->user_exists($user->username)) {
				return error("Invalid user `%s'", $user->username);
			}

			return \Opcenter\Mail\Vacation::get($user)->enabled();
		}

		/**
		 * Change existing vacation message
		 * @param string        $response
		 * @param string|null   $user
		 * @param array|null    $flags
		 * @return bool
		 */
		public function change_vacation_message($response, $user = null, array $flags = [])
		{
			deprecated_func('use set_vacation');
			return $this->enable_vacation($response, $user, $flags);
		}

		/**
		 * Disable vacation status
		 * @param string|null user
		 * @return bool
		 */
		public function remove_vacation(string $user = null)
		{
			if (!IS_CLI) {
				return $this->query('email_remove_vacation', $user);
			}

			if ($user && ($this->permission_level & PRIVILEGE_SITE) !== PRIVILEGE_SITE) {
				return error("Unable to check vacation for non-admin account");
			}
			if (!$user) {
				$user = $this->getAuthContext();
			} else {
				$user = \Auth::context($user, $this->site);
			}

			if (!$this->user_exists($user->username)) {
				return error($user . ": invalid user");
			}

			$driver = \Opcenter\Mail\Vacation::get($user);
			return $driver->disable();
		}

		public function clone_domain_mailboxes($source, $destination)
		{
			$this->remove_virtual_transport($destination);
			if (!$this->add_virtual_transport($destination)) {
				return false;
			}

			foreach ($this->list_mailboxes(null, null, $source) as $mailbox) {
				if ($mailbox['type'] == self::MAILBOX_USER) {
					if (preg_match('!^/home/([^/]+)/' . self::MAILDIR_HOME . '/?(.*)$!', $mailbox['destination'],
						$mailbox_dest)) {
						$username = $mailbox_dest[1];
						$subfolder = $mailbox_dest[2];
					} else {
						$subfolder = '';
						$username = $mailbox['destination'];
					}

					$this->add_mailbox($mailbox['user'],
						$destination,
						$this->user_get_uid_from_username($username),
						$subfolder);
				} else if ($mailbox['type'] == self::MAILBOX_FORWARD) {
					$this->add_alias($mailbox['user'],
						$destination,
						str_replace($source,
							$destination,
							$mailbox['destination']));
				}

				if (!$mailbox['enabled']) {
					$this->disable_address($mailbox['user'], $mailbox['domain']);
				}

			}
			return true;
		}

		/**
		 * Deauthorize server from handling mail for domain
		 *
		 * @param string $domain  domain name to deauthorize
		 * @param bool   $keepdns purge DNS MX settings, null auto-detect to purge
		 * @return bool
		 */
		public function remove_virtual_transport($domain, $keepdns = null)
		{
			$pgdb = \PostgreSQL::initialize();
			$q = $pgdb->query("SELECT site_id FROM domain_lookup WHERE domain = '" . pg_escape_string($domain) . "'");
			if ($q->num_rows() < 1) {
				return false;
			}

			$site_id = $pgdb->fetch_object()->site_id;

			if ($site_id && $site_id != $this->site_id) {
				return error("Table entry " . $domain . " owned by another site (" . $site_id . ")");
			} else {
				if ($pgdb->num_rows() < 1) {
					return error("Domain " . $domain . " not found in table");
				}
			}
			foreach ($this->majordomo_list_mailing_lists() as $list) {
				$tmp = $this->majordomo_get_domain_from_list_name($list);
				if ($tmp == $domain) {
					warn("Mailing list `%s' sends from `%s'. Delete via Mail > Mailing Lists", $list, $domain);
				}
			}
			$pgdb->query("DELETE FROM domain_lookup WHERE domain = '" . pg_escape_string($domain) . "' AND site_id = " . (int)$this->site_id . ";");
			$ok = $pgdb->affected_rows() > 0;

			if (!$this->dns_configured()) {
				return warn("DNS is not configured for `%s' - unable to remove MX records automatically", $domain);
			}

			if (!$this->dns_zone_exists($domain)) {
				// zone removed
				return true;
			}

			if (null === $keepdns) {
				// do an intelligent lookup to see if MX is default
				$split = $this->web_split_host($domain);
				$myip = $this->site_ip_address();
				if ($this->dns_record_exists($split['domain'], $split['subdomain'], 'MX')) {
					// record exists, confirm MX value
					$hostname = ltrim($split['subdomain'] . "." . $split['domain'], ".");
					$rec = $this->dns_get_records_by_rr('MX', $hostname);
					if (!is_array($rec)) {
						warn("error retrieving mx records for `%s'", $hostname);
						Error_Reporter::report("unable to remove record for `%s'", $hostname);
						return $ok;
					} else {
						if (!count($rec)) {
							// MX record exists remotely but not on the server
							info("no MX records found for hostname `%s'", $hostname);
							return $ok;
						}
					}
					// check just first record
					$rec = array_pop($rec);
					list($priority, $hostname) = preg_split("/\s+/", $rec['parameter']);
					// a fqdn is supplied, terminated by a period, strip it
					$hostname = trim($hostname, ".");
					$ip = $this->dns_gethostbyname_t($hostname, 5000);
					if ($ip && $ip != $myip) {
						warn("MX record for `%s' points to third-party server and thus will not be removed from local DNS",
							$domain);
						return -1;
					}
					// purge MX record from DNS
					$keepdns = false;
				}
			}

			if (!$keepdns) {
				$split = $this->web_split_host($domain);
				$mailsub = rtrim('mail.' . $split['subdomain'], '.');
				$records = $this->get_records($domain);
				foreach ($records as $r) {
					if ($this->dns_record_exists($split['domain'], $r['name'], $r['rr'], $r['parameter'])) {
						$this->dns_remove_record($split['domain'], $r['name'], $r['rr'], $r['parameter']);
					}
				}
			}
			return $ok;
		}

		public function add_virtual_transport($domain, $subdomain = '')
		{
			$aliases = $this->aliases_list_aliases();
			if (($domain != $this->domain) && !in_array($domain, $aliases)) {
				return error("domain `%s' not owned by site", $domain);
			}
			$transport = ($subdomain ? $subdomain . '.' : '') . $domain;
			$pgdb = \PostgreSQL::initialize();
			$rs = $pgdb->query("SELECT site_id FROM domain_lookup WHERE domain = '" . pg_escape_string($transport) . "'");
			$nr = $pgdb->num_rows();

			if ($nr > 0) {
				$site = $rs->fetch_object()->site_id;
				if ($site != $this->site_id) {
					return error("table entry `%s' owned by another site (%d)", $transport, $site);
				}
				return true;
			}

			$pgdb->query("INSERT INTO domain_lookup (domain, site_id) VALUES('" . pg_escape_string($transport) . "', " . (int)$this->site_id . ");");
			if ($pgdb->affected_rows() < 1) {
				return error("failed to add e-mail transport `%s'", $transport);
			}
			// default record
			$myip = $this->site_ip_address();
			$mymailrec = rtrim('mail.' . $subdomain, '.');

			if (!$this->dns_domain_uses_nameservers($domain)) {
				$nsrecs = join(", ", $this->dns_get_hosting_nameservers($domain));
				warn("Domain uses third-party nameservers to provide DNS. Continuing to make " .
					"local MX records on local nameservers. Email configuration in Mail > Manage Mailboxes " .
					"will not be reflected until nameservers are changed to %s",
					$nsrecs,
					$nsrecs
				);
			}

			/**
			 * forcefully set the record just in case, if external DNS is used
			 * if MX destination record is already present, elicit a warning and continue;
			 */
			if (!$this->dns_configured()) {
				return warn("DNS is not configured for `%s' - unable to provision DNS automatically", $domain);
			}

			if ($this->dns_record_exists($domain, $mymailrec, 'A')) {
				$srvrec = $this->dns_get_records($mymailrec, 'A', $domain);
				if (count($srvrec) === 0) {
					$srvrec = $this->dns_get_records('*', 'A', $domain);
				}
				// should only be 1 record...
				$srvrec = array_pop($srvrec);
				if ($srvrec['parameter'] && $srvrec['parameter'] !== $myip) {
					$hostname = implode(".", array($mymailrec, $domain));
					warn("A record for %s points to %s, not overwriting! Email will not " .
						"route properly until the record is changed from %s to %s.",
						$hostname,
						$srvrec['parameter'],
						$srvrec['parameter'],
						$myip
					);
				}
			} else {

				$this->dns_add_record($domain, $mymailrec, 'A', $myip) ||
				warn("failed to populate DNS record for MX!");
			}

			if (!$this->dns_record_exists($domain, $subdomain, 'MX')) {
				return $this->dns_add_record($domain, $subdomain, 'MX', '10 mail.' . $transport);
			}

			// record exists, confirm MX value matches
			$rec = $this->dns_get_records($subdomain, 'MX', $domain);
			// just examine the first record...
			$rec = array_pop($rec);
			if (!$rec) {
				return warn("Failed to examine MX records for `%s'",
					ltrim(implode('.', [$subdomain, $domain]), '.'));
			}
			list($priority, $host) = preg_split("/\s+/", (string)$rec['parameter']);
			$mxip = $this->dns_gethostbyname_t($host);
			if ($mxip != $myip) {
				$hostname = ltrim($subdomain . '.' . $domain, ".");
				warn("Custom MX record for `%s' already exists, not overwriting. Manually add a MX record for `%s' to `%s'",
					$hostname,
					$hostname,
					'10 mail.' . $transport);
			}

			return true;
		}

		public function add_mailbox($user, $domain, $uid, $mailbox = '')
		{
			$user = strtolower(trim($user));
			$domain = strtolower(trim($domain));
			if ($this->address_exists($user, $domain)) {
				if (!$user) {
					return error("catch-all for $domain already exists");
				}
				return error('%s@%s: address exists', $user, $domain);
			}
			$mailbox = ltrim(str_replace(array('/', '..'), '.', $mailbox), '.');
			$uid = intval($uid);
			$pgdb = \PostgreSQL::initialize();
			if ($mailbox) {
				$pgdb->query("SELECT \"user\" as name FROM uids WHERE uid = " . $uid . " AND site_id = " . $this->site_id);
				$luser = $pgdb->fetch_object();
				if (!$luser) {
					return error("lookup failed for `%s' with uid `%s'", $user, $uid);
				}
				$luser = trim($luser->name);
				$this->query('email_create_maildir_backend', $luser, $mailbox);
				$mailbox = pg_escape_string($mailbox);
			}

			$pgdb->query("INSERT INTO email_lookup (\"user\", domain, uid, type, enabled, fs_destination)
				VALUES ('" . pg_escape_string($user) . "',
					'" . pg_escape_string($domain) . "',
					" . intval($uid) . ",
					'" . self::MAILBOX_USER . "',
					1::bit,
					" . ($mailbox ? "'" . $mailbox . "'" : "NULL") . ");");
			$rows = $pgdb->affected_rows();

			$this->_shutdown_save_mailboxes();

			return $rows > 0;

		}

		public function add_alias($user, $domain, $destination)
		{
			$user = strtolower($user);
			$domain = strtolower($domain);
			if ($this->address_exists($user, $domain)) {
				return error("%s@%s: address exists", $user, $domain);
			}
			$user = trim($user);
			if (!$user) {
				return error("catch-all may not be forwarded");
			}
			$destination = preg_replace('/\s+|,+/', ",", trim($destination, ' ,'));
			if (!$destination) {
				return error("no destination specified");
			}
			$pgdb = \PostgreSQL::initialize();
			$pgdb->query("INSERT INTO email_lookup " .
				"(\"user\", domain, alias_destination, type, enabled) " .
				"VALUES('" . pg_escape_string($user) . "', '" . pg_escape_string($domain) . "', '" .
				trim(pg_escape_string($destination), ',') . "', '" . self::MAILBOX_FORWARD . "', 1::bit);");
			$rows = $pgdb->affected_rows();
			$this->_shutdown_save_mailboxes();

			return $rows > 0;
		}

		public function disable_address($account, $domain = null)
		{
			$where = 'AND email_lookup.domain = domain_lookup.domain AND domain_lookup.site_id = ' . $this->site_id;
			if ($domain) {
				$where .= 'AND domain_lookup.domain = \'' . pg_escape_string($domain) . '\'';
			}
			$pgdb = \PostgreSQL::initialize();
			$pgdb->query('UPDATE email_lookup SET enabled = 0::bit FROM domain_lookup WHERE "user" = \'' . pg_escape_string($account) . '\' ' . $where . ';');
			return $pgdb->affected_rows() > 0;
		}

		public function set_webmail_location($app, $subdomain)
		{
			if (!IS_CLI) {
				return $this->query('email_set_webmail_location', $app, $subdomain);
			}

			if (!array_key_exists($app, $this->webmail_apps())) {
				return error("unknown webmail app `%s'", $app);
			}

			$subdomain = strtolower($subdomain);
			$locations = $this->webmail_apps();
			$oldsubdomain = $locations[$app];
			if ($oldsubdomain == $subdomain) {
				// no-op
				return true;
			} else {
				if (!preg_match(Regex::SUBDOMAIN, $subdomain)) {
					return error("invalid subdomain `%s'", $subdomain);
				} else {
					if ($this->web_subdomain_exists($subdomain)) {
						return error("subdomain `%s' already exists - cannot overwrite", $subdomain);
					}
				}
			}


			// system-default webmail locations won't appear in subdomain_exists() query
			if ($this->web_subdomain_exists($oldsubdomain) && !$this->web_remove_subdomain($oldsubdomain)) {
				warn("cannot remove old webmail location `%s'", $oldsubdomain);
			}
			$paths = $this->_webmailPaths();
			$fspath = $paths[$app];
			$this->web_add_subdomain_raw($subdomain, $fspath);
			$locations[$app] = $subdomain;
			$cache = Cache_Account::spawn($this->getAuthContext());
			$cache->set('em.webmail', $locations);

			$file = $this->_customWebmailFile();
			file_put_contents($file, Util_Conf::build_ini($locations));
			if (!$this->dns_record_exists($this->domain, $subdomain, 'A')) {
				$ip = $this->common_get_ip_address();
				$this->dns_add_record($this->domain, $subdomain, 'A', $ip);
				info("added DNS for %s.%s to `%s'", $subdomain, $this->domain, $ip);
			}
			return info("webmail location changed from `%s.%s' to `%s.%s'",
					$oldsubdomain, $this->domain, $subdomain, $this->domain) || true;
		}

		public function webmail_apps()
		{
			if (!IS_CLI) {
				$cache = Cache_Account::spawn($this->getAuthContext());
				if (false !== ($webmail = $cache->get('em.webmail'))) {
					return $webmail;
				}
				$apps = $this->query('email_webmail_apps');
				$cache->set('em.webmail', $apps);
				return $apps;
			}
			return array_merge($this->_webmailSubdomains(), $this->_loadCustomWebmail());
		}

		public function get_webmail_location($app)
		{
			$cache = Cache_Account::spawn($this->getAuthContext());
			if (false !== ($webmail = $cache->get('em.webmail'))) {
				return $webmail[$app];
			}
			$webmail = $this->query('email_webmail_apps');
			if (!isset($webmail[$app])) {
				return error("unknown webmail app `%s'", $app);
			}
			return $webmail[$app];
		}

		public function _create()
		{
			// populate spam folders
			$conf = $this->getAuthContext()->getAccount()->cur;
			$user = $conf['siteinfo']['admin_user'];
			// stupid thor...
			$svcs = array('smtp_relay', 'imap', 'pop3');
			$pam = new Util_Pam($this->getAuthContext());
			foreach ($svcs as $svc) {
				if ($this->auth_is_demo() && $pam->check($user, $svc)) {
					$pam->remove($user, $svc);
				}
			}
			if (platform_is('7.5', '<')) {
				return true;
			}
			if (!$this->_create_user($user)) {
				return false;
			}
			$this->add_mailbox('postmaster', $this->domain, $this->user_id);
			return true;
		}

		public function _create_user(string $user)
		{
			// flush Dovecot auth cache to acknowledge pwdb changes
			$this->_reload('adduser');
			if (!$pwd = $this->user_getpwnam($user)) {
				return false;
			}
			// older platforms do this implicitly
			// @TODO when surrogate user drops hook, drop this
			if (!Opcenter\Provisioning\Mail::createUser($this->site_id, $pwd['uid'], $user)) {
				return error("failed to create mail lookup for `%s' on `site%d'", $user, $this->site_id);
			}
			if (!$pwd['home']) {
				return false;
			}

			// use imap as a marker for email creation
			$svc = 'imap';
			if ((new Util_Pam($this->getAuthContext()))->check($user, $svc)) {
				if ($this->address_exists($user, $this->domain)) {
					info("mailbox %s@%s already exists", $user, $this->domain);
				} else if (!$this->add_mailbox($user, $this->domain, $pwd['uid'])) {
					return error("failed to create email address %s@%s", $user, $this->domain);
				}
			}

			$path = $this->domain_fs_path() . DIRECTORY_SEPARATOR . $pwd['home'] .
				DIRECTORY_SEPARATOR . self::MAILDIR_HOME;
			if (!is_dir($path)) {
				Opcenter\Filesystem::mkdir($path, $pwd['uid'], $this->group_id, 0700, false);
				\Opcenter\Mail\Storage::bindTo($this->domain_fs_path())->createMaildir($this->file_unmake_path($path), $pwd['uid'], $pwd['gid']);
				file_put_contents($path . '/subscriptions', 'INBOX', FILE_APPEND);
			}


			foreach (['Spam', 'Trash', 'Sent'] as $folder) {
				$dir = $path . DIRECTORY_SEPARATOR . ".${folder}";
				if (!is_dir($dir)) {
					$this->create_maildir_backend($user, $folder);
				}

			}
			return true;
		}

		public function _reload($why = null)
		{
			if ($why == "letsencrypt") {
				// update ssl certs
				Util_Process::exec('/sbin/service dovecot restart');
				// restart necessary to load new cert
				Util_Process::exec('/sbin/service postfix restart');
			} else if ($why == "adduser") {
				// just flush auth cache
				if (platform_is('6')) {
					$cmd = 'doveadm auth cache flush';
				} else if (platform_is('5')) {
					$cmd = 'dovecot reload';
				} else {
					$cmd = '/sbin/service dovecot reload';
				}
				Util_Process::exec($cmd);
			}
		}

		public function create_maildir($mailbox)
		{
			if (!IS_CLI) {
				return $this->query('email_create_maildir', $mailbox);
			}
			return $this->create_maildir_backend($this->username, $mailbox);
		}

		/**
		 * Create
		 * @param $user
		 * @param $mailbox
		 * @return bool|void
		 */
		public function create_maildir_backend($user, $mailbox)
		{
			$mailbox = '.' . ltrim($mailbox, '.');
			if (!preg_match(Regex::EMAIL_MAILDIR_FOLDER, $mailbox)) {
				return error("invalid maildir folder name `%s'", $mailbox);
			}

			$pwd = $this->user_getpwnam($user);
			if (!$pwd) {
				return error("failed to create Maildir storage, user `%s' does not exist", $user);
			}

			$path = $pwd['home'] . DIRECTORY_SEPARATOR .
				static::MAILDIR_HOME . DIRECTORY_SEPARATOR . \Opcenter\Mail\Storage::mailbox2Maildir($mailbox);
			$chkvpath = dirname($path);
			$chkrpath = $this->domain_fs_path($chkvpath);
			if (!is_dir($chkrpath)) {
				return error("mail home `%s' does not exist", $chkvpath);
			}
			return \Opcenter\Mail\Storage::bindTo($this->domain_fs_path())->createMaildir($path, $pwd['uid'], $pwd['gid']);
		}

		/**
		 * Get DNS records
		 *
		 * @param string $domain
		 * @return array
		 */
		public function get_records(string $domain): array {
			$myip = $this->site_ip_address();
			$ttl = $this->dns_get_default('ttl');
			return [
				new \Opcenter\Dns\Record($domain,
					['name' => 'mail', 'ttl' => $ttl, 'rr' => 'a', 'parameter' => $myip]),
				new \Opcenter\Dns\Record($domain,
					['name' => '', 'ttl' => $ttl, 'rr' => 'mx', 'parameter' => '10 mail.' . $domain]),
				new \Opcenter\Dns\Record($domain,
					['name' => '', 'ttl' => $ttl, 'rr' => 'mx', 'parameter' => '20 mail.' . $domain]),
				new \Opcenter\Dns\Record($domain,
					['name' => '', 'ttl' => $ttl, 'rr' => 'txt', 'parameter' => '"v=spf1 a mx ~all"']),
				/* webmail */
				new \Opcenter\Dns\Record($domain,
					['name' => 'horde', 'ttl' => $ttl, 'rr' => 'a', 'parameter' => $myip]),
				new \Opcenter\Dns\Record($domain,
					['name' => 'roundcube', 'ttl' => $ttl, 'rr' => 'a', 'parameter' => $myip]),
			];
		}

		public function _delete()
		{
			$conf = $this->getAuthContext()->getAccount()->cur;
			$ips = $conf['ipinfo']['ipaddrs'];
			if (!$ips) {
				return true;
			}
			foreach ($ips as $ip) {
				$this->_removeMTA($ip);
			}
			$this->_removeIMAP($this->site);
		}

		public function _edit()
		{
			$conf_new = $this->getAuthContext()->getAccount()->new;
			$conf_old = $this->getAuthContext()->getAccount()->old;
			$user = array(
				'old' => $conf_old['siteinfo']['admin_user'],
				'new' => $conf_new['siteinfo']['admin_user']
			);
			/**
			 * update alias mapping, mailbox mappings update on the backend
			 *
			 * @TODO phase out legacy backend
			 */
			if ($user['old'] !== $user['new']) {
				// @XXX bug: _edit is called after EVD completes
				// old pwd is lost, but send anyway to placate _edit_user
				$this->_edit_user(
					$user['old'],
					$user['new'],
					$this->user_getpwnam($user['new'])
				);
			}

			/**
			 * Update private smtp routing + whitelabel dovecot config
			 */
			$ipcur = $conf_old['ipinfo'];
			$ipnew = $conf_new['ipinfo'];

			if ($ipnew === $ipcur) {
				return true;
			}
			// ip either added or removed
			if (!$ipcur['namebased'] && $ipnew['namebased']) {
				foreach ($ipcur['ipaddrs'] as $ip) {
					$this->_removeMTA($ip);
					$this->_removeIMAP($this->site);
				}
			} else if ($ipcur['namebased'] && !$ipnew['namebased']) {
				foreach ($ipnew['ipaddrs'] as $ip) {
					$this->_addMTA($ip);
				}
			} else if ($ipcur['ipaddrs'] != $ipnew['ipaddrs']) {
				$remove = array_diff($ipcur['ipaddrs'], $ipnew['ipaddrs']);
				$add = array_diff($ipnew['ipaddrs'], $ipcur['ipaddrs']);
				foreach ($remove as $ip) {
					$this->_removeMTA($ip);
				}
				foreach ($add as $ip) {
					$this->_addMTA($ip);
				}
				// @TODO update Dovecot config
			}
		}

		public function _edit_user(string $userold, string $usernew, array $oldpwd)
		{
			// Dovecot is a finnicky bastard
			$this->_reload('adduser');
			if ($userold === $usernew) {
				return;
			}
			// edit_user hooks enumerated after user changed
			$uid = $this->user_get_uid_from_username($usernew);
			if (!$uid) {
				return error("cannot determine uid from user `%s' in mailbox translation", $userold);
			}
			$pam = new Util_Pam($this->getAuthContext());
			mute_warn();
			foreach ($this->_pam_services() as $svc) {
				if ($this->user_enabled($userold, $svc)) {
					$pam->remove($userold, $svc);
					// edit_user hook renames user then calls
					$pam->add($usernew, $svc);
				}
			}
			unmute_warn();
			// update uids in uids table
			$db = \PostgreSQL::initialize();
			$query = \Opcenter\Database\PostgreSQL::vendor('mail')->renameUser($userold, $usernew, $uid);
			$db->query($query);
			// make 2 sweeps:
			// sweep 1: update mailboxes that refer to the uid
			// sweep 2: update aliases that forward to the user
			// aliases that deliver locally
			$mailboxes = $this->list_mailboxes('local', $userold);
			foreach ($mailboxes as $mailbox) {
				if ($mailbox['type'] === self::MAILBOX_USER) {
					$target = '/home/' . $mailbox['mailbox'] . '/' .
						self::MAILDIR_HOME . '/' . $mailbox['custom'];
				} else {
					$target = $mailbox['mailbox'];
				}
				$this->modify_mailbox($mailbox['user'],
					$mailbox['domain'],
					$usernew,
					$mailbox['domain'],
					$target,
					$mailbox['type']
				);
			}
			// sweep 2
			$this->_update_email_aliases($userold, $usernew);
			return true;
		}

		public function _delete_user(string $user)
		{
			$pwd = $this->user_getpwnam($user);
			foreach ($this->list_mailboxes(self::MAILBOX_DESTINATION, $user) as $mailbox) {
				$this->delete_mailbox($mailbox['user'], $mailbox['domain']);
			}
			\Opcenter\Provisioning\Mail::deleteUser($this->site_id, $pwd['uid']);
		}

		public function user_enabled($user, $svc = null)
		{
			if ($svc && $svc != 'imap' && $svc != 'smtp' && $svc != 'smtp_relay' && $svc !== 'pop3') {
				return error("unknown service `%s'", $svc);
			}
			if (!$this->enabled($svc)) {
				return false;
			}
			$enabled = 1;
			if (!$svc) {
				$enabled = (new Util_Pam($this->getAuthContext()))->check($user, 'imap');
				$svc = 'smtp_relay';
			} else if ($svc == 'smtp') {
				$svc = 'smtp_relay';
			}
			return $enabled && (new Util_Pam($this->getAuthContext()))->check($user, $svc);
		}

		public function permit_user($user, $svc = null)
		{
			if ($svc && $svc != 'smtp' && $svc != 'imap' && $svc != 'smtp_relay') {
				return error("service " . $svc . " is unknown (imap, smtp)");
			}

			if ($this->auth_is_demo()) {
				return error("Email disabled for demo account");
			}

			$pam = new Util_Pam($this->getAuthContext());
			if (!$svc) {
				$pam->add($user, 'imap');
				$svc = 'smtp_relay';
			} else if ($svc == 'smtp') {
				$svc = 'smtp_relay';
			} else if (platform_is('7.5')) {
				//
				$mirror = $svc === 'imap' ? 'pop3' : 'imap';
				$pam->add($user, $mirror);
			}
			return $pam->add($user, $svc);
		}

		public function deny_user($user, $svc = null)
		{
			if ($svc && $svc != 'smtp' && $svc != 'imap' && $svc != 'smtp_relay' && $svc !== 'pop3') {
				return error("service " . $svc . " not in list");
			}
			$pam = new Util_Pam($this->getAuthContext());
			if (!$svc) {
				$pam->remove($user, 'smtp');
				$svc = 'imap';
			} else if ($svc == 'smtp') {
				$svc = 'smtp_relay';
			}
			// v7.5 doesn't differentiate between IMAP/POP3 yet
			if ($svc === 'imap' && platform_is('7.5')) {
				$pam->remove($user, 'pop3');
			} else if ($svc === 'pop3' && platform_is('7.5')) {
				$pam->remove($user, 'imap');
			}
			return $pam->remove($user, $svc);
		}

		public function list_virtual_transports()
		{
			$virtual = array();
			$res = \PostgreSQL::initialize()->query("SELECT domain FROM domain_lookup WHERE site_id = " . $this->site_id);
			while (null !== ($row = $res->fetch_object())) {
				$virtual[] = trim($row->domain);
			}
			return $virtual;
		}

		private function _shutdown_save_mailboxes()
		{
			if (!IS_ISAPI) {
				$this->save_mailboxes();
			}
			static $called;
			if (isset($called)) {
				return;
			}
			$called = 1;
			return register_shutdown_function(array($this, 'save_mailboxes'));
		}

		private function _webmailSubdomains()
		{
			return array_combine(array_keys($this->_webmail), array_map(function ($v) {
				return $v['subdomain'];
			}, $this->_webmail));
		}

		private function _loadCustomWebmail()
		{
			$file = $this->_customWebmailFile();
			$apps = array();
			if (!file_exists($file)) {
				return $apps;
			}
			$apps = array_merge($apps, Util_Conf::parse_ini($file));
			return $apps;
		}

		private function _customWebmailFile()
		{
			return $this->domain_info_path() . '/webmail';
		}

		private function _webmailPaths()
		{
			return array_combine(array_keys($this->_webmail), array_map(function ($v) {
				return $v['path'];
			}, $this->_webmail));
		}

		private function _removeMTA($ip)
		{
			$hosts = file(Dns_Module::HOSTS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			$regex = Regex::compile(
				Regex::EMAIL_MTA_IP_RECORD,
				array(
					'ip' => preg_quote($ip, '/')
				)
			);

			$new = array();
			$found = false;
			foreach ($hosts as $host) {
				if (preg_match($regex, $host)) {
					$found = true;
					continue;
				}
				$new[] = $host;
			}
			$new[] = "";
			if (!$found) {
				return -1;
			}
			/**
			 * it's here for future consideration, but likely unnecessary
			 * $proc = new Util_Process_Schedule("1 minute");
			 * $proc->run(self::POSTFIX_CMD . ' reload');
			 */
			return file_put_contents(Dns_Module::HOSTS_FILE, join(PHP_EOL, $new), LOCK_EX) !== false;
		}

		private function _removeIMAP($site)
		{
			$path = self::DOVECOT_SSL_CONFIG_DIR . '/' . $site;
			$extensions = array('conf', 'crt', 'key', 'pem');
			foreach ($extensions as $ext) {
				$file = $path . '.' . $ext;
				if (file_exists($file)) {
					unlink($file);
				}
			}
		}

		private function _pam_services()
		{
			return array('smtp_relay', 'imap');
		}

		/**
		 * Update forwarded e-mail dependencies on user change
		 *
		 * @param $user
		 * @param $usernew
		 * @return int number mailboxes changed, -1 if update fails
		 */
		private function _update_email_aliases($user, $usernew)
		{
			$prepfunc = function ($domain) use ($user) {
				return '\b' . preg_quote($user, '/') . '@(' . preg_quote($domain, '/') . ')\b';
			};

			$regexcb = function ($matches) use ($usernew) {
				return $usernew . '@' . $matches[1];
			};

			$domains = $this->list_virtual_transports();
			$regex = '/' . join("|", array_map($prepfunc, $domains)) . '/S';

			$forwards = $this->list_mailboxes(self::MAILBOX_FORWARD);
			$changed = 0;
			foreach ($forwards as $forward) {
				$cnt = 0;
				$new = preg_replace_callback($regex, $regexcb, $forward['destination'], -1, $cnt);
				if ($cnt < 1) {
					continue;
				}
				if ($this->modify_mailbox(
					$forward['user'],
					$forward['domain'],
					$forward['user'],
					$forward['domain'],
					$new,
					$forward['type']
				)
				) {
					if ($changed > -1) {
						$changed++;
					}
				} else {
					warn("failed to adjust mailbox `%s@%s`", $forward['user'], $forward['domain']);
					$changed = -1;
				}

			}
			return $changed;
		}

		private function _addMTA($ip)
		{
			$hosts = file(Dns_Module::HOSTS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			$regex = Regex::compile(
				Regex::EMAIL_MTA_IP_RECORD,
				array(
					'ip' => preg_quote($ip, '/')
				)
			);
			foreach ($hosts as $host) {
				if (preg_match($regex, $host)) {
					return -1;
				}
			}

			$hosts[] = $ip . ' internal-multihome';
			$hosts[] = "";
			return file_put_contents(Dns_Module::HOSTS_FILE, join(PHP_EOL, $hosts), LOCK_EX) !== false;
		}

		public function _verify_conf(\Opcenter\Service\ConfigurationContext $ctx): bool
		{
			return true;
		}

		public function _housekeeping() {
			$dummyfile = webapp_path('webmail/dummyset.php');
			$dest = '/var/www/html/dummyset.php';
			if (!file_exists($dest) || fileinode($dummyfile) !== fileinode($dest)) {
				file_exists($dest) && unlink($dest);
				link($dummyfile, $dest);
			}
			return true;
		}
	}
