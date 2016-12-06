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
	 * E-mail functions (aliases, virtual mailboxes)
	 *
	 * @package core
	 */
	class Email_Module extends Module_Skeleton
	{
		const MAILDIR_HOME = 'Mail';
		const MAILBOX_SPECIAL = 's';
		const MAILBOX_FORWARD = 'a';
		const MAILBOX_USER = 'v';
		const MAILBOX_DISABLED = 'd';
		const MAILBOX_ENABLED = 'e';
		const MAILBOX_SINGLE = '1';
		const VACATION_RE = '^\s*include "\$HOME/\.vacationrc"';
		const VACATION_RECIPE = '/^(?:X-Original-To|Delivered-To): (.+)/
TOADDR=$MATCH1
if (!/^X-Spam-Flag: YES/ && /^(?:To|Cc):.*${TOADDR}/) # Make sure we are not BCC\'d
{
	 cc "| mailbot -c \'UTF-8\' -N -A \'From: $TOADDR\' -t $HOME/.vacation.msg -d .vacation.db /usr/sbin/sendmail -t -i -f \'\'"
}';
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
				'add_vacation_backend'            => PRIVILEGE_SITE | PRIVILEGE_USER | PRIVILEGE_SERVER_EXEC,
				'vacation_exists'                 => PRIVILEGE_SITE | PRIVILEGE_USER,
				'vacation_exists_backend'         => PRIVILEGE_SITE | PRIVILEGE_USER | PRIVILEGE_SERVER_EXEC,
				'remove_vacation'                 => PRIVILEGE_SITE | PRIVILEGE_USER,
				'get_vacation_message'            => PRIVILEGE_SITE | PRIVILEGE_USER,
				'get_vacation_message_backend'    => PRIVILEGE_SITE | PRIVILEGE_USER | PRIVILEGE_SERVER_EXEC,
				'change_vacation_message'         => PRIVILEGE_SITE | PRIVILEGE_USER,
				'change_vacation_message_backend' => PRIVILEGE_SITE | PRIVILEGE_USER | PRIVILEGE_SERVER_EXEC,
				'get_vacation_message'            => PRIVILEGE_SITE | PRIVILEGE_USER,
				'get_vacation_message_backend'    => PRIVILEGE_SITE | PRIVILEGE_USER | PRIVILEGE_SERVER_EXEC,
				'get_webmail_location'            => PRIVILEGE_SITE | PRIVILEGE_USER,
				'webmail_apps'                    => PRIVILEGE_SITE | PRIVILEGE_USER,
				'create_maildir'                  => PRIVILEGE_SITE | PRIVILEGE_USER,
				'remove_maildir'                  => PRIVILEGE_SITE | PRIVILEGE_USER,
				'*'                               => PRIVILEGE_SITE
			);
		}

		public function list_aliases()
		{
			return $this->list_mailboxes('forward');
		}

		/**
		 * Retrieve mailbox delivery maps from system
		 *
		 * @param $filter  string optional filter, possible values: forward, local, special, single, enabled, disabled
		 * @param $address string supplementary argument to 'single', restrict address to %expr%
		 * @param $domain  string optionally restrict to all addresses matching domain
		 *
		 * @return array
		 *
		 */
		public function list_mailboxes($filter = null, $address = null, $domain = null)
		{
			$filter_clause = '1=1';

			if ($filter == 'forward')
				$filter = self::MAILBOX_FORWARD;
			else if ($filter == 'local')
				$filter = self::MAILBOX_USER;
			else if ($filter == 'special')
				$filter = self::MAILBOX_SPECIAL;
			else if ($filter == 'disabled')
				$filter = self::MAILBOX_DISABLED;
			else if ($filter == 'enabled')
				$filter = self::MAILBOX_ENABLED;

			if ($filter && !in_array($filter, array(self::MAILBOX_FORWARD, self::MAILBOX_USER, self::MAILBOX_SPECIAL,
					self::MAILBOX_DISABLED, self::MAILBOX_ENABLED, self::MAILBOX_SINGLE))
			)
				return error("invalid filter specification `%s'", $filter);

			if ($filter == self::MAILBOX_FORWARD) {
				$filter_clause = 'type = \'' . self::MAILBOX_FORWARD . '\'';
			} else if ($filter == self::MAILBOX_USER) {
				$filter_clause = 'type = \'' . self::MAILBOX_USER . '\'';
			} else if ($filter == self::MAILBOX_SPECIAL) {

			} else if ($filter == self::MAILBOX_SINGLE) {
				$filter_clause = 'email_lookup."user" ' . (strstr($address, '%') ? 'LIKE' : '=') . ' \'' . pg_escape_string($address) . '\'';
			} else if ($filter == self::MAILBOX_ENABLED) {
				$filter_clause = 'enabled = 1::bit';
			} else if ($filter == self::MAILBOX_DISABLED) {
				$filter_clause = 'enabled = 0::bit';
			}
			if (!is_null($address)) {
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

			$this->pgsql->query($query);
			while ($row = $this->pgsql->fetch_object()) {
				$mailboxes[] = array(
					'user'        => trim($row->user),
					'domain'      => trim($row->domain),
					'type'        => $row->type,
					'enabled'     => $row->enabled,
					'mailbox'     => $row->destination,
					'uid'         => $row->uid,
					'custom'      => ($filter === 'local' ? $row->target : null),
					'destination' => $row->destination);
			}
			return $mailboxes;
		}

		public function enable_address($account, $domain = null)
		{
			$where = 'AND email_lookup.domain = domain_lookup.domain AND domain_lookup.site_id = ' . $this->site_id;
			if ($domain)
				$where .= 'AND domain_lookup.domain = \'' . pg_escape_string($domain) . '\'';
			$this->pgsql->query('UPDATE email_lookup SET enabled = 1::bit FROM domain_lookup WHERE "user" = \'' . pg_escape_string($account) . '\' ' . $where . ';');
			return $this->pgsql->affected_rows() > 0;
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
		 * @param        $olduser
		 * @param        $olddomain
		 * @param string $newuser
		 * @param string $newdomain
		 * @param string $newdestination
		 * @param null   $newtype
		 * @return bool|void
		 */
		public function modify_mailbox($olduser, $olddomain, $newuser = '', $newdomain = '', $newdestination = '', $newtype = null)
		{
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

			if (($olduser . '@' . $olddomain != $newuser . '@' . $newdomain) && $this->address_exists($newuser, $newdomain)) {
				return error("E-mail address %s@%s already exists. Can't rename!",
					$newuser, $newdomain);
			}

			if (!$newtype) {
				$newtype = $this->mailbox_type($olduser, $olddomain);
			}

			if ($newtype == self::MAILBOX_USER) {
				if (false != ($uid = intval($newdestination))) {
					$uid = intval($newdestination);
					$local_user = $this->user_get_username_from_uid($uid);
					$newdestination = '/home/' . $local_user . '/' . self::MAILDIR_HOME;
					if (!$local_user) {
						return error("Invalid mailbox destination, invalid uid `%d'", $uid);
					}
				} else if ($newdestination) {
					if (preg_match('!^/home/([^/]+)/' . self::MAILDIR_HOME . '([/.]*)$!', $newdestination, $match)) {
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


				$users = $this->user_get_users();
				if (!isset($users[$local_user])) {
					return error("User account `%s' does not exist", $local_user);
				}

				$uid = intval($users[$local_user]['uid']);

				if ($newdestination == '')
					$newdestination = null;
				else {
					$this->query('email_create_maildir_backend', $local_user, $newdestination);
				}

				$this->pgsql->query("UPDATE email_lookup SET \"user\" = '" . $newuser . "', domain = '" . $newdomain . "', " .
					"fs_destination = " . (($newdestination != null) ? "'" . pg_escape_string(rtrim($newdestination, ' /') . '/') . "'" : "NULL") . ", " .
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
				$this->pgsql->query("UPDATE email_lookup SET \"user\" = '" . pg_escape_string($newuser) . "', domain = '" . pg_escape_string($newdomain) . "', " .
					"alias_destination = '" . pg_escape_string($newdestination) . "', uid = NULL, type = '" .
					self::MAILBOX_FORWARD . "', fs_destination = NULL WHERE \"user\" = '" .
					pg_escape_string($olduser) . "' AND domain = '" . pg_escape_string($olddomain) . "';");

			}
			$rows = $this->pgsql->affected_rows();
			$this->_shutdown_save_mailboxes();

			return $rows > 0;
		}

		public function address_exists($user, $domain)
		{
			$user = strtolower($user);
			$domain = strtolower($domain);
			if (!preg_match('/^[a-z0-9\._@\+-]+$/', $user . '@' . $domain))
				return error("invalid address `" . $user . '@' . $domain . "'");
			$this->pgsql->query("SELECT 1 FROM email_lookup WHERE \"user\" = '" . pg_escape_string($user) . "' AND domain = '" . pg_escape_string($domain) . "'");

			return $this->pgsql->num_rows() > 0;
		}

		public function mailbox_type($user, $domain)
		{
			$user = strtolower($user);
			$domain = strtolower($domain);
			if (!preg_match(Regex::EMAIL, $user . '@' . $domain))
				return error("invalid address `" . $user . '@' . $domain . "'");
			$this->pgsql->query("SELECT type FROM email_lookup WHERE \"user\" = '" . $user . "' AND domain = '" . $domain . "'");

			if ($this->pgsql->num_rows() < 1) {
				return null;
			}
			return $this->pgsql->fetch_object()->type;
		}

		private function _shutdown_save_mailboxes()
		{
			if (!IS_ISAPI) {
				$this->save_mailboxes();
			}
			static $called;
			if (isset($called)) return;
			$called = 1;
			return register_shutdown_function(array($this, 'save_mailboxes'));
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
			if (!IS_CLI) return $this->query('email_save_mailboxes');
			$q = 'SELECT * FROM email_lookup WHERE domain IN
                (select domain FROM domain_lookup WHERE site_id = ' . $this->site_id . ')';
			$db = $this->pgsql;
			$email = array();
			$rs = $db->query($q);
			while ($row = $db->fetch_assoc()) {
				$email[] = array_map('trim', $row);
			}
			$file = $this->domain_info_path() . '/email_addr';
			return (bool)file_put_contents($file, serialize($email), LOCK_EX);
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
			if ($type == 'l' || $type == self::MAILBOX_USER)
				$type = self::MAILBOX_USER;
			else if ($type == 'f' || $type == self::MAILBOX_FORWARD)
				$type = self::MAILBOX_FORWARD;
			else if ($type != '') return error("unknown address type `%s'", $type);

			$clause = '';
			if ($type)
				$clause = "AND type = '$type' ";
			$this->pgsql->query('DELETE FROM
										email_lookup
								 WHERE
										"user" = \'' . pg_escape_string($user) . "'
										AND
										domain = '" . pg_escape_string($domain) . "'
										$clause
										AND '" . pg_escape_string($domain) . "' IN
											(SELECT domain from domain_lookup WHERE site_id = " . $this->site_id . ");");
			$rows = $this->pgsql->affected_rows();
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
				array($this->domain_fs_path(),
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
			chown($subscriptions, $this->user_id);
			chgrp($subscriptions, $this->group_id);
			chmod($subscriptions, 0600);
			return true;

		}

		/**
		 * Restore a saved copy of mailboxes
		 *
		 * @return boolean
		 */
		public function restore_mailboxes($file = 'email_addr')
		{
			if (!IS_CLI) return $this->query('email_restore_mailboxes', $file);
			if (!strspn($file[0], "abcdefghijklmnopqrstuvwxyz")) {
				return error("invalid mailbox backup `%s'", $file);
			}
			$file = $this->domain_info_path() . '/' . $file;
			if (!file_exists($file)) {
				warn("mailbox backup `%s' not found", basename($file));
				return -1;
			}
			$db = $this->pgsql;
			$recs = unserialize(file_get_contents($file));
			$escapef = function ($rec) {
				return '"' . $rec . '"';
			};

			$escapev = function ($rec) {
				// empty values inserted as NULL
				if ($rec === "") return "NULL";
				else if (ctype_digit($rec)) {
					if ($rec == 0 || $rec == 1) {
						/*
						 * assume this is the "enabled" column,
						 * which mandates a bit
						 */
						$rec .= '::bit';
					}
					return $rec;
				}
				return "'" . pg_escape_string($rec) . "'";
			};
			$db = $this->pgsql->getHandler();
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
					} else if ($errid == 23514) {
						warn("skipped entry `%s@%s': domain for `%s' not " .
							"assigned to handle mail", $r['user'],
							$r['domain'], $r['domain']);
					} else {
						error("skipped `%s@%s': unknown query error",
							$r['user'], $r['domain']);
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
			$q = $this->pgsql->query("SELECT site_id FROM domain_lookup WHERE domain = '" . pg_escape_string($domain) . "'");
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

			if (!array_key_exists($username, $this->user_get_users()))
				return new ArgumentError("Invalid user " . $username);
			return $this->query(
				'email_get_spool_size_backend',
				$this->domain_fs_path() . '/home/' . $username . '/' . self::MAILDIR_HOME
			);

		}

		public function get_spool_size_backend($path)
		{
			if (!file_exists($path))
				return 0;
			$proc = Util_Process_Safe::exec('du -s %s', $path);
			if (!$proc['success']) return false;
			return intval($proc['output']) * 1024;
		}

		public function get_vacation_message($user = null)
		{
			if (!IS_CLI) {
				return $this->query('email_get_vacation_message', $user);
			}
			if (!is_null($user) && !($this->permission_level & PRIVILEGE_SITE))
				return error("unprivileged user may not setup vacation responder for other users");

			if (is_null($user))
				$user = $this->username;

			if (!file_exists($this->domain_fs_path() . '/home/' . $user . '/.vacation.msg'))
				return false;

			return file_get_contents($this->domain_fs_path() . '/home/' . $user . '/.vacation.msg');
		}

		public function add_vacation($response, $user = null)
		{
			if (!IS_CLI) {
				return $this->query('email_add_vacation', $response, $user);
			}
			if (!is_null($user) && !($this->permission_level & PRIVILEGE_SITE))
				return error("Non-privileged user may not setup vacation responder for other users");

			if (is_null($user))
				$user = $this->username;

			$pwd = $this->user_getpwnam($user);
			if (!$pwd)
				return new error("invalid user `%s'", $user);

			$home = $this->domain_fs_path() . $pwd['home'];
			$mailfilter = $home . '/.mailfilter';
			$recipe = '';
			if (file_exists($mailfilter)) $recipe = trim(file_get_contents($mailfilter));
			if (!preg_match('!' . self::VACATION_RE . '!m', $recipe)) {
				file_put_contents($mailfilter, $recipe . "\n" . 'include "$HOME/.vacationrc"' . "\n");
			}

			//if (!file_exists($home.'/.vacationrc'))
			$recipe = self::VACATION_RECIPE;
			if (platform_version() < 5) {
				$recipe = str_replace('-N ', '', $recipe);
			}
			file_put_contents($home . '/.vacationrc', $recipe);

			file_put_contents($home . '/.vacation.msg', $response);
			chown($home . '/.vacation.msg', intval($pwd['uid']));
			chgrp($home . '/.vacation.msg', intval($pwd['gid']));

			chown($home . '/.vacationrc', intval($pwd['uid']));
			chgrp($home . '/.vacationrc', intval($pwd['gid']));
			chmod($home . '/.vacationrc', 0600);
			return true;
		}

		public function vacation_exists($user = null)
		{
			if (!is_null($user) && (($this->privilege_level & PRIVILEGE_SITE) != PRIVILEGE_SITE)) {
				return error("Unable to check vacation for non-admin account");
			}

			if (is_null($user))
				$user = $this->username;

			if (!$this->user_getpwnam($user))
				return error("Invalid user `%s'", $user);

			return $this->query('email_vacation_exists_backend', $user);
		}

		public function vacation_exists_backend($user)
		{
			return file_exists($this->domain_fs_path() . '/home/' . $user . '/.mailfilter') &&
			preg_match('!' . self::VACATION_RE . '!m',
				file_get_contents($this->domain_fs_path() . '/home/' . $user . '/.mailfilter'));
		}

		public function change_vacation_message($response, $user = null)
		{

			if (!is_null($user) && (($this->privilege_level & PRIVILEGE_SITE) != PRIVILEGE_SITE)) {
				return new PermissionError("Unable to check vacation for non-admin account");
			}
			if (is_null($user))
				$user = $this->username;

			if (!$this->user_getpwnam($user))
				return new ArgumentError("Invalid user " . $user);

			return $this->query('email_change_vacation_message_backend', $response, $user);

		}

		public function change_vacation_message_backend($response, $user)
		{
			$pwd = $this->user_getpwnam($user);
			if (!$pwd)
				return new ArgumentError("Invalid user, " . $user);
			file_put_contents($this->domain_fs_path() . '/home/' . $user . '/.vacation.msg', $response);
			chown($this->domain_fs_path() . '/home/' . $user . '/.vacation.msg', intval($pwd['uid']));
			chgrp($this->domain_fs_path() . '/home/' . $user . '/.vacation.msg', intval($pwd['gid']));
			return true;
		}

		/**
		 * bool remove_vacation ([string])
		 */
		public function remove_vacation($user = null)
		{
			if (!IS_CLI)
				return $this->query('email_remove_vacation', $user);

			if ($user && ($this->privilege_level & PRIVILEGE_SITE == 0))
				return error("Unable to check vacation for non-admin account");
			if (!$user) $user = $this->username;

			if (!$this->user_exists($user)) return error($user . ": invalid user");

			if (!file_exists($this->domain_fs_path() . '/home/' . $user . '/.mailfilter'))
				return false;

			file_put_contents($this->domain_fs_path() . '/home/' . $user . '/.mailfilter',
				preg_replace('!' . self::VACATION_RE . "\r?\n?!m", "", file_get_contents($this->domain_fs_path() . '/home/' . $user . '/.mailfilter')));
			$files = array('.vacation.db', '.vacation.db.gdbm', '.vacation.db.lock');
			foreach ($files as $f) {
				$file = $this->domain_fs_path() . '/home/' . $user . '/' . $f;
				if (file_exists($file))
					unlink($file);
			}
			return true;
		}

		public function clone_domain_mailboxes($source, $destination)
		{
			$this->remove_virtual_transport($destination);
			if (!$this->add_virtual_transport($destination))
				return false;

			foreach ($this->list_mailboxes(null, null, $source) as $mailbox) {
				if ($mailbox['type'] == self::MAILBOX_USER) {
					if (preg_match('!^/home/([^/]+)/' . self::MAILDIR_HOME . '/?(.*)$!', $mailbox['destination'], $mailbox_dest)) {
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

				if (!$mailbox['enabled'])
					$this->disable_address($mailbox['user'], $mailbox['domain']);

			}

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
			$q = $this->pgsql->query("SELECT site_id FROM domain_lookup WHERE domain = '" . pg_escape_string($domain) . "'");
			if ($q->num_rows() < 1)
				return false;

			$site_id = $this->pgsql->fetch_object()->site_id;

			if ($site_id && $site_id != $this->site_id)
				return error("Table entry " . $domain . " owned by another site (" . $site_id . ")");
			else if ($this->pgsql->num_rows() < 1)
				return error("Domain " . $domain . " not found in table");
			foreach ($this->majordomo_list_mailing_lists() as $list) {
				$tmp = $this->majordomo_get_domain_from_list_name($list);
				if ($tmp == $domain) {
					warn("Mailing list `%s' sends from `%s'. Delete via Mail > Mailing Lists", $list, $domain);
				}
			}
			$this->pgsql->query("DELETE FROM domain_lookup WHERE domain = '" . pg_escape_string($domain) . "' AND site_id = " . (int)$this->site_id . ";");
			$ok = $this->pgsql->affected_rows() > 0;
			if (is_null($keepdns)) {
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
					} else if (!count($rec)) {
						// MX record exists remotely but not on the server
						info("no MX records found for hostname `%s'", $hostname);
						return $ok;
					}
					// check just first record
					$rec = array_pop($rec);
					list($priority, $hostname) = preg_split("/\s+/", $rec['parameter']);
					// a fqdn is supplied, terminated by a period, strip it
					$hostname = trim($hostname, ".");
					$ip = $this->dns_gethostbyname_t($hostname, 5000);
					if ($ip && $ip != $myip) {
						warn("MX record for `%s' is custom and thus will not be removed", $domain);
						return -1;
					}
					// purge MX record from DNS
					$keepdns = false;
				}
			}

			if (!$keepdns) {
				$split = $this->web_split_host($domain);
				$mailsub = rtrim('mail.' . $split['subdomain'], '.');
				if ($this->dns_record_exists($split['domain'], $split['subdomain'], 'MX')) {
					$this->dns_remove_record($split['domain'], $split['subdomain'], 'MX');
				}
				if ($this->dns_record_exists($split['domain'], $mailsub, 'A')) {
					$this->dns_remove_record($split['domain'], $mailsub, 'A');
				}
			}
			return $ok;
		}

		public function add_virtual_transport($domain, $subdomain = '')
		{
			$aliases = $this->aliases_list_aliases();
			if (($domain != $this->domain) && !in_array($domain, $aliases))
				return error("domain `%s' not owned by site", $domain);
			$transport = ($subdomain ? $subdomain . '.' : '') . $domain;

			$rs = $this->pgsql->query("SELECT site_id FROM domain_lookup WHERE domain = '" . pg_escape_string($transport) . "'");
			$nr = $this->pgsql->num_rows();

			if ($nr > 0) {
				$site = $rs->fetch_object()->site_id;
				if ($site != $this->site_id)
					return error("table entry `%s' owned by another site (%d)", $transport, $site);
				return true;
			}

			$this->pgsql->query("INSERT INTO domain_lookup (domain, site_id) VALUES('" . pg_escape_string($transport) . "', " . (int)$this->site_id . ");");
			if ($this->pgsql->affected_rows() < 1) {
				return error("failed to add e-mail transport `%s'", $transport);
			}
			// default record
			$myip = $this->site_ip_address();
			$mymailrec = rtrim('mail.' . $subdomain, '.');
			$forcemake = false;
			if (!$this->dns_record_exists($domain, $subdomain, 'MX')) {
				// add DNS first
				$this->dns_add_record($domain, $subdomain, 'MX', '10 mail.' . $transport);
			} else {
				// record exists, confirm MX value
				$hostname = ltrim($subdomain . "." . $domain, ".");

				$rec = $this->dns_get_records_by_rr('MX', $hostname);
				// just examine the first record...
				if (!$rec) {
					// external DNS settings, dns_record_exists queries public DNS
					// get_records_by_rr queries internally
					$nsrecs = join(", ", $this->dns_get_hosting_nameservers());
					warn("external nameservers are used to provide DNS for domain. Continuing to make " .
						"local MX records on local nameservers. E-mail configuration in Mail > Manage Mailboxes " .
						"will not be reflected until nameservers are changed to %s",
						$nsrecs,
						$nsrecs
					);
					$forcemake = true;
					$this->dns_add_record($domain, $subdomain, 'MX', '10 mail.' . $transport);
				} else {
					$rec = array_pop($rec);
					list($priority, $host) = preg_split("/\s+/", $rec['parameter']);
					$mxip = $this->dns_gethostbyname_t($host);
					if ($mxip != $myip) {
						$hostname = ltrim($subdomain . '.' . $domain, ".");
						warn("Custom MX record for `%s' already exists, not overwriting. Manually add a MX record for `%s' to `%s'",
							$hostname,
							$hostname,
							'10 mail.' . $transport);
						return true;
					}
				}
			}

			/**
			 * forcefully set the record just in case, if external DNS is used
			 * if MX destination record is already present, elicit a warning and continue;
			 */
			if ($forcemake || !$this->dns_record_exists($domain, $mymailrec)) {
				$srvrec = $this->dns_get_records($mymailrec, 'A', $domain);
				if (!$srvrec) {
					return $this->dns_add_record($domain, $mymailrec, 'A', $myip) ||
					warn("failed to populate DNS record for MX!");
				}
				// should only be 1 record...
				$srvrec = array_pop($srvrec);
				if ($srvrec['parameter'] == $myip) {
					return true;
				}
				$hostname = join(".", array($mymailrec, $domain));
				warn("A record for %s points to %s, not overwriting! E-mail will not " .
					"route properly until the record is changed from %s to %s.",
					$hostname,
					$srvrec['parameter'],
					$srvrec['parameter'],
					$myip
				);
			}
			return true;
		}

		public function add_mailbox($user, $domain, $uid, $mailbox = '')
		{
			$user = trim($user);
			$domain = trim($domain);
			if ($this->address_exists($user, $domain)) {
				if (!$user)
					return error("catch-all for $domain already exists");
				return error('%s@%s: address exists', $user, $domain);
			}
			$mailbox = ltrim(str_replace(array('/', '..'), '.', $mailbox), '.');
			$uid = intval($uid);
			if ($mailbox) {
				$this->pgsql->query("SELECT \"user\" as name FROM uids WHERE uid = " . $uid . " AND site_id = " . $this->site_id);
				$luser = $this->pgsql->fetch_object();
				if (!$luser)
					return error("lookup failed for `%s' with uid `%s'", $user, $uid);
				$luser = trim($luser->name);
				$this->query('email_create_maildir_backend', $luser, $mailbox);
				$mailbox = pg_escape_string($mailbox);
			}

			$this->pgsql->query("INSERT INTO email_lookup (\"user\", domain, uid, type, enabled, fs_destination)
				VALUES ('" . pg_escape_string($user) . "',
					'" . pg_escape_string($domain) . "',
					" . intval($uid) . ",
					'" . self::MAILBOX_USER . "',
					1::bit,
					" . ($mailbox ? "'" . $mailbox . "'" : "NULL") . ");");
			$rows = $this->pgsql->affected_rows();

			$this->_shutdown_save_mailboxes();

			return $rows > 0;

		}

		public function add_alias($user, $domain, $destination)
		{
			$user = strtolower($user);
			$domain = strtolower($domain);
			if ($this->address_exists($user, $domain))
				return error("%s@%s: address exists", $user, $domain);
			$user = trim($user);
			if (!$user) return error("catch-all may not be forwarded");
			$destination = preg_replace('/\s+|,+/', ",", trim($destination, ' ,'));
			if (!$destination) {
				return error("no destination specified");
			}
			$this->pgsql->query("INSERT INTO email_lookup " .
				"(\"user\", domain, alias_destination, type, enabled) " .
				"VALUES('" . pg_escape_string($user) . "', '" . pg_escape_string($domain) . "', '" .
				trim(pg_escape_string($destination), ',') . "', '" . self::MAILBOX_FORWARD . "', 1::bit);");
			$rows = $this->pgsql->affected_rows();
			$this->_shutdown_save_mailboxes();

			return $rows > 0;
		}

		public function disable_address($account, $domain = null)
		{
			$where = 'AND email_lookup.domain = domain_lookup.domain AND domain_lookup.site_id = ' . $this->site_id;
			if ($domain)
				$where .= 'AND domain_lookup.domain = \'' . pg_escape_string($domain) . '\'';
			$this->pgsql->query('UPDATE email_lookup SET enabled = 0::bit FROM domain_lookup WHERE "user" = \'' . pg_escape_string($account) . '\' ' . $where . ';');
			return $this->pgsql->affected_rows() > 0;
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
			} else if (!preg_match(Regex::SUBDOMAIN, $subdomain)) {
				return error("invalid subdomain `%s'", $subdomain);
			} else if ($this->web_subdomain_exists($subdomain)) {
				return error("subdomain `%s' already exists - cannot overwrite", $subdomain);
			}


			// system-default webmail locations won't appear in subdomain_exists() query
			if ($this->web_subdomain_exists($oldsubdomain) && !$this->web_remove_subdomain($oldsubdomain)) {
				warn("cannot remove old webmail location `%s'", $oldsubdomain);
			}
			$paths = $this->_webmailPaths();
			$fspath = $paths[$app];
			$this->web_add_subdomain_raw($subdomain, $fspath);
			$locations[$app] = $subdomain;
			$cache = Cache_Account::spawn();
			$cache->set('em.webmail', $locations);

			$file = $this->_customWebmailFile();
			file_put_contents($file, Util_Conf::write_ini($locations));
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
				$cache = Cache_Account::spawn();
				if (false !== ($webmail = $cache->get('em.webmail'))) {
					return $webmail;
				}
				$apps = $this->query('email_webmail_apps');
				$cache->set('em.webmail', $apps);
				return $apps;
			}
			return array_merge($this->_webmailSubdomains(), $this->_loadCustomWebmail());
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

		public function get_webmail_location($app)
		{
			$cache = Cache_Account::spawn();
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
			$conf = Auth::profile()->conf->cur;
			$user = $conf['siteinfo']['admin_user'];
			// stupid thor...
			$svcs = array('smtp_relay', 'imap');
			foreach ($svcs as $svc) {
				if ($this->auth_is_demo() && Util_Pam::check_entry($user, $svc)) {
					Util_Pam::remove_entry($user, $svc);
				}
			}
			return $this->_create_user($user);
		}

		public function _create_user($user)
		{
			// flush Dovecot auth cache to acknowledge pwdb changes
			$this->_reload('adduser');

			$home = $this->user_get_home($user);
			if (!$home) {
				return false;
			}

			$path = $this->domain_fs_path() . DIRECTORY_SEPARATOR . $home .
				DIRECTORY_SEPARATOR . self::MAILDIR_HOME;
			if (!file_exists($path)) {
				// no maildir, maybe intentional?
				return true;
			}
			$spamdir = $path . DIRECTORY_SEPARATOR . '.Spam';
			if (!file_exists($spamdir)) {
				$this->create_maildir('Spam');
			}
			return true;
		}

		public function _reload($why = null)
		{
			if ($why == "letsencrypt") {
				// update ssl certs
				Util_Process::exec('/sbin/service dovecot reload');
				Util_Process::exec('/sbin/service postfix reload');
			} else if ($why == "adduser") {
				// just flush auth cache
				$platformver = platform_version();
				if (version_compare($platformver, '6', '>=')) {
					$cmd = 'doveadm auth cache flush';
				} else if (!is_debug() && version_compare($platformver, '5', '>=')) {
					// @TODO bring dev box dovecot up to spec
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

		public function create_maildir_backend($user, $mailbox)
		{
			$mailbox = trim($mailbox);
			// Maildir folders are prefixed with a period
			if ($mailbox[0] != ".") {
				$mailbox = '.' . $mailbox;
			}
			if (!preg_match(Regex::EMAIL_MAILDIR_FOLDER, $mailbox)) {
				return error("invalid maildir folder name `%s'", $mailbox);
			}
			if (!$this->user_exists($user)) {
				return error("invalid user specified `%s'", $user);
			}
			$pwd = $this->user_getpwnam($user);
			if (!$pwd) {
				return error("getpwnam() failed for user `%s'", $user);
			}
			$home = $pwd['home'];
			$folders = array('', 'new', 'cur', 'tmp');
			$mailhome = $this->domain_fs_path() . $home . DIRECTORY_SEPARATOR . self::MAILDIR_HOME;
			if (!file_exists($mailhome)) {
				return error("Mail home `%s' does not exist",
					join(DIRECTORY_SEPARATOR, array($home, self::MAILDIR_HOME))
				);
			}
			foreach ($folders as $f) {
				$f = join(DIRECTORY_SEPARATOR, array($mailhome, $mailbox, $f));
				if (file_exists($f)) {
					continue;
				}
				mkdir($f);
				chmod($f, 0700);
				chown($f, $pwd['uid']);
				chgrp($f, $pwd['gid']);
			}
			$subscriptions = join(DIRECTORY_SEPARATOR, array($mailhome, 'subscriptions'));
			$sname = trim($mailbox, '.');
			if (!file_exists($subscriptions)) {
				$contents = array();
			} else {
				$contents = file($subscriptions, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			}
			if (false !== array_search($sname, $contents)) {
				return info("mailbox `%s' already subscribed", $sname);
			}
			$contents[] = $sname;
			file_put_contents($subscriptions, join("\n", $contents) . "\n");
			chown($subscriptions, $pwd['uid']);
			chgrp($subscriptions, $pwd['gid']);
			chmod($subscriptions, 0600);
			return true;
		}

		public function _delete()
		{
			$conf = Auth::profile()->conf->cur;
			$ips = $conf['ipinfo']['ipaddrs'];
			if (!$ips) {
				return true;
			}
			foreach ($ips as $ip) {
				$this->_removeMTA($ip);
			}
			$this->_removeIMAP($this->site);
		}

		private function _removeMTA($ip)
		{
			$hosts = file(Dns_Module::HOSTS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			$regex = Regex::compile(
				Regex::EMAIL_MTA_IP_RECORD,
				array(
					'ip' => preg_quote($ip)
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

		public function _edit()
		{
			$conf_new = Auth::profile()->conf->new;
			$conf_cur = Auth::profile()->conf->cur;
			$user = array(
				'old' => $conf_cur['siteinfo']['admin_user'],
				'new' => $conf_new['siteinfo']['admin_user']
			);
			/**
			 * update alias mapping, mailbox mappings update on the backend
			 *
			 * @TODO phase out legacy backend
			 */
			if ($user['old'] != $user['new']) {
				$this->_edit_user($user['old'], $user['new']);
			}

			/**
			 * Update private smtp routing + whitelabel dovecot config
			 */
			$ipcur = $conf_cur['ipinfo'];
			$ipnew = $conf_new['ipinfo'];

			if ($ipnew != $ipcur) {
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

		}

		public function _edit_user($user, $usernew)
		{
			// edit_user hooks enumerated after user changed
			$uid = $this->user_get_uid_from_username($usernew);
			if (!$uid) {
				return error("cannot determine uid from user `%s' in mailbox translation", $user);
			}
			mute_warn();
			foreach ($this->_pam_services() as $svc) {
				if ($this->user_enabled($user, $svc)) {
					Util_Pam::remove_entry($user, $svc);
					// edit_user hook renames user then calls
					Util_Pam::add_entry($usernew, $svc);
				}
			}
			unmute_warn();
			// update uids in uids table
			$db = $this->pgsql;
			$q = 'UPDATE "uids" SET "user" = \'' . pg_escape_string($usernew) . '\' ' .
				'WHERE "user" = \'' . pg_escape_string($user) . '\' AND uid = ' . $uid;
			$db->query($q);
			// make 2 sweeps:
			// sweep 1: update mailboxes that refer to the uid
			// sweep 2: update aliases that forward to the user
			// aliases that deliver locally
			$mailboxes = $this->list_mailboxes('local', $user);
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
			$this->_update_email_aliases($user, $usernew);
			return true;
		}

		private function _pam_services()
		{
			return array('smtp_relay', 'imap');
		}

		public function user_enabled($user, $svc = null)
		{
			if ($svc && $svc != 'imap' && $svc != 'smtp' && $svc != 'smtp_relay')
				return error("service " . $svc . " is unknown (imap, smtp)");
			$enabled = 1;
			if (!$svc) {
				$enabled = Util_Pam::check_entry($user, $svc);
				$svc = 'smtp_relay';
			} else if ($svc == 'smtp')
				$svc = 'smtp_relay';

			return $enabled && Util_Pam::check_entry($user, $svc);
		}

		public function permit_user($user, $svc = null)
		{
			if ($svc && $svc != 'smtp' && $svc != 'imap' && $svc != 'smtp_relay')
				return error("service " . $svc . " is unknown (imap, smtp)");
			if (!$svc) {
				Util_Pam::add_entry($user, 'imap');
				$svc = 'smtp_relay';
			} else if ($svc == 'smtp') {
				$svc = 'smtp_relay'; // Ensim bastardization
			}
			if ($this->auth_is_demo()) {
				return error("Email disabled for demo account");
			}
			Util_Pam::add_entry($user, $svc);
		}

		public function deny_user($user, $svc = null)
		{
			if ($svc && $svc != 'smtp' && $svc != 'imap' && $svc != 'smtp_relay')
				return error("service " . $svc . " not in list (imap, smtp)");
			if (!$svc) {
				Util_Pam::remove_entry($user, 'imap');
				$svc = 'smtp_relay';
			} else if ($svc == 'smtp')
				$svc = 'smtp_relay'; // Ensim bastardization

			Util_Pam::remove_entry($user, $svc);
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
				return '\b' . preg_quote($user) . '@(' . preg_quote($domain) . ')\b';
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
					if ($changed > -1)
						$changed++;
				} else {
					warn("failed to adjust mailbox `%s@%s`", $forward['user'], $forward['domain']);
					$changed = -1;
				}

			}
			return $changed;
		}

		public function list_virtual_transports()
		{
			$virtual = array();
			$this->pgsql->query("SELECT domain FROM domain_lookup WHERE site_id = " . $this->site_id);
			while (false !== ($row = $this->pgsql->fetch_object())) {
				$virtual[] = trim($row->domain);
			}
			return $virtual;
		}

		private function _addMTA($ip)
		{
			if (version_compare(platform_version(), '4.5', '<')) {
				return info("private smtp routing available on 4.5 and newer platforms");
			}
			$hosts = file(Dns_Module::HOSTS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			$regex = Regex::compile(
				Regex::EMAIL_MTA_IP_RECORD,
				array(
					'ip' => preg_quote($ip)
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
	}

?>
