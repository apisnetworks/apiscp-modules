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
     * User tracking, trouble tickets
     *
     * @package core
     */
    class Crm_Module extends Module_Skeleton
    {
        const FROM_ADDRESS = CRM_FROM_ADDRESS;

        // @ignore
        const REPLY_ADDRESS = CRM_REPLY_ADDRESS;
        const FROM_NAME = CRM_FROM_NAME;
        const FROM_NO_REPLY_ADDRESS = CRM_FROM_NO_REPLY_ADDRESS;
        const TICKET_STCLOSE = 'close';
        const TICKET_STAPPEND = 'append';
        const TICKET_STOPEN = 'open';
        const MAX_SMS_LENGTH = 150;
        const PRIORITIES = array('normal', 'high', 'outage');
        const LOW_PRIORITY_SUBJECTS = array('billing');
        // lowercase list of ticket subject priorities that cannot change
        const COPY_ADMIN = CRM_FROM_ADDRESS;

        // @var string
        // @ignore
        const SHORT_COPY_ADMIN = CRM_SHORT_COPY_ADMIN;

        // @ignore
        protected static $_db;

        // @ignore
        private static $CRM_SERVER_HOST = CRM_TICKET_HOST;
        // @ignore
        private static $CRM_SERVER_USER = CRM_TICKET_USER;
        // @ignore
        private static $CRM_SERVER_PASSWORD = CRM_TICKET_PASSWORD;
        // @ignore
        private static $CRM_SERVER_DATABASE = CRM_TICKET_DB;

        private $_metaCache = array();

        /**
         * void __construct(void)
         *
         * @ignore
         */
        public function __construct()
        {
            parent::__construct();
            $this->exportedFunctions = array(
                '*'                       => PRIVILEGE_SITE | PRIVILEGE_ADMIN,
                'append_ticket_via_email' => PRIVILEGE_ADMIN
            );
        }

        public function connected()
        {
            $db = $this->_connect();
            return $db instanceof PDO;
        }

        private function _connect()
        {
            if (self::$_db instanceof PDO) {
                return self::$_db;
            }
            Error_Reporter::suppress_php_error('PDO::.*');
            $db = self::$CRM_SERVER_DATABASE;
            $host = self::$CRM_SERVER_HOST;
            $user = self::$CRM_SERVER_USER;
            $password = self::$CRM_SERVER_PASSWORD;
            $dsn = 'mysql:dbname=' . $db . ';host=' . $host;
            try {
                self::$_db = new PDO($dsn, $user, $password);
            } catch (PDOException $e) {
                Error_Reporter::report("unable to connect to ticket db - falling back" . $e->getMessage());
                self::$_db = null;
                if (!IS_ISAPI) {
                    error("unable to connect to ticket database - use %s", self::FROM_ADDRESS);
                }
                return false;
            }
            return self::$_db;

        }

        /**
         * array get_troubleticket_subjects (void)
         */
        public function get_trouble_ticket_subjects()
        {
            $subjects = array();
            $db = $this->_connect();
            if (!$db) {
                return $subjects;
            }
            $q = "SELECT `subject_id`, `subject` FROM `ticket_subjects`
				WHERE (" . $this->permission_level . " & `permissions` ) = " .
                $this->permission_level . " ORDER BY subject";
            $subjects = $db->query($q)->
            fetchAll(PDO::FETCH_GROUP | PDO::FETCH_COLUMN | PDO::FETCH_UNIQUE);
            return $subjects;
        }

        /**
         * array search_trouble_tickets (string, integer)
         *
         * @param $mQuery string
         * @param $mMode  int 0 = last filing date, 1 = relevancy
         * @return array
         */
        public function search_trouble_tickets($mQuery, $mMode)
        {
            if ($mMode != 1 && $mMode != 0) {
                return error("Invalid search mode");
            }
            $tickets = array();
            $db = $this->_connect();
            if (!$db) {
                return $tickets;
            }
            $restrictor = $this->_getRestrictor();
            $sort = 'last_modification DESC';
            if ($mMode == 1) {
                $sort = 'strength DESC';
            }
            $q = "SELECT
				subject,
				tickets.ticket_id,
				UNIX_TIMESTAMP(open_ts) AS open_ts,
				UNIX_TIMESTAMP(close_ts) AS close_ts,
				classifier,
				(close_ts IS NULL) OR (open_ts > close_ts) AS status,
				UNIX_TIMESTAMP(MAX(response_ts)) AS last_modification,
				`user` AS sender,
				tmd.data AS reference,
				priority,
				AVG(MATCH(response) AGAINST (:search)) AS strength
				FROM tickets
				JOIN ticket_metadata_cache tmc ON (tickets.ticket_id = tmc.ticket_id)
				JOIN ticket_responses tr ON (tickets.ticket_id = tr.ticket_id)
				JOIN ticket_subjects ts ON (tmc.subject_id = ts.subject_id)
				JOIN ticket_contacts tc ON (tickets.ticket_id = tc.ticket_id)
				JOIN ticket_contacts_meta tcm USING (email_id)
				LEFT JOIN apnscp.domain_information ON (tickets.invoice = apnscp.domain_information.di_invoice
					AND apnscp.domain_information.parent_domain IS NULL AND apnscp.domain_information.status = 1)
				LEFT JOIN ticket_metadata_data tmd ON (tickets.ticket_id = tmd.ticket_id AND tmd.key = 'reference')
				JOIN ticket_response_data trd ON (trd.response_id = tr.response_id)
				WHERE " . $restrictor . "
				AND trd.response_id = tr.response_id
				GROUP BY (tickets.ticket_id)
				HAVING (MIN(tr.response_ts) AND strength > 0)
				ORDER BY " . $sort;
            $rs = $db->prepare($q);
            $params = array('search' => $mQuery);
            if (!$rs->execute($params)) {
                return $tickets;
            }
            while (false !== ($row = $rs->fetchObject())) {
                $ticket = array(
                    'subject'   => $row->subject,
                    'id'        => $row->ticket_id,
                    'ctime'     => $row->open_ts,
                    'mtime'     => $row->last_modification,
                    'status'    => intval($row->status),
                    'sender'    => $row->sender,
                    'reference' => $row->reference,
                    'priority'  => $row->priority,
                    'strength'  => $row->strength
                );
                $meta = $this->_get_meta_by_id($row->ticket_id);
                $ticket = array_merge($ticket, $meta);
                $tickets[] = $ticket;
            }

            return $tickets;
        }

        private function _getRestrictor()
        {
            $restrictor = '1 = 1';
            if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
                // @xxx nix site_id because cross-server moves may alter the site id
                $restrictor = " invoice = '" . $this->billing_get_invoice() . "'";
            }
            return $restrictor;
        }

        private function _get_meta_by_id($id, $findkey = null)
        {

            if ($this->_isCached($id, $findkey)) {
                return $this->_getCache($id, $findkey);
            }

            $db = $this->_connect();
            if (!$db) {
                return new stdClass();
            }
            $id = intval($id);
            $rs = $db->query("SELECT `key`, `data`, MAX(`ts`) AS `ts` FROM
				(SELECT `key`, `data`, `ts` FROM ticket_metadata_data WHERE ticket_id = $id ORDER BY ts DESC) AS t2
				GROUP BY (`key`)");
            if ($rs->rowCount() < 1) {
                return false;
            }
            $res = array();
            while (false !== ($row = $rs->fetchObject())) {
                $k = $row->key;
                $data = $row->data;
                $ts = $row->ts;
                $res[$k] = $data;
            }
            $this->_cache($id, $res);
            if (!is_null($findkey)) {
                return isset($res[$findkey]) ? $res[$findkey] : null;
            }
            return $res;
        }

        private function _isCached($ticket, $key)
        {
            return isset($this->_metaCache[$ticket]) &&
                isset($this->_metaCache[$ticket][$key]);
        }

        private function _getCache($ticket, $key = null)
        {
            if (is_null($key)) {
                return $this->_metaCache[$ticket];
            }
            return $this->_metaCache[$ticket][$key];
        }

        /**
         * @param int    $ticket
         * @param string $key
         * @param string $data
         */
        private function _cache($ticket, $key = null, $data = null)
        {
            $response = "(base)";
            // cache request contains multiple fields
            if (!isset($this->_metaCache[$ticket])) {
                $this->_metaCache[$ticket] = array();
            }
            if (is_array($key)) {
                $this->_metaCache[$ticket] = array_merge($this->_metaCache[$ticket], $key);
            } else {
                $this->_metaCache[$ticket][$key] = $data;
            }
            return true;
        }

        /**
         * array get_trouble_tickets_unrestricted(bool)
         *
         * @throws PermissionError insufficient permissions to access method
         */
        public function get_trouble_tickets_unrestricted($mStatus)
        {
            return $this->get_trouble_tickets($mStatus);
        }

        public function get_trouble_tickets($mStatus, $maxAge = 0, $minAge = 0)
        {
            if ((int)($mStatus) !== 0 && (int)($mStatus) !== 1) {
                return error("unknown status flag `$mStatus'");
            }
            $tickets = array();
            $db = $this->_connect();
            if (!$db) {
                return $tickets;
            }
            // ticket closed
            if (!$mStatus) {
                $restrictor = '(close_ts IS NOT NULL) AND (close_ts >= open_ts)';
            } else {
                $restrictor = '((close_ts IS NULL) OR (open_ts > close_ts))';
            }
            $restrictor .= " AND " . $this->_getRestrictor() . " ";
            // HAVING restrictor
            $having = '';
            if ($maxAge > 0) {
                $having .= " AND last_modification > UNIX_TIMESTAMP(DATE_SUB(CURDATE(), INTERVAL " . intval($maxAge) . " DAY))";
            }
            if ($minAge > 0) {
                $having .= " AND last_modification < UNIX_TIMESTAMP(DATE_SUB(CURDATE(), INTERVAL " . intval($minAge) . " DAY))";
            }
            $sort = 'last_modification DESC, open_ts DESC';
            if ($mStatus) {
                $sort = 'priority DESC, ' . $sort;
                if ($this->permission_level & PRIVILEGE_ADMIN) {
                    $sort = 'elapsed DESC, ' . $sort;
                }
            }
            $q = "SELECT
				subject,
				tickets.ticket_id,
				tickets.site_id AS site_id,
				UNIX_TIMESTAMP(open_ts) AS open_ts,
				UNIX_TIMESTAMP(close_ts) AS close_ts,
				classifier,                
				priority,
				apnscp.domain_information.domain AS domain,
				GROUP_CONCAT(DISTINCT email) AS email,
				(close_ts IS NULL) OR (open_ts > close_ts) AS status,
				UNIX_TIMESTAMP(MAX(tr.response_ts)) AS last_modification,
				IF (tr2.user = 'admin',0,TIMESTAMPDIFF(SECOND, MAX(tr.response_ts), NOW() )) AS elapsed,
				tr.`user` AS sender,
				tr2.user AS u2,
				tmd.`data` AS reference,
                trd.response AS response
				FROM tickets
				JOIN ticket_metadata_cache tmc ON (tickets.ticket_id = tmc.ticket_id)
				JOIN ticket_responses tr ON (tickets.ticket_id = tr.ticket_id)
				JOIN ticket_subjects ts ON (tmc.subject_id = ts.subject_id)
				JOIN ticket_contacts tc ON (tickets.ticket_id = tc.ticket_id)
				JOIN ticket_contacts_meta tcm USING (email_id)
				JOIN ticket_responses tr2 ON (tr2.ticket_id = tr.ticket_id
					AND tr2.response_id = (
						SELECT MAX(response_id) FROM ticket_responses WHERE ticket_id = tr.ticket_id
					)
				)
				JOIN ticket_response_data trd ON (trd.response_id = tr.response_id)
				LEFT JOIN apnscp.domain_information ON (tickets.invoice = apnscp.domain_information.di_invoice
					AND apnscp.domain_information.parent_domain IS NULL AND apnscp.domain_information.status = 1)
				LEFT JOIN ticket_metadata_data tmd ON (tickets.ticket_id = tmd.ticket_id AND tmd.key = 'reference')
				WHERE " . $restrictor . "
				GROUP BY (tickets.ticket_id)
				HAVING (MIN(tr.response_ts) AND MAX(tr2.response_ts) " . $having . ")
				ORDER BY " . $sort;
            if (!($rs = $db->query($q))) {
                return $tickets;
            }

            while (false !== ($row = $rs->fetchObject())) {
                $ticket = array(
                    'subject'   => $row->subject,
                    'email'     => $row->email,
                    'id'        => $row->ticket_id,
                    'site'      => $row->site_id,
                    'ctime'     => (int)$row->open_ts,
                    'domain'    => $row->domain,
                    'mtime'     => (int)$row->last_modification,
                    'status'    => intval($row->status),
                    'sender'    => $row->sender,
                    'reference' => $row->reference,
                    'priority'  => $row->priority,
                    'elapsed'   => $row->elapsed,
                    'intro'     => $row->response
                );
                $meta = $this->_get_meta_by_id($row->ticket_id);
                $ticket = array_merge($ticket, $meta);
                $tickets[] = $ticket;
            }
            return $tickets;
        }

        /**
         * get_ticket_type_as_id(string)
         *
         * @param $mSubject string
         * @return int
         */
        public function get_id_by_subject($mSubject)
        {
            $db = $this->_connect();
            if (!$db) {
                return -1;
            }
            $q = "SELECT subject_id FROM ticket_subjects WHERE CONVERT(subject USING latin1) COLLATE latin1_swedish_ci LIKE ?";
            $rs = $db->prepare($q);
            if (!$rs->execute(array('%' . $mSubject . '%')) || $rs->rowCount() < 1) {
                return null;
            }
            return intval($rs->fetchObject()->subject_id);
        }

        /**
         * array get_trouble_ticket(integer)
         */
        public function get_trouble_ticket($mID)
        {
            if (intval($mID) != $mID) {
                Error_Reporter::report($mID);

                error("invalid ticket id `$mID'");
            }
            $db = $this->_connect();
            if (!$db) {
                return array();
            }
            $restrictor = 'tickets.ticket_id = ' . intval($mID);
            // evaluate whether removing site_id is the best idea...
            if ($this->permission_level & (PRIVILEGE_SITE | PRIVILEGE_USER)) {
                $restrictor .=  /*" AND tickets.site_id = ".$this->site_id .*/
                    " AND invoice = '" . $this->billing_get_invoice() . "'";
            }
            $q = "SELECT
				subject,
				ticket_id,
				tickets.site_id AS site_id,
				UNIX_TIMESTAMP(open_ts) AS open_ts,
				UNIX_TIMESTAMP(close_ts) AS close_ts,
				classifier,
				priority,
				tickets.server AS server,
				apnscp.domain_information.domain AS domain,
				GROUP_CONCAT(DISTINCT email SEPARATOR ', ') AS email,
				(close_ts IS NULL) OR (open_ts > close_ts) AS status,
				UNIX_TIMESTAMP(COALESCE(MAX(response_ts), open_ts)) AS last_modification,
				`user` AS sender,
				UNIX_TIMESTAMP(viewed_admin)  AS last_admin,
				UNIX_TIMESTAMP(viewed_site)  AS last_site
				FROM tickets
				JOIN ticket_metadata_cache USING (ticket_id)
				JOIN ticket_subjects USING (subject_id)
				JOIN ticket_contacts USING (ticket_id)
				JOIN ticket_contacts_meta USING (email_id)
				LEFT JOIN ticket_responses USING (ticket_id)
				LEFT JOIN apnscp.domain_information ON (tickets.invoice = apnscp.domain_information.di_invoice AND
					apnscp.domain_information.parent_domain IS NULL AND apnscp.domain_information.status = 1)
				WHERE " . $restrictor . "
				GROUP BY (ticket_id)
				HAVING (MIN(response_ts))
				LIMIT 1";
            $rs = $db->query($q);
            if (!$rs || $rs->rowCount() < 1) {
                return false;
            }
            $row = $rs->fetchObject();
            $ticket = array(
                'data'      => array(),
                'subject'   => $row->subject,
                'email'     => $row->email,
                'id'        => $row->ticket_id,
                'priority'  => $row->priority,
                'flags'     => $row->classifier,
                'ctime'     => $row->open_ts,
                'domain'    => $row->domain,
                'mtime'     => $row->last_modification,
                'status'    => intval($row->status),
                'sender'    => $row->sender,
                'admintime' => $row->last_admin,
                'sitetime'  => $row->last_site,
                'server'    => $row->server,
                'siteid'    => $row->site_id,

            );
            $meta = $this->_get_meta_by_id($row->ticket_id);
            $ticket = array_merge($meta, $ticket);
            $ticket['data'] = $this->get_responses_by_range($mID);
            $column = 'viewed_site';
            if ($this->permission_level & PRIVILEGE_ADMIN) {
                $column = 'viewed_admin';
            }
            $q = "UPDATE ticket_metadata_cache SET " . $column .
                ' = NOW() WHERE ticket_id = ' . $mID;
            $db->query($q);
            return $ticket;
        }

        /**
         * Get all ticket responses from $min to $max
         *
         * @param int $ticket_id
         * @param int $min
         * @param int $max
         * @return array
         */
        public function get_responses_by_range($ticket_id, $min = null, $max = null)
        {
            if (intval($ticket_id) != $ticket_id) {
                return error("invalid ticket id `%d'", $ticket_id);
            } else {
                if (!is_null($min) && $min < 1 || (intval($min) != $min)) {
                    return error("invalid minimum response id `%d'", $min);
                } else {
                    if (!is_null($max) && $max < 1 || (intval($max) != $max)) {
                        return error("invalid maximum response id `%d'", $max);
                    } else {
                        if (!is_null($min) && !is_null($max) && ($min > $max)) {
                            return error("invalid range specified (min,max) (%d,%d)", $min, $max);
                        }
                    }
                }
            }

            $responses = array();
            $db = $this->_connect();

            if (!$db) {
                return $responses;
            }
            $responses = array();

            $restrictor = array("ticket_id = " . intval($ticket_id));
            $restrictor[] = $this->_getRestrictor();

            if ($min > 0) {
                $restrictor[] = "ticket_responses.response_id >= " . intval($min);
            }
            if ($max > 0) {
                $restrictor[] = "ticket_responses.response_id <= " . intval($max);
            }
            $restrictor[] = "ticket_response_data.response_id = ticket_responses.response_id";

            $q = "SELECT
				 ticket_responses.response_id,
				 COUNT(attachment_id) > 0 AS has_attachments,
				 GROUP_CONCAT(attachment_id SEPARATOR ',') AS attachments,
				 response,
				 user,
				 UNIX_TIMESTAMP(response_ts) AS response_ts
				 FROM ticket_responses
				 JOIN ticket_response_data USING (response_id)
                 JOIN tickets USING (ticket_id)
				 LEFT JOIN ticket_attachments USING (response_id)
				 LEFT JOIN ticket_metadata_data USING (ticket_id, response_id)
				 WHERE " . join($restrictor, " AND ") . " 
				 GROUP BY (response_id)
				 ORDER BY response_ts ASC";
            $rs = $db->query($q);
            while (false !== ($row = $rs->fetchObject())) {
                $responses[] = array(
                    'body'        => $row->response,
                    'time'        => $row->response_ts,
                    'sender'      => $row->user,
                    'attachments' => explode(",", $row->attachments),
                    'id'          => $row->response_id
                );
            }
            return $responses;
        }

        /**
         * array get_trouble_tickets_restricted (bool)
         *
         * @param bool $status true for open, false for closed
         */
        public function get_trouble_tickets_restricted($mStatus)
        {
            return $this->get_trouble_tickets($mStatus);


        }

        /**
         *  bool reopen_trouble_ticket(int)
         *
         * @param $mID int
         * @return int
         */
        public function reopen_trouble_ticket($mID)
        {

            if (intval($mID) != $mID) {
                error("invalid ticket ID `$mID'");
            }
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $mID = intval($mID);
            $restrictor = $this->_getRestrictor();
            $q = "UPDATE `ticket_metadata_cache`, tickets SET open_ts = NOW() WHERE tickets.ticket_id = " . $mID . ' AND ' .
                'tickets.ticket_id = ticket_metadata_cache.ticket_id AND ' . $restrictor;
            $success = $db->exec($q) > 0;
            $this->_add_ticket_metadata($mID, null, 'state', 'open');
            if (!$success) {
                return false;
            }

            $priority = $db->query("SELECT priority FROM ticket_metadata_cache WHERE ticket_id = " . intval($mID))->fetchObject()->priority;
            $priorities = $this->get_priorities();
            if (Crm_Module::SHORT_COPY_ADMIN && $this->permission_level & ~PRIVILEGE_ADMIN &&
                $priority != $priorities[0]
            ) {
                Mail::send(
                    Crm_Module::SHORT_COPY_ADMIN,
                    "Ticket Reopened (" . $this->domain . ")",
                    "",
                    "From: " . Crm_Module::FROM_NAME . " <" . Crm_Module::FROM_ADDRESS . ">\r\nReply-To: " . Crm_Module::REPLY_ADDRESS
                );
            }

            return true;
        }

        private function _add_ticket_metadata($ticket, $responseid, $key, $data = null)
        {
            $db = $this->_connect();
            if (!$db) {
                return error("cannot connect to ticket db");
            }
            $q = "INSERT INTO ticket_metadata_data (
				ticket_id,
				response_id,
				`key`,
				`data`
			) VALUES ";
            $params = array(
                'ticket_id'   => $ticket,
                'response_id' => $responseid,
            );

            if (!is_null($data) || !is_array($key)) {
                $key = array($key => $data);
                $data = null;
            }
            $frag = array();

            for ($i = 0; $i < sizeof($key); $i++) {
                $k = key($key);
                $v = current($key);
                $this->_metadata_is_cached($k);
                if ($this->_metadata_is_cached($k)) {
                    $this->_update_metadata_cache($ticket, $k, $v);
                }
                $frag[] = "(:ticket_id, :response_id, :key$i, :data$i)";

                $params['key' . $i] = $k;
                $params['data' . $i] = $v;
                next($key);
            }
            $q .= join($frag, ",");
            $stmt = $db->prepare($q);
            if (!$responseid) {
                $responseid = null;
            }
            $success = $stmt->execute($params);
            $this->_cache($ticket, $key);
            return $success;

        }

        private function _metadata_is_cached($key)
        {
            return $key == 'state' || $key == 'classifier' || $key == 'priority' || $key == 'subject_id';
        }

        private function _update_metadata_cache($ticketid, $key, $value)
        {
            $db = $this->_connect();
            if ($key == 'state') {
                $field = $value == 'close' ? 'close_ts' : 'open_ts';
                $dbvalue = 'NOW()';
            } else {
                if ($key == 'subject') {
                    $field = 'subject_id';
                    $dbvalue = $this->get_subject_id_by_subject($value);
                } else {
                    if ($key == 'subject_id') {
                        $dbvalue = intval($value);
                        $field = $key;
                    } else {
                        $field = $key;
                        $dbvalue = $db->quote($value);
                    }
                }
            }
            $q = "UPDATE ticket_metadata_cache SET " . $field . " = " . $dbvalue . " WHERE ticket_id = :id";
            $stmt = $db->prepare($q);
            $stmt->execute(
                array(
                    'id' => $ticketid
                )
            );
            $this->_cache($ticketid, $key, $value);
            return true;
        }

        public function get_subject_id_by_subject($subject)
        {
            $db = $this->_connect();
            if (!$db) {
                return null;
            }
            $q = "SELECT subject_id FROM ticket_subjects WHERE subject = :subject";
            $rs = $db->prepare($q);
            if (!$rs->execute(array('subject' => $subject)) || $rs->rowCount() < 1) {
                return error("subject id not found for `$subject'");
            }
            return $rs->fetchColumn();
        }

        /**
         * array get_priorities()
         *
         * Get acceptable priorities
         *
         * @return array
         */
        public function get_priorities()
        {

            return self::PRIORITIES;
        }

        /**
         * int file_new_trouble_ticket(string, integer, string)
         *
         * @param  string $mContact  contact e-mail address
         * @param  int    $mSubject  subject title id {@link get_troubleticket_subjects}
         * @param  string $mPriority ticket priority
         * @return int               insert id of the ticket; call {@link append_trouble_ticket} with this value
         */
        public function file_new_trouble_ticket($mContact, $mSubject, $mPriority = null)
        {
            if ($this->auth_is_inactive()) {
                return error("account is deactivated and cannot use ticket interface");
            }

            $priorities = $this->get_priorities();
            if (!$mPriority) {
                $mPriority = $priorities[0];
            }
            if (intval($mSubject) != $mSubject || $mSubject < 1) {
                return error("invalid subject id `$mSubject'");
            } else {
                if (!$this->_isValidPriority($mPriority)) {
                    return error("unknown priority `" . $mPriority . "'");
                }
            }
            if ($this->permission_level & PRIVILEGE_ADMIN) {
                $domain = is_array($mContact) ? $mContact[0] : $mContact;
                $adminemail = $this->admin_get_address_from_domain($domain);
                if (is_array($mContact)) {
                    $mContact = array_slice($mContact, 1);
                    array_push($mContact, $adminemail);
                } else {
                    $mContact = array($adminemail);
                }
                $site_id = $this->admin_get_site_id_from_domain($domain);
                $username = $this->admin_get_meta_from_domain($domain, 'siteinfo', 'admin_user');
                $invoice = $this->admin_get_meta_from_domain($domain, 'billing', 'invoice');
                // reseller domain
                if (!$invoice) {
                    $invoice = $this->billing_get_invoice_from_domain($domain);
                }
            } else {
                $domain = $this->domain;
                $username = $this->username;
                $site_id = $this->site_id;
                if ($this->get_service_value('billing', 'parent_invoice')) {
                    return error("cannot open tickets from reseller account");
                }
                $invoice = $this->billing_get_invoice();
            }

            if (!$invoice) {
                return error("cannot file ticket - no invoice attached to account");
            }

            if (!$this->_subject_privileged($mSubject)) {
                return error('cannot use unprivileged subject id %d', $mSubject);
            }
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $sender = self::_role_as_string($this->permission_level);
            $id = $db->query("SELECT MAX(ticket_id) AS id FROM tickets")->fetchObject()->id;
            $id = mt_rand(1, 5) + $id;
            $stmt = $db->prepare("INSERT INTO `tickets` " .
                "(ticket_id, server, site_id, invoice, sender) " .
                "VALUES (:ticket_id, :server, :site, :invoice, :sender)");

            $server = null;

            if ($this->permission_level & PRIVILEGE_ADMIN) {
                $server = $this->dns_get_server_from_domain($domain);
            }

            // let's assume the user is filing from the server if non-admin
            if (!$server) {
                $server = SERVER_NAME_SHORT;
            }

            // assume server is posting ticket for recently-added domains
            //$server = substr($server, strpos($server, '.'));
            $stmt->execute(array(
                'server'    => $server,
                'site'      => $site_id,
                'invoice'   => $invoice,
                'sender'    => $sender,
                'ticket_id' => (float)$id,
            ));
            if ($stmt->rowCount() < 1) {
                report("%s %s %s",
                    var_export(func_get_args(), true),
                    var_export($stmt->errorInfo(), true),
                    var_export($db->errorInfo(), true)
                );
                return error('ticket post failed');
            }
            $id = $db->lastInsertId();

            $q = "INSERT INTO ticket_metadata_cache
				(`ticket_id`, `open_ts`, `subject_id`, `close_ts`, `classifier`, `priority`)
				VALUES(:ticket_id, NOW(), :subject_id, NULL, NULL, :priority);";
            $stmt = $db->prepare($q);
            $stmt->execute(
                array(
                    'ticket_id'  => $id,
                    'subject_id' => $mSubject,
                    'priority'   => $mPriority
                )
            );

            $subject = $this->get_subject_by_id($mSubject);

            $meta = array(
                'domain'     => $domain,
                'username'   => $username,
                'priority'   => $mPriority,
                'subject'    => $subject,
                'subject_id' => $mSubject,
                'reference'  => dechex(crc32($id . " " . $username)),
                'server'     => $server,
                'state'      => 'open',
            );
            $success = $this->_add_ticket_metadata($id, null, $meta);
            if (!$success) {
                error("cannot submit ticket - notifying admin");
                // set high
                Error_Reporter::report("failed to open ticket, ", var_export($meta, true));

            }
            $cids = $this->_get_ids_from_contacts($mContact);
            if (!$cids) {
                error("invalid e-mail address - no contacts attached");
            }
            $this->_attach_contacts_to_ticket($cids, $id);
            // issue with invalid ticket ID?
            if (!is_debug()) {
                sleep(1);
            }

            if (!$id) {
                $vars = get_defined_vars();
                Error_Reporter::report(var_export($vars, true));
            }
            return $id;
        }

        private function _isValidPriority($priority)
        {
            return in_array($priority, $this->get_priorities());
        }

        /**
         * User is privileged to use subject in ticket
         *
         * @param int $id
         * @return bool
         */
        private function _subject_privileged($id)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }

            $q = 'SELECT subject FROM ticket_subjects WHERE subject_id = ' . intval($id) .
                ' AND permissions&' . intval($this->permission_level);
            $rs = $db->query($q);
            return $rs->rowCount() > 0;
        }

        private static function _role_as_string($mPermID)
        {
            switch (true) {
                case ($mPermID & PRIVILEGE_ADMIN):
                    return 'admin';
                case ($mPermID & PRIVILEGE_SITE):
                    return 'site';
                case ($mPermID & PRIVILEGE_RESELLER):
                    return 'reseller';
                case ($mPermID & PRIVILEGE_USER):
                    return 'user';
            }
        }

        /**
         * string get subject_by_id(int)
         *
         * @param $id integer id number to lookup
         * @return string
         */
        public function get_subject_by_id($subject_id)
        {
            if (intval($subject_id) != $subject_id) {
                return error($subject_id . ": parameter must be integer");
            }
            $db = $this->_connect();
            if (!$db) {
                return null;
            }

            $q = "SELECT subject FROM ticket_subjects WHERE subject_id = :id " .
                "AND permissions&" . intval($this->permission_level);
            $rs = $db->prepare($q);
            if (!$rs->execute(array('id' => $subject_id)) || $rs->rowCount() < 1) {
                return error("unknown subject id `$subject_id'");
            }
            return $rs->fetchColumn();
        }

        /**
         * Convert email addresses into ids
         *
         * @param string|array $email
         */
        private function _get_ids_from_contacts($email)
        {
            $ids = array();
            if (!is_array($email)) {
                $str = $email;
                $email = array();
                $tok = strtok($str, ";, ");
                while ($tok !== false) {
                    $email[] = $tok;
                    $tok = strtok(";, ");
                }
            }
            $filtered = array();
            foreach ($email as $tmp) {
                if (!preg_match(Regex::EMAIL, $tmp)) {
                    continue;
                }
                $filtered[] = strtolower($tmp);
            }
            if (count($filtered) < 1) {
                return $ids;
            }
            $db = $this->_connect();
            if (!$db) {
                return $ids;
            }
            $q = "INSERT IGNORE INTO ticket_contacts_meta (email) VALUES " .
                '(' . join("),(", array_fill(0, count($filtered), '?')) . ')';
            $stmt = $db->prepare($q);

            if (!$stmt->execute($filtered)) {
                report('INSERT ticket_contacts_meta failed: ' . array_pop($stmt->errorInfo()));
            }
            $q = "SELECT email_id FROM ticket_contacts_meta WHERE email IN (" .
                join(",", array_fill(0, count($filtered), '?')) . ")";
            $stmt = $db->prepare($q);
            $rs = $stmt->execute($filtered);
            while (false !== ($row = $stmt->fetchObject())) {
                $ids[] = (int)$row->email_id;
            }
            return $ids;
        }

        private function _attach_contacts_to_ticket(array $cids, $tid)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            if (count($cids) < 1) {
                return false;
            }
            $q = "INSERT INTO ticket_contacts (ticket_id, email_id) VALUES " .
                '(' . $tid . ',' . join(",(" . $tid . ",", array_fill(0, count($cids), '?)'));
            $stmt = $db->prepare($q);
            if (!$stmt->execute($cids)) {
                return report("_attach_contacts_to_ticket FAIL: " . array_pop($stmt->errorInfo()));
            }

            return true;

        }

        public function set_description($id, $desc)
        {
            if (!$this->_canModify($id)) {
                return error("cannot set description for unknown ticket `%d'", $id);
            }

            return $this->_add_ticket_metadata($id, null, 'desc', $desc);
        }

        private function _canModify($ticket)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            if ($this->permission_level & PRIVILEGE_ADMIN) {
                return true;
            } else {
                if ($this->permission_level & ~PRIVILEGE_SITE) {
                    return false;
                }
            }

            $invoice = $this->billing_get_invoice();
            $rs = $db->query("SELECT 1 FROM tickets WHERE ticket_id = " .
                intval($ticket) . " AND invoice = '" . $invoice . "'");
            return $rs->rowCount() > 0;
        }

        /**
         * bool close_trouble_ticket (integer, string)
         * Wrapper for {@link append_trouble_ticket} with the state of "close"
         */

        public function close_trouble_ticket($mTicketID, $mData)
        {
            $status = $this->append_trouble_ticket($mTicketID, $mData, array('state' => self::TICKET_STCLOSE));
            if (!$status) {
                return $status;
            }
            $this->_add_ticket_metadata($mTicketID, $status, 'state', 'close');
            return $status > 0;
        }

        /**
         * Attach notes to an open ticket
         *
         * @param int    $id          ticket id
         * @param string $data        ticket data
         * @param array  $options     state, priority, sender, email
         * @param array  $attachments optional attachments
         *
         * @return int response id
         */
        public function append_trouble_ticket($id, $data, array $options = array(), array $attachments = array())
        {
            $priorities = $this->get_priorities();
            $default = array(
                'state'    => self::TICKET_STAPPEND,
                'priority' => $priorities[0],
                'sender'   => 'admin',
                'email'    => true,
            );

            $options = array_merge($default, $options);
            if (is_debug()) {
                $options['email'] = true;
            }
            if (!$data && !$attachments && $options['state'] != self::TICKET_STCLOSE) {
                return error("No data");
            }
            $id = intval($id);
            if ($options['state'] != "append" && $options['state'] != "new"
                && $options['state'] != self::TICKET_STCLOSE
            ) {
                return error("Invalid state `%s'", $options['state']);
            }

            $db = $this->_connect();
            if (!$db) {
                return false;
            }

            $restrictor = $this->_getRestrictor();

            $q = "SELECT
				ticket_id,
				tickets.site_id,
				classifier,
				priority,
				apnscp.domain_information.domain AS domain,
				(close_ts IS NULL) OR (open_ts > close_ts) AS status
				FROM tickets
				JOIN ticket_metadata_cache USING (ticket_id)
				JOIN ticket_subjects USING (subject_id)
				JOIN ticket_contacts USING (ticket_id)
				JOIN ticket_metadata_data USING (ticket_id)
				LEFT JOIN apnscp.domain_information ON (tickets.invoice = apnscp.domain_information.di_invoice AND
					apnscp.domain_information.parent_domain IS NULL AND apnscp.domain_information.status = 1)
				WHERE " . $restrictor . " AND ticket_id = " . $id . " GROUP BY (ticket_id)";
            $rs = $db->query($q);
            if ($rs->rowCount() < 1) {
                return error("ticket `%d' not found %s", $id, is_debug() ? $q : null);
            }

            $row = $rs->fetchObject();
            $domain = $row->domain;
            $id = $row->ticket_id;
            if ($this->permission_level & PRIVILEGE_ADMIN) {
                $user = $options['sender'];
            } else {
                $user = self::_role_as_string($this->permission_level);
            }
            $q = "INSERT INTO `ticket_responses`
				(ticket_id, user) VALUES($id,'$user')";
            $success = $db->query($q);
            $rid = 0;
            if ($success) {
                $rid = $db->lastInsertId();
            }
            // add an extra line of spacing to the end for attachments
            if ($attachments) {
                $data .= "\r\n";
            }

            $html = $data;
            // convert permitted HTML markup to BBcode
            $html = Util_HTML_BBCode::HTML2BB($html);
            //print "<strong>RD 1:</strong>";
            //var_dump($html);

            // escape all unsafe HTML
            $html = str_replace(array('<', '>'), array('&lt;', '&gt;'), $html);
            //print "<hr /><hr />RD 2:";
            //var_dump($html);
            // convert BBcode back to HTML
            $html = Util_HTML_BBCode::BB2HTML($html);

            $q = "INSERT INTO ticket_response_data (response_id, response) VALUES(?,?)";
            $stmt = $db->prepare($q);
            $stmt->execute(array($rid, $html));
            foreach ($attachments as $a) {
                if (!isset($a['name'])) {
                    warn("missing attachment name");
                } else {
                    if (!isset($a['content'])) {
                        warn("no attachment data for `%s'", $a['name']);
                    } else {
                        $this->add_attachment($rid, $a['name'], $a['content']);
                    }
                }
            }

            if ($options['email']) {
                $this->_send_ticket_email($id, $rid, $options['state']);
            }
            if (!$success) {
                return error("failure adding ticket response");
            }
            if ($options['state'] == self::TICKET_STCLOSE) {
                $this->_add_ticket_metadata($id, $rid, 'state', 'close');
            }
            if (!$q) {
                return false;
            }

            return $rid;
        }

        public function add_attachment($rid, $filename, $data, $raw = true)
        {
            if (!$raw && false == ($data = base64_decode($data))) {
                return error("corrupted data");
            }
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $ticket = $this->_get_ticket_by_rid($rid);
            $sender = $this->_get_sender_by_rid($rid);
            $pos = strrpos($filename, '.');
            $ext = substr($filename, $pos);
            $ext = strtolower(ltrim($ext, '.'));
            if (!$this->_attachmentExtensionAllowed($ext)) {
                return error("file `%s' contains disallowed extension", $filename);
            }
            $size = strlen($data);
            if ($size > 10 * 1024 * 1024) {
                return error("max attachment size 10 MB, file size is `%.2f MB'", ($size / 1024 / 1024));
            }
            if (!$ticket) {
                return error("unknown ticket for response `%d'", $rid);
            }
            $q = "INSERT INTO ticket_attachments (attachment_size,
			attachment_name,
			attachment_owner,
			attachment_extension,
			attachment_mime,
			attachment_charset,
			response_id) VALUES(:size, :name, :owner, :ext, :mime, :charset, :id);";
            $stmt = $db->prepare($q);
            $finfo = finfo_open(FILEINFO_MIME);
            $mime = finfo_buffer($finfo, $data);
            $charset = null;
            if (strstr($mime, ';')) {
                list($mime, $charset) = explode("; ", $mime);
                list($tmp, $charset) = explode('=', $charset);
            }
            $params = array(
                'size'    => $size,
                'name'    => $filename,
                'owner'   => $sender,
                'ext'     => $ext,
                'mime'    => $mime,
                'charset' => $charset,
                'id'      => $rid
            );
            $rs = $stmt->execute($params);
            if (!$rs) {
                return error("unable to add attachment for `%s'", $filename);
            }
            $aid = $db->lastInsertId();
            $q = "INSERT INTO ticket_attachment_data (attachment_id, attachment_data)
			 VALUES (:aid, :data);";
            $stmt = $db->prepare($q);
            $stmt->bindParam(':aid', $aid, PDO::PARAM_INT);
            $stmt->bindParam(':data', $data, PDO::PARAM_LOB);
            $msg = sprintf("\r\n* file: %s (%.2f KB)", $filename, $size / 1024);
            if (!$stmt->execute()) {
                /**
                 * typically this fails because max_allowed_packet is less than
                 * the file size
                 */
                $msg = $stmt->errorInfo();
                if (is_array($msg)) {
                    $msg = $msg[2];
                } else {
                    $msg = "unspecified DB error";
                }
                Error_Reporter::report(
                    "failed to add attachment `%s' with size '%d': %s",
                    $filename, $size, $msg
                );
                return error("failed to save attachment `%s' to database", $filename);
            }
            $this->_append_ticket_message_raw($ticket, $rid, $msg);
            return true;

        }

        private function _get_ticket_by_rid($rid)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $rid = intval($rid);
            $q = "SELECT ticket_id FROM ticket_responses JOIN tickets USING (ticket_id) WHERE response_id = " . $rid;
            $rs = $db->query($q);
            if ($rs->rowCount() < 1) {
                return null;
            }
            return $rs->fetchObject()->ticket_id;
        }

        private function _get_sender_by_rid($rid)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $rs = $db->query("SELECT `user` FROM ticket_responses WHERE response_id = " . intval($rid));
            if ($rs->rowCount() < 1) {
                return null;
            }
            return $rs->fetchObject()->user;
        }

        private function _attachmentExtensionAllowed($ext)
        {
            return !in_array(strtolower($ext), $this->get_disallowed_attachment_extensions());
        }

        public function get_disallowed_attachment_extensions()
        {
            return array('exe', 'scr', 'com', 'bat');
        }

        private function _append_ticket_message_raw($ticket, $response, $appended)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $rs = $db->query("UPDATE ticket_response_data, ticket_responses SET response = " .
                "CONCAT(response, " . $db->quote($appended) . ") WHERE ticket_response_data.response_id = " .
                intval($response) . " AND ticket_id = " . intval($ticket) . " AND ticket_response_data.response_id = " .
                "ticket_responses.response_id");
            return $rs->rowCount() > 0;
        }

        private function _send_ticket_email($id, $rid, $state = 'append')
        {
            /*if (is_debug()) {
                return debug("ignoring ticket email in debug");
            }*/

            $ticketData = $this->_get_response_by_rid($rid);
            /** e-mails */
            switch ($state) {
                /** new ticket */
                case "new":
                    $subject = "Confirmation:";
                    break;
                /** appending to the ticket */
                case "append":
                    $subject = "Re:";
                    break;
                /** closing ticket */
                case "close":
                    /** Ignore e-mail receipt if no ticket data added */
                    if (!$ticketData) {
                        return;
                    }
                    $subject = "Ticket Closed:";
                    break;
            }
            $recipient = $this->get_contact_by_id($id);
            $meta = $this->_get_meta_by_id($id);
            $domain = isset($meta['domain']) && $meta['domain'] ?
                $meta['domain'] : $this->_get_domain_by_id($id);

            // prefer the description, otherwise default to subject
            if (false != ($tmp = $this->get_description($id))) {
                $extdesc = $tmp;
            } else {
                $extdesc = $meta['subject'];
            }
            $subject = $subject . " " . $extdesc . " [" . $meta['reference'] . "]";
            $initiator = $this->_get_sender_by_rid($rid);
            if (is_null($initiator)) {
                if ($this->permission_level & PRIVILEGE_ADMIN) {
                    $initiator = 'admin';
                } else {
                    $initiator = 'site';
                }
            }
            // old tickets may not populate server meta
            if (!isset($meta['server']) || !$meta['server']) {
                $server = $this->dns_get_server_from_domain($domain);
                $meta['server'] = $server;
                $this->_add_ticket_metadata($id, null, 'server', $server);
                report("no server name found for ticket $id");
            }
            $username = $group_name = $package = $site_id = $invoice = null;
            /**
             * Tickets may be called via API. admin_get* assumes account is
             * on the same server. In certain situations, when the ticket is via
             * e-mail, this is not always true
             */
            if ($state == "new") {
                if ($this->permission_level & PRIVILEGE_ADMIN) {
                    $invoice = $this->admin_get_meta_from_domain($domain, 'billing', 'invoice');
                    $package = $this->billing_get_package_by_invoice($invoice);
                    $site_id = $this->admin_get_site_id_from_domain($domain);
                    $username = $meta['username'];
                    $group_name = $this->admin_get_meta_from_domain($domain, 'siteinfo', 'admin');
                } else {
                    $invoice = $this->billing_get_invoice();
                    $group_name = $this->get_service_value('siteinfo', 'admin');
                    $username = $this->get_service_value('siteinfo', 'admin_user');
                    $site_id = $this->site_id;
                    $package = $this->billing_get_package_type();
                }
            }

            $template = \Blade::factory('views/email');
            if ($state === "new") {
                $inreplyto = null;
            } else {
                $inreplyto = $this->_get_response_ids($id);
            }
            if (is_array($inreplyto) && count($inreplyto) >= 2) {
                // last rid will be this response, make sure one precedes it
                array_pop($inreplyto);
                $inreplyto = array_pop($inreplyto);
                $inreplyto = nl2br($this->_get_response_by_rid($inreplyto));
            } else {
                $inreplyto = null;
            }
            $vars = [
                // to be replaced when generating template
                'data'      => null,
                'category'  => $meta['subject'],
                'date'      => date('Y-m-d H:i (O \G\M\T)'),
                'email'     => $this->get_contact_by_id($id),
                'inreplyto' => $inreplyto,
                'priority'  => $meta['priority'],
                'ticket_id' => $meta['reference'],
                'url'       => Util_HTTP::makeUrl("/apps/troubleticket?view&id=" . $id),
                'urlpretty' => Util_HTTP::getHost(),
                'server'    => $meta['server'],
                'username'  => $username,
                'reference' => $meta['reference'],
                'package'   => $package,
                'siteid'    => $site_id,
                'subject'   => $subject,
                'group'     => $group_name,
                'domain'    => $meta['domain'],
                'invoice'   => $invoice,
                'state'     => $state,
                'sender'    => $initiator,
                'recipient' => null
            ];

            $replyto = $this->_get_reply_to($id);
            $from = Crm_Module::FROM_NAME . ' <' . Crm_Module::FROM_ADDRESS . '>';

            $headers = array(
                'Reply-To' => $replyto,
                'Sender'   => Crm_Module::FROM_NAME . ' <' . Crm_Module::FROM_ADDRESS . '>',
                'From'     => $from
            );
            $mailopts = array(
                'html_charset' => 'utf-8',
                'text_charset' => 'utf-8'
            );
            $mime = new Mail_Mime($mailopts);
            $attachments = $this->get_attachments($id, $rid);
            if ($attachments) {
                foreach ($attachments as $a) {
                    $tmp = $this->get_attachment($id, $a['id'], true);
                    $mime->addAttachment($tmp,
                        $a['mime'],
                        $a['name'],
                        false
                    );
                }
            }

            $ref = substr($replyto, strpos($replyto, '+') + 1);
            $ref = substr($ref, 0, strpos($ref, '@'));
            $ids = $this->_get_response_ids($id);
            $lastID = null;
            $references = array_map(function ($a) use ($ref) {
                return '<' . $ref . '-' . $a . '@' . MAIL_SENDING_DOMAIN . '>';
            }, $ids);

            array_pop($ids);
            if ($ids) {
                $lastID = array_pop($ids);
            }
            $headers["Message-Id"] = "<" . $ref . '-' . $rid . '@' . MAIL_SENDING_DOMAIN . '>';
            $headers["References"] = join(',', $references);

            /**
             * iOS 6 fix: Reply-To header is no longer honored
             * In-Reply-To is used by the ticket parser to determine
             * the ticket hash (was Reply-To). If the ticket is first-filed,
             * use a $rid of 0
             */
            if (!$lastID) {
                $rid = 0;
            }
            $headers["In-Reply-To"] = "<" . $ref . '-' . $rid . '@' . MAIL_SENDING_DOMAIN . '>';
            $mime->headers($headers, true);

            //  make separate copies for admin and site user
            $mail = array_fill_keys(['admin', 'site'], ['email', 'headers']);
            foreach (['admin', 'site'] as $target) {
                $vars = array_merge($vars, ['recipient' => $target]);
                $mime->setHTMLBody(
                    $template->make('crm.ticket-html', array_merge($vars, ['data' => nl2br($ticketData)]))->render()
                );
                $mime->setTXTBody(
                    $template->make('crm.ticket-text',
                        array_merge($vars, ['data' => strip_tags($ticketData)]))->render()
                );
                $mail[$target]['email'] = $mime->get();
                $mail[$target]['headers'] = $mime->txtHeaders();

            }

            // has multiple contacts attached to ticket, send notice to everyone
            // since there is no reliable means to tease out who sent out what
            // @todo possible loop?
            $hasmultiple = count(preg_split('/,; /', $recipient, -1, PREG_SPLIT_NO_EMPTY)) > 1;

            if ($initiator == 'admin' || $state == 'new' || $hasmultiple) {
                // modify subject to read Ticket Confirmation: instead of Confirmation
                $tmp = $subject;
                if ($state == 'new') {
                    $subject = 'Ticket ' . $subject;
                }
                Mail::send(
                    $recipient,
                    $subject,
                    $mail['site']['email'],
                    $mail['site']['headers'],
                    "-f " . Crm_Module::FROM_ADDRESS . " -F'" . Crm_Module::FROM_NAME . "'"
                );
                // restore Subject: line
                $subject = $tmp;
            }

            if ($initiator == 'site' || $state == 'new') {
                if ($state == 'new') {
                    $subject = str_replace("Confirmation: ", "", $subject);
                }

                Mail::send(
                    Crm_Module::COPY_ADMIN,
                    $subject,
                    $mail['admin']['email'],
                    $mail['admin']['headers'],
                    "-f " . Crm_Module::FROM_ADDRESS . " -F'" . Crm_Module::FROM_NAME . "'"
                );
                // dispatch sms notification if priority suggests
                if ($state == 'new') {
                    $this->_notifyPriority($id, null);
                }
            }
            return true;
        }

        private function _get_response_by_rid($rid)
        {
            $db = $this->_connect();
            if (!$db) {
                return '';
            }
            $rs = $db->query("SELECT response FROM ticket_response_data WHERE response_id = " . $rid);
            if ($rs->rowCount() < 1) {
                return '';
            }
            return $rs->fetchObject()->response;
        }

        /**
         * string get_contact_by_id(int)
         *
         * @param $mID int
         * @return string
         */
        public function get_contact_by_id($mID)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $restrictor = $this->_getRestrictor();
            $q = "SELECT GROUP_CONCAT(email SEPARATOR ', ') AS email FROM ticket_contacts_meta JOIN ticket_contacts USING (email_id) JOIN ticket_metadata_cache USING (ticket_id) JOIN tickets USING (ticket_id) WHERE ticket_id = " . intval($mID) . " AND " . $restrictor;
            $rs = $db->query($q);
            if (!$rs || $rs->rowCount() < 1) {
                return null;
            }
            return $rs->fetchObject()->email;
        }

        private function _get_domain_by_id($id)
        {
            $db = $this->_connect();
            if (!$db) {
                return '';
            }
            /**
             * @XXX a recent domain change won't propagate in time and may
             *      return the old domain
             *      (db data dependent upon find_domains.sh agent reporting)
             */
            $rs = $db->query("SELECT
			COALESCE(apnscp.domain_information.domain, ticket_metadata_data.`data`) AS domain
			FROM tickets
			JOIN ticket_metadata_data USING(ticket_id)
			LEFT JOIN apnscp.domain_information ON (tickets.invoice = apnscp.domain_information.di_invoice AND
				apnscp.domain_information.parent_domain IS NULL)
			WHERE ticket_id = $id AND ticket_metadata_data.`key` = 'domain'");
            if ($rs->rowCount() < 1) {
                return '';
            }
            return $rs->fetchObject()->domain;
        }

        public function get_description($id)
        {
            if (!$this->_canModify($id)) {
                return error("cannot get description for unknown ticket `%d'", $id);
            }
            return $this->_get_ticket_metadata($id, null, 'desc');
        }

        private function _get_ticket_metadata($ticket, $response, $key)
        {
            if ($this->_isCached($ticket, $key)) {
                return $this->_getCache($ticket, $key);
            }
            $db = $this->_connect();
            if (!$db) {
                return null;
            }
            $ticket = intval($ticket);
            $rs = $db->query("SELECT `key`, `data`, `response_id` FROM ticket_metadata_data WHERE ticket_id = $ticket");
            $datacache = array();
            while (false !== ($row = $rs->fetchObject())) {
                $rid = $row->response_id;
                $tmp = $row->key;
                if (!isset($datacache[$rid])) {
                    $datacache[$rid] = array();
                }

                $datacache[$rid][$tmp] = $row->data;
            }
            $this->_cache($ticket, $datacache);
            if (!isset($datacache[$rid][$key])) {
                return null;
            }
            return $datacache[$rid][$key];


        }

        private function _get_response_ids($id)
        {
            $ids = array();
            $db = $this->_connect();
            if (!$db) {
                return $ids;
            }
            $q = "SELECT response_id AS rid FROM ticket_responses WHERE ticket_id = " . intval($id);
            $rs = $db->query($q);
            if ($rs->rowCount() < 1) {
                return $ids;
            }
            $ids = $rs->fetchAll(PDO::FETCH_COLUMN);
            return $ids;
        }

        /**
         * Ticket response contact
         *
         * @param int $id ticket id
         * @return string
         */
        private function _get_reply_to($id)
        {
            $hash = $this->_get_reply_hash_from_ticket($id);
            if (!$hash) {
                return self::FROM_ADDRESS;
            }
            list($user, $domain) = explode('@', self::FROM_ADDRESS);
            return sprintf('%s+%s@%s', $user, $hash, $domain);
        }

        /**
         * Get ticket reply-to hash
         *
         * @param int $id ticket id
         * @return string
         */
        private function _get_reply_hash_from_ticket($id)
        {
            $db = $this->_connect();
            if (!$db) {
                return null;
            }
            $q = "SELECT hash FROM tickets WHERE ticket_id = " .
                intval($id);
            $rs = $db->query($q);
            if (!$rs || $rs->rowCount() < 1) {
                return null;
            }
            return $rs->fetchObject()->hash;
        }

        /**
         * Get metadata on attachments
         *
         * @param int $ticket ticket ID
         * @return array
         */
        public function get_attachments($ticket, $rid = null)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $attachments = array();
            $restrictor = $this->_getRestrictor();
            if (!is_null($rid)) {
                $restrictor .= " AND response_id = " . intval($rid);
            }
            $q = "SELECT attachment_id AS id,
				response_id AS rid,
				attachment_size AS size,
				attachment_name AS name,
				attachment_owner AS owner,
				UNIX_TIMESTAMP(attachment_created) AS ctime,
				attachment_extension AS ext,
				attachment_mime AS mime,
				attachment_charset AS charset
				FROM tickets
				JOIN ticket_responses USING (ticket_id)
				JOIN ticket_attachments USING (response_id)
				JOIN ticket_attachment_data USING (attachment_id)
				WHERE ticket_id = " . intval($ticket) . " AND " .
                $restrictor;
            $rs = $db->query($q);
            if ($rs->rowCount() < 1) {
                return $attachments;
            }
            while (false !== ($row = $rs->fetchObject())) {
                $attachments[] = array(
                    'id'      => $row->id,
                    'rid'     => $row->rid,
                    'name'    => $row->name,
                    'size'    => $row->size,
                    'owner'   => $row->owner,
                    'ctime'   => $row->ctime,
                    'ext'     => $row->ext,
                    'mime'    => $row->mime,
                    'charset' => $row->charset,
                );
            }
            return $attachments;
        }

        public function get_attachment($ticket, $aid, $raw = true)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $restrictor = $this->_getRestrictor();
            $q = "SELECT attachment_data AS data
				FROM tickets
				JOIN ticket_responses USING (ticket_id)
				JOIN ticket_attachments USING (response_id)
				JOIN ticket_attachment_data USING (attachment_id)
				WHERE ticket_id = " . intval($ticket) . " AND " .
                "attachment_id = " . intval($aid) . " AND " . $restrictor;
            $rs = $db->query($q);
            if ($rs->rowCount() < 1) {
                return null;
            }
            $data = $rs->fetchObject()->data;
            if (!$raw) {
                $data = base64_encode($data);
            }
            return $data;
        }

        private function _notifyPriority($ticket, $priority)
        {
            $rid = $this->get_last_response_id_by_ticket_id($ticket);
            $subject = $this->_get_meta_by_id($ticket, 'subject');
            $domain = $this->_get_meta_by_id($ticket, 'domain');
            $oldpriority = $this->_get_meta_by_id($ticket, 'priority');
            $priorities = $this->get_priorities();
            $posoldp = array_search($oldpriority, $priorities);

            // flip the variables around to accommodate when a
            // new ticket is filed. Old priority will be populated with current
            // priority metadata (meta insertion -> email -> notify).
            if (!$priority) {
                $posnewp = $posoldp;
                $posoldp = false;
            } else {
                $posnewp = array_search($priority, $priorities);
            }

            // no priority escalation, priorities ordered low -> high
            if ($posoldp && ($posnewp <= $posoldp) ||
                !$posoldp && !$posnewp ||
                ($this->permission_level & PRIVILEGE_ADMIN)
            ) {
                return false;
            }

            $response = $this->_get_response_by_rid($rid);
            $response = Util_HTML_BBCode::stripHTML($response);
            $header = $domain . ": " . $subject . "\r\n";
            $maxlen = self::MAX_SMS_LENGTH - strlen($header);
            if (Crm_Module::SHORT_COPY_ADMIN) {
                Mail::send(
                    Crm_Module::SHORT_COPY_ADMIN,
                    "",
                    /*$subject.": ".$domain,*/
                    $header . substr($response, 0, $maxlen),
                    "From: " . Crm_Module::FROM_NAME . " <" . Crm_Module::FROM_ADDRESS . ">",
                    "-f " . Crm_Module::FROM_ADDRESS . " -F '" . Crm_Module::FROM_NAME . "'"
                );
            }
        }

        /**
         * Get last response posted for a ticket
         *
         * @param  int|array $ticket_id     ticket id
         * @param  int       $last_response optional last response
         * @return int last response id, -1 indicates current, 0 error
         */
        public function get_last_response_id_by_ticket_id($ticket_id, $last_response = null)
        {
            if (!is_array($ticket_id)) {
                $ticket_id = array($ticket_id);
            }
            for ($i = 0, $n = sizeof($ticket_id); $i < $n; $i++) {
                $tid = $ticket_id[$i];
                if (intval($tid) != $tid || $tid < 1) {
                    return error("invalid ticket id `%s'", $tid);
                }

            }
            $restrictor = $this->_getRestrictor();
            $db = $this->_connect();
            $q = "SELECT MAX(response_id) AS response
                 FROM ticket_responses WHERE ticket_id IN(" . join(",", $ticket_id) .
                ") HAVING(response IS NOT NULL)";
            $db = self::_connect();
            if (!($rs = $db->query($q))) {
                return null;
            } else {
                if ($rs->rowCount() < 1) {
                    return null;
                }
            }
            $response = $rs->fetchObject()->response;
            if ($response == $last_response) {
                return -1;
            }
            return $response;
        }

        public function dispatch_email($id, $rid)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }

            if (!$this->_reponseMatchesTicket($id, $rid)) {
                return error("unknown ticket/response (%d/%d)", $id, $rid);
            }
            return $this->_send_ticket_email($id, $rid);
        }

        private function _reponseMatchesTicket($id, $rid)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $id = intval($id);
            $rid = intval($rid);
            $rs = $db->query("SELECT 1 FROM tickets JOIN ticket_responses USING (ticket_id) WHERE " .
                "ticket_id = " . $id . " AND response_id = " . $rid);
            return $rs && $rs->rowCount() > 0;
        }

        public function get_contacts()
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            /*if ($this->permission_level & (PRIVILEGE_SITE|PRIVILEGE_USER))
                $site_clause = 'tickets.site_id = ' . $this->site_id;
            else
                $site_clause = '1 = 1';*/
            $restrictor = $this->_getRestrictor();
            $q = "SELECT DISTINCT(email) AS email, COUNT(email) FROM ticket_contacts_meta JOIN ticket_contacts USING " .
                "(email_id) JOIN ticket_metadata_cache USING (ticket_id) JOIN tickets USING (ticket_id) WHERE " .
                $restrictor . " GROUP BY (email) ORDER BY COUNT(email) DESC";
            $rs = $db->query($q);
            $emails = array();
            while (false !== ($row = $rs->fetchObject())) {
                $emails[] = $row->email;
            }
            return $emails;
        }

        public function change_priority($ticket, $newpriority)
        {
            if (!$this->_canModify($ticket)) {
                return error("cannot modify ticket");
            }
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $oldpriority = $this->_get_meta_by_id($ticket, 'priority');
            $newpriority = strtolower($newpriority);
            // no change in priority;
            if ($oldpriority == $newpriority) {
                return true;
            }
            $subject = $this->_get_meta_by_id($ticket, 'subject');

            // permit priority change if subject is low priority
            $priorities = $this->get_priorities();
            $isLow = ($newpriority == $priorities[0]);
            if (!$isLow && in_array(strtolower($subject), self::LOW_PRIORITY_SUBJECTS)) {
                return error("cannot escalate priority on low priority issue");
            }
            if (!$this->_isValidPriority($newpriority)) {
                return error("invalid priority `$newpriority'");
            }
            $rid = $this->get_last_response_id_by_ticket_id($ticket);
            $this->_notifyPriority($ticket, $newpriority);
            $this->_add_ticket_metadata($ticket, $rid, 'priority', $newpriority);
            return true;
        }

        public function change_subject($ticket, $newsubject)
        {
            if (!$this->_canModify($ticket)) {
                return error("cannot modify ticket");
            }
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            if (intval($newsubject) != $newsubject) {
                $newsubject = $this->get_subject_id_by_subject($newsubject);
            }
            $oldsubject = $this->_get_meta_by_id($ticket, 'subject_id');
            if ($oldsubject == $newsubject) {
                return true;
            }
            if (!$this->_subject_privileged($newsubject)) {
                return error('cannot use unprivileged subject %d', $newsubject);
            }
            $response = $this->get_last_response_id_by_ticket_id($ticket);
            $this->_add_ticket_metadata($ticket, $response, array(
                    'subject_id' => $newsubject,
                    'subject'    => $this->get_subject_by_id($newsubject)
                )
            );
            return true;

        }

        /**
         * Change e-mail addresses affiliated with ticket
         *
         * @param  int          $ticket ticket id
         * @param  string|array $email  e-mail address(es)
         * @param  string       $method replace, add, or remove
         * @return bool
         */
        public function change_contact($ticket, $email, $method = 'replace')
        {
            if (!$this->_canModify($ticket)) {
                return error("cannot modify ticket");
            }
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $method = strtolower($method);
            if ($method != 'replace' && $method != 'add' && $method != 'remove') {
                return error("unknown method %s to change_contact()", $method);
            }

            if ($method == 'replace') {
                $this->_delete_contacts_from_ticket(null, $ticket);
            }
            $cids = $this->_get_ids_from_contacts($email);
            if ($method == 'remove') {
                return $this->_delete_contacts_from_ticket($cids, $ticket);
            }
            $this->_add_ticket_metadata($ticket, $this->get_last_response_id_by_ticket_id($ticket), 'email', $email);
            return $this->_attach_contacts_to_ticket($cids, $ticket);

        }

        private function _delete_contacts_from_ticket(array $cids = null, $tid)
        {
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $frag = '';
            $q = "DELETE FROM ticket_contacts WHERE ticket_id = ?";
            if (count($cids) > 0) {
                $q .= ' AND email_id IN (' . join(array_fill(0, count($cids), '?'), ',') . ')';
            } else {
                $cids = array();
            }
            $cids = array_merge(array($tid), $cids);
            $stmt = $db->prepare($q);
            if (!$stmt->execute($cids)) {
                return report("failure to remove contacts in %s: " . array_pop($stmt->errorInfo()), __FUNCTION__);
            }
            return true;
        }

        public function get_domain_by_id($id)
        {
            return $this->_get_domain_by_id($id);
        }

        /**
         * Trouble tickets enabled
         *
         * @return bool
         */
        public function enabled()
        {
            if ($this->permission_level & PRIVILEGE_ADMIN) {
                return true;
            } else {
                if ($this->permission_level & PRIVILEGE_SITE) {
                    return !!$this->get_config('billing', 'invoice');
                }
            }
            return false;
        }

        public function append_ticket_via_email($hash, $response, $sender, array $attachments = array())
        {
            if ($sender != 'site' && $sender != 'admin') {
                return error("unknown sender `%s'", $sender);
            }
            $db = $this->_connect();
            if (!$db) {
                return false;
            }
            $rs = $db->query("SELECT ticket_id FROM tickets WHERE hash = " . $db->quote($hash));

            if ($rs->rowCount() < 1) {
                return false;
            }
            $ticketid = $rs->fetchObject()->ticket_id;
            $response .= "\r\n\r\nSent via E-mail Response";

            do {
                $a = current($attachments);
                if (!$a) {
                    break;
                }
                $k = key($attachments);
                if (!isset($a['content']) || !isset($a['name'])) {
                    warn("malformed attachment found - missing content/name properties");
                    unset($attachments[$k]);
                } else {
                    $attachments[$k]['content'] = base64_decode($a['content']);
                }
                $a = next($attachments);
            } while (true);
            $rid = $this->append_trouble_ticket(
                $ticketid,
                $response,
                array('state' => 'append', 'email' => true, 'sender' => $sender), $attachments);
            if ($rid < 1) {
                return error("ticket posting failed");
            }
            return true;
        }

        private function _get_contacts_from_ids(array $ids)
        {
            foreach ($ids as $id) {
                if (intval($id) != $id) {
                    return error("invalid id `$id'");
                }
            }
            $emails = array();
            $db = $this->_connect();
            if (!$db) {
                return $emails;
            }
            $q = "SELECT email FROM ticket_contacts_meta WHERE email_id IN(" .
                join(",", array_fill(0, count($ids), '?')) . ')';
            $stmt = $db->prepare($q);
            $rs = $stmt->execute($ids);
            while (false !== ($row = $rs->fetchObject())) {
                $emails[] = $row->email;
            }

            return $emails;
        }

        private function _get_meta_by_rid($id, $rid)
        {
            $db = $this->_connect();
            if (!$db) {
                return new stdClass();
            }
            $id = intval($id);
            $rid = intval($rid);
            $rs = $db->query("SELECT `key`, `data`, MAX(`ts`) FROM
				(SELECT `key`, `data`, `ts` FROM ticket_metadata_data WHERE ticket_id = $id AND response_id = $rid ORDER BY ts DESC) AS t2
				GROUP BY (`key`)");
            if ($rs->rowCount() < 1) {
                return false;
            }
            return $rs->fetch(PDO::FETCH_ASSOC);
        }

        /**
         * Verify CRM module is configured
         *
         * @return bool
         */
        public function configured(): bool
        {
            return $this->connected();
        }
    }