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
	 * htaccess driver
	 *
	 * @package core
	 */
	include(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'personality' .
		DIRECTORY_SEPARATOR . 'helpers' . DIRECTORY_SEPARATOR . 'ipersonality.php');

	include(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'personality' .
		DIRECTORY_SEPARATOR . 'helpers' . DIRECTORY_SEPARATOR . 'base.php');

	class Personality_Module extends Module_Skeleton
	{
		const CONTROL_FILE = '.htaccess';
		const CACHE_KEY_PREFIX = 'pnlty:';
		// under modules/
		const PERSONALITY_MODULE_LOCATION = 'personality';

		public $exportedFunctions = array(
			'*' => PRIVILEGE_SITE
		);

		// loaded personalitiesv
		private $_personalities = array();
		private $_resolverCache = array();
		private $_instances = array();

		public function __wakeup()
		{
			$this->_personalities = array();
			$this->_instances = array();
			if (is_debug()) {
				$this->_resolverCache = array();
			}
		}

		public function scan($file)
		{
			if (!$this->file_file_exists($file)) {
				$this->file_touch($file);
			}
			$splfile = $this->_getSPLObjectFromFile($file);
			if (!is_object($splfile)) {
				return null;
			}
			if ((false === ($parser = $this->_getCache($splfile)))) {
				$parser = $this->_getParser($splfile);
				$this->_setCache($splfile, $parser);
				return $parser->parse();
			}
			return $parser;
		}

		private function _getSPLObjectFromFile($file)
		{
			$path = $this->file_make_path($file);
			try {
				$splfile = new SplFileObject($path);
			} catch (Exception $e) {
				return error("unable to access control file `%s': %s",
					$this->file_unmake_path($file),
					$e->getMessage()
				);
			}
			return $splfile;

		}

		private function _getCache(SplFileObject $file, $which = 'entry')
		{
			$cache = Cache_Account::spawn();
			$key = self::CACHE_KEY_PREFIX . $file->getInode();
			if (false !== ($res = $cache->get($key))) {
				if ($res['time'] == $file->getMTime()) {
					return $res[$which];
				}
			}
			return false;
		}

		private function _getParser(SplFileObject $splfile)
		{
			$parser = new \Tivie\HtaccessParser\Parser();
			$parser->ignoreComments(false)->ignoreWhitelines(false);
			$parser->setFile($splfile);
			return $parser;
		}

		/**
		 * Store Htaccess Parser
		 *
		 * @param SplFileObject                $file
		 * @param \Tivie\HtaccessParser\Parser $parser
		 * @return mixed
		 * @throws \Tivie\HtaccessParser\Exception\Exception
		 */
		private function _setCache(SplFileObject $file, \Tivie\HtaccessParser\Parser $parser)
		{
			$cache = Cache_Account::spawn();
			$ts = $file->getMtime();
			$key = self::CACHE_KEY_PREFIX . $file->getInode();
			$parsed = $parser->parse($file);
			return $cache->set($key, array(
				'time'  => $file->getMTime(),
				'hash'  => md5($parsed),
				'entry' => $parsed
			));
		}

		public function get_personalities()
		{
			$personalities = $this->_tryPersonalities();
			$ret = array();
			while (false !== ($personalities->valid())) {
				$name = $personalities->current();
				$ret[] = $name;
				$personalities->next();
			}
			return $ret;
		}

		private function _tryPersonalities()
		{
			if ($this->_personalities) {
				// arg! enumeration consumes the queue
				return clone $this->_personalities;
			}

			if (false && !is_debug()) {
				$key = 'prsntly';
				$cache = Cache_Global::spawn();
				$personalities = $cache->get($key);
				if ($personalities) {
					// arg! enumeration consumes the queue
					$tmp = unserialize($personalities);
					$this->_personalities = $tmp['personalities'];
					$this->_instances = $tmp['instances'];
					return clone $this->_personalities;
				}
			}


			$queue = new SplPriorityQueue();

			$dir = dirname(__FILE__) . DIRECTORY_SEPARATOR . self::PERSONALITY_MODULE_LOCATION;
			$dh = opendir($dir);
			if (!$dh) {
				return error("unable to access personality module location");
			}
			while (false !== ($entry = readdir($dh))) {
				if ($entry[0] === '.') {
					continue;
				}
				if (substr($entry, strrpos($entry, '.')) !== ".php") {
					continue;
				}

				$type = substr($entry, 0, strpos($entry, '.'));
				$class = $this->_getInstanceFromPersonality($type);
				$queue->insert($type, $class->getPriority());
			}

			closedir($dh);
			$queue->rewind();
			$this->_personalities = $queue;

			if (false && !is_debug()) {
				$data = array(
					'personalities' => $this->_personalities,
					'instances'     => $this->_instances
				);
				$cache->set($key, serialize($data));
			}
			return clone $queue;
		}

		private function _getInstanceFromPersonality($personality)
		{
			if (!$personality) {
				return error('no personality specified');
			}

			if (isset($this->_instances[$personality])) {
				return $this->_instances[$personality];
			}
			$class = 'Personality_' . ucwords($personality);
			if (!class_exists($class)) {
				$this->_loadPersonality($personality);
				if (!class_exists($class)) {
					return error("unknown personality `%s'", $personality);
				}
			}
			$this->_instances[$personality] = new $class;
			return $this->_instances[$personality];
		}

		private function _loadPersonality($personality)
		{
			$file = dirname(__FILE__) . DIRECTORY_SEPARATOR . self::PERSONALITY_MODULE_LOCATION
				. DIRECTORY_SEPARATOR . $personality . '.php';
			if (!file_exists($file)) {
				return error("unknown personality `%s'", $personality);
			}
			return include($file);

		}

		public function insert(\Tivie\HtaccessParser\HtaccessContainer $config, $line,
		                       \Tivie\HtaccessParser\Token\BaseToken $directive)
		{
			if ($line < 0 || !$config->offsetExists($line)) {
				return error("invalid offset `%d'", $line);
			}

			if (!$this->verify($directive->getName(), $directive->getArguments())) {
				return error("unknown directive `%s'", $directive->getName());
			}
			$config->insertAt($line, $directive);
			return $config;
		}

		public function verify($directive, $val = null, $personality = null)
		{
			if (!$personality) {
				$personality = $this->resolve($directive);
			}
			if (!$personality) {
				return false;
			}
			if (!$val) {
				return true;
			}
			$instance = $this->_getInstanceFromPersonality($personality);
			if (!$instance->resolves($directive)) {
				return error("personality `%s' doesn't know how to resolve `%s'",
					$personality,
					$directive
				);
			}
			$response = $instance->test($directive, $val);
			// if directive/val isn't tested, null is returned
			if (is_null($response)) {
				return true;
			}
			return $response;
		}

		/**
		 * Resolve a delegating personality
		 *
		 * @param string $token
		 * @return array
		 */
		public function resolve($token)
		{
			if (array_key_exists($token, $this->_resolverCache)) {
				// don't use isset; unmatched directives will return null
				return $this->_resolverCache[$token];
			}
			$personalities = $this->_tryPersonalities();
			while ($personalities->valid()) {
				$name = $personalities->current();
				$p = $this->_getPersonalityFromName($name);
				if ($p->resolves($token)) {
					$this->_resolverCache[$token] = $name;
					return $name;
				}
				$personalities->next();
			}

			$this->_resolverCache[$token] = null;
			return false;
		}

		private function _getPersonalityFromName($name)
		{
			if (isset($this->_instances[$name])) {
				return $this->_instances[$name];
			}


		}

		public function get_description($personality, $directive)
		{
			$personality = strtolower($personality);
			$instance = $this->_getInstanceFromPersonality($personality);
			if (!$instance) {
				return error("unknown personality `%s'", $personality);
			}

			return $instance->getTokenDescription($directive);
		}

		public function remove(\Tivie\HtaccessParser\HtaccessContainer $config, $line)
		{
			if (!$config->offsetExists($line)) {
				return error("invalid offset `%d'", $line);
			}

			$config->offsetUnset($line);
			return $config;
		}

		public function replace($config, $line, $directive, $val = '')
		{

			$directive = $this->_token2Object($directive);
			if (!$this->resolve($directive)) {
				return error("unknown directive `%s' specified", $directive);
			} else if ($val && !$this->verify($directive, $val)) {
				return error("unknown directive value `%s'", $val);
			}
		}

		/**
		 * Convert a string to a htaccess object
		 *
		 * @param string $token
		 * @return \Tivie\HtaccessParser\Token\BaseToken
		 * @throws \Tivie\HtaccessParser\Exception\DomainException
		 */
		private function _token2Object($token)
		{
			if ($token instanceof \Tivie\HtaccessParser\Token\BaseToken) {
				return $token;
			}
			$token = trim($token);
			if (!isset($token[0])) {
				return new \Tivie\HtaccessParser\Token\WhiteLine($token);
			}
			switch ($token[0]) {
				case '#':
					return new \Tivie\HtaccessParser\Token\Comment($token);
				case '<':
					// do extra formatting here
					break;
				default:
					// normal directive
					$tokens = explode(" ", $token);
					return new \Tivie\HtaccessParser\Token\Directive($tokens[0], array_slice($tokens, 1));

			}
			$args = explode(" ", substr($token, 1, strpos($token, '>') - 1));

			$block = new \Tivie\HtaccessParser\Token\Block($args[0]);
			if (isset($args[1])) {
				$block->setArguments(array_slice($args, 1));
			}

			// CRLF LF and CR
			$lines = preg_split('/\R/m', $token);
			unset($lines[0]);
			// skip final closing /IfDefine
			for ($i = 1, $n = sizeof($lines); $i < $n; $i++) {
				$block->addChild($this->_token2Object($lines[$i]));
			}
			return $block;

		}

		public function get_directives($personality)
		{
			$instance = $this->_getInstanceFromPersonality($personality);
			if (!$instance) {
				return error("unknown personality `%s'", $instance);
			}

			return $instance->getDirectives();
		}

		/**
		 * Write changes to control file
		 *
		 * @param $host
		 * @param $data
		 * @param $hash validation hash @see hash()
		 * @return bool
		 */
		public function commit($host, $hash, $data)
		{
			$docroot = $this->web_get_docroot($host);
			if (!$docroot) {
				return error("unknown host `%s'", $host);
			}
			$controlpath = $docroot . DIRECTORY_SEPARATOR . self::CONTROL_FILE;
			$olddata = '';
			// do a check to make sure data is consistent
			if ($this->file_file_exists($controlpath)) {
				$olddata = $this->file_get_file_contents($controlpath);
				if ($this->hash($controlpath) != $hash) {
					return error("control file `%s' out of sync", $controlpath);
				}
			}
			$data = trim($data);
			$res = $this->file_put_file_contents($controlpath, $data);
			if (!$res || $res instanceof Exception) {
				$reason = 'unknown';
				if ($res instanceof Exception) {
					$reason = $res->getMessage();
				}
				return error("failed to update htaccess contents in `%s', reason: %s", $controlpath, $reason);
			}
			// global subdomain -> plop on active domain to make request
			if (false === strpos($host, ".")) {
				$host = $host . '.' . $this->domain;
				info("personality applied to global subdomain, " .
					"converting to fqdn `%s'", $host);
			}
			$myip = $this->common_get_ip_address();
			try {
				$http = new HTTP_Request2('http://' . $myip);
				$http->setHeader('Host', $host);
				$status = $http->send()->getStatus();
				if ($status < 200 || $status >= 500) {
					warn("inconsistent status `%d' returned, reverted control file %s",
						$status,
						$controlpath
					);
					$this->file_put_file_contents($controlpath, $olddata);
					return false;
				}
			} catch (\Exception $e) {
				$this->file_put_file_contents($controlpath, $olddata);
				return error("unable to connect to server to test control file, reverting. Error message: `%s'",
					$e->getMessage()
				);
			}
			return true;
		}

		/**
		 * Calculate hash of a control file or htaccess object
		 *
		 * @param mixed $obj
		 * @return bool|null|string hash or error
		 */
		public function hash($obj)
		{
			if ($obj instanceof \Tivie\Htaccess\Parser) {
				$obj = $obj->parse();
			} else if ($obj instanceof \Tivie\HtaccessParser\HtaccessContainer) {
				// no-op

			} else if ($obj[0] !== "/") {
				// raw file
				/**
				 * this should only be the case after undergoing Htaccess
				 * parsing @see scan()
				 */

			} else {
				if (!$this->file_file_exists($obj)) {
					return error("unknown control file `%s'", $obj);
				}

				$spl = $this->_getSPLObjectFromFile($obj);
				if (!is_object($spl)) {
					return error("unknown control hash object `%s'", $obj);
				}
				$hash = $this->_getCache($spl, 'hash');
				if ($hash) {
					return $hash;
				}
				$obj = $this->_getParser($spl)->parse();
			}
			return md5($obj);

		}

		private function _loadPersonalityFromName($name)
		{
			//return $personalities->offsetGet($name);
		}

		private function _parse(\Tivie\HtaccessParser\Parser $parser)
		{
			try {
				$parsed = $parser->parse();
			} catch (Exception $e) {
				return error("unable to parse control file `%s': %s",
					$file,
					$e->getMessage()
				);
			}
			return $parsed;
		}

	}
