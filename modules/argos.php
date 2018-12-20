<?php declare(strict_types=1);

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
	class Argos_Module extends Module_Skeleton
	{
		const DEFAULT_BACKEND = 'default';
		protected $exportedFunctions = ['*' => PRIVILEGE_ADMIN];

		/**
		 * Set or get configuration for Argos backend
		 *
		 * @param string     $backend   backend name
		 * @param array|null $newparams parameters to apply
		 * @return bool|array
		 */
		public function config(string $backend, ?array $newparams)
		{
			if (!IS_CLI) {
				return $this->query('argos_config', $backend, $newparams);
			}

			if (!\in_array($backend, \Opcenter\Argos\Config::get()->getBackends(), true)) {
				return error("Unknown backend `%s'", $backend);
			}

			// clear backend with null
			if (null === $newparams) {
				$provider = array_get(\Opcenter\Argos\Config::get()->backend($backend), 'backend', $backend);
				if (!\Opcenter\Argos\Config::get()->deleteBackend($backend)) {
					warn("Failed to delete backend `%s'", $backend);
				}
				if (!\Opcenter\Argos\Config::get()->createBackend($provider, $backend)) {
					return error("Failed to create backend `%s'", $backend);
				}

				return true;
			}

			$cfg = \Opcenter\Argos\Config::get();
			$backend = $cfg->backend($backend);
			// writing backend vars
			foreach ($newparams as $k => $v) {
				$backend[$k] = $v;
			}

			return true;
		}

		public function get_config(string $backend, $param = null): ?array
		{
			if (!IS_CLI) {
				return $this->query('argos_get_config', $backend);
			}

			if (!\in_array($backend, \Opcenter\Argos\Config::get()->getBackends(), true)) {
				return error("Unknown backend `%s'", $backend);
			}

			// reading backend vars
			$cfg = \Opcenter\Argos\Config::get()->backend($backend)->toArray();

			return $param ? array_get($cfg, $param, null) : $cfg;
		}

		/**
		 * Set default backend
		 *
		 * @param $backend
		 * @return bool
		 */
		public function set_default($backend)
		{
			if (!IS_CLI) {
				return $this->query('argos_set_default', $backend);
			}
			$backends = $this->get_backends();
			foreach ((array)$backend as $b) {
				if (!\in_array($b, $backends, true)) {
					return error("Invalid backend `%s'", $b);
				}
			}

			return \Opcenter\Argos\Config::get()->setDefault($backend);
		}

		/**
		 * Get configured Argos backends
		 *
		 * @return array
		 */
		public function get_backends(): array
		{
			if (!IS_CLI) {
				return $this->query('argos_get_backends');
			}

			return \Opcenter\Argos\Config::get()->getBackends();
		}

		/**
		 * Create a new backend
		 *
		 * @param string $name
		 * @param string $driver
		 * @return bool
		 */
		public function create_backend(string $name, string $driver): bool
		{
			if (!IS_CLI) {
				return $this->query('argos_create_backend', $name, $driver);
			}
			if (\in_array($name, $this->get_backends(), true)) {
				return error("Backend `%s' already exists", $name);
			}
			if (!\in_array($driver, $this->get_backend_relays(), true)) {
				return error("Invalid backend relay `%s'. Use get_backend_relays() to view all", $driver);
			}

			$conf = \Opcenter\Argos\Config::get();
			$conf->createBackend($driver, $name);
			$conf->sync();

			return true;
		}

		/**
		 * Get relays for backend
		 *
		 * @return array
		 */
		public function get_backend_relays(): array
		{
			if (!IS_CLI) {
				return $this->query('argos_get_backend_relays');
			}

			return \Opcenter\Argos\Backend::getBackends();
		}

		/**
		 * Test Argos configuration
		 *
		 * @param string $backend
		 * @return mixed
		 */
		public function test(string $backend = null)
		{
			return $this->send('Argos test alert', $backend, '💯 test');
		}

		/**
		 * Relay a message through Argos
		 *
		 * @param string      $msg
		 * @param string      $backend
		 * @param string|null $title
		 * @return mixed
		 */
		public function send(string $msg, string $backend = null, string $title = null)
		{
			if (!IS_CLI) {
				return $this->query('argos_send', $msg, $backend, $title);
			}

			if ($title) {
				$title = '-t ' . escapeshellarg($title);
			}
			if ($backend) {
				$backend = '-b ' . escapeshellarg($backend);
			}

			return array_get(
				\Util_Process_Safe::exec("ntfy -c %(config)s " . $title . ' ' . $backend . ' send %(msg)s',
					[
						'config' => \Opcenter\Argos\Config::CONFIGURATION_FILE,
						'msg'    => $msg,
					]
				),
				'success',
				false
			);
		}
	}
