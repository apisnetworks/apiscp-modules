<?php declare(strict_types=1);
/**
 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
 *
 * Unauthorized copying of this file, via any medium, is
 * strictly prohibited without consent. Any dissemination of
 * material herein is prohibited.
 *
 * For licensing inquiries email <licensing@apisnetworks.com>
 *
 * Written by Matt Saladna <matt@apisnetworks.com>, August 2018
 */

class Config_Module extends Module_Skeleton {
	const CONFIG_CACHE_KEY = 'admin.syscfg';
	protected $exportedFunctions = ['*' => PRIVILEGE_ADMIN];

	public function __construct()
	{
		parent::__construct();
		if (!AUTH_ADMIN_API) {
			$this->exportedFunctions = ['*' => PRIVILEGE_NONE];
		}
	}

	/**
	 * Set server var
	 *
	 * @param string      $name
	 * @param mixed $val
	 * @return bool
	 */
	public function set(string $name, ...$val): bool
	{
		if (!is_debug() && !IS_CLI) {
			return $this->query('config_set', $name, ...$val);
		}
		$c = \Opcenter\Admin\Settings\Setting::className($name);
		if (!$c) {
			return error("Unknown admin setting `%s'", $name);
		}

		return (new $c)->set(...$val);
	}

	/**
	 * List available configuration settings
	 *
	 * @return array
	 */
	public function list(): array
	{
		$cache = Cache_Global::spawn();
		if (!is_debug() && (false !== ($c = $cache->get(self::CONFIG_CACHE_KEY)))) {
			return $c;
		}
		$path = INCLUDE_PATH . '/lib/Opcenter/Admin/Settings';
		$list = [];
		if (!$dh = opendir($path)) {
			return $list;
		}
		while (false !== ($class = readdir($dh))) {
			if ($class === '.' || $class === '..') {
				continue;
			}
			if (false !== strpos($class, '.')) {
				continue;
			}
			$config = glob("${path}/${class}/*.php");
			$class = strtolower($class);

			array_push($list, ...array_map(function ($f) use ($class) {
				return $class . '.' . strtolower(snake_case(basename($f, '.php'), '-'));
			}, $config));
		}
		closedir($dh);
		$cache->set(self::CONFIG_CACHE_KEY, $list);

		return $list;
	}

	public function info(string $name): ?array
	{
		$c = \Opcenter\Admin\Settings\Setting::className($name);
		if (!$c) {
			return null;
		}
		$class = new $c;

		return [
			'info'     => $class->getHelp(),
			'value'    => $class->get(),
			'settings' => $class->getValues()
		];
	}

	/**
	 * Set server var
	 *
	 * @param string $name
	 * @return bool
	 */
	public function get(string $name)
	{
		if (!is_debug() && !IS_CLI) {
			return $this->query('config_get', $name);
		}
		$c = \Opcenter\Admin\Settings\Setting::className($name);
		if (!$c) {
			return error("Unknown admin setting `%s'", $name);
		}

		return (new $c)->get();
	}

	public function _housekeeping()
	{
		Cache_Global::spawn()->delete(self::CONFIG_CACHE_KEY);
	}
}
