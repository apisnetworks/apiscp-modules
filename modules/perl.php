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
	 * @author  Matt Saladna <matt@apisnetworks.com>
	 * @package core
	 */
	class Perl_Module extends Module_Skeleton
	{
		public $exportedFunctions;

		public function __construct()
		{
			parent::__construct();
			$this->exportedFunctions = array(
				'*'           => PRIVILEGE_ALL,
				'get_modules' => PRIVILEGE_SITE | PRIVILEGE_USER

			);
		}

		public function get_modules()
		{
			$cmd = '/usr/bin/perl -e \'use File::Find;
                foreach $start (@INC) { find(\&modules, $start); }
                sub modules {
                if (-d && /^[a-z]/) {
                $File::Find::prune = 1; return; }
                return unless /\.pm$/;
                my $filename = "$File::Find::dir/$_";
                $filename =~ s!^$start/!!;
                $filename =~ s!\.pm\$!!;
                $filename =~ s!/!::!g;
                print "$filename\n";
                }\' 2>&1';
			$proc = Util_Process_Sudo::exec($cmd);
			$perlArray = explode("\n", $proc['output']);
			sort($perlArray);
			return $perlArray;
		}

		/**
		 * string get_pod()
		 * Returns the POD for a specific Perl module
		 *
		 * @param string $module module name to return the documentation for
		 * @privilege PRIVILEGE_ALL
		 * @return string returns a string of the documentation if found; otherwise
		 *                       false is returned
		 */
		public function get_pod($module)
		{
			$proc = Util_Process_Safe::exec('/usr/bin/perldoc %s', array($module));
			$perlDoc = $proc['output'];
			return $perlDoc;
		}

		/**
		 * string get_perl_version()
		 * Returns the version of the Perl interpreter
		 *
		 * @privilege PRIVILEGE_ALL
		 * @return string Perl version
		 */
		public function version()
		{
			$version = Util_Process::exec("/usr/bin/perl -e 'printf \"%vd\", \$^V;'");
			return $version['output'];
		}
	}

?>
