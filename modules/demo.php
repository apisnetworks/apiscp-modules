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
     *  Provides demonstrative results of various module invocations
     *
     * @package core
     */
    class Demo_Module extends Module_Skeleton
    {
        protected $exportedFunctions =
            array('*' => PRIVILEGE_ALL,);

        /* }}} */

        /**
         * Test AJAX tail support
         *
         * @param int    $cnt
         * @param double $timing
         */
        public function test_tail($cnt = 20, $timing = 0.5)
        {
            if (!is_debug()) {
                return error("test_tail may not be used in production");
            }
            if (!IS_CLI) {
                return $this->query("demo_test_tail", $cnt, $timing);
            }
            $tail = Util_Process_Tee::watch(new Util_Process);
            $script = 'echo ' . date("r") . '; for (( C=' . $cnt . '0; C > 0; C-- )) ; do echo $C; usleep ' . ($timing * 100000) . '; done';
            $tail->exec($script);
            $script = 'echo ' . date("r") . '; for (( C=0; C < ' . $cnt . ' ; C++ )) ; do echo $C; usleep ' . ($timing * 1000000) . '; done ; echo `date`';
            $tail->exec($script);
            return true;
        }

        public function test_tail2($cnt = 20, $timing = 0.5)
        {
            if (!is_debug()) {
                return error("test_tail may not be used in production");
            }
            if (!IS_CLI) {
                return $this->query("demo_test_tail2", $cnt, $timing);
            }
            $p = new Util_Process();
            $proc = Util_Process_Tee::auto($p);
            $script = 'echo ' . date("r") . '; for (( C=' . $cnt . '0; C > 0; C-- )) ; do echo $C; usleep ' . ($timing * 10000) . '; done';
            $proc->exec($script);
            $script = 'echo ' . date("r") . '; for (( C=0; C < ' . $cnt . ' ; C++ )) ; do echo $C; usleep ' . ($timing * 10000) . '; done ; echo `date`';
            $proc->exec($script);
            $p = null;
            sleep(10);
        }

        public function test_tail3()
        {
            if (!is_debug()) {
                return error("test_tail may not be used in production");
            }
            $proc = Util_Process_Tee::auto(new Util_Process());
            $proc->exec("idontexist");
            $proc->log("Testing!");
            $proc->exec('whoami');
            return true;
        }

        public function test_error($message = 'generic error')
        {
            return error($message);
        }

        public function test1()
        {
            return Util_Process::exec('test.sh');
        }

        public function test_backend_error($message = 'abcdef')
        {
            if (!IS_CLI) {
                return $this->query('demo_test_backend_error', $message);
            }
            return error($message);

        }

        public function test_sudo()
        {
            if (!IS_CLI) {
                return $this->query('demo_test_sudo');
            }
            return Util_Process_Sudo::exec('echo whoami: `whoami`');
        }

        /**
         * array test_array(int[, int])
         * Demonstration test of returning an array.  If invoked through a SOAP
         * call, this would return a three tuple object, non-associative, handled
         * by the function interceptor class
         *
         * @param int $arg1 integer to add
         * @param int $arg2 integer to add
         * @return array associative array containing indicies ret1, ret2, and ret3
         * @privilege PRIVILEGE_ALL
         */
        public function test_array($arg1, $arg2 = null)
        {
            return array("ret1" => 80, "ret2" => 10, "ret3" => $arg2 + $arg1);
        }


        /**
         * bool test_exception([bool = false])
         * Tests exception handling of modules
         *
         * @privilege PRIVILEGE_ALL
         * @param bool $trigger whether to trigger an exception or just return true
         * @return bool Returns true if no exception to be thrown,
         *                      exception obj otherwise, which is derived from the Exception
         *                      class
         */
        public function test_exception($trigger = false)
        {
            if ($trigger) {
                return new SocketError("This is another test for objects");
            } else {
                return true;
            }
        }
        /* }}} */

        /**
         * int test_scalar(int, int)
         *
         * @privilege PRIVILEGE_ALL
         * @param int $arg1 integer to add
         * @param int $arg2 integer to add
         *                  Similar to test_array, but returns the scalar sum of $arg1 + $arg2
         * @return int sum of $arg1 + $arg2
         */
        public function test_scalar($arg1, $arg2)
        {
            return $arg1 + $arg2;
        }

        /* }}} */

        public function test_basic()
        {
            return "Hello World!";
        }

        public function test_account_metadata()
        {
            return $this->get_service_value('sendmail', 'mailserver');
        }
    }

?>
