#!/usr/bin/php
<?php
echo 'Salt: '; $salt = trim(fgets(STDIN));
echo crypt('Hello World!', $salt);
?>

