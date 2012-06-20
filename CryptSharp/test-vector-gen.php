#!/usr/bin/php
<?php
$f = fopen('TestVectors.txt', "wb");
for ($i = 0; $i < 100; $i ++)
{
	for ($j = 0; $j < 4; $j ++)
	{
		$randomPW = '';
		for ($k = 0; $k < $i; $k ++) { $randomPW .= chr(mt_rand(45, 127)); }
		
		$salt = sprintf('$2a$%02d$%s', mt_rand(4, 8),
			strtr(str_replace(
			'=', '', base64_encode(openssl_random_pseudo_bytes(16))
			),
			'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
			'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'));
		$crypted = crypt($randomPW, $salt);
		fwrite($f, "$randomPW,$crypted\r\n");
	}
}
fclose($f);
?>

