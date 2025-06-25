<?php

$fn = "cert.json";
$file = __DIR__ . '/cert_clientes/' . $fn;
//echo("file: " . $file . "\r\n");
$p1 = strrpos($file, ".");
$fpBase = substr($file, 0, $p1);
$fpExt = substr($file, $p1);
for ($i=1; $i<10000; $i++) {
        $fp = $fpBase . "_" . $i . $fpExt;
        //echo("fp: " . $fp . "\n");
        if (!file_exists($fp))
        	break;
}


$input = fopen('php://input', 'rb');

//while (!feof($input))
//    fwrite($outf, fread($dta, 102400));
while (($dta=fread($input, 65536))) {
	if (!isset($outf)) {
		$outf = fopen($fp, 'wb');
		if (!is_resource($outf)) {
			echo "Could not open {$outf} for writting.";
			return;
		}
	}
	fwrite($outf, $dta);
}
fclose($input);
if (isset($outf))
	fclose($outf);

//echo("OK");

?>

