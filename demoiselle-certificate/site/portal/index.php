<?php

$pointer  = opendir(getcwd());

$folders = array();
while ($item = readdir($pointer)) {
	if (is_dir($item) && $item!="." && $item!="..") {
		$folders[filemtime($item)] = $item;
	}
}

krsort($folders);

foreach($folders as $folder){
	$recent=$folder;
	break;
}

header("Location: $recent");

?>










<script type="text/javascript" src="http://demoiselle.sf.net/script/analytic.js"></script>
