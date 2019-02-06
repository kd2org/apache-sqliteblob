<?php

$args = $_SERVER['argv'];

if (empty($args[1]) || empty($args[2]))
{
	printf('Usage : %s SQLITE_BLOB SOURCE_FILE_OR_DIRECTORY' . PHP_EOL, $args[0]);
	die();
}

$db = new SQLite3($args[1]);

$has_blob_write = PHP_VERSION_ID >= 70200;

$db->exec('PRAGMA application_id = 0x01021234;');
$db->exec('CREATE TABLE IF NOT EXISTS blobs (mimetype TEXT, updated INT, filename TEXT, content BLOB);
	CREATE INDEX IF NOT EXISTS blobs_filename ON blobs (filename);');

$insert_stmt = $db->prepare('INSERT INTO blobs VALUES (:mimetype, :updated, :filename, zeroblob(:filesize));');
$update_stmt = $db->prepare('UPDATE blobs SET content = :content WHERE rowid = :id;');

if (is_file($args[2]))
{
	add_file($args[2]);
}
elseif (is_dir($args[2]))
{
	$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($args[2]));

	foreach ($iterator as $file)
	{
		$file = (string) $file;

		if (is_file($file))
		{
			add_file($file);
		}
	}
}
else
{
	die('Cannot read source file or directory' . PHP_EOL);
}

function add_file($file)
{
	global $db, $insert_stmt, $update_stmt, $has_blob_write;

	printf("Adding %s", $file);
	$insert_stmt->reset();
	$insert_stmt->bindValue(':mimetype', mime_content_type($file));
	$insert_stmt->bindValue(':updated', filemtime($file));
	$insert_stmt->bindValue(':filename', ltrim($file, './'));
	$insert_stmt->bindValue(':filesize', filesize($file));
	$insert_stmt->execute();
	echo ".";

	$id = $db->lastInsertRowID();

	if ($has_blob_write)
	{
		$blob = $db->openBlob('blobs', 'content', $id, 'main', SQLITE3_OPEN_READWRITE);
		$fp = fopen($file, 'rb');
		stream_copy_to_stream($fp, $blob);
		fclose($fp);
		fclose($blob);
		echo ".";
	}
	else
	{
		$update_stmt->bindValue(':id', $id);
		$update_stmt->bindValue(':content', file_get_contents($file), SQLITE3_BLOB);
		$update_stmt->execute();
		echo ".";
	}

	echo "\n";

	return true;
}