# Apache SQLite Blob module

This module provides a handler to send file contents from a SQLite file instead
of the filesystem.

The idea is to use a SQLite database file as a file storage. This is specially
useful if you have a lot of small files, eg. images.

The idea is similar to what Facebook does with Haystack :

* [Paper (PDF)](https://www.usenix.org/event/osdi10/tech/full_papers/Beaver.pdf)
* [Needle in a haystack: efficient storage of billions of photos](https://code.fb.com/core-data/needle-in-a-haystack-efficient-storage-of-billions-of-photos/)

It's just adapted to a smaller scale, without the need of running specialized
daemons.

Instead of having millions of files scattered in the filesystem, you would
store your files directly in a SQLite file.

## Pros and cons

Compared to an object storage, this approach requires much less overhead. There
is no need to run new daemons or complex setups, just insert files to the
SQLite database.

SQLite also provides handy built-ins, for example you can just delete files
from the database and then just use `VACUUM` to have SQLite clean up the
database from old file fragments.

It's also easy to store extra data, just add columns to the table!

Finally, it's very hard to actually corrupt a SQLite database.

The major con will be that it's probably not as efficient as a dedicated
service, and you might reach limits faster if your data set grows to be
very large.

## Performance

According to my own benchmarks, HTTP performance is about 2 to 5% below serving
regular files from the filesystem.

I experimented successfully with databases up to 10 GB containing about a dozen
million files. It worked OK, but I recommend to not exceed 100,000 files or
1 GB per SQLite database to keep things simple and fast (just use
partitioning, or sharding, to keep separate database files).

Note that it's not a hard limit, and SQLite can manage up to 8 TB of data in a
single database using its default settings, or up to 140 TB if you change its
page size setting. This is just a suggestion to keep things simple for you, as
it may take a while to do a VACUUM or other heavy operation on a database once
it gets very large.

## Installation

On Debian/Ubuntu just start by installing the `apache2-dev` package:

```
	apt install apache2-dev
```

Usually, just running `make` from the src directory will be enough:

```
	cd src/
	make
```

If you want to install the module in the Apache directory you can also run
`sudo make install`. This will also enable the module in Apache2 config.

Last thing to do is to reload the Apache config using `sudo apache2ctl graceful`.

## Configuration

Just enable the correct handler in your configuration for the files you want to
handle. Here is an example:

```
	<Directory /var/www/images>
		# Treat filenames ending with ".img" as SQLite blob database
		AddHandler sqliteblob .img
		RewriteEngine On
		RewriteRule /img/((\d)\d+)\.jpg /store_$2.img?id=$1
	</Directory>
```



## Creation of the database

To be accepted by this module, the SQLite database file must have an
`application_id` set to `0x01021234`. To do that just run:

```
PRAGMA application_id = 0x01021234;
```

This is just so it's not possible to use this module to query any random
SQLite database.

The database must have a table named `blob` containing at least those columns:

* `hash` (TEXT), containg the hash identifier of the file
* `mimetype` (TEXT), a string containing the file mimetype (eg. `image/jpeg`)
* `updated` (INTEGER), a UNIX timestamp of the last change to the file (this is
  used for the `Last-Modified` HTTP header)
* `content` (BLOB), containing the file itself

You can add more columns if you wish, but if any of these columns is missing,
a 500 error will be returned.

Here is a simple example of a basic blob database file:

```sql
PRAGMA application_id = 0x01021234;
CREATE TABLE IF NOT EXISTS blobs (
	hash TEXT NOT NULL PRIMARY KEY,
	mimetype TEXT,
	updated INT,
	content BLOB
);
```

Then you can just insert files to the database. It is recommanded that you use
`sqlite3_blob_open` to write the blob to the database, as it is faster than
using binded parameters.

An example PHP script lies in `src/make-blob-archive.php` to create blob
archives.

`php make-blob-archive.php test.images images/` will append all files from the
`images` directory to the `test.images` blob archive.

## Thanks

This module was written thanks to the help of docs from [Apache](https://httpd.apache.org/docs/2.4/developer/modguide.html)