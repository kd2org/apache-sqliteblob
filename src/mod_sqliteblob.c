/* Include the required headers from httpd */
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"

#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "apr_hash.h"
#include "apr_base64.h"
//#include "apr_dbd.h"
//#include "apr_optional.h"
#include "http_log.h"
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_tables.h>
#include "util_script.h"

#include <sqlite3.h>

/* Define prototypes of our functions in this module */
static void register_hooks(apr_pool_t *pool);
static int sqliteblob_handler(request_rec *r);

/* Define our module as an entity and assign a function for registering hooks  */

module AP_MODULE_DECLARE_DATA   sqliteblob_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,            // Per-directory configuration handler
    NULL,            // Merge handler for per-directory configurations
    NULL,            // Per-server configuration handler
    NULL,            // Merge handler for per-server configurations
    NULL,            // Any directives we may have for httpd
    register_hooks   // Our hook registering function
};


/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool)
{
    /* Hook the request handler */
    ap_hook_handler(sqliteblob_handler, NULL, NULL, APR_HOOK_LAST);
}


static int sqliteblob_handler(request_rec *r)
{
    int rc, exists;
    apr_finfo_t finfo;
    apr_table_t* GET;

    char *filename;

    int buf_len = 1024;
    int i = 0;
    char buffer[buf_len];
    sqlite3 *db;

    const char *appid_sql = "PRAGMA application_id;";
    int appid;

    time_t updated = 0;
    char *mimetype = NULL;

    sqlite3_blob *blob = NULL;

    // Check that the "sqliteblob-handler" handler is being called.
    if (!r->handler || strcmp(r->handler, "sqliteblob-handler")) return (DECLINED);

    // Figure out which file is being requested
    filename = apr_pstrdup(r->pool, r->filename);

    // Figure out if the file we request a sum on exists and isn't a directory
    rc = apr_stat(&finfo, filename, APR_FINFO_MIN, r->pool);
    if (rc == APR_SUCCESS) {
        exists =
        (
            (finfo.filetype != APR_NOFILE)
        &&  !(finfo.filetype & APR_DIR)
        );
        if (!exists) return HTTP_NOT_FOUND; // Return a 404 if not found.
    }
    // If apr_stat failed, we're probably not allowed to check this file.
    else return HTTP_FORBIDDEN;

    // Parse the GET and, optionally, the POST data sent to us

    ap_args_to_table(r, &GET);

    const char *id = apr_table_get(GET, "id");

    if (NULL == id) return HTTP_BAD_REQUEST;

    int rowid = atoi(id);

    // Open DB
    rc = sqlite3_open(filename, &db);

    if (rc) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01471) "SQLite: Can't open %s: %s", filename, sqlite3_errmsg(db));
        sqlite3_close(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, appid_sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01471) "SQLite query error on %s: %s", filename, sqlite3_errmsg(db));
        sqlite3_close(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        appid = sqlite3_column_int(stmt, 0);
    }

    // 0x01021234
    if (appid != 16912948) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01471) "This file is not a SQLite Blob store: %s", filename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rc != SQLITE_DONE) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01471) "SQLite done error on %s: %s", filename, sqlite3_errmsg(db));
        sqlite3_close(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    sqlite3_finalize(stmt);

    const char * sql = sqlite3_mprintf("SELECT updated, mimetype FROM blobs WHERE rowid = %d;", rowid);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01471) "SQLite error in %s: %s", filename, sqlite3_errmsg(db));
        sqlite3_close(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        updated = sqlite3_column_int(stmt, 0);
        mimetype = (char *) sqlite3_column_text(stmt, 1);
    }

    if (mimetype == NULL) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01471) "No rowid %d found in: %s", rowid, filename);
        return HTTP_NOT_FOUND;
    }

    sqlite3_finalize(stmt);

    // Open blob
    rc = sqlite3_blob_open(db, "main", "blobs", "content", rowid, 0, &blob);

    if (rc != SQLITE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01471) "SQLite blob open error: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    int filesize;
    filesize = sqlite3_blob_bytes(blob);

    // Set the appropriate content type
    ap_set_content_type(r, mimetype);
    ap_set_content_length(r, filesize);

    // Set last modified header (updated_time is a UNIX timestamp, ap_update_mtime expects time in microseconds)
    ap_update_mtime(r, updated*1000000);
    ap_set_last_modified(r);

    // Read the blob

    while (i < filesize) {
        if (i + buf_len > filesize) {
            buf_len = filesize - i;
        }

        rc = sqlite3_blob_read(blob, buffer, buf_len, i);

        if (rc != SQLITE_OK) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01471) "SQLite blob reading error: %s", sqlite3_errmsg(db));
            sqlite3_close(db);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        ap_rputs(buffer, r);
        i += buf_len;
    }

    sqlite3_close(db);

    // Let Apache know that we responded to this request.
    return OK;
}