/*
	Anders Åsén, Anders.Asen@ltdalarna.se
	2013-10-29 
	2013-12-11 fix rivta v1 to address
	2014-02-10 fix multi requests problem, fix VP error log respons body read
	2014-05-16 fix location control
	2014-08-12 fix sopa faultstring read
*/

#include <stdio.h>
#include "apr_hash.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_strings.h"



#include "apr_buckets.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "util_filter.h"
#include "http_request.h"
#include "http_log.h"



#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"


module AP_MODULE_DECLARE_DATA rivta_module;

static const char ssl_io_buffer[] = "Rivta SSL buffer";
static ap_regex_t *LogicalAddressFilter;
static ap_regex_t *TagFilter;
static ap_regex_t *soapenvHeaderFilter1;
static ap_regex_t *soapenvHeaderFilter2;
static ap_regex_t *faultstringFilter1;
static ap_regex_t *faultstringFilter2;
static ap_regex_t *VPerrorFilter;

typedef struct {
	int enabled;      /* Enable or disable module RIVTA header in read*/
	int outfilterenable; /* Enable or disable RIVTA error out read*/
	int HttpStatusLevel;
} rivta_config;

struct rivtassl_buffer_ctx {
	apr_bucket_brigade *bb; /* temp buket brigade */
};

/*
Read incoming payload and set variabel
subprocess_env "rivta_to_hsaid"

If data contains "to" or "logicaladdress"
	set variabel
else
	look if header tag exist
	write to log
*/
static int setRivtaEnv(request_rec *r, char *data)
{
	ap_regmatch_t pmatch[1];
	apr_size_t matchSize;
	char *LogicalAddress;
	char *HSAID;
	int returnvalue = 0;

	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: data %s", data);
	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: LogicalAddressFilter %d", LogicalAddressFilter);
	
	//ap_regex_t *TagFilter;
	//ap_regex_t *LogicalAddressFilter;

	//LogicalAddressFilter = ap_pregcomp(r->pool, ":(to(.+)|to|logicaladdress(.+)|logicaladdress)>(.+)<\/(.+):(to|logicaladdress)", AP_REG_EXTENDED | AP_REG_ICASE);
	if (!ap_regexec(LogicalAddressFilter, data, 1, pmatch, 0))
	{
		//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: ap_regexec pmatch count: %d", pmatch[0].rm_so);

		if (pmatch[0].rm_so > -1)
		{
			//Copy to mem
			matchSize = pmatch[0].rm_eo - pmatch[0].rm_so;
			LogicalAddress = (char *)apr_pcalloc(r->pool, matchSize);
			LogicalAddress = apr_pstrndup(r->pool, data + pmatch[0].rm_so, matchSize);

			//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: LogicalAddress string: %s", LogicalAddress);

			//TagFilter = ap_pregcomp(r->pool, ">(.+)<", AP_REG_EXTENDED | AP_REG_ICASE);
			if (!ap_regexec(TagFilter, LogicalAddress, 1, pmatch, 0))
			{
				if (pmatch[0].rm_so > -1)
				{
					//Copy to mem
					matchSize = pmatch[0].rm_eo - pmatch[0].rm_so - 2;
					HSAID = (char *)apr_pcalloc(r->pool, matchSize);
					HSAID = apr_pstrndup(r->pool, LogicalAddress + pmatch[0].rm_so + 1, matchSize);
					apr_table_setn(r->subprocess_env, "rivta_to_hsaid", HSAID);
					//apr_table_setn(r->notes, "rivta_to_hsaid", HSAID);
					
					//apr_table_setn(r->headers_in, "x-rivta-to-hsaid-in", HSAID);
					//apr_table_setn(r->headers_out, "x-rivta-to-hsaid-out", HSAID);
					//apr_table_setn(r->subprocess_env, "rivta_to_hsaid", apr_itoa(r->pool, r->request_time));
					//APLOG_DEBUG
					//ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta: headers_in HSAID: %s", apr_table_get(r->headers_in, "x-rivta-to-hsaid"));
					//ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta: headers_out HSAID: %s", apr_table_get(r->headers_out, "x-rivta-to-hsaid"));

					ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta: Found HSAID: %s", HSAID);
					returnvalue = 1;
				}
			}
			else
			{
				ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta: no tags found!  'logical-' or 'to-' exist!");
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: %s", LogicalAddress);
			}
		}
		else
		{

			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:LogicalAddressFilter Reg seach return bad!");
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: %s", data);
		}
	}
	else
	{
		char *soapenvHeader;
		ap_regmatch_t soapenmatch1[1];
		ap_regmatch_t soapenmatch2[1];
		//ap_regmatch_t *soapenvHeaderFilter1 = ap_pregcomp(r->pool, ":Header>", AP_REG_EXTENDED | AP_REG_ICASE);
		//ap_regmatch_t *soapenvHeaderFilter2 = ap_pregcomp(r->pool, "<\/(.+):Header>", AP_REG_EXTENDED | AP_REG_ICASE);
		if (!ap_regexec(soapenvHeaderFilter1, data, 1, soapenmatch1, 0) && !ap_regexec(soapenvHeaderFilter2, data, 1, soapenmatch2, 0))
		{
			if (soapenmatch1[0].rm_so > -1)
			{
				//Copy to mem
				matchSize = soapenmatch2[0].rm_eo - soapenmatch1[0].rm_so;
				soapenvHeader = (char *)apr_pcalloc(r->pool, matchSize);
				soapenvHeader = apr_pstrndup(r->pool, data + soapenmatch1[0].rm_so, matchSize);

				ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta: no 'logical-' or 'to-' address found, sopa header exist!");
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: %s", soapenvHeader);
			}
			else
			{
				ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:soapenvHeader Reg seach return bad!");
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: %s", data);
			}
		}
		else
		{
			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta: No sopa header found!");
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: %s", data);
		}
	}
	return returnvalue;
}

/*
Read out payload and set variabel
subprocess_env "rivta_vp_error"
return true if error found

if contain VP status flag,  VP[0-9][0-9][0-9]
	set variabel
	write log
	return true
else 
	if contain "faultstring" tag
		set variabel
		write log
	else
		write log
*/
static int setRivtaErrorEnv(request_rec *r, char *data)
{

	ap_regmatch_t pmatch[1];
	apr_size_t matchSize;
	char *VPerror;
	char *faultstring;
	int returnvalue = 0;

	//ap_regex_t *TagFilter;
	//ap_regex_t *LogicalAddressFilter;

	if (!ap_regexec(VPerrorFilter, data, 1, pmatch, 0))
	{
		if (pmatch[0].rm_so > -1)
		{
			//Copy to mem
			matchSize = pmatch[0].rm_eo - pmatch[0].rm_so;
			VPerror = (char *)apr_pcalloc(r->pool, matchSize);
			VPerror = apr_pstrndup(r->pool, data + pmatch[0].rm_so, matchSize);


			apr_table_setn(r->subprocess_env, "rivta_vp_error", VPerror);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta VPerrorFilter: Found VP error: %s", VPerror); 
			returnvalue = 1;

		}
		else
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_rivta VPerrorFilter: Reg seach return bad!");
	}
	else
	{
		ap_regmatch_t faultstringmatch1[1];
		ap_regmatch_t faultstringmatch2[1];

		//if (!ap_regexec(config->faultstringFilter, data, 1, pmatch, 0))
		if (!ap_regexec(faultstringFilter1, data, 1, faultstringmatch1, 0) && !ap_regexec(faultstringFilter2, data, 1, faultstringmatch2, 0))
		{
			if (faultstringmatch1[0].rm_so > -1)
			{
				//Copy to mem
				matchSize = faultstringmatch2[0].rm_eo - faultstringmatch1[0].rm_so;
				faultstring = (char *)apr_pcalloc(r->pool, matchSize);
				faultstring = apr_pstrndup(r->pool, data + faultstringmatch1[0].rm_so, matchSize);

				//Copy to mem
				//matchSize = pmatch[0].rm_eo - pmatch[0].rm_so;
				//faultstring = (char *)apr_pcalloc(r->pool, matchSize);
				//faultstring = apr_pstrndup(r->pool, data + pmatch[0].rm_so, matchSize);

				//apr_table_setn(r->subprocess_env, "rivta_vp_error", VPerror);
				
				apr_table_setn(r->subprocess_env, "rivta_vp_error", "Error");
				//ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_rivta VPerrorFilter: ");
				ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_rivta VPerrorFilter: Found faultstring: %s", faultstring);

			}
			else
				ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_rivta VPerrorFilter: Reg seach return bad!");
		}
		else
		{
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "mod_rivta VPerrorFilter: No faultstring found!");
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta VPerrorFilter: %s", data);
		}
	}
	return returnvalue;
}

/*
	Copy from Apache code, modules\ssl\ssl_engine_io.c

	Change log info and add data parsing
*/
int ssl_io_buffer_fill(request_rec *r, apr_size_t maxlen) {
	conn_rec *c = r->connection;
	struct rivtassl_buffer_ctx *ctx;
	apr_bucket_brigade *tempb;
	apr_off_t total = 0; /* total length buffered */
	int eos = 0; /* non-zero once EOS is seen */

	/* Create the context which will be passed to the input filter;
	* containing a setaside pool and a brigade which constrain the
	* lifetime of the buffered data. */
	ctx = apr_palloc(r->pool, sizeof *ctx);
	ctx->bb = apr_brigade_create(r->pool, c->bucket_alloc);

	/* ... and a temporary brigade. */
	tempb = apr_brigade_create(r->pool, c->bucket_alloc);
	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ssl_io_buffer_fill: Run!");
	//ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, "filling buffer, max size " "%" APR_SIZE_T_FMT " bytes", maxlen);

	do {
		apr_status_t rv;
		apr_bucket *e, *next;

		/* The request body is read from the protocol-level input
		* filters; the buffering filter will reinject it from that
		* level, allowing content/resource filters to run later, if
		* necessary. */

		rv = ap_get_brigade(r->proto_input_filters, tempb, AP_MODE_READBYTES,
			APR_BLOCK_READ, 8192);
		if (rv) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02015)
				"could not read request body for SSL buffer");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/* Iterate through the returned brigade: setaside each bucket
		* into the context's pool and move it into the brigade. */
		for (e = APR_BRIGADE_FIRST(tempb);
			e != APR_BRIGADE_SENTINEL(tempb) && !eos; e = next) {
			const char *data;
			apr_size_t len;

			next = APR_BUCKET_NEXT(e);

			if (APR_BUCKET_IS_EOS(e)) {
				eos = 1;
			}
			else if (!APR_BUCKET_IS_METADATA(e)) {
				rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);

				//ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02016)"data buffer: %s", data);

				//apr_table_setn(r->subprocess_env, "X-My-Header-Insert", data);

				//if data is more then 500 char we suspect that we have read RIVTA header from payload
				if (len > 300)
				{
					//senda data to funtion
					setRivtaEnv(r, data);
				}

				if (rv != APR_SUCCESS) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
						APLOGNO(02016)
						"could not read bucket for SSL buffer");
					return HTTP_INTERNAL_SERVER_ERROR;
				}
				total += len;
			}

			rv = apr_bucket_setaside(e, r->pool);
			if (rv != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02017)
					"could not setaside bucket for SSL buffer");
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			APR_BUCKET_REMOVE(e);
			APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
		}

		//ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,"total of %" APR_OFF_T_FMT " bytes in buffer, eos=%d",total, eos);

		/* Fail if this exceeds the maximum buffer size. */
		if (total > maxlen) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02018)
				"request body exceeds maximum size (%"
				APR_SIZE_T_FMT
				") for SSL buffer", maxlen);
			return HTTP_REQUEST_ENTITY_TOO_LARGE;
		}

	} while (!eos);

	apr_brigade_destroy(tempb);

	/* After consuming all protocol-level input, remove all protocol-level
	* filters.  It should strictly only be necessary to remove filters
	* at exactly ftype == AP_FTYPE_PROTOCOL, since this filter will
	* precede all > AP_FTYPE_PROTOCOL anyway. */
	while (r->proto_input_filters->frec->ftype < AP_FTYPE_CONNECTION) {
		ap_remove_input_filter(r->proto_input_filters);
	}

	/* Insert the filter which will supply the buffered content. */
	ap_add_input_filter(ssl_io_buffer, ctx, r, c);

	return 0;
}

int ssl_hook_Access(request_rec *r)
{
	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ssl_hook_Access: %s %s", r->method, r->uri);
	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ssl_hook_Access: %d", strcmp(r->method, "POST"));
	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ssl_hook_Access: %s", strstr(r->uri, "rivtabp"));
	
	//get config
	rivta_config *config = (rivta_config *)ap_get_module_config(r->per_dir_config, &rivta_module);

	//read buffter if enalbe and post and uri is rivtabp
	if (config->enabled > 0 && strcmp(r->method, "POST") == 0 && strstr(r->uri, "rivtabp") != 0)
	{
		ssl_io_buffer_fill(r, (128 * 1024));
	}

	//Activate out filter if enable
	if (config->outfilterenable > 0)
	{
		ap_add_output_filter("rivta-output-filter", config, r, r->connection);
	}
	return DECLINED;
}

/*
Copy from Apache code, modules\ssl\ssl_engine_io.c
*/
static apr_status_t ssl_io_filter_buffer(ap_filter_t *f,
	apr_bucket_brigade *bb,
	ap_input_mode_t mode,
	apr_read_type_e block,
	apr_off_t bytes) {
	struct rivtassl_buffer_ctx *ctx = f->ctx;
	apr_status_t rv;
	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,"ssl_io_filter_buffer: Run!");

	//ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c,"read from buffered SSL brigade, mode %d, " "%" APR_OFF_T_FMT " bytes", mode, bytes);

	if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE) {
		return APR_ENOTIMPL;
	}

	if (APR_BRIGADE_EMPTY(ctx->bb)) {
		/* Suprisingly (and perhaps, wrongly), the request body can be
		* pulled from the input filter stack more than once; a
		* handler may read it, and ap_discard_request_body() will
		* attempt to do so again after *every* request.  So input
		* filters must be prepared to give up an EOS if invoked after
		* initially reading the request. The HTTP_IN filter does this
		* with its ->eos_sent flag. */

		APR_BRIGADE_INSERT_TAIL(bb,
			apr_bucket_eos_create(f->c->bucket_alloc));
		return APR_SUCCESS;
	}

	if (mode == AP_MODE_READBYTES) {
		apr_bucket *e;

		/* Partition the buffered brigade. */
		rv = apr_brigade_partition(ctx->bb, bytes, &e);
		if (rv && rv != APR_INCOMPLETE) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, f->c, APLOGNO(02019)
				"could not partition buffered SSL brigade");
			ap_remove_input_filter(f);
			return rv;
		}

		/* If the buffered brigade contains less then the requested
		* length, just pass it all back. */
		if (rv == APR_INCOMPLETE) {
			APR_BRIGADE_CONCAT(bb, ctx->bb);
		}
		else {
			apr_bucket *d = APR_BRIGADE_FIRST(ctx->bb);

			e = APR_BUCKET_PREV(e);

			/* Unsplice the partitioned segment and move it into the
			* passed-in brigade; no convenient way to do this with
			* the APR_BRIGADE_* macros. */
			APR_RING_UNSPLICE(d, e, link);
			APR_RING_SPLICE_HEAD(&bb->list, d, e, apr_bucket, link);

			APR_BRIGADE_CHECK_CONSISTENCY(bb);
			APR_BRIGADE_CHECK_CONSISTENCY(ctx->bb);
		}
	}
	else {
		/* Split a line into the passed-in brigade. */
		rv = apr_brigade_split_line(bb, ctx->bb, block, bytes);

		if (rv) {
			ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, f->c, APLOGNO(02020)
				"could not split line from buffered SSL brigade");
			ap_remove_input_filter(f);
			return rv;
		}
	}

	if (APR_BRIGADE_EMPTY(ctx->bb)) {
		apr_bucket *e = APR_BRIGADE_LAST(bb);

		/* Ensure that the brigade is terminated by an EOS if the
		* buffered request body has been entirely consumed. */
		if (e == APR_BRIGADE_SENTINEL(bb) || !APR_BUCKET_IS_EOS(e)) {
			e = apr_bucket_eos_create(f->c->bucket_alloc);
			APR_BRIGADE_INSERT_TAIL(bb, e);
		}

		//ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, f->c,"buffered SSL brigade exhausted");
		/* Note that the filter must *not* be removed here; it may be
		* invoked again, see comment above. */
	}

	return APR_SUCCESS;
}

/*
Out filter

if status > 400
	read payload 
	if we finde error code remove filter else keep it
else
	remove filter, we are done

pass to next filter

*/
static int rivta_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{

	apr_bucket *b;
	apr_status_t ret;
	rivta_config *config = f->ctx;
	int status;
	char *teststatus;
	teststatus = apr_table_get(f->r->headers_out, "http.status");

	if (teststatus != NULL)
	{
		status = atoi(teststatus);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "mod_rivta out filter: HttpStatusLevel %d", config->HttpStatusLevel);

		if (status >= config->HttpStatusLevel)
		{
			for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {

				const char *buf;
				apr_size_t nbytes;
				apr_status_t rv = apr_bucket_read(b, &buf, &nbytes, APR_BLOCK_READ);

				//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "mod_rivta out filter: %s: %d bytes", b->type->name, b->length);

				if (rv == APR_SUCCESS && b->length > 10)
				{

					//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "mod_rivta out filter: %s", buf);
					if (setRivtaErrorEnv(f->r, buf))
						ap_remove_output_filter(f);
				}


				//If we ever see an EOS, make sure to FLUSH.
				//if (APR_BUCKET_IS_EOS(b)) {
				//	apr_bucket *flush = apr_bucket_flush_create(f->c->bucket_alloc);
				//	APR_BUCKET_INSERT_BEFORE(b, flush);
				//}
			}
		}
		else
			ap_remove_output_filter(f);
		/*else
		{
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "mod_rivta out filter: http status is %d", status);
		}*/
	}

	return ap_pass_brigade(f->next, bb);
}


/*
Set config to enable
RIVTA read incoming message payload
*/
const char *set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
	//rivta_config *config = (rivta_config*)ap_get_module_config(cmd->server->module_config, &rivta_module);
	rivta_config    *config = (rivta_config *)cfg;

	if (config)
	{

		if (!strcasecmp(arg, "on")) {
			config->enabled = 1;
		}
		else config->enabled = 0;
	}

	return NULL;
}

/*
Set config to enable
RIVTA read outgoing message payload
*/
const char *set_enabled_outfilter(cmd_parms *cmd, void *cfg, const char *arg)
{
	//rivta_config *config = (rivta_config*)ap_get_module_config(cmd->server->module_config, &rivta_module);
	rivta_config    *config = (rivta_config *)cfg;

	if (config)
	{
		int temp = atoi(arg);

		if (!strcasecmp(arg, "on")) {
			config->outfilterenable = 1;
			config->HttpStatusLevel = 400;
		}
		else if (temp > -1)
		{
			config->outfilterenable = 1;
			config->HttpStatusLevel = temp;
		}
		else
		{
			config->outfilterenable = 0;
		}
	}

	return NULL;
}

/*
Set config to enable
RIVTA read outgoing message payload
*/
/*const char *set_HttpStatusLevel_outfilter(cmd_parms *cmd, void *cfg, const char *arg)
{
	//rivta_config *config = (rivta_config*)ap_get_module_config(cmd->server->module_config, &rivta_module);
	rivta_config    *config = (rivta_config *)cfg;

	if (config)
	{
		if (arg != NULL) {
			config->HttpStatusLevel = atoi(arg);
		}
		else config->HttpStatusLevel = 400;
	}

	return NULL;
}*/


/*static void *rivta_srv_config_create(apr_pool_t *p, server_rec *s) {
	rivta_config *config = (rivta_config*)apr_pcalloc(p, sizeof(rivta_config));

	config->enabled = 0;
	config->outfilterenable = 0;
	return config;
}*/

/*
Create config
*/
void* rivta_create_dir_conf(apr_pool_t *p, char *context)
{
	rivta_config *config = (rivta_config*)apr_pcalloc(p, sizeof(rivta_config));

	config->enabled = 0;
	config->outfilterenable = 0;
	config->HttpStatusLevel = 400;
	return config;
}

/*
Merge config for directorys
*/
void* rivta_merge_dir_conf(apr_pool_t *pool, void *BASE, void *ADD)
{
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	rivta_config    *base = (rivta_config *)BASE;
	rivta_config    *add = (rivta_config *)ADD;
	rivta_config    *conf = (rivta_config *)rivta_create_dir_conf(pool, "Merged configuration");
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	conf->enabled = (add->enabled == 0) ? base->enabled : add->enabled;
	conf->outfilterenable = (add->outfilterenable == 0) ? base->outfilterenable : add->outfilterenable;
	conf->HttpStatusLevel = (add->HttpStatusLevel > base->HttpStatusLevel) ? base->HttpStatusLevel : add->HttpStatusLevel;
	//conf->enabled = add->enabled ? add->enabled : base->enabled;
	//strcpy(conf->path, strlen(add->path) ? add->path : base->path);
	return conf;
}

/*
==============================================================================
The directive structure for our name tag:
==============================================================================
*/
static const command_rec        rivta_cmd[] =
{
	//AP_INIT_TAKE1("RivtaEnabled", set_enabled, NULL, RSRC_CONF, "Enable or disable rivta"),
	AP_INIT_TAKE1("RivtaEnabled", set_enabled, NULL, ACCESS_CONF, "Enable or disable rivta"),
	AP_INIT_TAKE1("RivtaEnabledError", set_enabled_outfilter, NULL, ACCESS_CONF, "Enable or disable rivta out error log, 'on' or int value (http status error)"),
	//AP_INIT_TAKE1("rivtaVersion", set_version, NULL, RSRC_CONF, "Only version 20(0) or 21(1), Default all(-1)"),
	//AP_INIT_RAW_ARGS("rivtaEnabled", set_enabled, NULL, OR_FILEINFO,"Enable or disable rivta"),
	{ NULL }
};

/*
==============================================================================
The hook registration function (also initializes the default config values):
==============================================================================
*/
static void rivta_register_hooks(apr_pool_t *pool)
{
	LogicalAddressFilter = ap_pregcomp(pool, ":(to|logicaladdress)(.+)<\/(.+):(to|logicaladdress)", AP_REG_EXTENDED | AP_REG_ICASE);
	TagFilter = ap_pregcomp(pool, ">(.+)<", AP_REG_EXTENDED | AP_REG_ICASE);
	soapenvHeaderFilter1 = ap_pregcomp(pool, ":Header>", AP_REG_EXTENDED | AP_REG_ICASE);
	soapenvHeaderFilter2 = ap_pregcomp(pool, "<\/(.+):Header>", AP_REG_EXTENDED | AP_REG_ICASE);
	//config->faultstringFilter = ap_pregcomp(pool, ":faultstring>(.+)<\/(.+):faultstring", AP_REG_EXTENDED | AP_REG_ICASE);
	faultstringFilter1 = ap_pregcomp(pool, "<faultstring>", AP_REG_EXTENDED | AP_REG_ICASE);
	faultstringFilter2 = ap_pregcomp(pool, "<\/faultstring>", AP_REG_EXTENDED | AP_REG_ICASE);
	VPerrorFilter = ap_pregcomp(pool, "VP[0-9][0-9][0-9]", AP_REG_EXTENDED | AP_REG_ICASE);


	//static const char *pre[] = { "mod_setenvif.c", "mod_deflate.c", "mod_headers.c", NULL };
	//config.enabled = 0;
	//config.version = -1;
	//config.data_body = "test";

	//ap_hook_header_parser(rivta_body_passer,NULL,NULL,APR_HOOK_FIRST);
	//ap_hook_insert_error_filter(rivta_error, NULL, NULL, APR_HOOK_MIDDLE);
	
	//ap_hook_pre_read_request(rivta_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);

	//ap_hook_post_read_request(rivta_post_read_request, NULL, NULL, APR_HOOK_FIRST);
	//ap_hook_pre_read_request(rivta_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);

	//ap_hook_fixups(rivta_fixups, NULL, NULL, APR_HOOK_FIRST);
	//ap_hook_header_parser(rivta_handler, pre, NULL, APR_HOOK_MIDDLE);
	//ap_hook_post_read_request(rivta_handler,NULL,NULL,APR_HOOK_FIRST);
	//ap_hook_handler(rivta_handler, NULL, NULL, APR_HOOK_FIRST);

	//ap_register_input_filter("rivta-input-filter", rivta_input_filter, NULL, AP_FTYPE_CONTENT_SET);
	//ap_register_input_filter("rivta-input-filter", rivta_input_filter, NULL, AP_FTYPE_PROTOCOL);

	ap_register_output_filter("rivta-output-filter", rivta_output_filter, NULL, AP_FTYPE_RESOURCE);
	ap_register_input_filter(ssl_io_buffer, ssl_io_filter_buffer, NULL, AP_FTYPE_PROTOCOL);
	ap_hook_check_access(ssl_hook_Access, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
	//APR_REGISTER_OPTIONAL_FN(rivta_body_data);
}
/*
==============================================================================
Our module name tag:
==============================================================================
*/
module AP_MODULE_DECLARE_DATA rivta_module =
{
	STANDARD20_MODULE_STUFF,
	rivta_create_dir_conf,               /* Per-directory configuration handler */
	rivta_merge_dir_conf,               /* Merge handler for per-directory configurations */
	NULL,               /* Per-server configuration handler */
	NULL,               /* Merge handler for per-server configurations */
	rivta_cmd, /* Any directives we may have for httpd */
	rivta_register_hooks      /* Our hook registering function */
};