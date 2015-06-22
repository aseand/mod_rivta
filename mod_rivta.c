/*
	Anders Åsén, Anders.Asen@ltdalarna.se
	2013-10-29 
	2013-12-11 fix rivta v1 to address
	2014-02-10 fix multi requests problem, fix VP error log respons body read
	2014-05-16 fix location control
	2014-08-12 fix sopa faultstring read
	2015-02-16	fix add support for out filter to change to soap:Fault format, text/xml;charset=UTF-8
				add support for multiple values "to" or "logicaladdress", on split #, rivta_to_hsaid = full string, rivta_to_hsaid{n} ...
				add support for rivta_namespace base on "Responder" end in rivta file
				fix read large request then 128*1024 bytes
				fix read only ones for soap header

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
static ap_regex_t *ResponderFilter;
static ap_regex_t *soapenvHeaderFilter1;
static ap_regex_t *soapenvHeaderFilter2;
static ap_regex_t *faultstringFilter1;
static ap_regex_t *faultstringFilter2;
static ap_regex_t *VPerrorFilter;

typedef struct {
	int enabled;      /* Enable or disable module RIVTA header in read*/
	int outfilterenable; /* Enable or disable RIVTA error out read*/
	int HttpStatusLevel; /* min http status level */
	int enabledToSoapFault; /* format to soap fault*/
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
static int setRivtaEnv(request_rec *r, char *data, apr_size_t DataLen)
{
	ap_regmatch_t pmatch[1];
	apr_size_t matchSize;
	char *NameSpace;
	//char *LogicalAddress;
	char *HSAID;
	char *HSAIDTmp;
	char *buf = "rivta_to_hsaid ";
	int returnvalue = 0;
	int index = 0;
	int Sindex = 0;
	int Eindex = 0;
	int error = 0;
	//int DataLen = strlen(data);
	size_t tempLen = 0;
	int count = 0;
	
	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: DataLen %d", DataLen);
	//ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:SetRivtaEnv: clength %d remaining %d", r->clength, r->remaining);
	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: data %s", data);
	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: LogicalAddressFilter %d", LogicalAddressFilter);
	
	if (ap_regexec(ResponderFilter, data, 1, pmatch, 0) == 0)
	{
		if (pmatch[0].rm_so < DataLen)
		{
			index = pmatch[0].rm_so;
			while (data[index] != '\"')
			{
				index--;
				if (index <= 0 || data[index] == ' ')
				{
					error = 1;
					break;
				}
			}
		}
		else
		{
			error = 1;
		}

		if (!error)
		{
			//Copy to mem 
			matchSize = pmatch[0].rm_eo - index - 2;
			NameSpace = (char *)apr_pcalloc(r->pool, matchSize);
			NameSpace = apr_pstrndup(r->pool, data + index + 1, matchSize);
			apr_table_setn(r->subprocess_env, "rivta_namespace", NameSpace);
			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:rivta_namespace: Found NameSpace: %s", NameSpace);
		}
		else
		{
			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:rivta_namespace: Index out of bounds");
			//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta:rivta_namespace: %s", data);
		}
	}
	else
	{
		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:rivta_namespace: NameSpace Not found");
		//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta:rivta_namespace: %s", data);
	}

	//LogicalAddressFilter = ap_pregcomp(r->pool, ":(to(.+)|to|logicaladdress(.+)|logicaladdress)>(.+)<\/(.+):(to|logicaladdress)", AP_REG_EXTENDED | AP_REG_ICASE);
	if (ap_regexec(LogicalAddressFilter, data, 1, pmatch, 0) == 0)
	{
		//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: ap_regexec pmatch count: %d", pmatch[0].rm_so);
		if (pmatch[0].rm_so < DataLen)
		{
			index = pmatch[0].rm_eo;
			while (data[index] != '<')
			{
				if (data[index] == '>')
					Sindex = index + 1;
				index++;
				if (index >= DataLen)
				{
					error = 1;
					break;
				}
			}
		}
		else
		{
			error = 1;
		}

		if (!error)
		{
			matchSize = index - Sindex;
			HSAID = (char *)apr_pcalloc(r->pool, matchSize);
			HSAID = apr_pstrndup(r->pool, data + Sindex, matchSize);

			apr_table_setn(r->subprocess_env, "rivta_to_hsaid", HSAID);
			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:rivta_to_hsaid: Found HSAID: %s", HSAID);

			tempLen = strlen(HSAID);
			index = 0;
			count = 1;
			Sindex = 0;
			while (index < tempLen)
			{
				if (HSAID[index] == '#')
				{
					if (Sindex > -1)
					{
						matchSize = index - Sindex;
						itoa(count, buf + 14, 10);
						if (matchSize > 0)
						{
							HSAIDTmp = (char *)apr_pcalloc(r->pool, matchSize);
							HSAIDTmp = apr_pstrndup(r->pool, HSAID + Sindex, matchSize);

							apr_table_setn(r->subprocess_env, buf, HSAIDTmp);
							ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:%s: Found HSAID: %s", buf, HSAIDTmp);
						}
						else
							ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:%s: Len is 0", buf);
					}
					Sindex = index + 1;
					count++;
					//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta:rivta_to_hsaid: Found# index %d Sindex %d", index, Sindex);
				}
				index++;
			}
			//last
			if (Sindex > 0)
			{
				matchSize = index - Sindex;
				itoa(count, buf + 14, 10);
				if (matchSize > 0)
				{
					HSAIDTmp = (char *)apr_pcalloc(r->pool, matchSize);
					HSAIDTmp = apr_pstrndup(r->pool, HSAID + Sindex, matchSize);

					apr_table_setn(r->subprocess_env, buf, HSAIDTmp);
					ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:%s: Found HSAID: %s", buf, HSAIDTmp);
				}
				else
					ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:%s: Len is 0", buf);
			}
		}
		else
		{
			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:rivta_to_hsaid: Index out of bounds");
			//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: %s", data);
		}
	}
	else
	{
		char *soapenvHeader;
		ap_regmatch_t soapenmatch1[1];
		ap_regmatch_t soapenmatch2[1];
		//ap_regmatch_t *soapenvHeaderFilter1 = ap_pregcomp(r->pool, ":Header>", AP_REG_EXTENDED | AP_REG_ICASE);
		//ap_regmatch_t *soapenvHeaderFilter2 = ap_pregcomp(r->pool, "<\/(.+):Header>", AP_REG_EXTENDED | AP_REG_ICASE);
		if (ap_regexec(soapenvHeaderFilter1, data, 1, soapenmatch1, 0) == 0 && ap_regexec(soapenvHeaderFilter2, data, 1, soapenmatch2, 0) == 0)
		{
			if (soapenmatch1[0].rm_so < DataLen && soapenmatch2[0].rm_so < DataLen)
			{
				//Copy to mem
				matchSize = soapenmatch2[0].rm_eo - soapenmatch1[0].rm_so;
				soapenvHeader = (char *)apr_pcalloc(r->pool, matchSize);
				soapenvHeader = apr_pstrndup(r->pool, data + soapenmatch1[0].rm_so, matchSize);

				ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:soapenvHeader: no 'logical-' or 'to-' address found, sopa header exist!");
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: %s", soapenvHeader);
			}
			else
			{
				ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:rivta_to_hsaid: Index out of bounds");
				//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_rivta: %s", data);
			}
		}
		else
		{
			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta:soapenvHeader: No sopa header found!");
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
			returnvalue = -1;
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
	int readDone = 0;
	//int DataLen = 0;

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
			apr_size_t len;

			next = APR_BUCKET_NEXT(e);

			if (APR_BUCKET_IS_EOS(e)) {
				eos = 1;
			}
			else if (!APR_BUCKET_IS_METADATA(e)) {
				char *dataTemp;
				rv = apr_bucket_read(e, &dataTemp, &len, APR_BLOCK_READ);
				if (rv != APR_SUCCESS) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
						APLOGNO(02016)
						"could not read bucket for SSL buffer");
					return HTTP_INTERNAL_SERVER_ERROR;
				}
				
				//ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(02016)"data buffer: %s", data);

				//apr_table_setn(r->subprocess_env, "X-My-Header-Insert", data);

				//if data is more then 300 char we suspect that we have read RIVTA header from payload
				//read only ones				
				if (!readDone && len > 300)
				{
					//copy data only len of data bucket read
					//char *data;
					//data = (char *)apr_pcalloc(r->pool, len);
					//data = apr_pstrndup(r->pool, dataTemp, len);
					//ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "mod_rivta: %s", data);

					readDone = 1;
					setRivtaEnv(r, dataTemp, len);
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

		//ignore max, another moduel will hit max and fail 
		//Fail if this exceeds the maximum buffer size. */
		/*if (total > maxlen) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02018)
				"request body exceeds maximum size (%"
				APR_SIZE_T_FMT
				") for SSL buffer", maxlen);
			return HTTP_REQUEST_ENTITY_TOO_LARGE;
		}*/

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


	//get config
	rivta_config *config = (rivta_config *)ap_get_module_config(r->per_dir_config, &rivta_module);


	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ssl_hook_Access: %s %s", r->method, r->uri);
	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ssl_hook_Access: %d", strcmp(r->method, "POST"));
	//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ssl_hook_Access: %s", strstr(r->uri, "rivtabp"));
	//read buffter if enalbe and post and uri is rivtabp


	if (config->enabled > 0 && strcmp(r->method, "POST") == 0 && apr_table_get(r->headers_in, "SOAPAction") != NULL)//strstr(r->uri, "rivtabp") != 0)
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
	//apr_status_t ret;
	rivta_config *config = f->ctx;
	int status,returnvalue;
	//char *teststatus;
	//char *data;
	apr_bucket *SoapBegin, *SoapEnd;
	//teststatus = apr_table_get(f->r->headers_out, "http.status");
	//ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, "mod_rivta out filter: ");
	
	//if (teststatus != NULL)
	//{
		//status = atoi(teststatus);
		status = f->r->status;
		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, "mod_rivta out filter status: %d >= %d", config->HttpStatusLevel, status);

		if (status >= config->HttpStatusLevel)
		{
			for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {

				char *buf;
				apr_size_t nbytes;
				apr_status_t rv = apr_bucket_read(b, &buf, &nbytes, APR_BLOCK_READ);

				//ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, "mod_rivta out filter: %s: %d bytes", b->type->name, b->length);

				if (rv == APR_SUCCESS && b->length > 10)
				{

					//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "mod_rivta out filter B: %s", buf);
					//
					// -1 = no SOAP error
					// 0 = no VP error
					// 1 = VP error
					returnvalue = setRivtaErrorEnv(f->r, buf);
					//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "mod_rivta out filter return %d", returnvalue);
					if (returnvalue)
					{
						ap_remove_output_filter(f);
					}
					//ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "mod_rivta out filter: %d %d", returnvalue, config->enabledToSoapFault);
					if (returnvalue == -1 && config->enabledToSoapFault > 0)
					{
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, "mod_rivta out filter add soap env tags");
						//apr_table_unset(f->r->headers_out, "Content-Length");
						ap_set_content_type(f->r, "text/xml;charset=UTF-8");
						//Format to SOAP env
						//APR_BUCKET_REMOVE(b);
						SoapBegin = apr_bucket_transient_create("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Header/><soapenv:Body><soap:Fault xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><faultcode>soap:Server</faultcode><faultstring>", 221, f->c->bucket_alloc);
						SoapEnd = apr_bucket_transient_create("</faultstring></soap:Fault></soapenv:Body></soapenv:Envelope>", 61, f->c->bucket_alloc);
						APR_BUCKET_INSERT_BEFORE(b, SoapBegin);
						APR_BUCKET_INSERT_AFTER(b, SoapEnd);
						rv = ap_pass_brigade(f->next, bb);

						//apr_brigade_cleanup(SoapBegin);
						//apr_brigade_cleanup(SoapEnd);

						ap_remove_output_filter(f);
						return rv;
					}

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
	//}

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

const char *set_enabledToSoapFault(cmd_parms *cmd, void *cfg, const char *arg)
{
	//rivta_config *config = (rivta_config*)ap_get_module_config(cmd->server->module_config, &rivta_module);
	rivta_config    *config = (rivta_config *)cfg;

	if (config)
	{

		if (!strcasecmp(arg, "on")) {
			config->enabledToSoapFault = 1;
		}
		else config->enabledToSoapFault = 0;
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
Create config
*/
void* rivta_create_dir_conf(apr_pool_t *p, char *context)
{
	rivta_config *config = (rivta_config*)apr_pcalloc(p, sizeof(rivta_config));

	config->enabled = 0;
	config->outfilterenable = 0;
	config->HttpStatusLevel = 400;
	config->enabledToSoapFault = 0;
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
	conf->enabledToSoapFault = (add->enabledToSoapFault == 0) ? base->enabledToSoapFault : add->enabledToSoapFault;
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
	AP_INIT_TAKE1("RivtaEnabled", set_enabled, NULL, ACCESS_CONF, "Enable or disable rivta"),
	AP_INIT_TAKE1("RivtaEnabledError", set_enabled_outfilter, NULL, ACCESS_CONF, "Enable or disable rivta out error log, 'on' or int value (http status error)"),
	AP_INIT_TAKE1("RivtaEnabledToSoapFault", set_enabledToSoapFault, NULL, ACCESS_CONF, "Enable or disable message to SoapFault format"),
	{ NULL }
};

/*
==============================================================================
The hook registration function (also initializes the default config values):
==============================================================================
*/
static void rivta_register_hooks(apr_pool_t *pool)
{
	//LogicalAddressFilter = ap_pregcomp(pool, ":(to|logicaladdress)(.+)<\/(.+):(to|logicaladdress)", AP_REG_EXTENDED | AP_REG_ICASE);
	LogicalAddressFilter = ap_pregcomp(pool, ":(to|logicaladdress)", AP_REG_EXTENDED | AP_REG_ICASE);
	//NameSpaceFilter = ap_pregcomp(pool, "xmlns:urn(|[1-9])=\"(.+?)\"", AP_REG_EXTENDED | AP_REG_ICASE);
	//xmlnsName = ap_pregcomp(pool, ":Body>(.+?)<(.+?):", AP_REG_EXTENDED | AP_REG_ICASE);
	ResponderFilter = ap_pregcomp(pool, "Responder:[0-9]\"", AP_REG_EXTENDED | AP_REG_ICASE);
	//NameSpaceFilter2 = ap_pregcomp(pool, "xmlns:(.+?)2=\"(.+?)\"", AP_REG_EXTENDED | AP_REG_ICASE);
	//TagFilter = ap_pregcomp(pool, ">(.+)<", AP_REG_EXTENDED | AP_REG_ICASE);
	//QuotaFilter = ap_pregcomp(pool, "\"(.+)\"", AP_REG_EXTENDED | AP_REG_ICASE);
	soapenvHeaderFilter1 = ap_pregcomp(pool, ":Header>", AP_REG_EXTENDED | AP_REG_ICASE);
	soapenvHeaderFilter2 = ap_pregcomp(pool, "<\/(.+):Header>", AP_REG_EXTENDED | AP_REG_ICASE);
	//config->faultstringFilter = ap_pregcomp(pool, ":faultstring>(.+)<\/(.+):faultstring", AP_REG_EXTENDED | AP_REG_ICASE);
	faultstringFilter1 = ap_pregcomp(pool, "<faultstring>", AP_REG_EXTENDED | AP_REG_ICASE);
	faultstringFilter2 = ap_pregcomp(pool, "<\/faultstring>", AP_REG_EXTENDED | AP_REG_ICASE);
	VPerrorFilter = ap_pregcomp(pool, "VP[0-9][0-9][0-9]", AP_REG_EXTENDED | AP_REG_ICASE);

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