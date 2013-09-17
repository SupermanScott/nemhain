/**
 *
 * Copyright (c) 2013, Scott Reynolds.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *     * Neither the name of the Nehmain Project, Scott Reynolds, nor the names
 *       of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "parser.h"
#include <stdlib.h>
#include "dbg.h"
#include "cJSON/cJSON.h"

#define LEN(AT, FPC) (FPC - buffer - parser->AT)
#define MARK(M,FPC) (parser->M = (FPC) - buffer)
#define PTR_TO(F) (buffer + parser->F)
#define TO_NUMBER(F, FPC) (parser->F = atoi(bstr2cstr(blk2bstr((buffer + parser->mark), (FPC - buffer - parser->mark)), (FPC - buffer - parser->mark))))
#define TO_FLOAT(F, FPC) (parser->F = atof(bstr2cstr(blk2bstr((buffer + parser->mark), (FPC - buffer - parser->mark)), (FPC - buffer - parser->mark))))

struct tagbstring PARSER_JAN		= bsStatic ("Jan");
struct tagbstring PARSER_FEB		= bsStatic ("Feb");
struct tagbstring PARSER_MAR		= bsStatic ("Mar");
struct tagbstring PARSER_APR		= bsStatic ("Apr");
struct tagbstring PARSER_MAY		= bsStatic ("May");
struct tagbstring PARSER_JUN		= bsStatic ("Jun");
struct tagbstring PARSER_JUL		= bsStatic ("Jul");
struct tagbstring PARSER_AUG		= bsStatic ("Aug");
struct tagbstring PARSER_SEP		= bsStatic ("Sep");
struct tagbstring PARSER_OCT		= bsStatic ("Oct");
struct tagbstring PARSER_NOV		= bsStatic ("Nov");
struct tagbstring PARSER_DEC		= bsStatic ("Dec");

struct tagbstring SEVERITY_EMERG	= bsStatic ("EMERGENCY");
struct tagbstring SEVERITY_ALERT	= bsStatic ("ALERT");
struct tagbstring SEVERITY_CRIT		= bsStatic ("CRITICAL");
struct tagbstring SEVERITY_ERR		= bsStatic ("ERROR");
struct tagbstring SEVERITY_WARN		= bsStatic("WARNING");
struct tagbstring SEVERITY_NOTICE	= bsStatic("NOTICE");
struct tagbstring SEVERITY_INFO		= bsStatic ("INFORMATION");
struct tagbstring SEVERITY_DEBUG	= bsStatic ("DEBUG");

struct tagbstring FACILITY_KERN		= bsStatic("KERN");
struct tagbstring FACILITY_USER		= bsStatic("USER");
struct tagbstring FACILITY_MAIL		= bsStatic("MAIL");
struct tagbstring FACILITY_DAEMON	= bsStatic("DAEMON");
struct tagbstring FACILITY_AUTH		= bsStatic("AUTH");
struct tagbstring FACILITY_SYSLOG	= bsStatic("SYSLOG");
struct tagbstring FACILITY_LPR		= bsStatic("LPR");
struct tagbstring FACILITY_NEWS		= bsStatic("NEWS");
struct tagbstring FACILITY_UUCP		= bsStatic("UUCP");
struct tagbstring FACILITY_CLOCK	= bsStatic("CLOCK"); // @TODO: yuck
struct tagbstring FACILITY_AUTHPRIV	= bsStatic("AUTHPRIV");
struct tagbstring FACILITY_FTP		= bsStatic("FTP");
struct tagbstring FACILITY_NTP		= bsStatic("NTP");
struct tagbstring FACILITY_AUDIT	= bsStatic("AUDIT");
struct tagbstring FACILITY_LOGALERT	= bsStatic("LOGALERT");
struct tagbstring FACILITY_CRON		= bsStatic("CRON");
struct tagbstring FACILITY_LOCAL0	= bsStatic("LOCAL0");
struct tagbstring FACILITY_LOCAL1	= bsStatic("LOCAL1");
struct tagbstring FACILITY_LOCAL2	= bsStatic("LOCAL2");
struct tagbstring FACILITY_LOCAL3	= bsStatic("LOCAL3");
struct tagbstring FACILITY_LOCAL4	= bsStatic("LOCAL4");
struct tagbstring FACILITY_LOCAL5	= bsStatic("LOCAL5");
struct tagbstring FACILITY_LOCAL6	= bsStatic("LOCAL6");
struct tagbstring FACILITY_LOCAL7	= bsStatic("LOCAL7");

char* syslog_parser_facility_name(syslog_parser *parser)
{
    if (parser->facility == KERN) {
	return bdata(&FACILITY_KERN);
    }
    if (parser->facility == USER) {
	return bdata(&FACILITY_USER);
    }
    if (parser->facility == MAIL) {
	return bdata(&FACILITY_MAIL);
    }
    if (parser->facility == DAEMON) {
	return bdata(&FACILITY_DAEMON);
    }
    if (parser->facility == AUTH) {
	return bdata(&FACILITY_AUTH);
    }
    if (parser->facility == SYSLOG) {
	return bdata(&FACILITY_SYSLOG);
    }
    if (parser->facility == LPR) {
	return bdata(&FACILITY_LPR);
    }
    if (parser->facility == NEWS) {
	return bdata(&FACILITY_NEWS);
    }
    if (parser->facility == UUCP) {
	return bdata(&FACILITY_UUCP);
    }
    if (parser->facility == CLOCK) {
	return bdata(&FACILITY_CLOCK);
    }
    if (parser->facility == AUTHPRIV) {
	return bdata(&FACILITY_AUTHPRIV);
    }
    if (parser->facility == FTP) {
	return bdata(&FACILITY_FTP);
    }
    if (parser->facility == NTP) {
	return bdata(&FACILITY_NTP);
    }
    if (parser->facility == AUDIT) {
	return bdata(&FACILITY_AUDIT);
    }
    if (parser->facility == LOGALERT) {
	return bdata(&FACILITY_LOGALERT);
    }
    if (parser->facility == CRON) {
	return bdata(&FACILITY_CRON);
    }
    if (parser->facility == LOCAL0) {
	return bdata(&FACILITY_LOCAL0);
    }
    if (parser->facility == LOCAL1) {
	return bdata(&FACILITY_LOCAL1);
    }
    if (parser->facility == LOCAL2) {
	return bdata(&FACILITY_LOCAL2);
    }
    if (parser->facility == LOCAL3) {
	return bdata(&FACILITY_LOCAL3);
    }
    if (parser->facility == LOCAL4) {
	return bdata(&FACILITY_LOCAL4);
    }
    if (parser->facility == LOCAL5) {
	return bdata(&FACILITY_LOCAL5);
    }
    if (parser->facility == LOCAL6) {
	return bdata(&FACILITY_LOCAL6);
    }
    if (parser->facility == LOCAL7) {
	return bdata(&FACILITY_LOCAL7);
    }
}

char* syslog_parser_severity_name(syslog_parser *parser)
{
    if (parser->severity == EMERG) {
	return bdata(&SEVERITY_EMERG);
    }
    if (parser->severity == ALERT) {
	return bdata(&SEVERITY_ALERT);
    }
    if (parser->severity == CRIT) {
	return bdata(&SEVERITY_CRIT);
    }
    if (parser->severity == ERR) {
	return bdata(&SEVERITY_ERR);
    }
    if (parser->severity == WARN) {
	return bdata(&SEVERITY_WARN);
    }
    if (parser->severity == NOTICE) {
	return bdata(&SEVERITY_NOTICE);
    }
    if (parser->severity == INFO) {
	return bdata(&SEVERITY_INFO);
    }
    if (parser->severity == DEBUG) {
	return bdata(&SEVERITY_DEBUG);
    }
}

void syslog_parser_destroy(syslog_parser *parser)
{
    bdestroy(parser->hostname);
    bdestroy(parser->message);
    bdestroy(parser->app_name);
    bdestroy(parser->proc_id);
    bdestroy(parser->msg_id);
}

char* syslog_parser_json_output(syslog_parser *parser)
{
    check(syslog_parser_is_finished(parser) == 1, "Parser is not finished!");
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "severity", parser->severity);
    cJSON_AddNumberToObject(root, "facility", parser->facility);
    cJSON_AddItemToObject(root, "severity_name",
			  cJSON_CreateString(syslog_parser_severity_name(parser)));
    cJSON_AddItemToObject(root, "facility_name",
			  cJSON_CreateString(syslog_parser_facility_name(parser)));
    cJSON_AddNumberToObject(root, "timestamp", 0);// @TODO!
    cJSON_AddItemToObject(root, "hostname",
			  cJSON_CreateString(syslog_parser_hostname(parser)));
    cJSON_AddItemToObject(root, "app_name",
			  cJSON_CreateString(syslog_parser_app_name(parser)));
    cJSON_AddItemToObject(root, "proc_id",
			  cJSON_CreateString(syslog_parser_proc_id(parser)));
    cJSON_AddItemToObject(root, "msg_id",
			  cJSON_CreateString(syslog_parser_msg_id(parser)));

    debug("json is :%s", cJSON_Print(root));
    return cJSON_Print(root);

 error:
    return NULL;
}

static inline int month_from_bstring(bstring month_data)
{
    if (bstrcmp(month_data, &PARSER_JAN) == 0) {
	return 1;
    }
    if (bstrcmp(month_data, &PARSER_FEB) == 0) {
	return 2;
    }
    if (bstrcmp(month_data, &PARSER_MAR) == 0) {
	return 3;
    }
    if (bstrcmp(month_data, &PARSER_APR) == 0) {
	return 4;
    }
    if (bstrcmp(month_data, &PARSER_MAY) == 0) {
	return 5;
    }
    if (bstrcmp(month_data, &PARSER_JUN) == 0) {
	return 6;
    }
    if (bstrcmp(month_data, &PARSER_JUL) == 0) {
	return 7;
    }
    if (bstrcmp(month_data, &PARSER_AUG) == 0) {
	return 8;
    }
    if (bstrcmp(month_data, &PARSER_SEP) == 0) {
	return 9;
    }
    if (bstrcmp(month_data, &PARSER_OCT) == 0) {
	return 10;
    }
    if (bstrcmp(month_data, &PARSER_NOV) == 0) {
	return 11;
    }
    if (bstrcmp(month_data, &PARSER_DEC) == 0) {
	return 12;
    }

    // @TODO: this can't happen as the parser won't have worked.
    return -1;
}


%%{
    machine syslog;

    action mark {MARK(mark, fpc);}

    action severity_facility {has_pri_field = 1; pri_field = blk2bstr(PTR_TO(mark + 1), LEN(mark + 1, fpc - 3));}

    rfc3164_month = ("Jan" | "Feb" | "Mar" | "Apr" | "May" | "Jun" | "Jul" | "Aug" | "Sep" | "Oct" | "Nov" | "Dec") >mark %{month_data = blk2bstr(PTR_TO(mark), LEN(mark, fpc));};
    date_fullyear = digit{4} >mark %{TO_NUMBER(year, fpc);};
    date_month = digit{2} >mark %{TO_NUMBER(month, fpc);}  ;
    date_mday = digit{2} >mark %{TO_NUMBER(day, fpc);} ;
    time_hour = digit{2} >mark %{TO_NUMBER(hour, fpc);}  ;
    time_minute = digit{2} >mark %{TO_NUMBER(minute, fpc);} ;
    time_second = digit{2} >mark %{TO_NUMBER(second, fpc);};
    time_secfrac = ("." digit+) >mark %{TO_FLOAT(second_fraction, fpc);};
    time_numoffset = ("+" | "-") time_hour ":" time_minute ;
    time_offset = ("Z" | "z") | time_numoffset ;

    partial_time = time_hour ":" time_minute ":" time_second time_secfrac? ;

    full_date = date_fullyear "-" date_month "-" date_mday ;
    full_time = partial_time time_offset ;
    date_time = full_date ("T" | "t") full_time ;

    rfc3164_day = (" "digit | digit{2}) >mark %{TO_NUMBER(day, fpc);} ;
    rfc3164_date_time = rfc3164_month " " rfc3164_day " " partial_time;

    pri = ( "<" [0-9]{1,3} ">") >mark %severity_facility ;

    hostname = ([A-z0-9_.:]+) >mark %{parser->hostname = blk2bstr(PTR_TO(mark), LEN(mark, fpc)); };
    nil = '-' ;

    header = (nil | date_time | rfc3164_date_time) " " (nil | hostname) ;

    app_name = alnum+ >mark %{parser->app_name = blk2bstr(PTR_TO(mark), LEN(mark, fpc)); };
    proc_id = alnum+ >mark %{parser->proc_id = blk2bstr(PTR_TO(mark), LEN(mark, fpc)); };
    msg_id = alnum+ >mark %{parser->msg_id = blk2bstr(PTR_TO(mark), LEN(mark, fpc)); } ;
#structured_data = ???;

    message_any = any+ >mark %{parser->message = blk2bstr(PTR_TO(mark), LEN(mark, fpc)); } ;
    message_utf8 = "BOM" message_any ;
    message = message_utf8 | message_any ;

    rfc5424_payload = ( pri "1" " " header " " (nil | app_name) " " (nil | proc_id) " " (nil | msg_id) " " (nil) " " message ) ;
    rfc3164_payload = (pri rfc3164_date_time " " (nil | hostname) " " (nil | app_name) ("[" digit+ "]" | " ") ":" " "? message) ;

    main := rfc3164_payload | rfc5424_payload;

}%%

/** Data **/
%% write data;
/** End Data **/
int syslog_parser_has_error(syslog_parser *parser)
{
    return parser->cs == syslog_error;
}

int syslog_parser_is_finished(syslog_parser *parser)
{
    if (syslog_parser_has_error(parser)) {
	return -1;
    }
    else if (parser->cs >= syslog_first_final) {
	return 1;
    }
    return 0;
}

syslog_parser *syslog_parser_init()
{
    int cs = 0;
    %% write init;
    syslog_parser *p = malloc(sizeof(syslog_parser));
	*p = (syslog_parser) {
	.cs = cs,
	.chars_read = 0,
	.mark = 0,
	.severity = DEBUG,
	.facility = LOCAL7,
	.month = -1,
	.year = -1,
	.day = 0,
	.hour = -1,
	.minute = -1,
	.second = -1,
	.hostname = bfromcstr(""),
	.message = bfromcstr(""),
	.app_name = bfromcstr(""),
	.proc_id = bfromcstr(""),
	.msg_id = bfromcstr("")
    };

    return p;
}

size_t syslog_parser_execute(syslog_parser *parser, const char *buffer, size_t len, size_t off)
{
    check(len != 0, "No length");
    check(off <= len, "Offset is past end of buffer");
    bstring pri_field, month_data = bfromcstr("");

    const char *p, *pe, *eof;
    int cs = parser->cs;
    int starting_length = parser->chars_read;
    int has_pri_field = 0;

    p = buffer+off;
    pe = buffer+len;
    eof = pe;

    /** Start Exec **/
    %% write exec;
    /** End Exec **/
    parser->cs = cs;

    if (has_pri_field && blength(pri_field)) {
        int pri_value = atoi(bdata(pri_field));
        parser->severity = pri_value & 7;
        parser->facility = pri_value >> 3;
    }
    if (blength(month_data) == 3) {
	parser->month = month_from_bstring(month_data);
    }

    check(p <= pe, "Buffer overflow after parsing");
    parser->chars_read += p - (buffer + off);
    check((parser->chars_read - starting_length) <= len, "Read more then length characters");
    check(parser->mark <= len, "Mark is passed buffer end");


    return parser->chars_read;

 error:
    return 0;
}
