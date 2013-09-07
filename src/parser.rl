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

#define LEN(AT, FPC) (FPC - buffer - parser->AT)
#define MARK(M,FPC) (parser->M = (FPC) - buffer)
#define PTR_TO(F) (buffer + parser->F)
#define TO_NUMBER(F, FPC) (parser->F = atoi(bstr2cstr(blk2bstr((buffer + parser->mark), (FPC - buffer - parser->mark)), (FPC - buffer - parser->mark))))
#define TO_FLOAT(F, FPC) (parser->F = atof(bstr2cstr(blk2bstr((buffer + parser->mark), (FPC - buffer - parser->mark)), (FPC - buffer - parser->mark))))

void syslog_parser_destroy(syslog_parser *parser)
{
    bdestroy(parser->hostname);
    bdestroy(parser->message);
    bdestroy(parser->app_name);
    bdestroy(parser->proc_id);
    bdestroy(parser->msg_id);
}


%%{
    machine syslog;

    action mark {MARK(mark, fpc);}

    action severity_facility {has_pri_field = 1; pri_field = blk2bstr(PTR_TO(mark + 1), LEN(mark + 1, fpc - 3));}

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

    rfc3164_month = "Jan" | "Feb" | "Mar" | "Apr" | "May" | "Jun" | "Jul" | "Aug" | "Sep" | "Oct" | "Nov" | "Dec";
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
	.severity = -1,
	.facility = -1,
	.month = -1,
	.year = -1,
	.day = 0,
	.hour = -1,
	.minute = -1,
	.second = -1
    };

    return p;
}

size_t syslog_parser_execute(syslog_parser *parser, const char *buffer, size_t len, size_t off)
{
    check(len != 0, "No length");
    check(off <= len, "Offset is past end of buffer");
    bstring pri_field;

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

    check(p <= pe, "Buffer overflow after parsing");
    parser->chars_read += p - (buffer + off);
    check((parser->chars_read - starting_length) <= len, "Read more then length characters");
    check(parser->mark <= len, "Mark is passed buffer end");


    return parser->chars_read;

 error:
    return 0;
}
