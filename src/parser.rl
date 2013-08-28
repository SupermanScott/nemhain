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
 *     * Neither the name of the Mongrel2 Project, Zed A. Shaw, nor the names
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

char* syslog_parser_hostname(syslog_parser *parser)
{
    return bdata(parser->hostname);
}

char* syslog_parser_month(syslog_parser *parser)
{
    return bdata(parser->month);
}

char* syslog_parser_message(syslog_parser *parser)
{
    return bdata(parser->message);
}

%%{
  machine syslog_rfc3164;

  action mark {MARK(mark, fpc);}

  action severity_facility {pri_field = blk2bstr(PTR_TO(mark + 1), LEN(mark + 1, fpc - 3));}

  pri = ( "<" [0-9]{1,3} ">") >mark %severity_facility ;

  month = ( "Jan" | "Feb" | "Mar" | "Apr" | "May" | "Jun"
            | "Jul" | "Aug" | "Sep" | "Oct" | "Nov" | "Dec" ) >mark %{parser->month = blk2bstr(PTR_TO(mark), 3);};

  day = ((" "? [1-9]) | ([12] [0-9]) | ("3" [01])) >mark %{TO_NUMBER(day, fpc);};

  hour = (([01] [0-9]) | "2" [0-4]) >mark %{TO_NUMBER(hour, fpc);};

  minute = ([0-5][0-9]) >mark %{TO_NUMBER(minute, fpc); };

  second = ([0-5][0-9]) >mark %{TO_NUMBER(second, fpc); };


  time = ( hour ":" minute ":" second ) ;
  timestamp = ( month " " day " " time ) ;

  hostname = ([A-z0-9_.:]+) >mark %{parser->hostname = blk2bstr(PTR_TO(mark), LEN(mark, fpc)); };

  header = timestamp " " hostname ;
  message = (32..127)+ >mark %{parser->message = blk2bstr(PTR_TO(mark), LEN(mark, fpc));} ;

  payload = ( pri "1" " " header " " message ) ;

  main := payload ;

}%%

/** Data **/
%% write data;
/** End Data **/
int syslog_parser_has_error(syslog_parser *parser)
{
    return parser->cs == syslog_rfc3164_error;
}

int syslog_parser_is_finished(syslog_parser *parser)
{
    if (syslog_parser_has_error(parser)) {
	return -1;
    }
    else if (parser->cs >= syslog_rfc3164_first_final) {
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

    p = buffer+off;
    pe = buffer+len;
    eof = pe;

    /** Start Exec **/
    %% write exec;
    /** End Exec **/
    parser->cs = cs;
    if (blength(pri_field)) {
	debug("Parsed pri: %s", bdata(pri_field));
        int pri_value = atoi(bdata(pri_field));
        parser->severity = pri_value & 7;
        parser->facility = pri_value >> 3;
        debug("Parsed pri values: %d, %d", parser->severity, parser->facility);
    }

    check(p <= pe, "Buffer overflow after parsing");
    parser->chars_read += p - (buffer + off);
    check((parser->chars_read - starting_length) <= len, "Read more then length characters");
    check(parser->mark <= len, "Mark is passed buffer end");


    return parser->chars_read;

 error:
    return 0;
}
