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
#pragma once
#include "bstring.h"

typedef struct syslog_parser {
    int cs;
    size_t mark;
    size_t chars_read;

    int severity;
    int facility;
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
    float second_fraction;

    bstring hostname;
    bstring message;
    bstring app_name;
    bstring proc_id;
    bstring msg_id;
} syslog_parser;

syslog_parser *syslog_parser_init();
size_t syslog_parser_execute(syslog_parser *parser, const char *data, size_t len, size_t off);
int syslog_parser_has_error(syslog_parser *parser);
int syslog_parser_is_finished(syslog_parser *parser);
void syslog_parser_destroy(syslog_parser *parser);

#define syslog_parser_hostname(parser) (bdata(parser->hostname))
#define syslog_parser_message(parser) (bdata(parser->message))
#define syslog_parser_app_name(parser) (bdata(parser->app_name))
#define syslog_parser_proc_id(parser) (bdata(parser->proc_id))
#define syslog_parser_msg_id(parser) (bdata(parser->msg_id))
