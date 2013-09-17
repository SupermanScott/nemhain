#include "../src/parser.h"
#include "../src/cJSON/cJSON.h"
#include "minunit/minunit.h"
#include <string.h>
#include "../src/bstring.h"

MU_TEST(test_parser_execute_rfc_no_structured)
{
    syslog_parser *p = syslog_parser_init();
    size_t read_chars = syslog_parser_execute(
					      p,
					      "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8",
					      113,
					      0);

    mu_assert_int_eq(syslog_parser_is_finished(p), 1);

    mu_assert_int_eq(read_chars, 113);
    mu_assert_int_eq(p->year, 2003);
    mu_assert_int_eq(p->month, 10);
    mu_assert_int_eq(p->day, 11);
    mu_assert_int_eq(p->hour, 22);
    mu_assert_int_eq(p->minute, 14);
    mu_assert_int_eq(p->second, 15);
    mu_assert_int_eq(p->severity, 2);
    mu_assert_int_eq(p->facility, 4);
    mu_assert(p->second_fraction == 0.00300000003f, "Fraction isn't correct");

    mu_assert(strcmp(syslog_parser_message(p), "'su root' failed for lonvick on /dev/pts/8") == 0,
		  "Message not parsed properly");
    mu_assert(strcmp(syslog_parser_hostname(p), "mymachine.example.com") == 0,
		  "Host name doesn't match");
    mu_assert(strcmp(syslog_parser_app_name(p), "su") == 0,
	      "App name doesn't match");

    mu_assert(strcmp(syslog_parser_proc_id(p), "") == 0,
	      "Proc id shouldn't be set");

    mu_assert(strcmp(syslog_parser_msg_id(p), "ID47") == 0,
	      "Failed to get the right msg_id");
}

MU_TEST(test_parser_execute_rfc_no_msg_id)
{
    char *msg = "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 PRC 8710 - - %% It's time to make the do-nuts.";

    syslog_parser *p = syslog_parser_init();
    syslog_parser_execute(p, msg, strlen(msg), 0);

    mu_assert(strcmp(syslog_parser_msg_id(p), "") == 0,
	      "Message id shouldn't be set");
    mu_assert(strcmp(syslog_parser_message(p), "%% It's time to make the do-nuts.") == 0,
	       "Message not parsed properly");
    mu_assert(strcmp(syslog_parser_proc_id(p), "8710") == 0,
	      "Proc id wasn't parsed properly");
}

MU_TEST(test_parser_execute_missing_version)
{
    char *msg = "<165>2003-08-24T05:14:15.000003-07:00 192.0.2.1 PRC 8710 - - %% It's time to make the do-nuts.";

    syslog_parser *p = syslog_parser_init();
    syslog_parser_execute(p, msg, strlen(msg), 0);

    mu_assert(syslog_parser_has_error(p), "Parser should have failed on this string");
}

MU_TEST(test_parser_execute_missing_pri_value)
{
    char *msg = "<1652003-08-24T05:14:15.000003-07:00 192.0.2.1 PRC 8710 - - %% It's time to make the do-nuts.";

    syslog_parser *p = syslog_parser_init();
    syslog_parser_execute(p, msg, strlen(msg), 0);

    mu_assert(syslog_parser_has_error(p), "Parser should have failed on this string");
}

MU_TEST(test_parser_rfc3164)
{
    char *msg = "<141>Sep  7 17:34:14 precise64 exampleprog[29258]: Program started by User 1000";
    syslog_parser *p = syslog_parser_init();
    syslog_parser_execute(p, msg, strlen(msg), 0);

    mu_assert_int_eq(p->facility, 17);
    mu_assert_int_eq(p->month, 9);
    mu_assert_int_eq(p->day, 7);
    mu_assert_int_eq(p->hour, 17);
    mu_assert_int_eq(p->minute, 34);
    mu_assert_int_eq(p->second, 14);

    mu_assert(strcmp(syslog_parser_hostname(p), "precise64") == 0,
	      "Host name doesn't match");
    mu_assert(strcmp(syslog_parser_app_name(p), "exampleprog") == 0,
	      "App name doesn't match");
    mu_assert(strcmp(syslog_parser_message(p), "Program started by User 1000") == 0,
	      "Message doesn't match");

    mu_assert(strcmp(syslog_parser_proc_id(p), "") == 0,
	      "Proc id shouldn't be set");
    mu_assert(strcmp(syslog_parser_msg_id(p), "") == 0,
	      "Msg id shouldn't be set");
}

MU_TEST(test_json_success)
{
    syslog_parser *p = syslog_parser_init();
    p->severity = 1;
    p->facility = 10;
    p->year = 2013;
    p->month = 9;
    p->day = 7;
    p->hour = 3;
    p->minute = 49;
    p->second = 12;
    p->hostname = bfromcstr("precise64");
    p->message = bfromcstr("Program started !");
    p->app_name = bfromcstr("exampletest");

    p->cs = 128;

    char *out = syslog_parser_json_output(p);
    mu_assert(out != NULL, "Output was expected");

    cJSON *response = NULL;
    response = cJSON_Parse(out);
    mu_assert(response != NULL, "Failed to parse");

    mu_assert(cJSON_GetObjectItem(response, "severity")->valueint == 1,
	      "Severity doesn't match 1");

    cJSON *hostname_node = cJSON_GetObjectItem(response, "hostname");
    mu_assert(strcmp(hostname_node->valuestring, "precise64") == 0,
	      "Host name doesn't match");
}

MU_TEST(test_severity_name)
{
    syslog_parser *p = syslog_parser_init();
    mu_assert(strcmp(syslog_parser_severity_name(p), "DEBUG") == 0,
	      "Debug string name not properly handled");
    p->severity = EMERG;
    mu_assert(strcmp(syslog_parser_severity_name(p), "EMERGENCY") == 0,
	      "Emergency string name not properly handled");
    p->severity = ALERT;
    mu_assert(strcmp(syslog_parser_severity_name(p), "ALERT") == 0,
	      "Alert string name not properly handled");
    p->severity = CRIT;
    mu_assert(strcmp(syslog_parser_severity_name(p), "CRITICAL") == 0,
	      "Critical string name not properly handled");
    p->severity = ERR;
    mu_assert(strcmp(syslog_parser_severity_name(p), "ERROR") == 0,
	      "Error string name not properly handled");
    p->severity = WARN;
    mu_assert(strcmp(syslog_parser_severity_name(p), "WARNING") == 0,
	      "Warning string name not properly handled");
    p->severity = NOTICE;
    mu_assert(strcmp(syslog_parser_severity_name(p), "NOTICE") == 0,
	      "Notice string name not properly handled");
    p->severity = INFO;
    mu_assert(strcmp(syslog_parser_severity_name(p), "INFORMATION") == 0,
	      "Info string name not properly handled");
    p->severity = DEBUG;
    mu_assert(strcmp(syslog_parser_severity_name(p), "DEBUG") == 0,
	      "Debug string name not properly handled");
}

MU_TEST(test_facility_name)
{
    syslog_parser *p = syslog_parser_init();
    mu_assert(strcmp(syslog_parser_facility_name(p), "LOCAL7") == 0,
	      "LOCAL7 failed");
    p->facility = KERN;
    mu_assert(strcmp(syslog_parser_facility_name(p), "KERN") == 0,
	      "KERN failed");
}

MU_TEST_SUITE(parser_suite)
{
    MU_RUN_TEST(test_parser_rfc3164);
    MU_RUN_TEST(test_parser_execute_rfc_no_structured);
    MU_RUN_TEST(test_parser_execute_rfc_no_msg_id);
    MU_RUN_TEST(test_parser_execute_missing_version);
    MU_RUN_TEST(test_parser_execute_missing_pri_value);
    MU_RUN_TEST(test_severity_name);
    MU_RUN_TEST(test_facility_name);
}

MU_TEST_SUITE(json_suite)
{
    MU_RUN_TEST(test_json_success);
}

int main(int argc, char *argv[]) {
    MU_RUN_SUITE(parser_suite);
    MU_RUN_SUITE(json_suite);
    MU_REPORT();
    return 0;
}
