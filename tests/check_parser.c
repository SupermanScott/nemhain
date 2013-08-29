#include "../src/parser.h"
#include "minunit/minunit.h"
#include <string.h>

MU_TEST(test_parser_execute_rfc_no_structured) {
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

    mu_assert(strcmp(syslog_parser_message(p), "BOM'su root' failed for lonvick on /dev/pts/8") == 0,
		  "Message not parsed properly");
    mu_assert(strcmp(syslog_parser_hostname(p), "mymachine.example.com") == 0,
		  "Host name doesn't match");
    mu_assert(strcmp(syslog_parser_app_name(p), "su") == 0,
	      "App name doesn't match");

    mu_assert(!syslog_parser_proc_id(p), "Proc id shouldn't be set");

    mu_assert(strcmp(syslog_parser_msg_id(p), "ID47") == 0,
	      "Failed to get the right msg_id");
}
MU_TEST_SUITE(test_suite) {
    MU_RUN_TEST(test_parser_execute_rfc_no_structured);
}

int main(int argc, char *argv[]) {
    MU_RUN_SUITE(test_suite);
    MU_REPORT();
    return 0;
}
