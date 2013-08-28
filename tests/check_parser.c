#include <check.h>
#include <stdlib.h>
#include "../src/parser.h"

START_TEST (test_parser_execute_rfc_no_structured)
{
    syslog_parser *p = syslog_parser_init();
    size_t read_chars = syslog_parser_execute(
					      p,
					      "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8",
					      113,
					      0);
    ck_assert_int_eq(syslog_parser_is_finished(p), 1);

    ck_assert_int_eq(read_chars, 113);
    ck_assert_int_eq(p->year, 2003);
    ck_assert_int_eq(p->month, 10);
    ck_assert_int_eq(p->day, 11);
    ck_assert_int_eq(p->hour, 22);
    ck_assert_int_eq(p->minute, 14);
    ck_assert_int_eq(p->second, 15);
    ck_assert_str_eq(syslog_parser_message(p), "BOM'su root' failed for lonvick on /dev/pts/8");
    ck_assert_int_eq(p->severity, 2);
    ck_assert_int_eq(p->facility, 4);
    ck_assert_str_eq(syslog_parser_hostname(p), "mymachine.example.com");
    ck_assert_str_eq(syslog_parser_app_name(p), "su");
    ck_assert(!syslog_parser_proc_id(p));
    ck_assert_str_eq(syslog_parser_msg_id(p), "ID47");
}
END_TEST

Suite* execute_suite()
{
    Suite *s = suite_create ("Parser");
    TCase *tc_core = tcase_create ("Core");
    tcase_add_test(tc_core, test_parser_execute_rfc_no_structured);
    suite_add_tcase (s, tc_core);

    return s;
}

int main ()
{
    int number_failed;
    Suite *s = execute_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
