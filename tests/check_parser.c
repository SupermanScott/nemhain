#include <check.h>
#include <stdlib.h>
#include "../src/parser.h"
START_TEST (test_parser_execute_success)
{
    syslog_parser *p;
    p = syslog_parser_init();
    size_t read_chars = syslog_parser_execute(
			  p,
			  "<12>Mar  1 15:43:35 snack kernel: Kernel logging (proc) stopped.",
			  64,
			  0);
    ck_assert_int_eq(read_chars, 64);
    ck_assert_int_eq(syslog_parser_has_error(p), 0);
    ck_assert_str_eq(syslog_parser_hostname(p), "snack");

    ck_assert_str_eq(syslog_parser_month(p), "Mar");
    ck_assert_int_eq(p->day, 1);
    ck_assert_int_eq(p->hour, 15);
    ck_assert_int_eq(p->second, 35);
    ck_assert_str_eq(syslog_parser_message(p), "kernel: Kernel logging (proc) stopped.");
    ck_assert_int_eq(p->severity, 4);
    ck_assert_int_eq(p->facility, 1);
}
END_TEST

START_TEST (test_parser_execute_more_chars)
{
    syslog_parser *p;
    p = syslog_parser_init();
    size_t read_chars = syslog_parser_execute(
					      p,
					      "<12>Mar  1 15:43:35 snack kernel: Kernel logging (proc) stopped.",
					      164,
					      0);
    ck_assert_int_eq(read_chars, 64);
    ck_assert_int_eq(syslog_parser_has_error(p), 1);
}
END_TEST

START_TEST (test_parser_execute_fail)
{
    syslog_parser *p;
    p = syslog_parser_init();
    size_t read_chars = syslog_parser_execute(
					      p,
					      "<12>1 15:43:35 snack kernel: Kernel logging (proc) stopped.",
					      64,
					      0);
    ck_assert_int_eq(read_chars, 4);
    ck_assert_int_eq(syslog_parser_has_error(p), 1);
}
END_TEST

START_TEST (test_parser_execute_partial)
{
    syslog_parser *p;
    p = syslog_parser_init();
    size_t read_chars = syslog_parser_execute(
					      p,
					      "<12>Mar",
					      7,
					      0);
    ck_assert_int_eq(read_chars, 7);
    read_chars = syslog_parser_execute(p, "  1 15:43:35 snack kernel: Kernel logging (proc) stopped.", 64-7, 0);
    ck_assert_int_eq(read_chars, 64);
}
END_TEST

Suite* execute_suite()
{
    Suite *s = suite_create ("Parser");
    TCase *tc_core = tcase_create ("Core");
    tcase_add_test (tc_core, test_parser_execute_success);
    tcase_add_test (tc_core, test_parser_execute_more_chars);
    tcase_add_test (tc_core, test_parser_execute_fail);
    tcase_add_test(tc_core, test_parser_execute_partial);
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
