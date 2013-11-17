#include "../src/parser.h"
#include "../src/cJSON/cJSON.h"
#include "minunit/minunit.h"
#include <string.h>
#include "../src/bstring.h"

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

    cJSON *message_node = cJSON_GetObjectItem(response, "message");
    mu_assert(strcmp(message_node->valuestring, bdata(p->message)) == 0,
	      "Message doesn't match");
}

MU_TEST(test_json_internal)
{
    char *out = syslog_parser_internal_message(ERR, "Failed issue");
    mu_assert(out != NULL, "Output was expected");

    cJSON *response = NULL;
    response = cJSON_Parse(out);
    mu_assert(response != NULL, "Failed to parse");

    mu_assert(cJSON_GetObjectItem(response, "severity")->valueint == 3,
	      "Severity doesn't match 3");
    cJSON *message_node = cJSON_GetObjectItem(response, "message");
    mu_assert(strcmp(message_node->valuestring, "Failed issue") == 0,
	      "Message doesn't match");
}

MU_TEST_SUITE(json_suite)
{
    MU_RUN_TEST(test_json_success);
    MU_RUN_TEST(test_json_internal);
}

int main(int argc, char *argv[]) {
    MU_RUN_SUITE(json_suite);
    MU_REPORT();
    MU_RETURN_VALUE();
}
