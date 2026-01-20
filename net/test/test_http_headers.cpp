#include <assert.h>
#include <limits.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#include "common/utils.h"
#include "net/http_header.h"
#include "net/utils.h"

using namespace ag;

#define NONEMPTY_FIELD_NAME "Non-Empty-Field"
#define NONEXISTING_FIELD_NAME "Non-Existing-Field"
#define EMPTY_FIELD_NAME "Empty-Field"

static const char CORRECT_OUTPUT[] = "GET / HTTP/1.1\r\n" NONEMPTY_FIELD_NAME ": 1\r\n" NONEMPTY_FIELD_NAME
                                     ": 2\r\n" EMPTY_FIELD_NAME "2: \r\n" NONEMPTY_FIELD_NAME "2: 2\r\n\r\n";

static const char CORRECT_OUTPUT_RESPONSE[] = "HTTP/1.1 200 OK\r\n" NONEMPTY_FIELD_NAME ": 1\r\n" NONEMPTY_FIELD_NAME
                                              ": 2\r\n" EMPTY_FIELD_NAME "2: \r\n" NONEMPTY_FIELD_NAME "2: 2\r\n\r\n";

static constexpr std::string_view HTTP_STATUS_OK_STR = "OK";

int main() { // NOLINT(bugprone-exception-escape)
    HttpHeaders message{.version = HTTP_VER_1_1};

    message.method = "GET";
    message.path = "/";
    // Add header field named "Empty-Field"
    message.put_field(EMPTY_FIELD_NAME, "");
    message.put_field(NONEMPTY_FIELD_NAME, "1");
    message.put_field(NONEMPTY_FIELD_NAME, "2");
    message.put_field(EMPTY_FIELD_NAME "2", "");
    message.put_field(NONEMPTY_FIELD_NAME "2", "2");
    message.fields.erase(std::remove_if(message.fields.begin(), message.fields.end(),
                                 [](const HttpHeaderField &field) {
                                     return field.name == EMPTY_FIELD_NAME;
                                 }),
            message.fields.end());

    HttpHeaders clone = message;

    clone.status_code = HTTP_STATUS_OK;
    clone.status_string = HTTP_STATUS_OK_STR;

    assert(message.contains_field(ag::utils::to_lower(NONEMPTY_FIELD_NAME)));

    assert(http_headers_to_http1_message(&message, false) == CORRECT_OUTPUT);
    assert(http_headers_to_http1_message(&clone, false) == CORRECT_OUTPUT_RESPONSE);
}
