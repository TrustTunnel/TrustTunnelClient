#include "trusttunnel/trusttunnel_service.h"

#include <gtest/gtest.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// ---------------------------------------------------------------------------
// Error mapping without a service: the SCM is consulted before the registry, so a service that
// does not exist is reported as missing and discovery is not attempted, whatever the pipe name is.
// ---------------------------------------------------------------------------

TEST(Attach, MissingServiceIsReportedAsNoSuchServiceForEveryPipeNameKind) {
    constexpr const wchar_t *MISSING_SERVICE = L"trusttunnel_attach_test_no_such_service";

    EXPECT_EQ(trusttunnel_service_attach(MISSING_SERVICE, nullptr, nullptr, nullptr, nullptr, nullptr),
            TRUSTTUNNEL_SVC_ERR_NO_SUCH_SERVICE);
    EXPECT_EQ(trusttunnel_service_attach(MISSING_SERVICE, L"", nullptr, nullptr, nullptr, nullptr),
            TRUSTTUNNEL_SVC_ERR_NO_SUCH_SERVICE);
    EXPECT_EQ(trusttunnel_service_attach(MISSING_SERVICE, L"\\\\.\\pipe\\trusttunnel_attach_test_explicit", nullptr,
                      nullptr, nullptr, nullptr),
            TRUSTTUNNEL_SVC_ERR_NO_SUCH_SERVICE);
}

// ---------------------------------------------------------------------------
// A running service that published nothing: the SCM reports it as running, so discovery is
// attempted and its failure is reported as the generic error.
// ---------------------------------------------------------------------------

/// Return true if the named service exists and is running.
static bool service_is_running(const wchar_t *name) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        return false;
    }
    SC_HANDLE service = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
    CloseServiceHandle(scm);
    if (service == nullptr) {
        return false;
    }
    SERVICE_STATUS status{};
    bool running = QueryServiceStatus(service, &status) != 0 && status.dwCurrentState == SERVICE_RUNNING;
    CloseServiceHandle(service);
    return running;
}

TEST(Attach, RunningServiceWithoutAPublishedNameReturnsGenericError) {
    // The Windows Event Log service is always running and never publishes a pipe name.
    constexpr const wchar_t *RUNNING_SERVICE = L"EventLog";
    if (!service_is_running(RUNNING_SERVICE)) {
        GTEST_SKIP() << "the Windows Event Log service is not running";
    }

    EXPECT_EQ(trusttunnel_service_attach(RUNNING_SERVICE, nullptr, nullptr, nullptr, nullptr, nullptr),
            TRUSTTUNNEL_SVC_ERR_OTHER);
}
