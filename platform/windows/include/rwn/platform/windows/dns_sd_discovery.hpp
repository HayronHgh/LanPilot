#pragma once

#include <mutex>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windns.h>

namespace rwn::platform::windows {

class DnsSdDiscovery {
public:
    explicit DnsSdDiscovery(std::wstring service_type = L"_rwn._tcp.local");
    ~DnsSdDiscovery();

    DnsSdDiscovery(const DnsSdDiscovery&) = delete;
    DnsSdDiscovery& operator=(const DnsSdDiscovery&) = delete;

    void start();
    void stop() noexcept;
    [[nodiscard]] bool running() const;
    [[nodiscard]] std::vector<std::string> instance_names() const;

private:
    static void WINAPI browse_callback(
        DWORD status, void* context, DNS_RECORD* records);
    void observe(DNS_RECORD* records);

    std::wstring service_type_;
    DNS_SERVICE_BROWSE_REQUEST request_{};
    DNS_SERVICE_CANCEL cancellation_{};
    mutable std::mutex mutex_;
    std::vector<std::string> instance_names_;
    bool running_{};
};

}  // namespace rwn::platform::windows
