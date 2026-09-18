#include "rwn/platform/windows/dns_sd_discovery.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace rwn::platform::windows {

DnsSdDiscovery::DnsSdDiscovery(std::wstring service_type)
    : service_type_(std::move(service_type)) {
    if (service_type_.empty()) {
        throw std::invalid_argument("DNS-SD service type must not be empty");
    }
}

DnsSdDiscovery::~DnsSdDiscovery() {
    stop();
}

void DnsSdDiscovery::start() {
    {
        std::scoped_lock lock(mutex_);
        if (running_) {
            throw std::logic_error("DNS-SD browse is already running");
        }
        request_ = {};
        cancellation_ = {};
        request_.Version = DNS_QUERY_REQUEST_VERSION1;
        request_.InterfaceIndex = 0;
        request_.QueryName = service_type_.c_str();
        request_.pBrowseCallback = &DnsSdDiscovery::browse_callback;
        request_.pQueryContext = this;
        running_ = true;
    }
    const auto status = DnsServiceBrowse(&request_, &cancellation_);
    if (status != ERROR_SUCCESS && status != DNS_REQUEST_PENDING) {
        std::scoped_lock lock(mutex_);
        running_ = false;
        throw std::runtime_error("Windows DNS-SD browse could not start");
    }
}

void DnsSdDiscovery::stop() noexcept {
    {
        std::scoped_lock lock(mutex_);
        if (!running_) {
            return;
        }
        running_ = false;
    }
    static_cast<void>(DnsServiceBrowseCancel(&cancellation_));
}

bool DnsSdDiscovery::running() const {
    std::scoped_lock lock(mutex_);
    return running_;
}

std::vector<std::string> DnsSdDiscovery::instance_names() const {
    std::scoped_lock lock(mutex_);
    return instance_names_;
}

void WINAPI DnsSdDiscovery::browse_callback(
    const DWORD status, void* const context, DNS_RECORD* const records) {
    if (status != ERROR_SUCCESS || context == nullptr || records == nullptr) {
        return;
    }
    static_cast<DnsSdDiscovery*>(context)->observe(records);
}

void DnsSdDiscovery::observe(DNS_RECORD* records) {
    std::scoped_lock lock(mutex_);
    for (auto* record = records; record != nullptr; record = record->pNext) {
        if (record->wType != DNS_TYPE_PTR || record->Data.PTR.pNameHost == nullptr) {
            continue;
        }
        std::string name(record->Data.PTR.pNameHost);
        if (std::ranges::find(instance_names_, name) == instance_names_.end()) {
            instance_names_.push_back(std::move(name));
        }
    }
}

}  // namespace rwn::platform::windows
