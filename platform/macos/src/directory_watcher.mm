#include "rwn/platform/macos/directory_watcher.hpp"

#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>

#include <condition_variable>
#include <limits.h>
#include <limits.h>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

namespace rwn::platform::macos {

class DirectoryWatcher::Impl {
public:
    explicit Impl(const std::filesystem::path& root)
        : root_(std::filesystem::weakly_canonical(root)) {
        if (!std::filesystem::is_directory(root_)) {
            throw std::invalid_argument("watch root is not a directory");
        }
        const auto root_utf8 = root_.string();
        const auto root_string = CFStringCreateWithCString(
            kCFAllocatorDefault, root_utf8.c_str(), kCFStringEncodingUTF8);
        if (root_string == nullptr) {
            throw std::runtime_error("FSEvents root encoding failed");
        }
        const void* values[]{root_string};
        const auto paths = CFArrayCreate(
            kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
        CFRelease(root_string);
        FSEventStreamContext context{
            .version = 0,
            .info = this,
            .retain = nullptr,
            .release = nullptr,
            .copyDescription = nullptr,
        };
        stream_ = FSEventStreamCreate(
            kCFAllocatorDefault, &Impl::callback, &context, paths,
            kFSEventStreamEventIdSinceNow, 0.05,
            kFSEventStreamCreateFlagFileEvents |
                kFSEventStreamCreateFlagNoDefer |
                kFSEventStreamCreateFlagUseCFTypes);
        CFRelease(paths);
        if (stream_ == nullptr) {
            throw std::runtime_error("FSEvents stream creation failed");
        }
        queue_ = dispatch_queue_create("rwn.workspace.fsevents", DISPATCH_QUEUE_SERIAL);
        FSEventStreamSetDispatchQueue(stream_, queue_);
        if (!FSEventStreamStart(stream_)) {
            FSEventStreamInvalidate(stream_);
            FSEventStreamRelease(stream_);
            stream_ = nullptr;
            throw std::runtime_error("FSEvents stream start failed");
        }
    }

    ~Impl() {
        if (stream_ != nullptr) {
            FSEventStreamStop(stream_);
            FSEventStreamInvalidate(stream_);
            FSEventStreamRelease(stream_);
        }
#if !OS_OBJECT_USE_OBJC
        if (queue_ != nullptr) {
            dispatch_release(queue_);
        }
#endif
    }

    std::vector<rwn::core::WorkspaceTrigger> poll(
        const std::chrono::milliseconds timeout) {
        if (timeout < std::chrono::milliseconds::zero()) {
            throw std::invalid_argument("watch timeout must not be negative");
        }
        std::unique_lock lock(mutex_);
        static_cast<void>(condition_.wait_for(lock, timeout, [this] {
            return !pending_.empty();
        }));
        auto result = std::move(pending_);
        pending_.clear();
        return result;
    }

private:
    static void callback(
        ConstFSEventStreamRef, void* context, std::size_t count,
        void* paths, const FSEventStreamEventFlags flags[],
        const FSEventStreamEventId[]) {
        auto& self = *static_cast<Impl*>(context);
        const auto path_array = static_cast<CFArrayRef>(paths);
        std::scoped_lock lock(self.mutex_);
        for (std::size_t index = 0; index < count; ++index) {
            const auto dropped =
                (flags[index] & (kFSEventStreamEventFlagMustScanSubDirs |
                                 kFSEventStreamEventFlagUserDropped |
                                 kFSEventStreamEventFlagKernelDropped)) != 0;
            if (dropped) {
                self.pending_.push_back({
                    .kind = rwn::core::WorkspaceTriggerKind::overflow, .path = {}});
                continue;
            }
            const auto value = static_cast<CFStringRef>(
                CFArrayGetValueAtIndex(path_array, static_cast<CFIndex>(index)));
            char buffer[PATH_MAX]{};
            if (!CFStringGetCString(
                    value, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
                self.pending_.push_back({
                    .kind = rwn::core::WorkspaceTriggerKind::overflow, .path = {}});
                continue;
            }
            const auto relative = std::filesystem::path(buffer)
                                      .lexically_relative(self.root_)
                                      .generic_string();
            self.pending_.push_back({
                .kind = rwn::core::WorkspaceTriggerKind::modified,
                .path = relative,
            });
        }
        self.condition_.notify_all();
    }

    std::filesystem::path root_;
    FSEventStreamRef stream_{};
    dispatch_queue_t queue_{};
    std::mutex mutex_;
    std::condition_variable condition_;
    std::vector<rwn::core::WorkspaceTrigger> pending_;
};

DirectoryWatcher::DirectoryWatcher(const std::filesystem::path& root)
    : impl_(std::make_unique<Impl>(root)) {}

DirectoryWatcher::~DirectoryWatcher() = default;

std::vector<rwn::core::WorkspaceTrigger> DirectoryWatcher::poll(
    const std::chrono::milliseconds timeout) {
    return impl_->poll(timeout);
}

}  // namespace rwn::platform::macos
