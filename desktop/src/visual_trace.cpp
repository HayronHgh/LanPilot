#include "rwn/desktop/visual_trace.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <stdexcept>

namespace rwn::desktop {
namespace {

void require(const bool condition, const char* message) {
    if (!condition) throw std::invalid_argument(message);
}

template <typename T>
T parse_unsigned(std::string_view input, std::size_t& offset) {
    const auto start = offset;
    while (offset < input.size() && input[offset] >= '0' &&
           input[offset] <= '9') {
        ++offset;
    }
    require(offset > start, "visual trace number is missing");
    require(offset - start == 1 || input[start] != '0',
            "visual trace number is not canonical");
    T value{};
    const auto [end, error] = std::from_chars(
        input.data() + start, input.data() + offset, value);
    require(error == std::errc{} && end == input.data() + offset,
            "visual trace number is invalid");
    return value;
}

void expect(
    const std::string_view input,
    std::size_t& offset,
    const std::string_view literal) {
    require(input.substr(offset, literal.size()) == literal,
            "visual trace JSON is not canonical");
    offset += literal.size();
}

std::string_view parse_token(
    const std::string_view input,
    std::size_t& offset) {
    const auto end = input.find('"', offset);
    require(end != std::string_view::npos,
            "visual trace token is unterminated");
    const auto token = input.substr(offset, end - offset);
    require(!token.empty(), "visual trace token is empty");
    offset = end + 1U;
    return token;
}

VisualTraceHost parse_host(const std::string_view token) {
    if (token == "mac") return VisualTraceHost::mac;
    if (token == "windows") return VisualTraceHost::windows;
    throw std::invalid_argument("unknown visual trace host");
}

VisualLifecycleStage parse_stage(const std::string_view token) {
    for (const auto stage : {
             VisualLifecycleStage::none,
             VisualLifecycleStage::sck_callback,
             VisualLifecycleStage::latest_publish,
             VisualLifecycleStage::superseded,
             VisualLifecycleStage::metal_analysis,
             VisualLifecycleStage::metal_rect_decision,
             VisualLifecycleStage::rect_readback,
             VisualLifecycleStage::nonvisual_pipeline_advance,
             VisualLifecycleStage::vt_submit,
             VisualLifecycleStage::vt_output,
             VisualLifecycleStage::wire_write_complete,
             VisualLifecycleStage::wire_receive,
             VisualLifecycleStage::raw_rect_write_complete,
             VisualLifecycleStage::snapshot_write_complete,
             VisualLifecycleStage::raw_rect_receive,
             VisualLifecycleStage::mf_output,
             VisualLifecycleStage::framebuffer_commit,
             VisualLifecycleStage::gpu_patch,
             VisualLifecycleStage::present_submitted,
             VisualLifecycleStage::frame_commit_write_complete,
             VisualLifecycleStage::ack_created,
             VisualLifecycleStage::ack_enqueued,
             VisualLifecycleStage::ack_write_complete,
             VisualLifecycleStage::ack_bytes_received,
             VisualLifecycleStage::ack_parsed,
             VisualLifecycleStage::ack_accepted,
             VisualLifecycleStage::representation_state,
             VisualLifecycleStage::h264_quality_compare,
             VisualLifecycleStage::gpu_exact_verify,
             VisualLifecycleStage::input_captured,
             VisualLifecycleStage::input_enqueued,
             VisualLifecycleStage::input_superseded,
             VisualLifecycleStage::input_write_complete,
             VisualLifecycleStage::input_bytes_received,
             VisualLifecycleStage::input_injected,
             VisualLifecycleStage::input_rejected,
             VisualLifecycleStage::input_release_all,
             VisualLifecycleStage::visual_stall,
             VisualLifecycleStage::visual_recovered,
             VisualLifecycleStage::trace_dropped}) {
        if (token == to_string(stage)) return stage;
    }
    throw std::invalid_argument("unknown visual lifecycle stage");
}

VisualSckStatus parse_sck_status(const std::string_view token) {
    for (const auto status : {
             VisualSckStatus::unknown,
             VisualSckStatus::complete,
             VisualSckStatus::idle,
             VisualSckStatus::blank,
             VisualSckStatus::suspended,
             VisualSckStatus::started,
             VisualSckStatus::stopped}) {
        if (token == to_string(status)) return status;
    }
    throw std::invalid_argument("unknown visual SCK status");
}

VisualRepresentationMode parse_representation_mode(
    const std::string_view token) {
    for (const auto mode : {
             VisualRepresentationMode::unknown,
             VisualRepresentationMode::video_lossy,
             VisualRepresentationMode::snapshot,
             VisualRepresentationMode::rect_exact}) {
        if (token == to_string(mode)) return mode;
    }
    throw std::invalid_argument("unknown visual representation mode");
}

VisualFallbackReason parse_fallback_reason(const std::string_view token) {
    for (const auto reason : {
             VisualFallbackReason::none,
             VisualFallbackReason::dirty_ratio,
             VisualFallbackReason::rectangle_count,
             VisualFallbackReason::packed_bytes,
             VisualFallbackReason::ack_timeout,
             VisualFallbackReason::base_mismatch,
             VisualFallbackReason::recovery_request,
             VisualFallbackReason::newer_incompatible_source,
             VisualFallbackReason::feature_disabled}) {
        if (token == to_string(reason)) return reason;
    }
    throw std::invalid_argument("unknown visual fallback reason");
}

VisualInputTraceClass parse_input_trace_class(const std::string_view token) {
    for (const auto value : {
             VisualInputTraceClass::none,
             VisualInputTraceClass::pointer_latest,
             VisualInputTraceClass::reliable,
             VisualInputTraceClass::release_all}) {
        if (token == to_string(value)) return value;
    }
    throw std::invalid_argument("unknown input trace class");
}

bool parse_bool(const std::string_view input, std::size_t& offset) {
    if (input.substr(offset, 4) == "true") {
        offset += 4;
        return true;
    }
    if (input.substr(offset, 5) == "false") {
        offset += 5;
        return false;
    }
    throw std::invalid_argument("visual trace boolean is invalid");
}

void advance_generation(
    std::uint64_t& current,
    const std::uint64_t frame_id) {
    if (frame_id == 0) return;
    if (frame_id < current) {
        throw std::invalid_argument("visual generation regressed");
    }
    current = frame_id;
}

}  // namespace

std::string_view to_string(const VisualTraceHost host) noexcept {
    return host == VisualTraceHost::mac ? "mac" : "windows";
}

std::string_view to_string(const VisualLifecycleStage stage) noexcept {
    switch (stage) {
        case VisualLifecycleStage::none: return "none";
        case VisualLifecycleStage::sck_callback: return "sck_callback";
        case VisualLifecycleStage::latest_publish: return "latest_publish";
        case VisualLifecycleStage::superseded: return "superseded";
        case VisualLifecycleStage::metal_analysis: return "metal_analysis";
        case VisualLifecycleStage::metal_rect_decision:
            return "metal_rect_decision";
        case VisualLifecycleStage::rect_readback: return "rect_readback";
        case VisualLifecycleStage::nonvisual_pipeline_advance:
            return "nonvisual_pipeline_advance";
        case VisualLifecycleStage::vt_submit: return "vt_submit";
        case VisualLifecycleStage::vt_output: return "vt_output";
        case VisualLifecycleStage::wire_write_complete:
            return "wire_write_complete";
        case VisualLifecycleStage::wire_receive: return "wire_receive";
        case VisualLifecycleStage::raw_rect_write_complete:
            return "raw_rect_write_complete";
        case VisualLifecycleStage::snapshot_write_complete:
            return "snapshot_write_complete";
        case VisualLifecycleStage::raw_rect_receive:
            return "raw_rect_receive";
        case VisualLifecycleStage::mf_output: return "mf_output";
        case VisualLifecycleStage::framebuffer_commit:
            return "framebuffer_commit";
        case VisualLifecycleStage::gpu_patch: return "gpu_patch";
        case VisualLifecycleStage::present_submitted:
            return "present_submitted";
        case VisualLifecycleStage::frame_commit_write_complete:
            return "frame_commit_write_complete";
        case VisualLifecycleStage::ack_created: return "ack_created";
        case VisualLifecycleStage::ack_enqueued: return "ack_enqueued";
        case VisualLifecycleStage::ack_write_complete:
            return "ack_write_complete";
        case VisualLifecycleStage::ack_bytes_received:
            return "ack_bytes_received";
        case VisualLifecycleStage::ack_parsed: return "ack_parsed";
        case VisualLifecycleStage::ack_accepted: return "ack_accepted";
        case VisualLifecycleStage::representation_state:
            return "representation_state";
        case VisualLifecycleStage::h264_quality_compare:
            return "h264_quality_compare";
        case VisualLifecycleStage::gpu_exact_verify:
            return "gpu_exact_verify";
        case VisualLifecycleStage::input_captured: return "input_captured";
        case VisualLifecycleStage::input_enqueued: return "input_enqueued";
        case VisualLifecycleStage::input_superseded:
            return "input_superseded";
        case VisualLifecycleStage::input_write_complete:
            return "input_write_complete";
        case VisualLifecycleStage::input_bytes_received:
            return "input_bytes_received";
        case VisualLifecycleStage::input_injected: return "input_injected";
        case VisualLifecycleStage::input_rejected: return "input_rejected";
        case VisualLifecycleStage::input_release_all:
            return "input_release_all";
        case VisualLifecycleStage::visual_stall: return "visual_stall";
        case VisualLifecycleStage::visual_recovered: return "visual_recovered";
        case VisualLifecycleStage::trace_dropped: return "trace_dropped";
    }
    return "none";
}

std::string_view to_string(const VisualSckStatus status) noexcept {
    switch (status) {
        case VisualSckStatus::unknown: return "unknown";
        case VisualSckStatus::complete: return "complete";
        case VisualSckStatus::idle: return "idle";
        case VisualSckStatus::blank: return "blank";
        case VisualSckStatus::suspended: return "suspended";
        case VisualSckStatus::started: return "started";
        case VisualSckStatus::stopped: return "stopped";
    }
    return "unknown";
}

std::string_view to_string(const VisualRepresentationMode mode) noexcept {
    switch (mode) {
        case VisualRepresentationMode::unknown: return "unknown";
        case VisualRepresentationMode::video_lossy: return "video_lossy";
        case VisualRepresentationMode::snapshot: return "snapshot";
        case VisualRepresentationMode::rect_exact: return "rect_exact";
    }
    return "unknown";
}

std::string_view to_string(const VisualFallbackReason reason) noexcept {
    switch (reason) {
        case VisualFallbackReason::none: return "none";
        case VisualFallbackReason::dirty_ratio: return "dirty_ratio";
        case VisualFallbackReason::rectangle_count:
            return "rectangle_count";
        case VisualFallbackReason::packed_bytes: return "packed_bytes";
        case VisualFallbackReason::ack_timeout: return "ack_timeout";
        case VisualFallbackReason::base_mismatch: return "base_mismatch";
        case VisualFallbackReason::recovery_request:
            return "recovery_request";
        case VisualFallbackReason::newer_incompatible_source:
            return "newer_incompatible_source";
        case VisualFallbackReason::feature_disabled:
            return "feature_disabled";
    }
    return "none";
}

std::string_view to_string(const VisualInputTraceClass value) noexcept {
    switch (value) {
        case VisualInputTraceClass::none: return "none";
        case VisualInputTraceClass::pointer_latest: return "pointer_latest";
        case VisualInputTraceClass::reliable: return "reliable";
        case VisualInputTraceClass::release_all: return "release_all";
    }
    return "none";
}

std::string render_visual_trace_json(const VisualTraceEvent& event) {
    if (event.schema_version < minimum_supported_visual_trace_schema_version ||
        event.schema_version > visual_trace_schema_version ||
        event.session_generation == 0 ||
        event.event_sequence == 0 || event.local_monotonic_us == 0) {
        throw std::invalid_argument("invalid visual trace event");
    }
    std::string output;
    output.reserve(768);
    const auto number = [&](const auto value) { output += std::to_string(value); };
    output += "{\"schema_version\":"; number(event.schema_version);
    output += ",\"host\":\""; output += to_string(event.host); output += '"';
    output += ",\"session_generation\":"; number(event.session_generation);
    output += ",\"representation_epoch\":";
    number(event.representation_epoch);
    output += ",\"event_sequence\":"; number(event.event_sequence);
    output += ",\"callback_sequence\":"; number(event.callback_sequence);
    output += ",\"frame_id\":"; number(event.frame_id);
    output += ",\"stage\":\""; output += to_string(event.stage); output += '"';
    output += ",\"related_stage\":\"";
    output += to_string(event.related_stage); output += '"';
    output += ",\"local_monotonic_us\":"; number(event.local_monotonic_us);
    output += ",\"sck_status\":\"";
    output += to_string(event.sck_status); output += '"';
    output += ",\"valid_image\":"; output += event.valid_image ? "true" : "false";
    output += ",\"content_x\":"; number(event.content_x);
    output += ",\"content_y\":"; number(event.content_y);
    output += ",\"content_width\":"; number(event.content_width);
    output += ",\"content_height\":"; number(event.content_height);
    output += ",\"sck_dirty_rect_count\":"; number(event.sck_dirty_rect_count);
    output += ",\"sck_dirty_union_area\":"; number(event.sck_dirty_union_area);
    output += ",\"sck_dirty_ratio_ppm\":"; number(event.sck_dirty_ratio_ppm);
    output += ",\"metal_dirty_tiles\":"; number(event.metal_dirty_tiles);
    output += ",\"metal_dirty_ratio_ppm\":"; number(event.metal_dirty_ratio_ppm);
    output += ",\"queue_depth\":"; number(event.queue_depth);
    output += ",\"stage_duration_us\":"; number(event.stage_duration_us);
    output += ",\"payload_bytes\":"; number(event.payload_bytes);
    output += ",\"rectangle_count\":"; number(event.rectangle_count);
    output += ",\"representation_mode\":\"";
    output += to_string(event.representation_mode); output += '"';
    output += ",\"fallback_reason\":\"";
    output += to_string(event.fallback_reason); output += '"';
    output += ",\"exact_residency_ratio_ppm\":";
    number(event.exact_residency_ratio_ppm);
    output += ",\"representation_switches\":";
    number(event.representation_switches);
    output += ",\"rect_superseded_sources\":";
    number(event.rect_superseded_sources);
    output += ",\"verification_mismatches\":";
    number(event.verification_mismatches);
    output += ",\"absolute_error_sum\":";
    number(event.absolute_error_sum);
    output += ",\"squared_error_sum\":";
    number(event.squared_error_sum);
    output += ",\"superseded_by\":"; number(event.superseded_by);
    output += ",\"stalled_us\":"; number(event.stalled_us);
    output += ",\"trace_dropped\":"; number(event.trace_dropped);
    if (event.schema_version >= 5U) {
        output += ",\"input_correlation_id\":";
        number(event.input_correlation_id);
        output += ",\"input_epoch\":"; number(event.input_epoch);
        output += ",\"input_sequence\":"; number(event.input_sequence);
        output += ",\"input_trace_class\":\"";
        output += to_string(event.input_trace_class); output += '"';
    }
    if (event.schema_version >= 6U) {
        output += ",\"latest_source_frame_id\":"; number(event.latest_source_frame_id);
        output += ",\"latest_content_frame_id\":"; number(event.latest_content_frame_id);
        output += ",\"exact_base_frame_id\":"; number(event.exact_base_frame_id);
        output += ",\"exact_base_content_frame_id\":"; number(event.exact_base_content_frame_id);
    }
    output += '}';
    if (output.size() > maximum_visual_trace_line_bytes) {
        throw std::length_error("visual trace JSON exceeds line limit");
    }
    return output;
}

VisualTraceEvent decode_visual_trace_json(const std::string_view json) {
    require(!json.empty() && json.size() <= maximum_visual_trace_line_bytes,
            "visual trace JSON size is invalid");
    require(json.find('\n') == std::string_view::npos &&
                json.find('\r') == std::string_view::npos,
            "visual trace JSON must be one line");
    std::size_t offset{};
    VisualTraceEvent event;
    expect(json, offset, "{\"schema_version\":");
    event.schema_version = parse_unsigned<std::uint32_t>(json, offset);
    require(event.schema_version >= minimum_supported_visual_trace_schema_version &&
                event.schema_version <= visual_trace_schema_version,
            "unsupported visual trace schema");
    expect(json, offset, ",\"host\":\"");
    event.host = parse_host(parse_token(json, offset));
    expect(json, offset, ",\"session_generation\":");
    event.session_generation = parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"representation_epoch\":");
    event.representation_epoch =
        parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"event_sequence\":");
    event.event_sequence = parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"callback_sequence\":");
    event.callback_sequence = parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"frame_id\":");
    event.frame_id = parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"stage\":\"");
    event.stage = parse_stage(parse_token(json, offset));
    expect(json, offset, ",\"related_stage\":\"");
    event.related_stage = parse_stage(parse_token(json, offset));
    expect(json, offset, ",\"local_monotonic_us\":");
    event.local_monotonic_us = parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"sck_status\":\"");
    event.sck_status = parse_sck_status(parse_token(json, offset));
    expect(json, offset, ",\"valid_image\":");
    event.valid_image = parse_bool(json, offset);
    expect(json, offset, ",\"content_x\":");
    event.content_x = parse_unsigned<std::uint32_t>(json, offset);
    expect(json, offset, ",\"content_y\":");
    event.content_y = parse_unsigned<std::uint32_t>(json, offset);
    expect(json, offset, ",\"content_width\":");
    event.content_width = parse_unsigned<std::uint32_t>(json, offset);
    expect(json, offset, ",\"content_height\":");
    event.content_height = parse_unsigned<std::uint32_t>(json, offset);
    expect(json, offset, ",\"sck_dirty_rect_count\":");
    event.sck_dirty_rect_count = parse_unsigned<std::uint32_t>(json, offset);
    expect(json, offset, ",\"sck_dirty_union_area\":");
    event.sck_dirty_union_area = parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"sck_dirty_ratio_ppm\":");
    event.sck_dirty_ratio_ppm = parse_unsigned<std::uint32_t>(json, offset);
    expect(json, offset, ",\"metal_dirty_tiles\":");
    event.metal_dirty_tiles = parse_unsigned<std::uint32_t>(json, offset);
    expect(json, offset, ",\"metal_dirty_ratio_ppm\":");
    event.metal_dirty_ratio_ppm = parse_unsigned<std::uint32_t>(json, offset);
    expect(json, offset, ",\"queue_depth\":");
    event.queue_depth = parse_unsigned<std::uint32_t>(json, offset);
    expect(json, offset, ",\"stage_duration_us\":");
    event.stage_duration_us = parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"payload_bytes\":");
    event.payload_bytes = parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"rectangle_count\":");
    event.rectangle_count = parse_unsigned<std::uint32_t>(json, offset);
    expect(json, offset, ",\"representation_mode\":\"");
    event.representation_mode =
        parse_representation_mode(parse_token(json, offset));
    expect(json, offset, ",\"fallback_reason\":\"");
    event.fallback_reason =
        parse_fallback_reason(parse_token(json, offset));
    expect(json, offset, ",\"exact_residency_ratio_ppm\":");
    event.exact_residency_ratio_ppm =
        parse_unsigned<std::uint32_t>(json, offset);
    expect(json, offset, ",\"representation_switches\":");
    event.representation_switches =
        parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"rect_superseded_sources\":");
    event.rect_superseded_sources =
        parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"verification_mismatches\":");
    event.verification_mismatches =
        parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"absolute_error_sum\":");
    event.absolute_error_sum =
        parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"squared_error_sum\":");
    event.squared_error_sum =
        parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"superseded_by\":");
    event.superseded_by = parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"stalled_us\":");
    event.stalled_us = parse_unsigned<std::uint64_t>(json, offset);
    expect(json, offset, ",\"trace_dropped\":");
    event.trace_dropped = parse_unsigned<std::uint64_t>(json, offset);
    if (event.schema_version >= 5U) {
        expect(json, offset, ",\"input_correlation_id\":");
        event.input_correlation_id =
            parse_unsigned<std::uint64_t>(json, offset);
        expect(json, offset, ",\"input_epoch\":");
        event.input_epoch = parse_unsigned<std::uint64_t>(json, offset);
        expect(json, offset, ",\"input_sequence\":");
        event.input_sequence = parse_unsigned<std::uint64_t>(json, offset);
        expect(json, offset, ",\"input_trace_class\":\"");
        event.input_trace_class = parse_input_trace_class(
            parse_token(json, offset));
    }
    if (event.schema_version >= 6U) {
        expect(json, offset, ",\"latest_source_frame_id\":");
        event.latest_source_frame_id = parse_unsigned<std::uint64_t>(json, offset);
        expect(json, offset, ",\"latest_content_frame_id\":");
        event.latest_content_frame_id = parse_unsigned<std::uint64_t>(json, offset);
        expect(json, offset, ",\"exact_base_frame_id\":");
        event.exact_base_frame_id = parse_unsigned<std::uint64_t>(json, offset);
        expect(json, offset, ",\"exact_base_content_frame_id\":");
        event.exact_base_content_frame_id = parse_unsigned<std::uint64_t>(json, offset);
    }
    expect(json, offset, "}");
    require(offset == json.size(), "visual trace JSON has trailing data");
    require(event.session_generation != 0 && event.event_sequence != 0 &&
                event.local_monotonic_us != 0,
            "visual trace identity is invalid");
    require(event.sck_dirty_ratio_ppm <= 1'000'000 &&
                event.metal_dirty_ratio_ppm <= 1'000'000 &&
                event.exact_residency_ratio_ppm <= 1'000'000,
            "visual trace ratio is invalid");
    return event;
}

void validate_visual_trace_destination(const std::filesystem::path& path) {
    if (!path.is_absolute() || path.extension() != ".jsonl" ||
        path.filename().empty() || std::filesystem::exists(path) ||
        !std::filesystem::is_directory(path.parent_path())) {
        throw std::invalid_argument(
            "visual trace destination must be a new absolute JSONL file");
    }
}

VisualTraceQueue::VisualTraceQueue(const std::size_t capacity)
    : capacity_(capacity) {
    if (capacity == 0 || capacity > default_visual_trace_queue_capacity) {
        throw std::invalid_argument("invalid visual trace queue capacity");
    }
}

bool VisualTraceQueue::try_push(VisualTraceEvent event) {
    std::lock_guard lock(mutex_);
    if (closed_ || events_.size() >= capacity_) {
        ++dropped_events_;
        return false;
    }
    events_.push_back(std::move(event));
    condition_.notify_one();
    return true;
}

std::optional<VisualTraceEvent> VisualTraceQueue::wait_pop(
    const std::chrono::milliseconds timeout) {
    if (timeout < std::chrono::milliseconds::zero()) {
        throw std::invalid_argument("visual trace timeout must be non-negative");
    }
    std::unique_lock lock(mutex_);
    condition_.wait_for(lock, timeout, [&] {
        return closed_ || !events_.empty();
    });
    if (events_.empty()) return std::nullopt;
    auto event = std::move(events_.front());
    events_.pop_front();
    return event;
}

void VisualTraceQueue::close() {
    {
        std::lock_guard lock(mutex_);
        closed_ = true;
    }
    condition_.notify_all();
}

std::uint64_t VisualTraceQueue::dropped_events() const {
    std::lock_guard lock(mutex_);
    return dropped_events_;
}

std::size_t VisualTraceQueue::size() const {
    std::lock_guard lock(mutex_);
    return events_.size();
}

VisualLifecycleTracker::VisualLifecycleTracker(
    const VisualTraceHost host,
    const std::uint64_t session_generation,
    VisualTraceQueue* trace_queue)
    : host_(host),
      session_generation_(session_generation),
      trace_queue_(trace_queue) {
    if (session_generation == 0) {
        throw std::invalid_argument("visual lifecycle session is zero");
    }
}

void VisualLifecycleTracker::record(
    const VisualLifecycleStage stage,
    const std::uint64_t frame_id,
    const std::uint64_t local_monotonic_us,
    const VisualTraceEvent& metadata) {
    if (local_monotonic_us == 0) {
        throw std::invalid_argument("visual lifecycle timestamp is zero");
    }
    VisualTraceEvent event = metadata;
    {
        std::lock_guard lock(mutex_);
        switch (stage) {
            case VisualLifecycleStage::sck_callback:
                if ((metadata.sck_status == VisualSckStatus::complete ||
                     metadata.sck_status == VisualSckStatus::started) &&
                    metadata.valid_image) {
                    advance_generation(snapshot_.source_generation, frame_id);
                }
                break;
            case VisualLifecycleStage::latest_publish:
                advance_generation(snapshot_.published_generation, frame_id);
                break;
            case VisualLifecycleStage::vt_submit:
                advance_generation(snapshot_.submitted_generation, frame_id);
                break;
            case VisualLifecycleStage::vt_output:
                advance_generation(snapshot_.encoded_generation, frame_id);
                break;
            case VisualLifecycleStage::wire_write_complete:
                advance_generation(snapshot_.written_generation, frame_id);
                break;
            case VisualLifecycleStage::wire_receive:
                advance_generation(snapshot_.received_generation, frame_id);
                break;
            case VisualLifecycleStage::mf_output:
                advance_generation(snapshot_.decoded_generation, frame_id);
                break;
            case VisualLifecycleStage::framebuffer_commit:
                advance_generation(snapshot_.committed_generation, frame_id);
                break;
            case VisualLifecycleStage::present_submitted:
                advance_generation(
                    snapshot_.present_submitted_generation, frame_id);
                break;
            default: break;
        }
        event.schema_version = visual_trace_schema_version;
        event.host = host_;
        event.session_generation = session_generation_;
        event.event_sequence = ++event_sequence_;
        event.frame_id = frame_id;
        event.stage = stage;
        event.local_monotonic_us = local_monotonic_us;
    }
    if (trace_queue_ != nullptr) {
        static_cast<void>(trace_queue_->try_push(std::move(event)));
    }
}

VisualLifecycleSnapshot VisualLifecycleTracker::snapshot() const {
    std::lock_guard lock(mutex_);
    return snapshot_;
}

std::uint64_t VisualLifecycleTracker::trace_dropped() const {
    return trace_queue_ == nullptr ? 0 : trace_queue_->dropped_events();
}

VisualLivenessWatchdog::VisualLivenessWatchdog(
    const VisualLifecycleDomain domain)
    : domain_(domain) {}

std::pair<VisualLifecycleStage, std::uint64_t>
VisualLivenessWatchdog::gap(
    const VisualLifecycleSnapshot& snapshot) const noexcept {
    if (domain_ == VisualLifecycleDomain::mac) {
        if (snapshot.published_generation < snapshot.source_generation)
            return {VisualLifecycleStage::latest_publish,
                    snapshot.source_generation};
        if (snapshot.submitted_generation < snapshot.published_generation)
            return {VisualLifecycleStage::vt_submit,
                    snapshot.published_generation};
        if (snapshot.encoded_generation < snapshot.submitted_generation)
            return {VisualLifecycleStage::vt_output,
                    snapshot.submitted_generation};
        if (snapshot.written_generation < snapshot.encoded_generation)
            return {VisualLifecycleStage::wire_write_complete,
                    snapshot.encoded_generation};
    } else {
        if (snapshot.decoded_generation < snapshot.received_generation)
            return {VisualLifecycleStage::mf_output,
                    snapshot.received_generation};
        if (snapshot.committed_generation < snapshot.decoded_generation)
            return {VisualLifecycleStage::framebuffer_commit,
                    snapshot.decoded_generation};
        if (snapshot.present_submitted_generation <
            snapshot.committed_generation)
            return {VisualLifecycleStage::present_submitted,
                    snapshot.committed_generation};
    }
    return {VisualLifecycleStage::none, 0};
}

std::optional<VisualWatchdogEvent> VisualLivenessWatchdog::poll(
    const VisualLifecycleSnapshot& snapshot,
    const std::uint64_t now_us,
    const std::uint64_t stall_threshold_us,
    const std::uint64_t hard_timeout_us) {
    if (now_us == 0 || stall_threshold_us == 0 ||
        hard_timeout_us < stall_threshold_us) {
        throw std::invalid_argument("invalid visual watchdog timing");
    }
    const auto [stage, frame_id] = gap(snapshot);
    if (stage == VisualLifecycleStage::none) {
        if (stall_reported_) {
            const auto stalled_us = now_us >= observed_since_us_
                ? now_us - observed_since_us_ : 0;
            const auto recovered_stage = observed_stage_;
            const auto recovered_frame_id = observed_frame_id_;
            stall_reported_ = false;
            hard_timeout_reported_ = false;
            observed_stage_ = VisualLifecycleStage::none;
            observed_frame_id_ = 0;
            observed_since_us_ = 0;
            return VisualWatchdogEvent{
                .recovered = true,
                .related_stage = recovered_stage,
                .frame_id = recovered_frame_id,
                .stalled_us = stalled_us,
            };
        }
        observed_stage_ = VisualLifecycleStage::none;
        observed_frame_id_ = 0;
        observed_since_us_ = 0;
        return std::nullopt;
    }
    if (stage != observed_stage_ || frame_id != observed_frame_id_) {
        observed_stage_ = stage;
        observed_frame_id_ = frame_id;
        observed_since_us_ = now_us;
        stall_reported_ = false;
        hard_timeout_reported_ = false;
        return std::nullopt;
    }
    const auto stalled_us = now_us >= observed_since_us_
        ? now_us - observed_since_us_ : 0;
    if (!stall_reported_ && stalled_us >= stall_threshold_us) {
        stall_reported_ = true;
        return VisualWatchdogEvent{
            .stalled = true,
            .related_stage = stage,
            .frame_id = frame_id,
            .stalled_us = stalled_us,
        };
    }
    if (!hard_timeout_reported_ && stalled_us >= hard_timeout_us) {
        hard_timeout_reported_ = true;
        return std::nullopt;
    }
    return std::nullopt;
}

bool VisualLivenessWatchdog::hard_timeout_active() const noexcept {
    return hard_timeout_reported_;
}

VisualTailRefreshBudget::VisualTailRefreshBudget(
    const std::uint32_t refresh_count,
    const std::uint64_t quiet_delay_us)
    : refresh_count_(refresh_count), quiet_delay_us_(quiet_delay_us) {
    if (refresh_count == 0 || refresh_count > 16 || quiet_delay_us == 0 ||
        quiet_delay_us > 100'000) {
        throw std::invalid_argument("invalid visual tail refresh budget");
    }
}

void VisualTailRefreshBudget::publish_visual(
    const std::uint64_t frame_id,
    const std::uint64_t published_at_us) {
    if (frame_id == 0 || published_at_us == 0 ||
        published_at_us >
            std::numeric_limits<std::uint64_t>::max() - quiet_delay_us_) {
        throw std::invalid_argument("invalid visual tail publication");
    }
    frame_id_ = frame_id;
    repeat_after_us_ = published_at_us + quiet_delay_us_;
    remaining_ = refresh_count_;
}

bool VisualTailRefreshBudget::repeat_due(
    const std::uint64_t now_us) const noexcept {
    return remaining_ != 0 && frame_id_ != 0 &&
        now_us >= repeat_after_us_;
}

void VisualTailRefreshBudget::repeat_completed(
    const std::uint64_t frame_id) {
    if (frame_id == 0 || frame_id != frame_id_ || remaining_ == 0) {
        throw std::invalid_argument("invalid visual tail refresh completion");
    }
    --remaining_;
}

std::uint32_t VisualTailRefreshBudget::remaining() const noexcept {
    return remaining_;
}

}  // namespace rwn::desktop
