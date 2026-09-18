#pragma once

#include "rwn/core/authorization.hpp"
#include "rwn/transport/transport.hpp"

#include <chrono>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::desktop {

inline constexpr std::uint16_t media_protocol_version = 1;
inline constexpr std::size_t maximum_media_datagram_size = 1200;
inline constexpr std::size_t maximum_encoded_frame_size = 8U * 1024U * 1024U;
inline constexpr std::size_t maximum_input_text_size = 64U * 1024U;
inline constexpr std::size_t maximum_clipboard_text_size = 1024U * 1024U;
inline constexpr std::uint16_t preview_protocol_version = 1;
inline constexpr std::uint16_t visual_protocol_version = 3;
inline constexpr std::size_t preview_frame_header_size = 36;
inline constexpr std::size_t encoded_preview_frame_header_size = 36;
inline constexpr std::size_t visual_message_header_size = 56;
inline constexpr std::uint16_t reverse_control_protocol_version = 2;
inline constexpr std::size_t reverse_control_header_size = 40;
inline constexpr std::size_t maximum_reverse_control_payload = 64U * 1024U;
inline constexpr std::size_t maximum_snapshot_total_bytes = 32U * 1024U * 1024U;
inline constexpr std::size_t maximum_snapshot_wire_chunk_bytes = 64U * 1024U;
inline constexpr std::size_t maximum_raw_rect_protocol_bytes =
    1920U * 1080U * 4U;
inline constexpr std::size_t maximum_raw_rect_transaction_count = 256U;
inline constexpr std::size_t default_raw_rect_selector_bytes = 128U * 1024U;
inline constexpr std::uint32_t default_raw_rect_selector_ratio_ppm = 10'000U;
inline constexpr std::uint32_t default_raw_rect_selector_count = 8U;
inline constexpr std::uint32_t maximum_preview_width = 1920;
inline constexpr std::uint32_t maximum_preview_height = 1080;
inline constexpr std::size_t maximum_preview_frame_size =
    static_cast<std::size_t>(maximum_preview_width) * maximum_preview_height * 4U;

enum class VideoCodec : std::uint8_t { h264 = 1 };

struct VideoFrame {
    std::uint64_t frame_id{};
    std::uint64_t representation_epoch{1};
    std::uint64_t captured_at_us{};
    std::uint32_t width{};
    std::uint32_t height{};
    VideoCodec codec{VideoCodec::h264};
    bool keyframe{};
    std::vector<std::byte> encoded;
};

struct RawFrame {
    std::uint64_t frame_id{};
    std::uint64_t captured_at_us{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t row_stride{};
    std::vector<std::byte> bgra;
};

struct PreviewFrameHeader {
    std::uint64_t frame_id{};
    std::uint64_t captured_at_us{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t payload_size{};

    [[nodiscard]] bool operator==(const PreviewFrameHeader&) const = default;
};

struct EncodedPreviewFrameHeader {
    std::uint64_t frame_id{};
    std::uint64_t captured_at_us{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t payload_size{};
    bool keyframe{};

    [[nodiscard]] bool operator==(
        const EncodedPreviewFrameHeader&) const = default;
};

enum class VisualMessageType : std::uint8_t {
    h264_access_unit = 1,
    full_snapshot = 2,
    raw_rect = 3,
    lz4_rect = 4,
    copy_rect = 5,
    cursor_position = 6,
    cursor_shape = 7,
    frame_commit = 8,
    state_reset = 9,
};

enum class VisualRuntimeMode : std::uint8_t {
    h264,
    hybrid,
    exact_only,
};

[[nodiscard]] bool visual_message_allowed(
    VisualRuntimeMode mode, VisualMessageType type) noexcept;

inline constexpr std::uint8_t visual_flag_frame_final = 1U << 0U;
inline constexpr std::uint8_t visual_flag_keyframe = 1U << 1U;

struct VisualMessageHeader {
    VisualMessageType type{VisualMessageType::h264_access_unit};
    std::uint8_t flags{};
    std::uint32_t payload_size{};
    std::uint64_t session_generation{};
    std::uint64_t representation_epoch{};
    std::uint64_t visual_sequence{};
    std::uint64_t frame_id{};
    std::uint64_t captured_at_us{};

    [[nodiscard]] bool operator==(const VisualMessageHeader&) const = default;
};

enum class CanonicalPixelFormat : std::uint32_t {
    bgra8_premultiplied_srgb = 1,
};

struct VisualFullSnapshotChunk {
    std::uint32_t surface_width{};
    std::uint32_t surface_height{};
    std::uint32_t row_stride{};
    CanonicalPixelFormat pixel_format{
        CanonicalPixelFormat::bgra8_premultiplied_srgb};
    std::uint32_t total_bytes{};
    std::uint32_t chunk_offset{};
    std::vector<std::byte> chunk;

    [[nodiscard]] bool operator==(
        const VisualFullSnapshotChunk&) const = default;
};

struct VisualRawRect {
    std::uint64_t base_frame_id{};
    std::uint32_t surface_width{};
    std::uint32_t surface_height{};
    std::uint32_t x{};
    std::uint32_t y{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t row_stride{};
    CanonicalPixelFormat pixel_format{
        CanonicalPixelFormat::bgra8_premultiplied_srgb};
    std::vector<std::byte> bgra;

    [[nodiscard]] bool operator==(const VisualRawRect&) const = default;
};

struct VisualFrameCommit {
    std::uint64_t base_frame_id{};
    [[nodiscard]] bool operator==(const VisualFrameCommit&) const = default;
};

enum class VisualStateResetReason : std::uint32_t {
    representation_transition = 1,
    sequence_gap = 2,
    base_mismatch = 3,
    snapshot_required = 4,
};

struct VisualStateReset {
    VisualStateResetReason reason{
        VisualStateResetReason::representation_transition};
    [[nodiscard]] bool operator==(const VisualStateReset&) const = default;
};

[[nodiscard]] std::vector<std::byte> encode_visual_full_snapshot_chunk(
    const VisualFullSnapshotChunk& chunk);
[[nodiscard]] VisualFullSnapshotChunk decode_visual_full_snapshot_chunk(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_visual_raw_rect(
    const VisualRawRect& rect);
[[nodiscard]] VisualRawRect decode_visual_raw_rect(
    std::span<const std::byte> payload);
[[nodiscard]] std::array<std::byte, 32> advance_canonical_rect_digest(
    const std::array<std::byte, 32>& base_digest,
    std::uint64_t target_frame_id,
    std::span<const VisualRawRect> rectangles);
[[nodiscard]] std::vector<std::byte> encode_visual_frame_commit(
    const VisualFrameCommit& commit);
[[nodiscard]] VisualFrameCommit decode_visual_frame_commit(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_visual_state_reset(
    const VisualStateReset& reset);
[[nodiscard]] VisualStateReset decode_visual_state_reset(
    std::span<const std::byte> payload);

struct VisualH264AccessUnit {
    std::uint32_t width{};
    std::uint32_t height{};
    std::vector<std::byte> encoded;

    [[nodiscard]] bool operator==(const VisualH264AccessUnit&) const = default;
};

struct VisualCursorPosition {
    std::uint32_t x{};
    std::uint32_t y{};
    bool visible{true};
    std::uint64_t shape_id{};

    [[nodiscard]] bool operator==(const VisualCursorPosition&) const = default;
};

struct VisualCursorShape {
    std::uint64_t shape_id{};
    std::uint16_t width{};
    std::uint16_t height{};
    std::uint16_t hotspot_x{};
    std::uint16_t hotspot_y{};
    std::vector<std::byte> bgra;

    [[nodiscard]] bool operator==(const VisualCursorShape&) const = default;
};

[[nodiscard]] std::vector<std::byte> encode_visual_message_header(
    const VisualMessageHeader& header);
[[nodiscard]] VisualMessageHeader decode_visual_message_header(
    std::span<const std::byte> bytes);
void validate_visual_message_payload(
    const VisualMessageHeader& header, std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_visual_h264_access_unit(
    const VisualH264AccessUnit& access_unit);
[[nodiscard]] VisualH264AccessUnit decode_visual_h264_access_unit(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_visual_cursor_position(
    const VisualCursorPosition& cursor);
[[nodiscard]] VisualCursorPosition decode_visual_cursor_position(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_visual_cursor_shape(
    const VisualCursorShape& cursor);
[[nodiscard]] VisualCursorShape decode_visual_cursor_shape(
    std::span<const std::byte> payload);

enum class VisualSequenceResult {
    accepted,
    new_generation,
    gap,
};

class VisualSequenceTracker {
public:
    [[nodiscard]] VisualSequenceResult receive(
        const VisualMessageHeader& header) noexcept;
    void reset() noexcept;
    [[nodiscard]] std::uint64_t generation() const noexcept {
        return generation_;
    }
    [[nodiscard]] std::uint64_t last_sequence() const noexcept {
        return last_sequence_;
    }

private:
    std::uint64_t generation_{};
    std::uint64_t last_sequence_{};
};

[[nodiscard]] RawFrame fit_preview_frame(
    const RawFrame& frame, std::uint32_t maximum_width,
    std::uint32_t maximum_height);
[[nodiscard]] std::vector<std::byte> encode_preview_frame_header(
    const PreviewFrameHeader& header);
[[nodiscard]] PreviewFrameHeader decode_preview_frame_header(
    std::span<const std::byte> bytes);
[[nodiscard]] std::vector<std::byte> encode_encoded_preview_frame_header(
    const EncodedPreviewFrameHeader& header);
[[nodiscard]] EncodedPreviewFrameHeader decode_encoded_preview_frame_header(
    std::span<const std::byte> bytes);

class CaptureBackend {
public:
    virtual ~CaptureBackend() = default;
    [[nodiscard]] virtual std::optional<RawFrame> capture(
        std::chrono::milliseconds timeout) = 0;
};

class VideoEncoder {
public:
    virtual ~VideoEncoder() = default;
    [[nodiscard]] virtual VideoFrame encode(
        const RawFrame& frame, const struct VideoSettings& settings,
        bool force_keyframe) = 0;
};

class VideoDecoder {
public:
    virtual ~VideoDecoder() = default;
    [[nodiscard]] virtual RawFrame decode(const VideoFrame& frame) = 0;
};

struct VideoFragment {
    std::uint64_t frame_id{};
    std::uint64_t captured_at_us{};
    std::uint32_t width{};
    std::uint32_t height{};
    VideoCodec codec{VideoCodec::h264};
    bool keyframe{};
    std::uint16_t fragment_index{};
    std::uint16_t fragment_count{};
    std::uint32_t total_size{};
    std::vector<std::byte> payload;
};

[[nodiscard]] std::vector<VideoFragment> fragment_frame(const VideoFrame& frame);
[[nodiscard]] std::vector<std::byte> encode_video_fragment(const VideoFragment& fragment);
[[nodiscard]] VideoFragment decode_video_fragment(std::span<const std::byte> bytes);

class FrameReassembler {
public:
    [[nodiscard]] std::optional<VideoFrame> receive(VideoFragment fragment);
    void notify_loss() noexcept;
    [[nodiscard]] bool keyframe_required() const noexcept { return keyframe_required_; }
    [[nodiscard]] std::uint64_t dropped_frames() const noexcept { return dropped_frames_; }

private:
    void begin(VideoFragment fragment);
    void abandon_incomplete() noexcept;

    std::optional<VideoFragment> current_;
    std::vector<std::optional<std::vector<std::byte>>> fragments_;
    std::size_t received_bytes_{};
    std::uint16_t received_count_{};
    bool keyframe_required_{true};
    std::uint64_t dropped_frames_{};
    std::uint64_t last_completed_frame_id_{};
};

class LatestFrameQueue {
public:
    void push(VideoFrame frame);
    [[nodiscard]] std::optional<VideoFrame> take();
    [[nodiscard]] std::uint64_t dropped_frames() const noexcept { return dropped_frames_; }

private:
    std::optional<VideoFrame> pending_;
    std::uint64_t dropped_frames_{};
};

struct KeyframeRequest {
    std::uint64_t after_frame_id{};
    std::string reason_code;

    [[nodiscard]] bool operator==(const KeyframeRequest&) const = default;
};

[[nodiscard]] std::vector<std::byte> encode_keyframe_request(
    const KeyframeRequest& request);
[[nodiscard]] KeyframeRequest decode_keyframe_request(
    std::span<const std::byte> bytes);

enum class InputKind : std::uint8_t {
    raw_key = 1,
    text_commit = 2,
    pointer_move = 3,
    pointer_button = 4,
    vertical_wheel = 5,
    horizontal_wheel = 6,
};

enum class ReverseControlType : std::uint8_t {
    input_event = 1,
    release_all_input = 2,
    request_full_snapshot = 3,
    frame_commit_ack = 4,
    ping = 5,
};

struct ReverseControlHeader {
    ReverseControlType type{ReverseControlType::ping};
    std::uint8_t flags{};
    std::uint32_t payload_size{};
    std::uint64_t input_epoch{};
    std::uint64_t sequence{};
    std::uint64_t occurred_at_us{};

    [[nodiscard]] bool operator==(const ReverseControlHeader&) const = default;
};

struct FrameCommitAck {
    std::uint64_t session_generation{};
    std::uint64_t representation_epoch{};
    std::uint64_t frame_id{};
    std::array<std::byte, 32> canonical_sha256{};

    [[nodiscard]] bool operator==(const FrameCommitAck&) const = default;
};

[[nodiscard]] std::vector<std::byte> encode_frame_commit_ack(
    const FrameCommitAck& ack);
[[nodiscard]] FrameCommitAck decode_frame_commit_ack(
    std::span<const std::byte> payload);
[[nodiscard]] bool frame_commit_ack_matches(
    const FrameCommitAck& ack,
    std::uint64_t session_generation,
    std::uint64_t representation_epoch,
    std::uint64_t frame_id,
    const std::array<std::byte, 32>& canonical_sha256) noexcept;

[[nodiscard]] std::vector<std::byte> encode_reverse_control_header(
    const ReverseControlHeader& header);
[[nodiscard]] ReverseControlHeader decode_reverse_control_header(
    std::span<const std::byte> bytes);
void validate_reverse_control_payload(
    const ReverseControlHeader& header,
    std::span<const std::byte> payload);

struct InputEvent {
    InputKind kind{InputKind::pointer_move};
    std::uint64_t sequence{};
    std::uint64_t occurred_at_us{};
    std::uint32_t value_a{};
    std::uint32_t value_b{};
    bool pressed{};
    std::string text;

    [[nodiscard]] bool operator==(const InputEvent&) const = default;
};

[[nodiscard]] bool valid_utf8(std::string_view text) noexcept;
void validate_input_event(const InputEvent& event);
[[nodiscard]] std::vector<std::byte> encode_input_event(const InputEvent& event);
[[nodiscard]] InputEvent decode_input_event(std::span<const std::byte> bytes);

class InputBackend {
public:
    virtual ~InputBackend() = default;
    virtual void raw_key(std::uint32_t hid_usage, bool pressed) = 0;
    virtual void text_commit(std::string_view utf8) = 0;
    virtual void pointer_move(std::uint16_t normalized_x, std::uint16_t normalized_y) = 0;
    virtual void pointer_button(std::uint8_t button, bool pressed) = 0;
    virtual void pointer_wheel(std::int32_t delta, bool horizontal) = 0;
};

class ClipboardBackend {
public:
    virtual ~ClipboardBackend() = default;
    [[nodiscard]] virtual std::string read_utf8_text() = 0;
    virtual void write_utf8_text(std::string_view text) = 0;
};

enum class PermissionState { not_determined, denied, granted };

struct DesktopPermissionStatus {
    PermissionState capture{PermissionState::not_determined};
    PermissionState input{PermissionState::not_determined};
};

class DesktopPermissionBackend {
public:
    virtual ~DesktopPermissionBackend() = default;
    [[nodiscard]] virtual DesktopPermissionStatus status() const = 0;
    virtual void request_capture() = 0;
    virtual void request_input() = 0;
};

class InputReceiver {
public:
    explicit InputReceiver(InputBackend& backend) : backend_(backend) {}
    [[nodiscard]] bool receive(
        const InputEvent& event, bool reliable,
        const core::AuthorizationResult& authorization);
    [[nodiscard]] std::size_t release_stuck_keys(
        std::uint64_t now_us, std::chrono::milliseconds maximum_hold);
    [[nodiscard]] std::size_t release_all_keys();
    [[nodiscard]] std::size_t release_all_input();
    [[nodiscard]] bool accept_input_epoch(
        std::uint64_t epoch, bool release_all);
    [[nodiscard]] std::uint64_t input_epoch() const noexcept {
        return input_epoch_;
    }

private:
    InputBackend& backend_;
    std::optional<std::uint64_t> last_reliable_sequence_;
    std::optional<std::uint64_t> last_pointer_sequence_;
    std::map<std::uint32_t, std::uint64_t> pressed_keys_;
    std::set<std::uint8_t> pressed_buttons_;
    std::uint64_t input_epoch_{1};
};

enum class VisualRepresentation : std::uint8_t {
    video,
    snapshot,
    rect,
    recovery,
};

enum class FramebufferQuality : std::uint8_t {
    unavailable,
    lossy,
    exact,
};

class CanonicalFramebufferState final {
public:
    [[nodiscard]] bool enter_representation(
        VisualRepresentation representation, std::uint64_t epoch) noexcept;
    [[nodiscard]] bool commit_video(
        std::uint64_t epoch, std::uint64_t frame_id) noexcept;
    [[nodiscard]] bool commit_snapshot(
        std::uint64_t epoch, std::uint64_t frame_id) noexcept;
    [[nodiscard]] bool can_commit_snapshot(
        std::uint64_t epoch, std::uint64_t frame_id) const noexcept;
    [[nodiscard]] bool begin_rect(
        std::uint64_t epoch, std::uint64_t base_frame_id,
        std::uint64_t target_frame_id) noexcept;
    [[nodiscard]] bool commit_rect(
        std::uint64_t epoch, std::uint64_t base_frame_id,
        std::uint64_t target_frame_id) noexcept;
    void cancel_rect(std::uint64_t epoch) noexcept;
    void present_submitted(std::uint64_t frame_id) noexcept;
    [[nodiscard]] std::optional<FrameCommitAck> take_commit_ack(
        std::uint64_t session_generation,
        std::array<std::byte, 32> canonical_sha256) noexcept;

    [[nodiscard]] std::uint64_t representation_epoch() const noexcept {
        return representation_epoch_;
    }
    [[nodiscard]] std::uint64_t committed_frame_id() const noexcept {
        return committed_frame_id_;
    }
    [[nodiscard]] std::uint64_t present_submitted_frame_id() const noexcept {
        return present_submitted_frame_id_;
    }
    [[nodiscard]] FramebufferQuality quality() const noexcept {
        return quality_;
    }
    [[nodiscard]] VisualRepresentation representation() const noexcept {
        return representation_;
    }

private:
    VisualRepresentation representation_{VisualRepresentation::recovery};
    FramebufferQuality quality_{FramebufferQuality::unavailable};
    std::uint64_t representation_epoch_{};
    std::uint64_t committed_frame_id_{};
    std::uint64_t present_submitted_frame_id_{};
    std::uint64_t pending_rect_base_{};
    std::uint64_t pending_rect_target_{};
    std::optional<std::uint64_t> ack_frame_id_;
};

class FullSnapshotAssemblyGuard final {
public:
    [[nodiscard]] bool begin(
        const VisualMessageHeader& header,
        const VisualFullSnapshotChunk& first) noexcept;
    [[nodiscard]] bool accept(
        const VisualMessageHeader& header,
        const VisualFullSnapshotChunk& chunk) noexcept;
    [[nodiscard]] bool ready_to_commit(
        const VisualMessageHeader& header,
        const VisualFrameCommit& commit) const noexcept;
    void cancel() noexcept;

    [[nodiscard]] bool active() const noexcept { return active_; }
    [[nodiscard]] std::uint32_t next_offset() const noexcept {
        return next_offset_;
    }
    [[nodiscard]] std::uint64_t frame_id() const noexcept {
        return frame_id_;
    }

private:
    bool matches(
        const VisualMessageHeader& header,
        const VisualFullSnapshotChunk& chunk) const noexcept;
    bool active_{};
    std::uint64_t session_generation_{};
    std::uint64_t representation_epoch_{};
    std::uint64_t frame_id_{};
    std::uint32_t width_{};
    std::uint32_t height_{};
    std::uint32_t row_stride_{};
    std::uint32_t total_bytes_{};
    std::uint32_t next_offset_{};
};

struct SnapshotWireRange {
    std::uint32_t offset{};
    std::uint32_t size{};
    bool final{};

    [[nodiscard]] bool operator==(const SnapshotWireRange&) const = default;
};

class SnapshotWireDrainPlan final {
public:
    [[nodiscard]] bool begin(
        std::uint64_t source_frame_id,
        std::uint32_t total_bytes,
        std::uint32_t row_stride,
        std::uint32_t chunk_limit = static_cast<std::uint32_t>(
            maximum_snapshot_wire_chunk_bytes),
        std::uint32_t burst_limit = 512U * 1024U) noexcept;
    [[nodiscard]] std::vector<SnapshotWireRange> take_burst();
    void observe_latest_source(std::uint64_t frame_id) noexcept;
    void cancel() noexcept;

    [[nodiscard]] bool active() const noexcept { return active_; }
    [[nodiscard]] bool complete() const noexcept {
        return active_ && next_offset_ == total_bytes_;
    }
    [[nodiscard]] std::uint64_t source_frame_id() const noexcept {
        return source_frame_id_;
    }
    [[nodiscard]] std::uint64_t latest_source_frame_id() const noexcept {
        return latest_source_frame_id_;
    }
    [[nodiscard]] std::uint64_t superseded_sources() const noexcept {
        return superseded_sources_;
    }
    [[nodiscard]] bool superseded() const noexcept {
        return latest_source_frame_id_ > source_frame_id_;
    }
    [[nodiscard]] std::uint32_t next_offset() const noexcept {
        return next_offset_;
    }

private:
    bool active_{};
    std::uint64_t source_frame_id_{};
    std::uint64_t latest_source_frame_id_{};
    std::uint64_t superseded_sources_{};
    std::uint32_t total_bytes_{};
    std::uint32_t row_stride_{};
    std::uint32_t chunk_bytes_{};
    std::uint32_t burst_limit_{};
    std::uint32_t next_offset_{};
};

class RawRectTransactionGuard final {
public:
    [[nodiscard]] bool accept(
        const VisualMessageHeader& header,
        const VisualRawRect& rectangle) noexcept;
    [[nodiscard]] bool ready_to_commit(
        const VisualMessageHeader& header,
        const VisualFrameCommit& commit) const noexcept;
    void cancel() noexcept;

    [[nodiscard]] bool active() const noexcept { return active_; }
    [[nodiscard]] std::size_t rectangle_count() const noexcept {
        return rectangles_.size();
    }
    [[nodiscard]] std::size_t packed_bytes() const noexcept {
        return packed_bytes_;
    }

private:
    struct Bounds {
        std::uint32_t left{};
        std::uint32_t top{};
        std::uint32_t right{};
        std::uint32_t bottom{};
    };

    bool active_{};
    std::uint64_t session_generation_{};
    std::uint64_t representation_epoch_{};
    std::uint64_t base_frame_id_{};
    std::uint64_t target_frame_id_{};
    std::uint32_t width_{};
    std::uint32_t height_{};
    std::size_t packed_bytes_{};
    std::vector<Bounds> rectangles_;
};

class InputFocusReleaseGate final {
public:
    void focus_acquired() noexcept;
    [[nodiscard]] bool focus_lost() noexcept;

private:
    bool focused_{true};
};

struct Viewport {
    std::uint32_t width{};
    std::uint32_t height{};
};

struct SurfacePoint {
    std::uint32_t x{};
    std::uint32_t y{};
};

[[nodiscard]] std::optional<SurfacePoint> map_pointer_to_surface(
    std::uint16_t normalized_x, std::uint16_t normalized_y,
    Viewport viewer, Viewport surface);

struct ClipboardUpdate {
    std::string origin;
    std::uint64_t revision{};
    std::string content_sha256;
    std::string utf8_text;
};

[[nodiscard]] std::vector<std::byte> encode_clipboard_update(const ClipboardUpdate& update);
[[nodiscard]] ClipboardUpdate decode_clipboard_update(std::span<const std::byte> bytes);

class ClipboardSynchronizer {
public:
    explicit ClipboardSynchronizer(std::string local_origin);
    [[nodiscard]] ClipboardUpdate make_update(
        std::string text, std::uint64_t revision,
        const core::AuthorizationResult& authorization);
    [[nodiscard]] bool apply(
        const ClipboardUpdate& update,
        const core::AuthorizationResult& authorization);
    [[nodiscard]] const std::optional<std::string>& latest_text() const noexcept {
        return latest_text_;
    }

private:
    std::string local_origin_;
    std::map<std::string, std::uint64_t> revisions_;
    std::optional<std::string> latest_hash_;
    std::optional<std::string> latest_text_;
};

struct VideoSettings {
    std::uint32_t width{1920};
    std::uint32_t height{1080};
    std::uint32_t frames_per_second{60};
    std::uint32_t bitrate_kbps{12000};
    std::uint32_t keyframe_interval{60};
};

struct NetworkTelemetry {
    std::uint32_t round_trip_ms{};
    std::uint32_t loss_basis_points{};
    std::uint32_t send_queue_ms{};
};

[[nodiscard]] VideoSettings adapt_video_settings(
    VideoSettings current, NetworkTelemetry telemetry);

struct LatencySample {
    std::uint64_t captured_at_us{};
    std::uint64_t encoded_at_us{};
    std::uint64_t received_at_us{};
    std::uint64_t decoded_at_us{};
    std::uint64_t displayed_at_us{};
};

class LatencyTelemetry {
public:
    void record(const LatencySample& sample);
    [[nodiscard]] std::uint64_t percentile_end_to_end(double percentile) const;
    [[nodiscard]] std::size_t size() const noexcept { return end_to_end_us_.size(); }

private:
    std::vector<std::uint64_t> end_to_end_us_;
};

class DesktopTransportSession {
public:
    DesktopTransportSession(
        transport::Transport& transport,
        core::AuthorizationResult authorization);
    void send_frame(const VideoFrame& frame);
    void request_keyframe(const KeyframeRequest& request);
    void send_input(const InputEvent& event);
    void send_clipboard(const ClipboardUpdate& update);

private:
    transport::Transport& transport_;
    core::AuthorizationResult authorization_;
    std::unique_ptr<transport::ReliableStream> control_stream_;
    std::unique_ptr<transport::ReliableStream> input_stream_;
    std::unique_ptr<transport::ReliableStream> clipboard_stream_;
};

}  // namespace rwn::desktop
