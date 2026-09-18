#pragma once

#include <cstddef>
#include <stdexcept>

namespace rwn::desktop {

// GPU upload batching is independent from transport chunk boundaries.
inline std::size_t snapshot_upload_batch_size(std::size_t row_stride,
                                             std::size_t budget) {
    if (row_stride == 0 || row_stride > budget)
        throw std::invalid_argument("snapshot row exceeds upload budget");
    return (budget / row_stride) * row_stride;
}

} // namespace rwn::desktop
