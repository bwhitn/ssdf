// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ssdf {

inline constexpr char SSDF_TOKEN_SEPARATOR = ':';
inline constexpr size_t SSDF_MINHASH_VALUES = 80;
inline constexpr size_t SSDF_MINHASH18X24_VALUES = 24;
inline constexpr std::string_view SSDF_MINHASH18X24_ALG = "mh-buz32-96-192-w12-k24-h18-hh64-b64url";

struct Stats {
    uint64_t bytes_processed = 0;
    uint64_t rolling_windows = 0;
    uint64_t selected_features = 0;
    uint64_t minhash_updates = 0;
};

class Hasher {
public:
    Hasher();

    void update(const uint8_t* data, size_t len);

    std::optional<std::string> finalize() const;
    std::optional<std::array<uint64_t, SSDF_MINHASH_VALUES>> minhash_signature() const;

    const Stats& stats() const { return stats_; }

private:
    struct WinnowEntry {
        uint64_t value = 0;
        uint64_t index = 0;
    };

    struct RollingState {
        size_t window_size = 0;
        uint64_t scale_salt = 0;
        std::array<uint8_t, 192> rolling_window = {};
        size_t rolling_fill = 0;
        size_t rolling_pos = 0;
        uint64_t rolling_hash = 0;
        uint64_t feature_index = 0;
        std::array<WinnowEntry, 12> winnow_queue = {};
        size_t winnow_begin = 0;
        size_t winnow_size = 0;
        std::optional<uint64_t> last_selected_index;
    };

    void update_scale(RollingState& scale, uint8_t byte);
    void observe_complete_window(RollingState& scale);
    void select_feature(uint64_t feature_hash);

    std::array<RollingState, 3> rolling_scales_;
    std::optional<uint64_t> last_minhash_feature_;

    std::array<uint64_t, SSDF_MINHASH_VALUES> minhash_values_;
    Stats stats_;
};

std::string EncodeBase64Url18(uint32_t value);

namespace detail {

uint64_t Mix64(uint64_t value);
std::string MinHash18TokenForValue(std::string_view alg, size_t row_index, uint64_t value);

} // namespace detail

} // namespace ssdf
