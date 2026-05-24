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
inline constexpr size_t SSDF_MINHASH18X24_VALUES = 24;
inline constexpr size_t SSDF_MINHASH_VALUES = SSDF_MINHASH18X24_VALUES;
inline constexpr std::string_view SSDF_MINHASH18X24_ALG = "ssdf-alpha";

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

    void observe_cdc_window(uint64_t rolling_hash, uint64_t scale_salt);
    void observe_winnow64_window();
    void select_feature_range(uint64_t feature_hash, size_t row_begin, size_t row_end, bool& has_last,
                              uint64_t& last);

    std::array<uint64_t, 256> hash_history_ = {};
    uint64_t rolling64_hash_ = 0;
    uint64_t rolling192_hash_ = 0;

    uint64_t winnow64_salt_ = 0;
    uint64_t cdc192_salt_ = 0;

    uint64_t winnow64_feature_index_ = 0;
    std::array<WinnowEntry, 12> winnow64_queue_ = {};
    size_t winnow64_begin_ = 0;
    size_t winnow64_size_ = 0;
    bool has_winnow64_selected_index_ = false;
    uint64_t winnow64_selected_index_ = 0;

    bool has_last_winnow_feature_ = false;
    uint64_t last_winnow_feature_ = 0;
    bool has_last_cdc_feature_ = false;
    uint64_t last_cdc_feature_ = 0;

    std::array<uint64_t, SSDF_MINHASH_VALUES> minhash_values_;
    Stats stats_;
};

std::string EncodeBase64Url18(uint32_t value);

namespace detail {

uint64_t Mix64(uint64_t value);
std::string MinHash18TokenForValue(std::string_view alg, size_t row_index, uint64_t value);

} // namespace detail

} // namespace ssdf
