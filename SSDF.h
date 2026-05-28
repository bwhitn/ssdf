// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#ifndef SSDF_ENTROPY_WINDOW_SIZE
#define SSDF_ENTROPY_WINDOW_SIZE 64
#endif

#ifndef SSDF_ENTROPY_MODE
#define SSDF_ENTROPY_MODE 0
#endif

#ifndef SSDF_PROFILE_MINHASH_VALUES
#define SSDF_PROFILE_MINHASH_VALUES 24
#endif

#ifndef SSDF_PROFILE_BOTTOMK_VALUES
#define SSDF_PROFILE_BOTTOMK_VALUES 0
#endif

#ifndef SSDF_PROFILE_TOKEN_BITS
#define SSDF_PROFILE_TOKEN_BITS 18
#endif

namespace ssdf {

inline constexpr char SSDF_TOKEN_SEPARATOR = ':';
inline constexpr size_t SSDF_MINHASH18X24_VALUES = SSDF_PROFILE_MINHASH_VALUES;
inline constexpr size_t SSDF_MINHASH_VALUES = SSDF_MINHASH18X24_VALUES;
inline constexpr size_t SSDF_BOTTOMK_VALUES = SSDF_PROFILE_BOTTOMK_VALUES;
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

    void observe_cdc_window(uint64_t rolling_hash, uint64_t previous_rolling_hash, uint64_t scale_salt,
                            uint64_t gate_mask, size_t row_begin, size_t row_end, bool& has_last, uint64_t& last,
                            bool& pending_next);
    void observe_pending_cdc_next(uint64_t rolling_hash, uint64_t scale_salt, size_t row_begin, size_t row_end,
                                  bool& has_last, uint64_t& last, bool& pending_next);
    void observe_winnow64_window();
    void select_feature_range(uint64_t feature_hash, size_t row_begin, size_t row_end, bool& has_last,
                              uint64_t& last);
    void observe_bottomk(uint64_t feature_hash);
    void update_entropy_window(uint8_t byte);
    bool take_sample_slot(size_t& countdown);
    void reset_sample_slot(size_t& countdown) const;
    void refresh_entropy_sample_stride();

    std::array<uint64_t, 256> hash_history_ = {};
    uint64_t rolling64_hash_ = 0;
    uint64_t rolling96_hash_ = 0;
    uint64_t rolling128_hash_ = 0;
    uint64_t rolling192_hash_ = 0;

    uint64_t winnow64_salt_ = 0;
    uint64_t cdc64_salt_ = 0;
    uint64_t cdc96_salt_ = 0;
    uint64_t cdc128_salt_ = 0;
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
    bool has_last_cdc64_feature_ = false;
    uint64_t last_cdc64_feature_ = 0;
    bool has_last_cdc96_feature_ = false;
    uint64_t last_cdc96_feature_ = 0;
    bool has_last_cdc128_feature_ = false;
    uint64_t last_cdc128_feature_ = 0;
    bool pending_cdc64_next_ = false;
    bool pending_cdc96_next_ = false;
    bool pending_cdc128_next_ = false;
    bool pending_cdc192_next_ = false;

    std::array<uint8_t, SSDF_ENTROPY_WINDOW_SIZE> entropy_window_ = {};
#if SSDF_ENTROPY_MODE == 6
    std::array<uint8_t, 256> entropy_counts_ = {};
    uint32_t entropy_count_term_sum_scaled_ = 0;
#endif
    size_t entropy_window_size_ = 0;
    size_t entropy_window_next_ = 0;
    size_t entropy_bytes_since_stride_refresh_ = 0;
    size_t entropy_sample_stride_ = 64;

    size_t winnow_sample_countdown_ = 0;
    size_t cdc64_sample_countdown_ = 0;
    size_t cdc96_sample_countdown_ = 0;
    size_t cdc128_sample_countdown_ = 0;
    size_t cdc_sample_countdown_ = 0;

    std::array<uint64_t, SSDF_MINHASH_VALUES> minhash_values_;
    std::array<uint64_t, SSDF_MINHASH_VALUES> minhash_second_values_;
    std::array<uint64_t, SSDF_BOTTOMK_VALUES> bottomk_values_;
    Stats stats_;
};

std::string EncodeBase64Url18(uint32_t value);
std::string EncodeBase64Url24(uint32_t value);
std::string EncodeBase64Url30(uint32_t value);

namespace detail {

uint64_t Mix64(uint64_t value);
std::string MinHash18TokenForValue(std::string_view alg, size_t row_index, uint64_t value);

} // namespace detail

} // namespace ssdf
