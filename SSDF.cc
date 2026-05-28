// See the file "COPYING" in the main distribution directory for copyright.

#include "SSDF.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>

#include "c/highwayhash.h"

#if defined(SSDF_PROFILE_NOINLINE) && (defined(__GNUC__) || defined(__clang__))
#define SSDF_ALWAYS_INLINE __attribute__((noinline))
#elif defined(__GNUC__) || defined(__clang__)
#define SSDF_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define SSDF_ALWAYS_INLINE inline
#endif

#ifndef SSDF_ENTROPY_STRIDE_MULTIPLIER
#define SSDF_ENTROPY_STRIDE_MULTIPLIER 1
#endif

#ifndef SSDF_ENTROPY_MODE
#define SSDF_ENTROPY_MODE 0
#endif

#ifdef SSDF_PROFILE_FIXED_SAMPLE_STRIDE
static_assert(SSDF_PROFILE_FIXED_SAMPLE_STRIDE > 0, "SSDF_PROFILE_FIXED_SAMPLE_STRIDE must be positive");
#endif

#ifndef SSDF_PROFILE_SAMPLE_SCHEDULE
#define SSDF_PROFILE_SAMPLE_SCHEDULE 0
#endif

#ifndef SSDF_PROFILE_WINNOW_ONLY
#define SSDF_PROFILE_WINNOW_ONLY 0
#endif

#ifndef SSDF_PROFILE_CDC_ONLY
#define SSDF_PROFILE_CDC_ONLY 0
#endif

#ifndef SSDF_PROFILE_CDC_WINDOW_SIZE
#define SSDF_PROFILE_CDC_WINDOW_SIZE 192
#endif

#ifndef SSDF_PROFILE_CDC_GATE_MASK
#define SSDF_PROFILE_CDC_GATE_MASK 127
#endif

#ifndef SSDF_PROFILE_CDC64_GATE_MASK
#define SSDF_PROFILE_CDC64_GATE_MASK SSDF_PROFILE_CDC_GATE_MASK
#endif

#ifndef SSDF_PROFILE_CDC96_GATE_MASK
#define SSDF_PROFILE_CDC96_GATE_MASK SSDF_PROFILE_CDC_GATE_MASK
#endif

#ifndef SSDF_PROFILE_CDC128_GATE_MASK
#define SSDF_PROFILE_CDC128_GATE_MASK SSDF_PROFILE_CDC_GATE_MASK
#endif

#ifndef SSDF_PROFILE_CDC192_GATE_MASK
#define SSDF_PROFILE_CDC192_GATE_MASK SSDF_PROFILE_CDC_GATE_MASK
#endif

#ifndef SSDF_PROFILE_CDC_MULTI_SIZE
#define SSDF_PROFILE_CDC_MULTI_SIZE 0
#endif

#ifndef SSDF_PROFILE_CDC64_ROWS
#define SSDF_PROFILE_CDC64_ROWS 8
#endif

#ifndef SSDF_PROFILE_CDC128_ROWS
#define SSDF_PROFILE_CDC128_ROWS 8
#endif

#ifndef SSDF_PROFILE_CDC192_ROWS
#define SSDF_PROFILE_CDC192_ROWS 8
#endif

#ifndef SSDF_PROFILE_CDC_ADJACENT_SAMPLES
#define SSDF_PROFILE_CDC_ADJACENT_SAMPLES 0
#endif

#ifndef SSDF_PROFILE_OUTPUT_MODE
#define SSDF_PROFILE_OUTPUT_MODE 0
#endif

#ifndef SSDF_PROFILE_HYBRID_STRICT_ROWS
#define SSDF_PROFILE_HYBRID_STRICT_ROWS 16
#endif

namespace ssdf {

namespace {

constexpr size_t kMinUsefulBytes = 64;
constexpr size_t kActiveWinnowingWindow = 12;
constexpr size_t kWinnowWindowSize = 64;
constexpr size_t kMinHashValues = SSDF_MINHASH_VALUES;
constexpr size_t kBottomKValues = SSDF_BOTTOMK_VALUES;
constexpr size_t kCdcWindowSize = SSDF_PROFILE_CDC_WINDOW_SIZE;
constexpr int kCdcMultiSize = SSDF_PROFILE_CDC_MULTI_SIZE;
constexpr size_t kCdc64Rows = SSDF_PROFILE_CDC64_ROWS;
constexpr size_t kCdc128Rows = SSDF_PROFILE_CDC128_ROWS;
constexpr size_t kCdc192Rows = SSDF_PROFILE_CDC192_ROWS;
constexpr size_t kCdc64RowBegin = 0;
constexpr size_t kCdc64RowEnd = kCdc64Rows;
constexpr size_t kCdc128RowBegin = kCdc64RowEnd;
constexpr size_t kCdc128RowEnd = kCdc128RowBegin + kCdc128Rows;
constexpr size_t kCdc192RowBegin = kCdc128RowEnd;
constexpr size_t kCdc192RowEnd = kCdc192RowBegin + kCdc192Rows;
constexpr size_t kMultiCdcMaxWindowSize = kCdc192Rows != 0 ? 192 : (kCdc128Rows != 0 ? 128 : 64);
constexpr size_t kMaxCdcWindowSize = kCdcMultiSize == 0 ? kCdcWindowSize : (kCdcMultiSize == 2 ? kMultiCdcMaxWindowSize : 192);
constexpr size_t kEntropyWindowSize = SSDF_ENTROPY_WINDOW_SIZE;
constexpr size_t kMaxEntropySampleStride = 64;
constexpr size_t kEntropyStrideRefreshBytes = 32;
constexpr size_t kEntropySampleStrideMultiplier = SSDF_ENTROPY_STRIDE_MULTIPLIER;
constexpr int kEntropyMode = SSDF_ENTROPY_MODE;
constexpr bool kWinnowOnly = SSDF_PROFILE_WINNOW_ONLY != 0;
constexpr bool kCdcOnly = SSDF_PROFILE_CDC_ONLY != 0;
constexpr size_t kWinnowRows = kWinnowOnly ? SSDF_MINHASH_VALUES : (kCdcOnly ? 0 : 14);
constexpr uint64_t kCdcGateMask = SSDF_PROFILE_CDC_GATE_MASK;
constexpr uint64_t kCdc64GateMask = SSDF_PROFILE_CDC64_GATE_MASK;
constexpr uint64_t kCdc96GateMask = SSDF_PROFILE_CDC96_GATE_MASK;
constexpr uint64_t kCdc128GateMask = SSDF_PROFILE_CDC128_GATE_MASK;
constexpr uint64_t kCdc192GateMask = SSDF_PROFILE_CDC192_GATE_MASK;
constexpr int kCdcAdjacentSamples = SSDF_PROFILE_CDC_ADJACENT_SAMPLES;
constexpr int kOutputMode = SSDF_PROFILE_OUTPUT_MODE;
constexpr size_t kHybridStrictRows = SSDF_PROFILE_HYBRID_STRICT_ROWS;
constexpr bool kTrackSecondMinHash = kOutputMode == 1;
constexpr bool kTrackBottomK = kBottomKValues != 0;
constexpr size_t kOutputTokenBits = SSDF_PROFILE_TOKEN_BITS;
constexpr size_t kOutputTokenChars = kOutputTokenBits == 30 ? 5 : (kOutputTokenBits == 24 ? 4 : 3);
constexpr uint64_t kFeatureSalt = 0x7a09e667f3bcc909ULL;
constexpr uint64_t kMinHashSeed = 0x243f6a8885a308d3ULL;
constexpr uint64_t kMinUsefulSelectedFeatures = 4;
constexpr uint64_t kWinnowPreGateMask = 3;
constexpr uint64_t kWinnowPostGateMask = 3;
// Fixed public key for stable HighwayHash output. This is algorithm domain
// separation, not a secret authentication key.
constexpr uint64_t kHighwayHashKey[4] = {0x6d682d6c73682d76ULL, 0x312d62757a36342dULL, 0x7733322d6b33322dULL,
                                         0x6831382d68363834ULL};

static_assert(kMinHashValues == SSDF_MINHASH_VALUES);
static_assert(kWinnowRows <= SSDF_MINHASH_VALUES);
static_assert(kWinnowRows > 0 || kCdcOnly);
static_assert(! (kWinnowOnly && kCdcOnly));
static_assert(kCdcWindowSize <= 192);
static_assert(kCdcMultiSize >= 0 && kCdcMultiSize <= 2);
static_assert(kCdcMultiSize == 0 || kCdcOnly);
static_assert(kCdcMultiSize != 2 || kOutputMode == 3 || kCdc64Rows + kCdc128Rows + kCdc192Rows == kMinHashValues);
static_assert(kCdc64Rows + kCdc128Rows + kCdc192Rows <= kMinHashValues);
static_assert(kCdcAdjacentSamples >= 0 && kCdcAdjacentSamples <= 3);
static_assert(kOutputMode >= 0 && kOutputMode <= 3);
static_assert(kOutputMode != 2 || kBottomKValues != 0);
static_assert(kOutputMode != 3 || kBottomKValues != 0);
static_assert(kOutputMode != 3 || kHybridStrictRows <= kMinHashValues);
static_assert(kOutputTokenBits == 18 || kOutputTokenBits == 24 || kOutputTokenBits == 30);
static_assert(kEntropyMode >= 0 && kEntropyMode <= 6);

constexpr std::array<uint64_t, 256> kByteHashTable = {
    0x71f56d55bb21ddd7ULL, 0xf7dbbedc4cb6c316ULL, 0x9b323244a20947a6ULL, 0x76ae578f4cefa3dbULL,
    0x91e27edc43d76f1dULL, 0x808bce4b89c8f68eULL, 0x9f0f107fd6d65b6aULL, 0x318627f810634537ULL,
    0xf38355cb8484007dULL, 0x4fdd70dcd4062fd4ULL, 0x17d977a50b8782ddULL, 0x90714cee5d970f07ULL,
    0x4146fcc724b0ececULL, 0x7adf9a7159d09b1aULL, 0x905fed86b360335eULL, 0x6b9f7b199a070897ULL,
    0x366e9ae64b050509ULL, 0x7c03904eb419e137ULL, 0x1d0b07b72f689684ULL, 0xa117b03017f78942ULL,
    0xa0713ffa48058a59ULL, 0x1ce64c3a0f988f0cULL, 0x2f6abcdb5b9e8a1bULL, 0x95c815eb6b5be327ULL,
    0x5ff202236699bd1fULL, 0x66d02c1fe566e837ULL, 0x836dded9f5b7d5b6ULL, 0xeb60b78fd7ec9917ULL,
    0x5fb18ecf4cacf28aULL, 0x140b292354a98dc0ULL, 0x846b86686f05b63dULL, 0x49fc3e99b31311ceULL,
    0x6e6e10a6c227f08cULL, 0x5a6e292fc04a96dfULL, 0x2a7ffa89ede5817dULL, 0xfdd6d74055cc2b34ULL,
    0x266fd31dd3edad87ULL, 0xddecb333da60681cULL, 0x2f6bf6519076c6cfULL, 0xb5b72477d78e275eULL,
    0xa1441d270a936040ULL, 0xfe5e979b5bf0de0eULL, 0x4eb6ac209da0061eULL, 0xab1e0551d3571717ULL,
    0x2f226552af923092ULL, 0x299b024fc7a14d9dULL, 0x8bebe223aba73eb1ULL, 0xc319af8c550640eaULL,
    0x26a88ab7d0f9d016ULL, 0x34fc72aceacd7011ULL, 0x3e72357ffcee72b3ULL, 0xceeaec2d1c041c11ULL,
    0x338cf495cb563d75ULL, 0x639c86174587337bULL, 0xc74d2d7d07df7f98ULL, 0xee5aac6b973b2240ULL,
    0x382587ef26b337e6ULL, 0x5cf8df39bc02a3c1ULL, 0x1b36b49d9575a7e1ULL, 0xe21d57c0335a042cULL,
    0xba555927a13fd480ULL, 0x7ff510765659f745ULL, 0xd18e4e17fa025a25ULL, 0xd9f5e708afec0691ULL,
    0x9707b4d872f1c492ULL, 0x5043809eec9c0538ULL, 0x867c973afa4b70a8ULL, 0x604de846ae93fb57ULL,
    0x6c1e663a2b88ecadULL, 0x2f19afe4725e9472ULL, 0x289a87a0b20932c9ULL, 0xed0d02f3da02c628ULL,
    0x08f31d91976808c9ULL, 0x58cc83ad827f7fafULL, 0xc92efa31e56e6789ULL, 0x10bcc19474f4e671ULL,
    0x2946b91eb651127dULL, 0x808206790847895bULL, 0x2c452e5feec89300ULL, 0x9f1ef227b05a11dfULL,
    0x7b222657cd8bcac9ULL, 0x3519dd61b92e38a2ULL, 0x80fbadd0a207517eULL, 0x8591f0231e895337ULL,
    0x4ac52dfe199cca09ULL, 0x0df08f05825467b9ULL, 0x904fd38750bec071ULL, 0x14286d474f4ed4d2ULL,
    0x37c806b87493c058ULL, 0xccbc75ffedbd79afULL, 0x9ff95e41758d80b0ULL, 0xe435df79df408599ULL,
    0x9b2147be47dda650ULL, 0x69dd1767ec2595e5ULL, 0x49c80e494797d38cULL, 0x3b000fe095c9ae40ULL,
    0xfd9539a585bb8cbdULL, 0x806bb7e58ce29a41ULL, 0xbb1b9485f8d81d18ULL, 0x6ee634142dd4a853ULL,
    0x08aa309a094c64d5ULL, 0x138f9cb2ffb085e2ULL, 0x833404f9ac916167ULL, 0x7e0a09c1eb77b8ceULL,
    0xa998a094f267224eULL, 0xbf5c32a13d4fee37ULL, 0x4ab296659d516ebcULL, 0x53e0bdffea669250ULL,
    0x014e82d8eaa9156cULL, 0x6a0d9964a08cf843ULL, 0x088068bda513f0daULL, 0x80652a76145fb078ULL,
    0x9fa430e20bd83c21ULL, 0xe2e0bca678a5d2efULL, 0xc08d61dca8d044eaULL, 0x03c75605f4fd0b64ULL,
    0xda508aa3a50bf1bfULL, 0x85492379e9de1417ULL, 0xdf9087204cfe4a5dULL, 0x019089edbfb91980ULL,
    0x6db4a1e25437faeaULL, 0x3a0c2e919300cac6ULL, 0xe5f359bfb3dd4f6fULL, 0xd41c9eaf6519d20fULL,
    0x95b3bf5923a59c90ULL, 0x1e02013580465017ULL, 0x4b4635c808adcbe7ULL, 0xd6da2ad1ff1e1d50ULL,
    0xae66e16d6cbccb46ULL, 0x6964e8ed026426f0ULL, 0x0a6724f0fc18c118ULL, 0x606776d30412b44aULL,
    0xf04ca0380d1ef3ddULL, 0x8dfab93698d03797ULL, 0x15c1e480c6e4d1b6ULL, 0xeabe1fc3ee028cbdULL,
    0x00c3fbc73cf9602eULL, 0xbb99dafcb608ee44ULL, 0xa06949120bbf3620ULL, 0xdee8512940ad70c8ULL,
    0x9f4d13e3e3bf32d1ULL, 0x40f614ed3d120df2ULL, 0x496818f57052ccb9ULL, 0x15668cc85209c900ULL,
    0xcd677ef6199726d8ULL, 0xa92aa4f7b1109064ULL, 0x97cf302ee495ced8ULL, 0xa6fd5e049df12bc4ULL,
    0xf0d5115ec4adf524ULL, 0xa9f7e542ddff5ad8ULL, 0x52b6024c43e7ae16ULL, 0xf302016aeb2693deULL,
    0x2d547228e58a43caULL, 0x3464ddbe467c2ba5ULL, 0xed5e48fb967533acULL, 0x8ef31d9c21e33bbdULL,
    0x7ee3113d68ee073cULL, 0x711541ebb6e3c582ULL, 0x862ba5ed6be708caULL, 0x71ad6bdb9339453bULL,
    0xd0319efef3e7954fULL, 0x27d3b2f243b579bbULL, 0x48487440a9cf2914ULL, 0x8ca377337f297096ULL,
    0xe520d2d80a15723cULL, 0x7f74e45dc7eb1844ULL, 0x923728508ac12e2cULL, 0x0b6b013ef54bbebdULL,
    0x2df45a73ed17739fULL, 0xeb33ec8a90250112ULL, 0x5593a0158b5c663fULL, 0xb24397a1b7e50d10ULL,
    0x3e19856813b2fd6eULL, 0x8245ebfca358d939ULL, 0x353ab0fded9edab8ULL, 0xa3ff3fd951752426ULL,
    0xbaffac320b5b4933ULL, 0x2c75c991878942e1ULL, 0xa490eba6c1b7d2acULL, 0xe29e7c8280db5978ULL,
    0x774974de6adba8d3ULL, 0xe897dcf3f7bad8aeULL, 0x37ecee2956e92536ULL, 0xe5f12112a7c2e9a4ULL,
    0xca21ac8a7ab7818bULL, 0x27f66637c9de58b1ULL, 0x785a84e49cab4740ULL, 0x3cf9bf69bed7bfbfULL,
    0x774ff3de4790c006ULL, 0x7fdc379aeb0e3320ULL, 0xe9adbd6586db717aULL, 0x88d32e287d71bcaaULL,
    0x57eb6e38e4e52addULL, 0x3f5457126d338baeULL, 0x99a4d6a8989aab7cULL, 0x5e1c80c3ff83d4fbULL,
    0x88ac90e7e0958b57ULL, 0x5a6bd48cab3501a3ULL, 0x9bd2b751e0538b34ULL, 0x439bf587480bb471ULL,
    0x1861301c35c37fd5ULL, 0x40732587344d261fULL, 0xb449b41a1b604569ULL, 0xb0c71032a38a69c3ULL,
    0x7c17350d32912c4fULL, 0xfea85c596464cc1cULL, 0xc7a26d08ebaab92aULL, 0xa2d7b725e82609fbULL,
    0x1ca6e1f595d7bd4fULL, 0x91197ff90841e8a5ULL, 0xb5bce2e1e62df995ULL, 0x81c08d165f72a2d8ULL,
    0x828870bb331144b7ULL, 0xa4756c9f75f9a556ULL, 0x185d2ec4df98b244ULL, 0x37571b6a2d3332daULL,
    0xe78f94a022637e7bULL, 0x52fc508e26bf9fc8ULL, 0x2006dc09b1ad0a53ULL, 0x7d3a4af8dd1a3628ULL,
    0x5aaa896e15cab041ULL, 0xd9bad282d9082acaULL, 0xf318e15db8151875ULL, 0x9b480577b09ecc66ULL,
    0xc49604d8bd642ee8ULL, 0x76e31c9f587ffcfeULL, 0x4f28e5fa0f7f7ac5ULL, 0xab28deef79cc971eULL,
    0xf6a322988cc688d1ULL, 0x9f5da25cca3ec263ULL, 0x27197594abc094d0ULL, 0x4a62f70d1e925fb8ULL,
    0x0fd9580334076d10ULL, 0xc4ca068902b9663dULL, 0x5c7605c12e81259bULL, 0x44a956b3da939f0bULL,
    0x5fffa6dbef35c6ecULL, 0x1c97ac770a7aadfaULL, 0x758f1159ea6157b8ULL, 0x39e3808e5d53424cULL,
    0xcbadc54723d957caULL, 0x4fcf7f4b0f0ba16cULL, 0x155901136d4b11a3ULL, 0xe30b088cd9e0fa61ULL,
    0xb0b5d1029ac5fde4ULL, 0x6d582dbaaebc8c72ULL, 0x3931f902dcabd7c9ULL, 0x44319d04005a85aeULL,
    0x044c1eede1778530ULL, 0x355f923ea2e8aaf6ULL, 0x58377c4612ba5662ULL, 0xd50d74b0f2ce3b42ULL,
    0x62011324d27c74a3ULL, 0x57fc081a25435f33ULL, 0x6895926a03752492ULL, 0x99ca11d67fbeab3cULL};


SSDF_ALWAYS_INLINE uint64_t Rotl1(uint64_t value) {
    return (value << 1U) | (value >> 63U);
}

SSDF_ALWAYS_INLINE uint64_t UpdateRollingWindowHash(uint64_t rolling_hash, uint64_t byte_hash,
                                                    const std::array<uint64_t, 256>& history, uint64_t offset,
                                                    size_t window_size) {
    if ( offset < window_size )
        return Rotl1(rolling_hash) ^ byte_hash;

    return Rotl1(rolling_hash) ^ history[(offset - window_size) & 0xffU] ^ byte_hash;
}

class HighwayHashInput {
public:
    void AppendBytes(const void* bytes, size_t len) {
        if ( size_ + len > data_.size() )
            throw std::length_error("ssdf HighwayHash input buffer is too small");

        const auto* src = static_cast<const uint8_t*>(bytes);
        std::copy_n(src, len, data_.data() + size_);
        size_ += len;
    }

    void AppendAlg(std::string_view alg) {
        AppendBytes(alg.data(), alg.size());
        AppendU8(0);
    }

    void AppendU8(uint8_t value) { AppendBytes(&value, sizeof(value)); }

    void AppendU64(uint64_t value) {
        std::array<uint8_t, sizeof(value)> bytes = {};

        for ( auto& byte : bytes ) {
            byte = static_cast<uint8_t>(value & 0xffU);
            value >>= 8U;
        }

        AppendBytes(bytes.data(), bytes.size());
    }

    uint64_t Hash() const { return HighwayHash64(data_.data(), size_, kHighwayHashKey); }

private:
    std::array<uint8_t, 192> data_ = {};
    size_t size_ = 0;
};

std::array<uint64_t, kMinHashValues> MakeMinHashRowSeeds() {
    std::array<uint64_t, kMinHashValues> seeds = {};

    for ( size_t i = 0; i < seeds.size(); ++i ) {
        const auto seed = kMinHashSeed + static_cast<uint64_t>(i) * 0x9e3779b97f4a7c15ULL;
        seeds[i] = detail::Mix64(seed);
    }

    return seeds;
}

const auto kMinHashRowSeeds = MakeMinHashRowSeeds();

uint64_t FeatureSalt(size_t window_size, size_t scale_index) {
    return kFeatureSalt ^ detail::Mix64(window_size + static_cast<uint64_t>(scale_index) * 0x9e3779b97f4a7c15ULL);
}

SSDF_ALWAYS_INLINE uint64_t CdcAdjacentSalt(uint64_t scale_salt, uint64_t direction) {
    return scale_salt ^ detail::Mix64(0x6a09e667f3bcc909ULL + direction * 0x9e3779b97f4a7c15ULL);
}

SSDF_ALWAYS_INLINE size_t NextWinnowIndex(size_t index) {
    ++index;
    return index == kActiveWinnowingWindow ? 0 : index;
}

SSDF_ALWAYS_INLINE size_t WinnowIndex(size_t begin, size_t offset) {
    auto index = begin + offset;
    return index >= kActiveWinnowingWindow ? index - kActiveWinnowingWindow : index;
}

const std::array<double, kEntropyWindowSize + 1>& CountLog2CountTable() {
    static const auto table = [] {
        std::array<double, kEntropyWindowSize + 1> values = {};
        for ( size_t i = 1; i < values.size(); ++i )
            values[i] = static_cast<double>(i) * std::log2(static_cast<double>(i));

        return values;
    }();

    return table;
}

const std::array<uint32_t, kEntropyWindowSize + 1>& ScaledCountLog2CountTable() {
    static constexpr double kEntropyScale = 1024.0;
    static const auto table = [] {
        std::array<uint32_t, kEntropyWindowSize + 1> values = {};
        for ( size_t i = 1; i < values.size(); ++i )
            values[i] = static_cast<uint32_t>(
                std::llround(static_cast<double>(i) * std::log2(static_cast<double>(i)) * kEntropyScale));

        return values;
    }();

    return table;
}

const std::array<double, kEntropyWindowSize * 2 + 1>& NibbleCountLog2CountTable() {
    static const auto table = [] {
        std::array<double, kEntropyWindowSize * 2 + 1> values = {};
        for ( size_t i = 1; i < values.size(); ++i )
            values[i] = static_cast<double>(i) * std::log2(static_cast<double>(i));

        return values;
    }();

    return table;
}

SSDF_ALWAYS_INLINE size_t PopCount64(uint64_t value) {
#if defined(__GNUC__) || defined(__clang__)
    return static_cast<size_t>(__builtin_popcountll(value));
#else
    size_t count = 0;
    while ( value != 0 ) {
        value &= value - 1;
        ++count;
    }
    return count;
#endif
}

SSDF_ALWAYS_INLINE void MarkSeenByte(std::array<uint64_t, 4>& seen, uint8_t byte) {
    seen[byte >> 6U] |= uint64_t{1} << (byte & 63U);
}

SSDF_ALWAYS_INLINE size_t CountSeenBytes(const std::array<uint64_t, 4>& seen) {
    return PopCount64(seen[0]) + PopCount64(seen[1]) + PopCount64(seen[2]) + PopCount64(seen[3]);
}

size_t EntropyStride(double entropy) {
    if ( entropy <= 0.0 )
        return kMaxEntropySampleStride;

    const auto stride = static_cast<size_t>(std::ceil(8.0 / entropy)) * kEntropySampleStrideMultiplier;
    return std::clamp(stride, size_t{1}, kMaxEntropySampleStride);
}

size_t EntropyStrideFromScaled(uint32_t entropy_scaled) {
    static constexpr uint32_t kEntropyScale = 1024;
    if ( entropy_scaled == 0 )
        return kMaxEntropySampleStride;

    const auto numerator = 8U * kEntropyScale;
    const auto stride = static_cast<size_t>((numerator + entropy_scaled - 1U) / entropy_scaled) *
                        kEntropySampleStrideMultiplier;
    return std::clamp(stride, size_t{1}, kMaxEntropySampleStride);
}

} // namespace

namespace detail {

uint64_t Mix64(uint64_t value) {
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31U;
    return value;
}

std::string MinHash18TokenForValue(std::string_view alg, size_t row_index, uint64_t value) {
    HighwayHashInput input;
    input.AppendAlg(alg);
    input.AppendU64(static_cast<uint64_t>(row_index));
    input.AppendU64(value);

    const auto final_hash = input.Hash();
    return EncodeBase64Url18(static_cast<uint32_t>(final_hash & 0x3ffffU));
}

std::string MinHash24TokenForValue(std::string_view alg, size_t row_index, uint64_t value) {
    HighwayHashInput input;
    input.AppendAlg(alg);
    input.AppendU64(static_cast<uint64_t>(row_index));
    input.AppendU64(value);

    const auto final_hash = input.Hash();
    return EncodeBase64Url24(static_cast<uint32_t>(final_hash & 0xffffffU));
}

std::string MinHash30TokenForValue(std::string_view alg, size_t row_index, uint64_t value) {
    HighwayHashInput input;
    input.AppendAlg(alg);
    input.AppendU64(static_cast<uint64_t>(row_index));
    input.AppendU64(value);

    const auto final_hash = input.Hash();
    return EncodeBase64Url30(static_cast<uint32_t>(final_hash & 0x3fffffffU));
}

std::string MinHashProfileTokenForValue(std::string_view alg, size_t row_index, uint64_t value) {
    if constexpr ( kOutputTokenBits == 30 )
        return MinHash30TokenForValue(alg, row_index, value);
    else if constexpr ( kOutputTokenBits == 24 )
        return MinHash24TokenForValue(alg, row_index, value);
    else
        return MinHash18TokenForValue(alg, row_index, value);
}

} // namespace detail

std::string EncodeBase64Url18(uint32_t value) {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    value &= 0x3ffffU;

    std::string result;
    result.resize(3);
    result[0] = kAlphabet[(value >> 12U) & 0x3fU];
    result[1] = kAlphabet[(value >> 6U) & 0x3fU];
    result[2] = kAlphabet[value & 0x3fU];
    return result;
}

std::string EncodeBase64Url24(uint32_t value) {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    value &= 0xffffffU;

    std::string result;
    result.resize(4);
    result[0] = kAlphabet[(value >> 18U) & 0x3fU];
    result[1] = kAlphabet[(value >> 12U) & 0x3fU];
    result[2] = kAlphabet[(value >> 6U) & 0x3fU];
    result[3] = kAlphabet[value & 0x3fU];
    return result;
}

std::string EncodeBase64Url30(uint32_t value) {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    value &= 0x3fffffffU;

    std::string result;
    result.resize(5);
    result[0] = kAlphabet[(value >> 24U) & 0x3fU];
    result[1] = kAlphabet[(value >> 18U) & 0x3fU];
    result[2] = kAlphabet[(value >> 12U) & 0x3fU];
    result[3] = kAlphabet[(value >> 6U) & 0x3fU];
    result[4] = kAlphabet[value & 0x3fU];
    return result;
}

void Hasher::update(const uint8_t* data, size_t len) {
    if ( ! data && len != 0 )
        throw std::invalid_argument("Hasher::update received null data with non-zero length");

    size_t i = 0;

    for ( ; i < len && stats_.bytes_processed < kMaxCdcWindowSize; ++i ) {
        const auto byte = data[i];
        const auto byte_hash = kByteHashTable[byte];
        const auto offset = stats_.bytes_processed++;
        hash_history_[offset & 0xffU] = byte_hash;
        update_entropy_window(byte);

        if constexpr ( ! kCdcOnly ) {
            if ( offset < kWinnowWindowSize ) {
                rolling64_hash_ = Rotl1(rolling64_hash_) ^ byte_hash;
                if ( offset + 1 == kWinnowWindowSize && take_sample_slot(winnow_sample_countdown_) ) {
                    observe_winnow64_window();
                    reset_sample_slot(winnow_sample_countdown_);
                }
            }
            else {
                const auto old_hash = hash_history_[(offset - kWinnowWindowSize) & 0xffU];
                rolling64_hash_ = Rotl1(rolling64_hash_) ^ old_hash ^ byte_hash;
                if ( take_sample_slot(winnow_sample_countdown_) ) {
                    observe_winnow64_window();
                    reset_sample_slot(winnow_sample_countdown_);
                }
            }
        }

        if constexpr ( ! kWinnowOnly ) {
            if constexpr ( kCdcMultiSize == 1 ) {
                const auto previous96_hash = rolling96_hash_;
                const auto previous192_hash = rolling192_hash_;
                rolling96_hash_ = UpdateRollingWindowHash(rolling96_hash_, byte_hash, hash_history_, offset, 96);
                rolling192_hash_ = UpdateRollingWindowHash(rolling192_hash_, byte_hash, hash_history_, offset, 192);
                if ( offset + 1 >= 96 ) {
                    observe_pending_cdc_next(rolling96_hash_, cdc96_salt_, 0, kMinHashValues / 2,
                                             has_last_cdc96_feature_, last_cdc96_feature_, pending_cdc96_next_);
                    if ( take_sample_slot(cdc96_sample_countdown_) ) {
                        observe_cdc_window(rolling96_hash_, offset + 1 > 96 ? previous96_hash : 0, cdc96_salt_,
                                           kCdc96GateMask, 0, kMinHashValues / 2, has_last_cdc96_feature_,
                                           last_cdc96_feature_, pending_cdc96_next_);
                        reset_sample_slot(cdc96_sample_countdown_);
                    }
                }
                if ( offset + 1 == 192 ) {
                    observe_pending_cdc_next(rolling192_hash_, cdc192_salt_, kMinHashValues / 2, kMinHashValues,
                                             has_last_cdc_feature_, last_cdc_feature_, pending_cdc192_next_);
                    if ( take_sample_slot(cdc_sample_countdown_) ) {
                        observe_cdc_window(rolling192_hash_, offset + 1 > 192 ? previous192_hash : 0, cdc192_salt_,
                                           kCdc192GateMask, kMinHashValues / 2, kMinHashValues,
                                           has_last_cdc_feature_, last_cdc_feature_, pending_cdc192_next_);
                        reset_sample_slot(cdc_sample_countdown_);
                    }
                }
            }
            else if constexpr ( kCdcMultiSize == 2 ) {
                const auto previous64_hash = rolling64_hash_;
                const auto previous128_hash = rolling128_hash_;
                const auto previous192_hash = rolling192_hash_;
                if constexpr ( kCdc64Rows != 0 )
                    rolling64_hash_ = UpdateRollingWindowHash(rolling64_hash_, byte_hash, hash_history_, offset, 64);
                if constexpr ( kCdc128Rows != 0 )
                    rolling128_hash_ =
                        UpdateRollingWindowHash(rolling128_hash_, byte_hash, hash_history_, offset, 128);
                if constexpr ( kCdc192Rows != 0 )
                    rolling192_hash_ =
                        UpdateRollingWindowHash(rolling192_hash_, byte_hash, hash_history_, offset, 192);
                if constexpr ( kCdc64Rows != 0 ) {
                    if ( offset + 1 >= 64 ) {
                        observe_pending_cdc_next(rolling64_hash_, cdc64_salt_, kCdc64RowBegin, kCdc64RowEnd,
                                                 has_last_cdc64_feature_, last_cdc64_feature_, pending_cdc64_next_);
                        if ( take_sample_slot(cdc64_sample_countdown_) ) {
                            observe_cdc_window(rolling64_hash_, offset + 1 > 64 ? previous64_hash : 0,
                                               cdc64_salt_, kCdc64GateMask, kCdc64RowBegin, kCdc64RowEnd,
                                               has_last_cdc64_feature_, last_cdc64_feature_, pending_cdc64_next_);
                            reset_sample_slot(cdc64_sample_countdown_);
                        }
                    }
                }
                if constexpr ( kCdc128Rows != 0 ) {
                    if ( offset + 1 >= 128 ) {
                        observe_pending_cdc_next(rolling128_hash_, cdc128_salt_, kCdc128RowBegin, kCdc128RowEnd,
                                                 has_last_cdc128_feature_, last_cdc128_feature_,
                                                 pending_cdc128_next_);
                        if ( take_sample_slot(cdc128_sample_countdown_) ) {
                            observe_cdc_window(rolling128_hash_, offset + 1 > 128 ? previous128_hash : 0,
                                               cdc128_salt_, kCdc128GateMask, kCdc128RowBegin, kCdc128RowEnd,
                                               has_last_cdc128_feature_, last_cdc128_feature_,
                                               pending_cdc128_next_);
                            reset_sample_slot(cdc128_sample_countdown_);
                        }
                    }
                }
                if constexpr ( kCdc192Rows != 0 ) {
                    if ( offset + 1 == 192 ) {
                        observe_pending_cdc_next(rolling192_hash_, cdc192_salt_, kCdc192RowBegin, kCdc192RowEnd,
                                                 has_last_cdc_feature_, last_cdc_feature_, pending_cdc192_next_);
                        if ( take_sample_slot(cdc_sample_countdown_) ) {
                            observe_cdc_window(rolling192_hash_, offset + 1 > 192 ? previous192_hash : 0,
                                               cdc192_salt_, kCdc192GateMask, kCdc192RowBegin, kCdc192RowEnd,
                                               has_last_cdc_feature_, last_cdc_feature_, pending_cdc192_next_);
                            reset_sample_slot(cdc_sample_countdown_);
                        }
                    }
                }
            }
            else {
                const auto previous192_hash = rolling192_hash_;
                rolling192_hash_ =
                    UpdateRollingWindowHash(rolling192_hash_, byte_hash, hash_history_, offset, kCdcWindowSize);
                if ( offset + 1 == kCdcWindowSize ) {
                    observe_pending_cdc_next(rolling192_hash_, cdc192_salt_, kWinnowRows, minhash_values_.size(),
                                             has_last_cdc_feature_, last_cdc_feature_, pending_cdc192_next_);
                    if ( take_sample_slot(cdc_sample_countdown_) ) {
                        observe_cdc_window(rolling192_hash_, offset + 1 > kCdcWindowSize ? previous192_hash : 0,
                                           cdc192_salt_, kCdc192GateMask, kWinnowRows, minhash_values_.size(),
                                           has_last_cdc_feature_, last_cdc_feature_, pending_cdc192_next_);
                        reset_sample_slot(cdc_sample_countdown_);
                    }
                }
            }
        }
    }

    for ( ; i < len; ++i ) {
        const auto byte = data[i];
        const auto byte_hash = kByteHashTable[byte];
        const auto offset = stats_.bytes_processed++;
        hash_history_[offset & 0xffU] = byte_hash;
        update_entropy_window(byte);

        if constexpr ( ! kCdcOnly ) {
            rolling64_hash_ =
                UpdateRollingWindowHash(rolling64_hash_, byte_hash, hash_history_, offset, kWinnowWindowSize);
            if ( take_sample_slot(winnow_sample_countdown_) ) {
                observe_winnow64_window();
                reset_sample_slot(winnow_sample_countdown_);
            }
        }

        if constexpr ( ! kWinnowOnly ) {
            if constexpr ( kCdcMultiSize == 1 ) {
                const auto previous96_hash = rolling96_hash_;
                const auto previous192_hash = rolling192_hash_;
                rolling96_hash_ = UpdateRollingWindowHash(rolling96_hash_, byte_hash, hash_history_, offset, 96);
                rolling192_hash_ = UpdateRollingWindowHash(rolling192_hash_, byte_hash, hash_history_, offset, 192);
                observe_pending_cdc_next(rolling96_hash_, cdc96_salt_, 0, kMinHashValues / 2,
                                         has_last_cdc96_feature_, last_cdc96_feature_, pending_cdc96_next_);
                if ( take_sample_slot(cdc96_sample_countdown_) ) {
                    observe_cdc_window(rolling96_hash_, previous96_hash, cdc96_salt_, kCdc96GateMask, 0,
                                       kMinHashValues / 2, has_last_cdc96_feature_, last_cdc96_feature_,
                                       pending_cdc96_next_);
                    reset_sample_slot(cdc96_sample_countdown_);
                }
                observe_pending_cdc_next(rolling192_hash_, cdc192_salt_, kMinHashValues / 2, kMinHashValues,
                                         has_last_cdc_feature_, last_cdc_feature_, pending_cdc192_next_);
                if ( take_sample_slot(cdc_sample_countdown_) ) {
                    observe_cdc_window(rolling192_hash_, previous192_hash, cdc192_salt_, kCdc192GateMask,
                                       kMinHashValues / 2, kMinHashValues, has_last_cdc_feature_,
                                       last_cdc_feature_, pending_cdc192_next_);
                    reset_sample_slot(cdc_sample_countdown_);
                }
            }
            else if constexpr ( kCdcMultiSize == 2 ) {
                const auto previous64_hash = rolling64_hash_;
                const auto previous128_hash = rolling128_hash_;
                const auto previous192_hash = rolling192_hash_;
                if constexpr ( kCdc64Rows != 0 )
                    rolling64_hash_ = UpdateRollingWindowHash(rolling64_hash_, byte_hash, hash_history_, offset, 64);
                if constexpr ( kCdc128Rows != 0 )
                    rolling128_hash_ =
                        UpdateRollingWindowHash(rolling128_hash_, byte_hash, hash_history_, offset, 128);
                if constexpr ( kCdc192Rows != 0 )
                    rolling192_hash_ =
                        UpdateRollingWindowHash(rolling192_hash_, byte_hash, hash_history_, offset, 192);
                if constexpr ( kCdc64Rows != 0 ) {
                    observe_pending_cdc_next(rolling64_hash_, cdc64_salt_, kCdc64RowBegin, kCdc64RowEnd,
                                             has_last_cdc64_feature_, last_cdc64_feature_, pending_cdc64_next_);
                    if ( take_sample_slot(cdc64_sample_countdown_) ) {
                        observe_cdc_window(rolling64_hash_, previous64_hash, cdc64_salt_, kCdc64GateMask,
                                           kCdc64RowBegin, kCdc64RowEnd, has_last_cdc64_feature_,
                                           last_cdc64_feature_, pending_cdc64_next_);
                        reset_sample_slot(cdc64_sample_countdown_);
                    }
                }
                if constexpr ( kCdc128Rows != 0 ) {
                    observe_pending_cdc_next(rolling128_hash_, cdc128_salt_, kCdc128RowBegin, kCdc128RowEnd,
                                             has_last_cdc128_feature_, last_cdc128_feature_,
                                             pending_cdc128_next_);
                    if ( take_sample_slot(cdc128_sample_countdown_) ) {
                        observe_cdc_window(rolling128_hash_, previous128_hash, cdc128_salt_, kCdc128GateMask,
                                           kCdc128RowBegin, kCdc128RowEnd, has_last_cdc128_feature_,
                                           last_cdc128_feature_, pending_cdc128_next_);
                        reset_sample_slot(cdc128_sample_countdown_);
                    }
                }
                if constexpr ( kCdc192Rows != 0 ) {
                    observe_pending_cdc_next(rolling192_hash_, cdc192_salt_, kCdc192RowBegin, kCdc192RowEnd,
                                             has_last_cdc_feature_, last_cdc_feature_, pending_cdc192_next_);
                    if ( take_sample_slot(cdc_sample_countdown_) ) {
                        observe_cdc_window(rolling192_hash_, previous192_hash, cdc192_salt_, kCdc192GateMask,
                                           kCdc192RowBegin, kCdc192RowEnd, has_last_cdc_feature_,
                                           last_cdc_feature_, pending_cdc192_next_);
                        reset_sample_slot(cdc_sample_countdown_);
                    }
                }
            }
            else {
                const auto previous192_hash = rolling192_hash_;
                rolling192_hash_ =
                    UpdateRollingWindowHash(rolling192_hash_, byte_hash, hash_history_, offset, kCdcWindowSize);
                observe_pending_cdc_next(rolling192_hash_, cdc192_salt_, kWinnowRows, minhash_values_.size(),
                                         has_last_cdc_feature_, last_cdc_feature_, pending_cdc192_next_);
                if ( take_sample_slot(cdc_sample_countdown_) ) {
                    observe_cdc_window(rolling192_hash_, previous192_hash, cdc192_salt_, kCdc192GateMask,
                                       kWinnowRows, minhash_values_.size(), has_last_cdc_feature_,
                                       last_cdc_feature_, pending_cdc192_next_);
                    reset_sample_slot(cdc_sample_countdown_);
                }
            }
        }
    }
}

Hasher::Hasher() {
    std::fill(minhash_values_.begin(), minhash_values_.end(), std::numeric_limits<uint64_t>::max());
    std::fill(minhash_second_values_.begin(), minhash_second_values_.end(), std::numeric_limits<uint64_t>::max());
    std::fill(bottomk_values_.begin(), bottomk_values_.end(), std::numeric_limits<uint64_t>::max());

    winnow64_salt_ = FeatureSalt(64, 1);
    cdc64_salt_ = FeatureSalt(64, 4);
    cdc96_salt_ = FeatureSalt(96, 5);
    cdc128_salt_ = FeatureSalt(128, 6);
    cdc192_salt_ = FeatureSalt(kCdcMultiSize == 0 ? kCdcWindowSize : 192, 3);
#ifdef SSDF_PROFILE_FIXED_SAMPLE_STRIDE
    entropy_sample_stride_ = std::clamp<size_t>(SSDF_PROFILE_FIXED_SAMPLE_STRIDE, 1, kMaxEntropySampleStride);
#elif SSDF_PROFILE_SAMPLE_SCHEDULE != 0
    entropy_sample_stride_ = 1;
#endif
}

SSDF_ALWAYS_INLINE void Hasher::observe_pending_cdc_next(uint64_t rolling_hash, uint64_t scale_salt, size_t row_begin,
                                                         size_t row_end, bool& has_last, uint64_t& last,
                                                         bool& pending_next) {
    if constexpr ( (kCdcAdjacentSamples & 2) == 0 ) {
        (void)rolling_hash;
        (void)scale_salt;
        (void)row_begin;
        (void)row_end;
        (void)has_last;
        (void)last;
        (void)pending_next;
    }
    else {
        if ( ! pending_next )
            return;

        pending_next = false;
        if ( row_begin == row_end )
            return;

        select_feature_range(detail::Mix64(rolling_hash ^ CdcAdjacentSalt(scale_salt, 2)), row_begin, row_end,
                             has_last, last);
    }
}

SSDF_ALWAYS_INLINE void Hasher::observe_cdc_window(uint64_t rolling_hash, uint64_t previous_rolling_hash,
                                                   uint64_t scale_salt, uint64_t gate_mask, size_t row_begin,
                                                   size_t row_end, bool& has_last, uint64_t& last,
                                                   bool& pending_next) {
    if ( row_begin == row_end )
        return;

    const auto raw_feature = rolling_hash ^ scale_salt;
    if ( (raw_feature & gate_mask) != 0 )
        return;

    if constexpr ( (kCdcAdjacentSamples & 1) != 0 ) {
        if ( previous_rolling_hash != 0 )
            select_feature_range(detail::Mix64(previous_rolling_hash ^ CdcAdjacentSalt(scale_salt, 1)), row_begin,
                                 row_end, has_last, last);
    }

    select_feature_range(detail::Mix64(raw_feature), row_begin, row_end, has_last, last);

    if constexpr ( (kCdcAdjacentSamples & 2) != 0 )
        pending_next = true;
    else
        (void)pending_next;
}

SSDF_ALWAYS_INLINE void Hasher::observe_winnow64_window() {
    const auto raw_feature = rolling64_hash_ ^ winnow64_salt_;

    if ( (raw_feature & kWinnowPreGateMask) != 0 )
        return;

    const auto feature_index = winnow64_feature_index_++;
    const auto feature_hash = detail::Mix64(raw_feature);

    while ( winnow64_size_ != 0 &&
            winnow64_queue_[winnow64_begin_].index + kActiveWinnowingWindow <= feature_index ) {
        winnow64_begin_ = NextWinnowIndex(winnow64_begin_);
        --winnow64_size_;
    }

    while ( winnow64_size_ != 0 ) {
        const auto back = WinnowIndex(winnow64_begin_, winnow64_size_ - 1);
        if ( winnow64_queue_[back].value <= feature_hash )
            break;

        --winnow64_size_;
    }

    const auto insert = WinnowIndex(winnow64_begin_, winnow64_size_);
    winnow64_queue_[insert] = {feature_hash, feature_index};
    ++winnow64_size_;

    if ( feature_index + 1 < kActiveWinnowingWindow )
        return;

    const auto& minimizer = winnow64_queue_[winnow64_begin_];
    if ( has_winnow64_selected_index_ && winnow64_selected_index_ == minimizer.index )
        return;

    has_winnow64_selected_index_ = true;
    winnow64_selected_index_ = minimizer.index;

    if ( (minimizer.value & kWinnowPostGateMask) != 0 )
        return;

    select_feature_range(minimizer.value, 0, kWinnowRows, has_last_winnow_feature_, last_winnow_feature_);
}

SSDF_ALWAYS_INLINE void Hasher::select_feature_range(uint64_t feature_hash, size_t row_begin, size_t row_end,
                                                     bool& has_last, uint64_t& last) {
    if ( has_last && last == feature_hash )
        return;

    has_last = true;
    last = feature_hash;
    ++stats_.minhash_updates;
    observe_bottomk(feature_hash);

    auto* value = minhash_values_.data() + row_begin;
    auto* second_value = minhash_second_values_.data() + row_begin;
    const auto* seed = kMinHashRowSeeds.data() + row_begin;
    const auto* const end = minhash_values_.data() + row_end;

    for ( ; value != end; ++value, ++second_value, ++seed ) {
        const auto candidate = detail::Mix64(feature_hash ^ *seed);
        if ( candidate < *value ) {
            if constexpr ( kTrackSecondMinHash )
                *second_value = *value;

            *value = candidate;
        }
        else if constexpr ( kTrackSecondMinHash ) {
            if ( candidate != *value && candidate < *second_value )
                *second_value = candidate;
        }
    }
}

SSDF_ALWAYS_INLINE void Hasher::observe_bottomk(uint64_t feature_hash) {
    if constexpr ( ! kTrackBottomK ) {
        (void)feature_hash;
    }
    else {
        const auto candidate = detail::Mix64(feature_hash ^ 0x9e3779b97f4a7c15ULL);
        size_t replace = 0;
        auto worst = bottomk_values_[0];

        for ( size_t i = 0; i < bottomk_values_.size(); ++i ) {
            if ( bottomk_values_[i] == candidate )
                return;

            if ( bottomk_values_[i] > worst ) {
                worst = bottomk_values_[i];
                replace = i;
            }
        }

        if ( candidate < worst )
            bottomk_values_[replace] = candidate;
    }
}

SSDF_ALWAYS_INLINE void Hasher::update_entropy_window(uint8_t byte) {
#if defined(SSDF_PROFILE_FIXED_SAMPLE_STRIDE) || SSDF_PROFILE_SAMPLE_SCHEDULE != 0
    (void)byte;
    return;
#endif

#if SSDF_ENTROPY_MODE == 6
    const auto& count_log2_count = ScaledCountLog2CountTable();
    const auto add_entropy_byte = [&](uint8_t value) {
        const auto old_count = entropy_counts_[value]++;
        entropy_count_term_sum_scaled_ += count_log2_count[old_count + 1] - count_log2_count[old_count];
    };
    const auto remove_entropy_byte = [&](uint8_t value) {
        const auto old_count = entropy_counts_[value]--;
        entropy_count_term_sum_scaled_ -= count_log2_count[old_count] - count_log2_count[old_count - 1];
    };
#endif

    if ( entropy_window_size_ < kEntropyWindowSize ) {
        entropy_window_[entropy_window_size_++] = byte;
#if SSDF_ENTROPY_MODE == 6
        add_entropy_byte(byte);
#endif
        entropy_window_next_ = entropy_window_size_ % kEntropyWindowSize;
        if ( entropy_window_size_ == kEntropyWindowSize )
            refresh_entropy_sample_stride();

        return;
    }

#if SSDF_ENTROPY_MODE == 6
    remove_entropy_byte(entropy_window_[entropy_window_next_]);
    add_entropy_byte(byte);
#endif
    entropy_window_[entropy_window_next_] = byte;
    entropy_window_next_ = (entropy_window_next_ + 1) % kEntropyWindowSize;

    ++entropy_bytes_since_stride_refresh_;
    if ( entropy_bytes_since_stride_refresh_ >= kEntropyStrideRefreshBytes )
        refresh_entropy_sample_stride();
}

SSDF_ALWAYS_INLINE bool Hasher::take_sample_slot(size_t& countdown) {
    if ( countdown != 0 ) {
        --countdown;
        return false;
    }

    return true;
}

SSDF_ALWAYS_INLINE void Hasher::reset_sample_slot(size_t& countdown) const {
#if SSDF_PROFILE_SAMPLE_SCHEDULE == 1
    const auto stride = std::min<size_t>(8, 1 + stats_.minhash_updates / SSDF_MINHASH_VALUES);
    countdown = stride - 1;
#elif SSDF_PROFILE_SAMPLE_SCHEDULE == 2
    const auto stride = std::min<size_t>(12, 1 + stats_.minhash_updates / (SSDF_MINHASH_VALUES * 2));
    countdown = stride - 1;
#elif SSDF_PROFILE_SAMPLE_SCHEDULE == 3
    const auto stride = std::min<size_t>(16, 1 + stats_.minhash_updates / (SSDF_MINHASH_VALUES * 4));
    countdown = stride - 1;
#elif SSDF_PROFILE_SAMPLE_SCHEDULE == 4
    const auto stride = stats_.minhash_updates < SSDF_MINHASH_VALUES ? size_t{1} : size_t{2};
    countdown = stride - 1;
#elif SSDF_PROFILE_SAMPLE_SCHEDULE == 5
    const auto stride = stats_.minhash_updates < SSDF_MINHASH_VALUES * 2 ? size_t{1} : size_t{2};
    countdown = stride - 1;
#elif SSDF_PROFILE_SAMPLE_SCHEDULE == 6
    const auto stride = stats_.bytes_processed < 4096 ? size_t{1} :
                        stats_.bytes_processed < 65536 ? size_t{2} :
                        stats_.bytes_processed < 1048576 ? size_t{4} :
                        size_t{8};
    countdown = stride - 1;
#elif SSDF_PROFILE_SAMPLE_SCHEDULE == 7
    const auto stride = std::min<size_t>(4, 1 + stats_.minhash_updates / SSDF_MINHASH_VALUES);
    countdown = stride - 1;
#elif SSDF_PROFILE_SAMPLE_SCHEDULE == 8
    const auto stride = std::min<size_t>(6, 1 + stats_.minhash_updates / SSDF_MINHASH_VALUES);
    countdown = stride - 1;
#elif SSDF_PROFILE_SAMPLE_SCHEDULE == 9
    const auto stride = std::min<size_t>(12, 1 + stats_.minhash_updates / SSDF_MINHASH_VALUES);
    countdown = stride - 1;
#elif SSDF_PROFILE_SAMPLE_SCHEDULE == 10
    const auto stride = std::min<size_t>(16, 1 + stats_.minhash_updates / SSDF_MINHASH_VALUES);
    countdown = stride - 1;
#elif SSDF_PROFILE_SAMPLE_SCHEDULE == 11
    const auto stride = std::min<size_t>(64, 1 + stats_.minhash_updates / SSDF_MINHASH_VALUES);
    countdown = stride - 1;
#else
    countdown = entropy_sample_stride_ - 1;
#endif
}

SSDF_ALWAYS_INLINE void Hasher::refresh_entropy_sample_stride() {
    entropy_bytes_since_stride_refresh_ = 0;

    if ( entropy_window_size_ < kEntropyWindowSize ) {
        entropy_sample_stride_ = kMaxEntropySampleStride;
        return;
    }

    static const double kLog2EntropyWindowSize = std::log2(static_cast<double>(kEntropyWindowSize));

    if constexpr ( kEntropyMode == 0 ) {
        std::array<uint8_t, 256> counts = {};
        for ( auto byte : entropy_window_ )
            ++counts[byte];

        const auto& count_log2_count = CountLog2CountTable();
        double count_term_sum = 0.0;
        for ( auto count : counts )
            count_term_sum += count_log2_count[count];

        const auto entropy = kLog2EntropyWindowSize - count_term_sum / static_cast<double>(kEntropyWindowSize);
        entropy_sample_stride_ = EntropyStride(entropy);
    }
    else if constexpr ( kEntropyMode == 1 ) {
        std::array<uint64_t, 4> seen = {};
        for ( auto byte : entropy_window_ )
            MarkSeenByte(seen, byte);

        const auto unique = CountSeenBytes(seen);
        const auto entropy = unique == 0 ? 0.0 : std::min(kLog2EntropyWindowSize, std::log2(static_cast<double>(unique)));
        entropy_sample_stride_ = EntropyStride(entropy);
    }
    else if constexpr ( kEntropyMode == 2 ) {
        std::array<uint8_t, 16> counts = {};
        for ( auto byte : entropy_window_ ) {
            ++counts[byte >> 4U];
            ++counts[byte & 0x0fU];
        }

        const auto& count_log2_count = NibbleCountLog2CountTable();
        double count_term_sum = 0.0;
        for ( auto count : counts )
            count_term_sum += count_log2_count[count];

        constexpr auto kNibbleCount = static_cast<double>(kEntropyWindowSize * 2);
        static const double kLog2NibbleCount = std::log2(kNibbleCount);
        const auto nibble_entropy = kLog2NibbleCount - count_term_sum / kNibbleCount;
        const auto entropy = std::min(kLog2EntropyWindowSize, nibble_entropy * 2.0);
        entropy_sample_stride_ = EntropyStride(entropy);
    }
    else if constexpr ( kEntropyMode == 3 ) {
        size_t changes = 0;
        auto previous = entropy_window_[entropy_window_next_];

        for ( size_t i = 1; i < kEntropyWindowSize; ++i ) {
            const auto current = entropy_window_[(entropy_window_next_ + i) % kEntropyWindowSize];
            if ( current != previous )
                ++changes;

            previous = current;
        }

        const auto entropy = kLog2EntropyWindowSize *
                             (static_cast<double>(changes) / static_cast<double>(kEntropyWindowSize - 1));
        entropy_sample_stride_ = EntropyStride(entropy);
    }
    else if constexpr ( kEntropyMode == 4 ) {
        constexpr size_t kSampledEntropyStep = 4;
        constexpr size_t kSampledEntropyCount = kEntropyWindowSize / kSampledEntropyStep;
        static const double kSampleEntropyScale =
            kLog2EntropyWindowSize / std::log2(static_cast<double>(kSampledEntropyCount));

        std::array<uint64_t, 4> seen = {};
        for ( size_t i = 0; i < kEntropyWindowSize; i += kSampledEntropyStep )
            MarkSeenByte(seen, entropy_window_[(entropy_window_next_ + i) % kEntropyWindowSize]);

        const auto unique = CountSeenBytes(seen);
        const auto entropy = unique == 0 ? 0.0 :
                                           std::min(kLog2EntropyWindowSize,
                                                    std::log2(static_cast<double>(unique)) * kSampleEntropyScale);
        entropy_sample_stride_ = EntropyStride(entropy);
    }
    else if constexpr ( kEntropyMode == 5 ) {
        std::array<uint8_t, 256> counts = {};
        for ( auto byte : entropy_window_ )
            ++counts[byte];

        const auto& count_log2_count = ScaledCountLog2CountTable();
        uint32_t count_term_sum = 0;
        for ( auto count : counts )
            count_term_sum += count_log2_count[count];

        constexpr uint32_t kEntropyScale = 1024;
        static const auto kLog2EntropyWindowSizeScaled =
            static_cast<uint32_t>(std::llround(kLog2EntropyWindowSize * kEntropyScale));
        const auto entropy_scaled =
            kLog2EntropyWindowSizeScaled -
            static_cast<uint32_t>((count_term_sum + kEntropyWindowSize / 2) / kEntropyWindowSize);
        entropy_sample_stride_ = EntropyStrideFromScaled(entropy_scaled);
    }
#if SSDF_ENTROPY_MODE == 6
    else if constexpr ( kEntropyMode == 6 ) {
        constexpr uint32_t kEntropyScale = 1024;
        static const auto kLog2EntropyWindowSizeScaled =
            static_cast<uint32_t>(std::llround(kLog2EntropyWindowSize * kEntropyScale));
        const auto entropy_scaled =
            kLog2EntropyWindowSizeScaled -
            static_cast<uint32_t>((entropy_count_term_sum_scaled_ + kEntropyWindowSize / 2) /
                                  kEntropyWindowSize);
        entropy_sample_stride_ = EntropyStrideFromScaled(entropy_scaled);
    }
#endif
}

std::optional<std::string> Hasher::finalize() const {
    if ( stats_.bytes_processed < kMinUsefulBytes )
        return std::nullopt;

    if ( stats_.minhash_updates < kMinUsefulSelectedFeatures )
        return std::nullopt;

    const auto empty = std::numeric_limits<uint64_t>::max();

    const auto minhash_ready = [&](size_t row_count) {
        return std::none_of(minhash_values_.begin(), minhash_values_.begin() + row_count,
                            [empty](uint64_t value) { return value == empty; });
    };

    const auto second_ready = [&](size_t row_count) {
        return std::none_of(minhash_second_values_.begin(), minhash_second_values_.begin() + row_count,
                            [empty](uint64_t value) { return value == empty; });
    };

    const auto bottomk_ready = [&]() {
        if constexpr ( ! kTrackBottomK )
            return false;
        else
            return std::none_of(bottomk_values_.begin(), bottomk_values_.end(),
                                [empty](uint64_t value) { return value == empty; });
    };

    size_t output_tokens = SSDF_MINHASH18X24_VALUES;
    if constexpr ( kOutputMode == 1 )
        output_tokens = SSDF_MINHASH18X24_VALUES * 2;
    else if constexpr ( kOutputMode == 2 )
        output_tokens = kBottomKValues;
    else if constexpr ( kOutputMode == 3 )
        output_tokens = kHybridStrictRows + kBottomKValues;

    if constexpr ( kOutputMode == 0 ) {
        if ( ! minhash_ready(SSDF_MINHASH18X24_VALUES) )
            return std::nullopt;
    }
    else if constexpr ( kOutputMode == 1 ) {
        if ( ! minhash_ready(SSDF_MINHASH18X24_VALUES) || ! second_ready(SSDF_MINHASH18X24_VALUES) )
            return std::nullopt;
    }
    else if constexpr ( kOutputMode == 2 ) {
        if ( ! bottomk_ready() )
            return std::nullopt;
    }
    else if constexpr ( kOutputMode == 3 ) {
        if ( ! minhash_ready(kHybridStrictRows) || ! bottomk_ready() )
            return std::nullopt;
    }

    std::string result;
    result.reserve(output_tokens * kOutputTokenChars + (output_tokens - 1));

    const auto append_token = [&](size_t row_scope, uint64_t value) {
        if ( ! result.empty() )
            result.push_back(SSDF_TOKEN_SEPARATOR);

        result += detail::MinHashProfileTokenForValue(SSDF_MINHASH18X24_ALG, row_scope, value);
    };

    if constexpr ( kOutputMode == 0 ) {
        for ( size_t row = 0; row < SSDF_MINHASH18X24_VALUES; ++row )
            append_token(row, minhash_values_[row]);
    }
    else if constexpr ( kOutputMode == 1 ) {
        for ( size_t row = 0; row < SSDF_MINHASH18X24_VALUES; ++row ) {
            append_token(row * 2, minhash_values_[row]);
            append_token(row * 2 + 1, minhash_second_values_[row]);
        }
    }
    else if constexpr ( kOutputMode == 2 ) {
        auto values = bottomk_values_;
        std::sort(values.begin(), values.end());
        for ( auto value : values )
            append_token(0x2000, value);
    }
    else if constexpr ( kOutputMode == 3 ) {
        for ( size_t row = 0; row < kHybridStrictRows; ++row )
            append_token(row, minhash_values_[row]);

        auto values = bottomk_values_;
        std::sort(values.begin(), values.end());
        for ( auto value : values )
            append_token(0x2000, value);
    }

    return result;
}

std::optional<std::array<uint64_t, SSDF_MINHASH_VALUES>> Hasher::minhash_signature() const {
    if ( stats_.bytes_processed < kMinUsefulBytes )
        return std::nullopt;

    if ( stats_.minhash_updates < kMinUsefulSelectedFeatures )
        return std::nullopt;

    const auto empty = std::numeric_limits<uint64_t>::max();
    if ( std::any_of(minhash_values_.begin(), minhash_values_.end(),
                     [empty](uint64_t value) { return value == empty; }) )
        return std::nullopt;

    return minhash_values_;
}

} // namespace ssdf
