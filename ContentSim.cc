// See the file "COPYING" in the main distribution directory for copyright.

#include "ContentSim.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

#include "c/highwayhash.h"

namespace zeek::content_sim {

namespace {

constexpr size_t kMinUsefulBytes = 64;
constexpr size_t kActiveWinnowingWindow = 12;
constexpr std::array<size_t, 3> kActiveBuzHashWindows = {32, 96, 192};
constexpr size_t kMinHashValues = CONTENT_SIM_MINHASH_VALUES;
constexpr uint64_t kFeatureSalt = 0x7a09e667f3bcc909ULL;
constexpr uint64_t kMinHashSeed = 0x243f6a8885a308d3ULL;
constexpr uint64_t kMinUsefulSelectedFeatures = 4;
// Fixed public key for stable HighwayHash output. This is algorithm domain
// separation, not a secret authentication key.
constexpr uint64_t kHighwayHashKey[4] = {0x6d682d6c73682d76ULL, 0x312d62757a36342dULL, 0x7733322d6b33322dULL,
                                         0x6831382d68363834ULL};

static_assert(kMinHashValues == CONTENT_SIM_MINHASH_VALUES);

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


uint64_t Rotl64(uint64_t value, unsigned bits) {
    bits &= 63U;
    if ( bits == 0 )
        return value;

    return (value << bits) | (value >> (64U - bits));
}

class HighwayHashInput {
public:
    void AppendBytes(const void* bytes, size_t len) {
        if ( size_ + len > data_.size() )
            throw std::length_error("content-sim HighwayHash input buffer is too small");

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

uint64_t MinHashCandidate(uint64_t feature_hash, size_t index) {
    auto seed = kMinHashSeed + static_cast<uint64_t>(index) * 0x9e3779b97f4a7c15ULL;
    return detail::Mix64(feature_hash ^ detail::Mix64(seed));
}

uint64_t FeatureSalt(size_t window_size, size_t scale_index) {
    return kFeatureSalt ^ detail::Mix64(window_size + static_cast<uint64_t>(scale_index) * 0x9e3779b97f4a7c15ULL);
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

void ContentSimHasher::update(const uint8_t* data, size_t len) {
    if ( ! data && len != 0 )
        throw std::invalid_argument("ContentSimHasher::update received null data with non-zero length");

    for ( size_t i = 0; i < len; ++i ) {
        const auto byte = data[i];
        ++stats_.bytes_processed;

        for ( auto& scale : rolling_scales_ )
            update_scale(scale, byte);
    }
}

ContentSimHasher::ContentSimHasher() {
    std::fill(minhash_values_.begin(), minhash_values_.end(), std::numeric_limits<uint64_t>::max());

    for ( size_t i = 0; i < rolling_scales_.size(); ++i ) {
        rolling_scales_[i].window_size = kActiveBuzHashWindows[i];
        rolling_scales_[i].scale_salt = FeatureSalt(kActiveBuzHashWindows[i], i);
    }
}

void ContentSimHasher::update_scale(RollingState& scale, uint8_t byte) {
    if ( scale.rolling_fill < scale.window_size ) {
        scale.rolling_hash = Rotl64(scale.rolling_hash, 1) ^ kByteHashTable[byte];
        scale.rolling_window[scale.rolling_pos] = byte;
        scale.rolling_pos = (scale.rolling_pos + 1) % scale.window_size;
        ++scale.rolling_fill;

        if ( scale.rolling_fill == scale.window_size )
            observe_complete_window(scale);

        return;
    }

    const auto old_byte = scale.rolling_window[scale.rolling_pos];
    scale.rolling_window[scale.rolling_pos] = byte;
    scale.rolling_pos = (scale.rolling_pos + 1) % scale.window_size;
    scale.rolling_hash = Rotl64(scale.rolling_hash, 1) ^ Rotl64(kByteHashTable[old_byte], scale.window_size) ^
                         kByteHashTable[byte];
    observe_complete_window(scale);
}

void ContentSimHasher::observe_complete_window(RollingState& scale) {
    const auto feature_index = scale.feature_index;
    ++scale.feature_index;

    ++stats_.rolling_windows;
    const auto feature_hash = detail::Mix64(scale.rolling_hash ^ scale.scale_salt);

    while ( scale.winnow_size != 0 &&
            scale.winnow_queue[scale.winnow_begin].index + kActiveWinnowingWindow <= feature_index ) {
        scale.winnow_begin = (scale.winnow_begin + 1) % kActiveWinnowingWindow;
        --scale.winnow_size;
    }

    while ( scale.winnow_size != 0 ) {
        const auto back = (scale.winnow_begin + scale.winnow_size - 1) % kActiveWinnowingWindow;
        if ( scale.winnow_queue[back].value <= feature_hash )
            break;

        --scale.winnow_size;
    }

    const auto insert = (scale.winnow_begin + scale.winnow_size) % kActiveWinnowingWindow;
    scale.winnow_queue[insert] = {feature_hash, feature_index};
    ++scale.winnow_size;

    if ( feature_index + 1 < kActiveWinnowingWindow )
        return;

    const auto& minimizer = scale.winnow_queue[scale.winnow_begin];
    if ( scale.last_selected_index && *scale.last_selected_index == minimizer.index )
        return;

    scale.last_selected_index = minimizer.index;
    select_feature(minimizer.value);
}

void ContentSimHasher::select_feature(uint64_t feature_hash) {
    ++stats_.selected_features;

    if ( last_minhash_feature_ && *last_minhash_feature_ == feature_hash )
        return;

    last_minhash_feature_ = feature_hash;
    ++stats_.minhash_updates;

    for ( size_t i = 0; i < minhash_values_.size(); ++i )
        minhash_values_[i] = std::min(minhash_values_[i], MinHashCandidate(feature_hash, i));
}

std::optional<std::string> ContentSimHasher::finalize() const {
    const auto signature = minhash_signature();
    if ( ! signature )
        return std::nullopt;

    std::string result;
    result.reserve(CONTENT_SIM_MINHASH18X24_VALUES * 3 + (CONTENT_SIM_MINHASH18X24_VALUES - 1));

    for ( size_t row = 0; row < CONTENT_SIM_MINHASH18X24_VALUES; ++row ) {
        if ( row != 0 )
            result.push_back(CONTENT_SIM_TOKEN_SEPARATOR);

        result += detail::MinHash18TokenForValue(CONTENT_SIM_MINHASH18X24_ALG, row, (*signature)[row]);
    }

    return result;
}

std::optional<std::array<uint64_t, CONTENT_SIM_MINHASH_VALUES>> ContentSimHasher::minhash_signature() const {
    if ( stats_.bytes_processed < kMinUsefulBytes )
        return std::nullopt;

    if ( stats_.minhash_updates < kMinUsefulSelectedFeatures )
        return std::nullopt;

    return minhash_values_;
}

} // namespace zeek::content_sim
