// See the file "COPYING" in the main distribution directory for copyright.

#include "ContentSim.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace {

using zeek::content_sim::CONTENT_SIM_MINHASH18X24_ALG;
using zeek::content_sim::CONTENT_SIM_MINHASH18X24_VALUES;
using zeek::content_sim::CONTENT_SIM_MINHASH_VALUES;
using zeek::content_sim::CONTENT_SIM_TOKEN_SEPARATOR;
using zeek::content_sim::ContentSimHasher;

int failures = 0;

void Check(bool condition, const char* expression, const char* file, int line) {
    if ( condition )
        return;

    std::cerr << file << ':' << line << ": check failed: " << expression << '\n';
    ++failures;
}

#define CHECK(expr) Check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)
#define REQUIRE(expr)                                                                                                   \
    do {                                                                                                                \
        Check(static_cast<bool>(expr), #expr, __FILE__, __LINE__);                                                      \
        if ( ! (expr) )                                                                                                 \
            return;                                                                                                     \
    } while ( false)

std::vector<uint8_t> MakeData(size_t size, uint64_t seed) {
    std::vector<uint8_t> data(size);
    auto state = seed;

    for ( size_t i = 0; i < size; i += sizeof(uint64_t) ) {
        state += 0x9e3779b97f4a7c15ULL;
        auto value = zeek::content_sim::detail::Mix64(state);
        auto n = std::min(sizeof(value), size - i);
        std::copy_n(reinterpret_cast<const uint8_t*>(&value), n, data.data() + i);
    }

    return data;
}

std::optional<std::string> HashWithChunk(const std::vector<uint8_t>& data, size_t chunk_size) {
    ContentSimHasher hasher;

    for ( size_t offset = 0; offset < data.size(); offset += chunk_size ) {
        const auto n = std::min(chunk_size, data.size() - offset);
        hasher.update(data.data() + offset, n);
    }

    return hasher.finalize();
}

std::optional<std::array<uint64_t, CONTENT_SIM_MINHASH_VALUES>> MinHashWithChunk(const std::vector<uint8_t>& data,
                                                                                 size_t chunk_size) {
    ContentSimHasher hasher;

    for ( size_t offset = 0; offset < data.size(); offset += chunk_size ) {
        const auto n = std::min(chunk_size, data.size() - offset);
        hasher.update(data.data() + offset, n);
    }

    return hasher.minhash_signature();
}

std::vector<std::string> SplitTokens(const std::string& value) {
    std::vector<std::string> tokens;
    size_t start = 0;

    while ( start <= value.size() ) {
        const auto separator = value.find(CONTENT_SIM_TOKEN_SEPARATOR, start);
        if ( separator == std::string::npos ) {
            tokens.emplace_back(value.substr(start));
            break;
        }

        tokens.emplace_back(value.substr(start, separator - start));
        start = separator + 1;
    }

    return tokens;
}

size_t MatchingTokenCount(const std::string& lhs, const std::string& rhs) {
    auto lhs_tokens = SplitTokens(lhs);
    auto rhs_tokens = SplitTokens(rhs);
    const auto n = std::min(lhs_tokens.size(), rhs_tokens.size());
    size_t shared = 0;

    for ( size_t i = 0; i < n; ++i ) {
        if ( lhs_tokens[i] == rhs_tokens[i] )
            ++shared;
    }

    return shared;
}

bool IsBase64UrlChar(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

void CheckTokenSeparators(const std::string& value, size_t expected_tokens) {
    CHECK(CONTENT_SIM_TOKEN_SEPARATOR == ':');
    CHECK(value.find(',') == std::string::npos);
    CHECK(static_cast<size_t>(std::count(value.begin(), value.end(), CONTENT_SIM_TOKEN_SEPARATOR)) == expected_tokens - 1);
}

void TestBase64Url18Encoding() {
    CHECK(zeek::content_sim::EncodeBase64Url18(0x00000U) == "AAA");
    CHECK(zeek::content_sim::EncodeBase64Url18(0x3ffffU) == "___");

    for ( uint32_t value = 0; value < 0x40000U; value += 1021U ) {
        auto encoded = zeek::content_sim::EncodeBase64Url18(value);
        CHECK(encoded.size() == 3);
        CHECK(encoded.find('=') == std::string::npos);
        CHECK(std::all_of(encoded.begin(), encoded.end(), IsBase64UrlChar));
    }
}

void TestOutputFormat() {
    auto data = MakeData(8192, 0x5252525252525252ULL);
    auto result = HashWithChunk(data, 4096);
    REQUIRE(result);

    CHECK(CONTENT_SIM_MINHASH18X24_ALG == "mh-buz32-96-192-w12-k24-h18-hh64-b64url");
    CHECK(result->size() == CONTENT_SIM_MINHASH18X24_VALUES * 3 + (CONTENT_SIM_MINHASH18X24_VALUES - 1));
    CheckTokenSeparators(*result, CONTENT_SIM_MINHASH18X24_VALUES);

    auto tokens = SplitTokens(*result);
    REQUIRE(tokens.size() == CONTENT_SIM_MINHASH18X24_VALUES);

    for ( const auto& token : tokens ) {
        CHECK(token.size() == 3);
        CHECK(std::all_of(token.begin(), token.end(), IsBase64UrlChar));
    }
}

void TestStreamingStability() {
    auto data = MakeData(32768, 0x2727272727272727ULL);
    auto expected = HashWithChunk(data, data.size());
    REQUIRE(expected);

    for ( auto chunk_size : {size_t{1}, size_t{7}, size_t{64}, size_t{4096}, data.size()} ) {
        auto actual = HashWithChunk(data, chunk_size);
        REQUIRE(actual);
        CHECK(*actual == *expected);
    }
}

void TestDeterminism() {
    auto data = MakeData(16384, 0x3333333333333333ULL);
    auto first = HashWithChunk(data, 1024);
    auto second = HashWithChunk(data, 1024);
    REQUIRE(first);
    REQUIRE(second);
    CHECK(*first == *second);
}

void TestMinHashRows() {
    auto data = MakeData(32768, 0x3131313131313131ULL);
    auto first = MinHashWithChunk(data, 1);
    auto second = MinHashWithChunk(data, 4096);
    REQUIRE(first);
    REQUIRE(second);

    size_t matching_rows = 0;
    for ( size_t i = 0; i < CONTENT_SIM_MINHASH_VALUES; ++i ) {
        if ( (*first)[i] == (*second)[i] )
            ++matching_rows;
    }

    CHECK(matching_rows == CONTENT_SIM_MINHASH_VALUES);
}

void TestSensitivity() {
    auto data = MakeData(65536, 0x4444444444444444ULL);
    auto same = data;
    auto inserted = data;
    auto block = MakeData(257, 0x5555555555555555ULL);
    inserted.insert(inserted.begin() + static_cast<std::ptrdiff_t>(inserted.size() / 2), block.begin(), block.end());
    auto random_other = MakeData(65536, 0x9999999999999999ULL);

    auto data_hash = HashWithChunk(data, 4096);
    auto same_hash = HashWithChunk(same, 7);
    auto inserted_hash = HashWithChunk(inserted, 64);
    auto random_hash = HashWithChunk(random_other, 4096);

    REQUIRE(data_hash);
    REQUIRE(same_hash);
    REQUIRE(inserted_hash);
    REQUIRE(random_hash);

    CHECK(*data_hash == *same_hash);
    CHECK(MatchingTokenCount(*data_hash, *inserted_hash) >= 1);
    CHECK(MatchingTokenCount(*data_hash, *random_hash) <= 4);

    auto too_small = MakeData(63, 0x7777777777777777ULL);
    CHECK(! HashWithChunk(too_small, 1));
}

void TestRowIndexScoping() {
    constexpr uint64_t value = 0x0102030405060708ULL;

    auto first = zeek::content_sim::detail::MinHash18TokenForValue(CONTENT_SIM_MINHASH18X24_ALG, 0, value);
    auto second = zeek::content_sim::detail::MinHash18TokenForValue(CONTENT_SIM_MINHASH18X24_ALG, 1, value);
    auto repeat = zeek::content_sim::detail::MinHash18TokenForValue(CONTENT_SIM_MINHASH18X24_ALG, 0, value);

    CHECK(first == repeat);
    CHECK(first != second);
}

void TestMinimumUsefulInput() {
    auto too_small = MakeData(63, 0x1212121212121212ULL);
    CHECK(! HashWithChunk(too_small, 1));

    auto enough = MakeData(512, 0x3434343434343434ULL);
    auto result = HashWithChunk(enough, 1);
    REQUIRE(result);
    CHECK(result->size() == CONTENT_SIM_MINHASH18X24_VALUES * 3 + (CONTENT_SIM_MINHASH18X24_VALUES - 1));
    CheckTokenSeparators(*result, CONTENT_SIM_MINHASH18X24_VALUES);
}

} // namespace

int main() {
    TestBase64Url18Encoding();
    TestOutputFormat();
    TestStreamingStability();
    TestDeterminism();
    TestMinHashRows();
    TestSensitivity();
    TestRowIndexScoping();
    TestMinimumUsefulInput();

    if ( failures != 0 ) {
        std::cerr << failures << " content-sim checks failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "content-sim tests passed\n";
    return EXIT_SUCCESS;
}
