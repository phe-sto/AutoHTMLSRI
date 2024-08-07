#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
/*******************************************************************************
 * Test results are obtained using the following command (from https://developer.mozilla.org/fr/docs/Web/Security/Subresource_Integrity):
 * cat <file> | openssl dgst -sha384 -binary | openssl enc -base64 -A
 * */
#include "../lib/doctest.h"
#include "../src/SRI.h"

/*******************************************************************************
 * SHA 256 related tests
 * */
TEST_SUITE("SHA256") {
    TEST_CASE("Test SRI with sha256Algorithm") {
        map<string, string> sha256FileHash = {
                {"index2.html",     "sha256-TXXv1+7Ja3pgmjoUZZyP4aFf1q03sgTDufk+EuAdDnc="},
                {"data.html",       "sha256-/ZVanFW9c+qgjBPSYrF2nVkH7WOqo4XeG//uAOSVHd8="},
                {"utiles.html",     "sha256-TrUZPIQBTwLqlfHW0qDSgne7N8LUDollY82jO3MXwtQ="},
                {"references.html", "sha256-GTj3kKoyFUO6ZD8jsFT8H7Troy+Zzct8jUop/QLEwpQ="},
                {"contact.html",    "sha256-hCYwhz7hKxii9BPxCUGSU8F8scHWvR1WdVs8LEwAeFY="}
        };
        SRI sha256SRI = SRI(sha256Algorithm);
        for (auto &file: sha256FileHash) {
            SUBCASE(file.first.c_str()) {
                CHECK(
                        sha256SRI.getHash(
                                file.first.c_str()
                        ) == file.second
                );
            }
        }
    }
}

/*******************************************************************************
 * SHA 384 related tests
 * */
TEST_SUITE("SHA384") {
    map<string, string> sha384FileHash = {
            {"index2.html",     "sha384-279AoLfGRS+l3d2F+njZFi8hwsVxMU298xbicVdnKn3yIJGV+qKX3t6kbC/4N+Ot"},
            {"data.html",       "sha384-Mb6+mP2HdNj18m+mr9a6bnJtZAR7AQUsI1FT1RTN8J1oEplnjY2gq+sjjhX3njnT"},
            {"utiles.html",     "sha384-PzIbmVFlKHWVpWqAsJ6jz5DjuyMZd8WGVu+USnZSFg/bCBCRqqTbaD44FxwwkFvq"},
            {"references.html", "sha384-Quv570PMVcsWb2JqoltAfQhgwwF329h5astSNFlYOrDMOh7V9OAE9UCDBuH+oL2Q"},
            {"contact.html",    "sha384-tT+C6dq4xvWDptyII7bKwureMBwfMe0s+Yke7KeHs674FO87L3N6FPmGgt35au46"}
    };

    TEST_CASE("Test SRI with sha384Algorithm") {
        SRI sha384SRI = SRI(sha384Algorithm);
        for (auto &file: sha384FileHash) {
            SUBCASE(file.first.c_str()) {
                CHECK(
                        sha384SRI.getHash(
                                file.first.c_str()
                        ) == file.second
                );
            }
        }
    }

    TEST_CASE("Test SRI with default algorithm which is sha384") {
        SRI defaultSRI = SRI();
        for (auto &file: sha384FileHash) {
            SUBCASE(file.first.c_str()) {
                CHECK(
                        defaultSRI.getHash(
                                file.first.c_str()
                        ) == file.second
                );
            }
        }
    }
}

/*******************************************************************************
 * SHA 512 related tests
 * */
TEST_SUITE("SHA512") {
    TEST_CASE("Test SRI with sha512Algorithm") {
        SRI sha512SRI = SRI(sha512Algorithm);

        map<string, string> sha512FileHash = {
                {"index2.html",     "sha512-H9NbQSP5bFn31ci63DV2acvz3Lnht4fKpuW5HYnmtBmf6fFlrghG6QvHvh4yRHBqaNpVpH/snmaqvxHqfoXyhg=="},
                {"data.html",       "sha512-ZELM8HQjhl04aMX8fRbZ76aWm5oMx3PfMaN+8LKsAD46+//MQ6EaT+VtueVGA05xjoTvquQyOaA0d57dkpcH6g=="},
                {"utiles.html",     "sha512-YBn+TQDI5qdeaKccvgKRPluw6YghloyYSB6HP4AFKu9dUGL9O2y3GSEcq0QxVbV4iKniZbR1ME27tWUlPulX3Q=="},
                {"references.html", "sha512-9RMeGicHH++NHENyVCgoTXKsfzR64CeiM0bwd22Yvs4chuADuA2plF3ZMbqfsM3A/yT9xncfIuuhaPa1ZuYEAQ=="},
                {"contact.html",    "sha512-CXxXngTeJD+ya3ZBNZ6r7695GzQxFJI+TSBo5pA9risYd5qgSxIlLRVAoKQ2aWylwksdFuTFXn0D9YIRP3UsCw=="}
        };
        for (auto &file: sha512FileHash) {
            SUBCASE(file.first.c_str()) {
                CHECK(
                        sha512SRI.getHash(
                                file.first.c_str()
                        ) == file.second
                );
            }
        }
    }
}
