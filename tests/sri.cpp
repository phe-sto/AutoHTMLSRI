#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
/*******************************************************************************
 * Test results are obtained using the following command (from https://developer.mozilla.org/fr/docs/Web/Security/Subresource_Integrity):
 * cat <file> | openssl dgst -sha384 -binary | openssl enc -base64 -A
 * */
#include "../lib/doctest.h"
#include "../src/SRI.h"

SRI defaultSRI = SRI();
SRI sha384SRI = SRI(sha384Algorithm);

map<string, string> sha384FileHash = {
        {"index2.html",     "sha384-279AoLfGRS+l3d2F+njZFi8hwsVxMU298xbicVdnKn3yIJGV+qKX3t6kbC/4N+Ot"},
        {"data.html",       "sha384-Mb6+mP2HdNj18m+mr9a6bnJtZAR7AQUsI1FT1RTN8J1oEplnjY2gq+sjjhX3njnT"},
        {"utiles.html",     "sha384-yaD0WwXGPHqgwUZnC+HklSykoY1s8l/VdMNwh6FV6IPtwYJppmOkyg/lC6qFuKd6"},
        {"references.html", "sha384-Quv570PMVcsWb2JqoltAfQhgwwF329h5astSNFlYOrDMOh7V9OAE9UCDBuH+oL2Q"},
        {"contact.html",    "sha384-tT+C6dq4xvWDptyII7bKwureMBwfMe0s+Yke7KeHs674FO87L3N6FPmGgt35au46"}
};
TEST_SUITE("SHA384") {
    TEST_CASE("Test SRI with sha384Algorithm") {
        for (auto &it: sha384FileHash) {
            SUBCASE(it.first.c_str()) {
                CHECK(sha384SRI.getHash(it.first.c_str()) == it.second);
            }
        }
    }

    TEST_CASE("Test SRI with default algorithm which is sha384") {
        for (auto &it: sha384FileHash) {
            SUBCASE(it.first.c_str()) {
                CHECK(defaultSRI.getHash(it.first.c_str()) == it.second);
            }
        }
    }
}

SRI sha256SRI = SRI(sha256Algorithm);
SRI sha512SRI = SRI(sha512Algorithm);