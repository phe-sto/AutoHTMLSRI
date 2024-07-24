#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
/*******************************************************************************
 * Test results are obtained using the following command (from https://developer.mozilla.org/fr/docs/Web/Security/Subresource_Integrity):
 * cat <file> | openssl dgst -sha384 -binary | openssl enc -base64 -A
 * */

#include "../lib/doctest.h"
#include "../src/HTMLFile.h"

const char *STR_HTML_FILE_PATH = "index2.html";
const char *STR_CARBON_CSS_PATH = "/css/carbon-components.min.css";
const char *STR_CARBON_JS_PATH = "/js/carbon-components.js";
const char *STR_JSONLD_PATH = "/js/papit-jsonld.json";
const char *STR_PAPIT_CSS_PATH = "/css/papit.css";
const char *STR_INDEX_URL = "https://www.papit.fr/index.html";

TEST_SUITE("HTMLFile") {

    TEST_CASE("Test HTMLFile with sha256") {
        SRI sri = SRI(sha256Algorithm);

        HTMLFile htmlFile = HTMLFile(STR_HTML_FILE_PATH, sri);
        SUBCASE(STR_CARBON_CSS_PATH) {
            CHECK(htmlFile.mapResHash[STR_CARBON_CSS_PATH] ==
                  "sha256-QVchB75szyivIy45+pC9ZJric46gwec50Qm7eGY4TKY=");
        }
        SUBCASE(STR_PAPIT_CSS_PATH) {
            CHECK(htmlFile.mapResHash[STR_PAPIT_CSS_PATH] ==
                  "sha256-OaM7/4kGxgPZLvcDJaVgHjPkm2H8jRmLmNl1EgzKb6M=");
        }
        SUBCASE(STR_CARBON_JS_PATH) {
            CHECK(htmlFile.mapResHash[STR_CARBON_JS_PATH] ==
                  "sha256-En9pgfzyLwHyNTzZBmD9D860imUY6L4Njsum5GYAGD8=");
        }
        SUBCASE(STR_JSONLD_PATH) {
            CHECK(htmlFile.mapResHash[STR_JSONLD_PATH] ==
                  "sha256-yHOfoR5v5cf4I5zOL6Ckl/p+NIcexOKdi8+nTcUX4lg=");
        }
        SUBCASE(STR_INDEX_URL) {
            CHECK(htmlFile.mapResHash[STR_INDEX_URL] ==
                  "sha256-cEhQAGDmyb5D3fHuVb3QOn5K+9zEtmWZncDS3ZgJHus=");
        }
    }

    TEST_CASE("Test HTMLFile with sha384") {
        SRI sri = SRI(sha384Algorithm);
        HTMLFile htmlFile = HTMLFile(STR_HTML_FILE_PATH, sri);
        SUBCASE(STR_CARBON_CSS_PATH) {
            CHECK(htmlFile.mapResHash[STR_CARBON_CSS_PATH] ==
                  "sha384-g65YrXVd+usTrCpPlEuquASCw2KLag7dpKScl07YZdse0iDiBrxUtL7cVgTzOaKs");
        }
        SUBCASE(STR_PAPIT_CSS_PATH) {
            CHECK(htmlFile.mapResHash[STR_PAPIT_CSS_PATH] ==
                  "sha384-p/aRlPD2Qrc1woUTib5cApxsGawecE8qUd4dsj22HDUcLfzIrvHQPK46kcoPGC/I");
        }
        SUBCASE(STR_CARBON_JS_PATH) {

            CHECK(htmlFile.mapResHash[STR_CARBON_JS_PATH] ==
                  "sha384-hNcEjaSYJCYv9IMpr1c7+UbR9TTaapEHAUsK5K4VAE0jtoNHIrDkUJM6CRDsuxd5");
        }
        SUBCASE(STR_JSONLD_PATH) {

            CHECK(htmlFile.mapResHash[STR_JSONLD_PATH] ==
                  "sha384-SbYYVqbVpsNIeoUcQHgM6V71n6khAPurdqueXzjtz9zQXX8gktidx6XoDLEy0VY8");
        }
        SUBCASE(STR_INDEX_URL) {
            CHECK(htmlFile.mapResHash[STR_INDEX_URL] ==
                  "sha384-eIXphhWCAfBv5odThH7/r2JvToRl8fGEBoc4EHG+vviUqvQJKleQatbR50T72c/C");
        }
    }

    TEST_CASE("Test HTMLFile with default SHA being sha384") {
        SRI sri = SRI();
        HTMLFile htmlFile = HTMLFile(STR_HTML_FILE_PATH, sri);
        SUBCASE(STR_CARBON_CSS_PATH) {
            CHECK(htmlFile.mapResHash[STR_CARBON_CSS_PATH] ==
                  "sha384-g65YrXVd+usTrCpPlEuquASCw2KLag7dpKScl07YZdse0iDiBrxUtL7cVgTzOaKs");
        }
        SUBCASE(STR_PAPIT_CSS_PATH) {
            CHECK(htmlFile.mapResHash[STR_PAPIT_CSS_PATH] ==
                  "sha384-p/aRlPD2Qrc1woUTib5cApxsGawecE8qUd4dsj22HDUcLfzIrvHQPK46kcoPGC/I");
        }
        SUBCASE(STR_CARBON_JS_PATH) {

            CHECK(htmlFile.mapResHash[STR_CARBON_JS_PATH] ==
                  "sha384-hNcEjaSYJCYv9IMpr1c7+UbR9TTaapEHAUsK5K4VAE0jtoNHIrDkUJM6CRDsuxd5");
        }
        SUBCASE(STR_JSONLD_PATH) {

            CHECK(htmlFile.mapResHash[STR_JSONLD_PATH] ==
                  "sha384-SbYYVqbVpsNIeoUcQHgM6V71n6khAPurdqueXzjtz9zQXX8gktidx6XoDLEy0VY8");
        }
        SUBCASE(STR_INDEX_URL) {
            CHECK(htmlFile.mapResHash[STR_INDEX_URL] ==
                  "sha384-eIXphhWCAfBv5odThH7/r2JvToRl8fGEBoc4EHG+vviUqvQJKleQatbR50T72c/C");
        }
    }

    TEST_CASE("Test HTMLFile with sha512") {
        SRI sri = SRI(sha512Algorithm);
        HTMLFile htmlFile = HTMLFile(STR_HTML_FILE_PATH, sri);
        SUBCASE(STR_CARBON_CSS_PATH) {
            CHECK(htmlFile.mapResHash[STR_CARBON_CSS_PATH] ==
                  "sha512-UKDrVpTJRMT3rlyw/2agFfqF6kZqWrlN9lVMGTjaSZhHV8bd0IfIFtdKtTaoBprh8mJGgj4IkhZHekcnMfC91w==");
        }
        SUBCASE(STR_PAPIT_CSS_PATH) {
            CHECK(htmlFile.mapResHash[STR_PAPIT_CSS_PATH] ==
                  "sha512-XbERz4DMpkejqTVJMcyY/ugFV8rcag222c1NFMJOWY20xp+hDYn4ZSZOJXrnDBGSSMWCZquFcllg2y5n19X86w==");
        }
        SUBCASE(STR_CARBON_JS_PATH) {

            CHECK(htmlFile.mapResHash[STR_CARBON_JS_PATH] ==
                  "sha512-+S9OC7VWMNNdQyEM2qUFnnPcRLn7b1G7mXL6ZqOeA7w15mwjCHu8GPyFY54rRWCkKvUC0eBYStUmOuLHilu6Iw==");
        }
        SUBCASE(STR_JSONLD_PATH) {

            CHECK(htmlFile.mapResHash[STR_JSONLD_PATH] ==
                  "sha512-Kj1hg/FbzS4BkuRopLR8M3PJDnNW2RfXMjwqtmuoIt27P2Qhsw30ig7ieO7VTFGDh0DtxBib37KnbcRrldMP8Q==");
        }
        SUBCASE(STR_INDEX_URL) {
            CHECK(htmlFile.mapResHash[STR_INDEX_URL] ==
                  "sha512-w7wT4v2OIaf4Lt1S0dDNzYKxPWqc5w9eTxd6x8Li34hUtmoQCrHau99R7cXCNKGkKG9/2rhuleocVmVvkyWszQ==");
        }
    }

    TEST_CASE("Test static getStringFromLocalPath") {
        CHECK(HTMLFile::getStringFromLocalPath("small.html") == "<html><body>hey</body></html>");

    }

    TEST_CASE("Test static bIsFile with a right path") {
        CHECK(HTMLFile::bIsFile(STR_HTML_FILE_PATH) == true);

    }

    TEST_CASE("Test static bIsFile with a wrong path") {
        CHECK(HTMLFile::bIsFile("dkljdgg.html") == false);

    }

}