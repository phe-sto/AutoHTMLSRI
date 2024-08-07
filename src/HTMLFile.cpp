//
// Created by chrichri on 16/06/24.
//

#include "HTMLFile.h"
#include "SRI.h"
// Use Curl library to download remote resources
#include <curl/curl.h>
#include <sys/stat.h>
#include <regex>
#include <fstream>
#include <iostream>
// For HTML parsing downloaded from https://htmlcxx.sourceforge.net/
// as libhtmlcxx-dev package is not working
#include "../lib/htmlcxx-0.86/html/ParserDom.h"

using namespace std;

/*******************************************************************************
 * The constructor of the HTMLFile class. It requires a path to the HTML file
 * and a SRI instance to get the hash of the resources.
 * @param chFSPath The path to the HTML file
 * @param sri The SRI instance to get the hash of the resources
 * */
HTMLFile::HTMLFile(const char *chFSPath, SRI &sri) {
    this->chFSPath = chFSPath;
    this->strHTML = getStringFromLocalPath(this->chFSPath);
    this->sri = sri;
    this->mapResHash = this->getSrcHash();
}

/*******************************************************************************
 * Method to get the content of a file as a string.
 * Used to get the content of the HTML input.
 * @param strHTMLFilePath The path to the file to read
 * */
string HTMLFile::getStringFromLocalPath(const string &strHTMLFilePath) {
    ifstream t(strHTMLFilePath);
    string str(
            (
                    istreambuf_iterator<char>(t)
            ),
            istreambuf_iterator<char>()
    );
    return str;
}

/*******************************************************************************
 * Method to write the resulting HTML file with the SRI hash.
 * It uses regex to modify the HTML file with the SRI hash.
 * */
string HTMLFile::resultingHTMLFile() {
    string strResultingHTML = this->strHTML;
    // Remove potential existing integrity attribute
    strResultingHTML = regex_replace(
            strResultingHTML,
            regex(R"(\sintegrity=.*("|')(\s|$))"),
            " "
    );

    // Modify the HTML file with the SRI hash using regex
    for (const auto &pair: this->mapResHash) {
        // Replace the src with the src and the hash
        strResultingHTML = regex_replace(
                strResultingHTML,
                regex(pair.first + "(\"|\')"),
                pair.first + "\" integrity=\"" + pair.second + "\""
        );
    }
    // Return the new HTML file as a string
    return strResultingHTML;
}

/*******************************************************************************
 * Function to get the hash of all the src tags in the HTML file.
 * The parser is used according to https://developer.mozilla.org/fr/docs/Web/Security/Subresource_Integrity
 * It uses HTMLCXX to parse the HTML file and get the src tags.
 * If the resource is local, it uses the SRI class to get the hash.
 * If the resource is remote, it uses Curl to download the resource and then
 * get the hash.
 * */
map<string, string> HTMLFile::getSrcHash() {

    htmlcxx::HTML::ParserDom parser;
    tree<htmlcxx::HTML::Node> dom = parser.parseTree(
            this->strHTML
    );

    //Dump all links in the tree
    tree<htmlcxx::HTML::Node>::iterator it = dom.begin();
    tree<htmlcxx::HTML::Node>::iterator end = dom.end();

    // Output all the tag and child tag recursively found in the document
    map<string, string> hash;
    for (; it != end; ++it) {
        if (it->isTag()) {
            // Only does tags according to
            // https://developer.mozilla.org/fr/docs/Web/Security/Subresource_Integrity
            if (it->tagName() == "script" || it->tagName() == "link") {
                it->parseAttributes();

                // Pairs of attributes and values
                map<string, string> pairs = it->attributes();
                for (auto &pair: pairs) {

                    // Only does tags and attributes according to
                    // https://developer.mozilla.org/fr/docs/Web/Security/Subresource_Integrity
                    if ((pair.first == "src" && it->tagName() == "script") ||
                        (pair.first == "href" && it->tagName() == "link")) {
                        string strPath = pair.second;
                        // Turn an eventual absolute to a relative one
                        // A HTTP server does not have the same absolute strPath...
                        if (strPath[0] == '/') {
                            strPath.insert(0, ".");
                        }
                        // Nothing to download, it is a local file
                        if (bIsFile(strPath)) {
                            hash[pair.second] = this->sri.getHash(
                                    strPath.c_str()
                            );
                        } else { // Download the strPath using Curl lib
                            CURL *curl;
                            CURLcode res;
                            curl_global_init(CURL_GLOBAL_ALL);
                            curl = curl_easy_init();
                            if (curl) {
                                const char *chTempPath;
                                chTempPath = tmpnam(nullptr);
                                FILE *file = fopen(chTempPath, "wb");
                                curl_easy_setopt(
                                        curl, CURLOPT_URL, strPath.c_str()
                                );
                                curl_easy_setopt(
                                        curl, CURLOPT_WRITEFUNCTION, NULL
                                );
                                if (file) {
                                    curl_easy_setopt(
                                            curl, CURLOPT_WRITEDATA, file
                                    );
                                    res = curl_easy_perform(curl);
                                    // If download went fine, get the hash of the
                                    // temp file
                                    if (res == CURLE_OK) {
                                        fseek(file, 0, SEEK_SET);
                                        hash[pair.second] = this->sri.getHash(
                                                chTempPath
                                        );
                                    }

                                    // Always close a file!
                                    fclose(file);
                                }
                                curl_easy_cleanup(curl);
                            }
                        }
                    }
                }
            }
        }
    }
    return hash;
}


/*******************************************************************************
 * Function to check if a file exists.
 * @param strFilePath The file strFilePath to check
 * @return A boolean true if the file exists, false otherwise
 */
bool HTMLFile::bIsFile(const string &strFilePath) {
    struct stat buffer{};
    return (stat(strFilePath.c_str(), &buffer) == 0);
}