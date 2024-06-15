/*******************************************************************************
 * Main file for the SRI project, the Subresource Integrity project.
 * It was developed according
 * https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity.
 *
 * Code under WTFPL, "Do What The Fuck You Want to Public License" feel free to
 * and please contribute.
 *
 * @file main.cpp
 * @version 0.0
 * @date 2024-06-14
 * @brief Main file for the SRI project
 * @note C++17
 ******************************************************************************/
#include "SRI.h"
#include <iostream>
#include <map>
#include <sys/stat.h>
// TCLAP for the CLI, it requires https://launchpad.net/ubuntu/+source/tclap
// Installed using apt-get install libtclap-dev
#include <tclap/CmdLine.h>
#include <tclap/UnlabeledValueArg.h>
#include <tclap/ValueArg.h>
#include <tclap/ArgException.h>
#include <fstream>
#include <regex>
#include <cryptopp/files.h>
// Use Curl library to download remote resources
#include <curl/curl.h>
// For HTML parsing downloaded from https://htmlcxx.sourceforge.net/
// as libhtmlcxx-dev package is not working
#include "lib/htmlcxx-0.86/html/ParserDom.h"

using namespace std;

/*******************************************************************************
 * Generic function printing an error strMessage and exit
 * @param strMessage The error strMessage to print as a string
 * @param intReturnCode The return code to use when exiting, an integer, default
 * is 1
 * @return The return code
 */
int errorMessageAndExit(const string &strMessage, int intReturnCode = 1) {
    cerr << strMessage << endl;
    return intReturnCode;
}

/*******************************************************************************
 * Function printing an error message about an CLI argument issue and exit
 * and exit its specific return code 2.
 * @param strMessage The error strMessage to print as a string
 * @return The return code 2 as an integer
 */
int wrongArguments(const string &strMessage) {
    return errorMessageAndExit(
            "Argument error: " + strMessage, 2
    );
}

/*******************************************************************************
 * Method to get the content of a file as a string.
 * Used to get the content of the HTML input.
 * @param strHTMLFilePath The path to the file to read
 * */
string getStringFromLocalPath(const string &strHTMLFilePath) {
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
 * Function to check if a file exists.
 * @param strFilePath The file strFilePath to check
 * @return A boolean true if the file exists, false otherwise
 */
inline bool bIsFile(const string &strFilePath) {
    struct stat buffer{};
    return (stat(strFilePath.c_str(), &buffer) == 0);
}

/*******************************************************************************
 * Function to get the hash of all the src tags in the HTML file.
 * It uses HTMLCXX to parse the HTML file and get the src tags.
 * If the resource is local, it uses the SRI class to get the hash.
 * If the resource is remote, it uses Curl to download the resource and then
 * get the hash.
 * */
map<string, string> getSrcHash(const string &strHTMLFilePath, SRI &sri) {

    htmlcxx::HTML::ParserDom parser;
    tree<htmlcxx::HTML::Node> dom = parser.parseTree(strHTMLFilePath);

    //Dump all links in the tree
    tree<htmlcxx::HTML::Node>::iterator it = dom.begin();
    tree<htmlcxx::HTML::Node>::iterator end = dom.end();

    // Output all the tag and child tag recursively found in the document
    map<string, string> mapResHash;
    for (; it != end; ++it) {
        if (it->isTag()) {
            // Only does tags according to
            // https://developer.mozilla.org/fr/docs/Web/Security/Subresource_Integrity
            if (it->tagName() == "script" || it->tagName() == "link") {
                it->parseAttributes();

                // Pairs of attributes and values
                map<string, string> pairs = it->attributes();
                for (
                        auto iter = pairs.begin();
                        iter != pairs.end();
                        ++iter
                        ) {

                    // Only does tags and attributes according to
                    // https://developer.mozilla.org/fr/docs/Web/Security/Subresource_Integrity
                    if ((iter->first == "src" && it->tagName() == "script") ||
                        (iter->first == "href" && it->tagName() == "link")) {
                        string strPath = iter->second;
                        // Turn an eventual absolute to a relative one
                        // A HTTP server does not have the same absolute strPath...
                        if (strPath[0] == '/') {
                            strPath.insert(0, ".");
                        }
                        // Nothing to download, it is a local file
                        if (bIsFile(strPath)) {
                            mapResHash[iter->second] = sri.getHash(
                                    strPath.c_str()
                            );
                        } else { // Download the strPath using Curl lib
                            CURL *curl;
                            CURLcode res;
                            curl = curl_easy_init();
                            if (curl) {
                                FILE *file = tmpfile();
                                const char *chTempPath = to_string(
                                        fileno(file)
                                ).c_str();
                                curl_easy_setopt(
                                        curl, CURLOPT_URL, strPath.c_str()
                                );
                                curl_easy_setopt(
                                        curl, CURLOPT_WRITEFUNCTION, NULL
                                );
                                curl_easy_setopt(
                                        curl, CURLOPT_WRITEDATA, file
                                );
                                res = curl_easy_perform(curl);
                                // Always close a file!
                                fclose(file);
                                // If download went fine, get the hash of the
                                // temp file
                                if (res == CURLE_OK) {
                                    mapResHash[iter->second] = sri.getHash(
                                            chTempPath
                                    );
                                }
                                // In any case delete file and clean the download
                                remove(chTempPath);
                                curl_easy_cleanup(curl);
                            }
                        }
                    }
                }
            }
        }
    }
    return mapResHash;
}


/*******************************************************************************
 * Function to get the Enum Algorithm from a string. The enum is from the SRI.h.
 * @param strAlgo A string that has to match the enum Algorithm sha256 or
 * sha384 or sha512.
 * @return An Algorithm enum
 * @throws invalid_argument if the string does not match the enum
 */
Algorithm getEnumAlgorithm(const string &strAlgo) {
    static map<string, Algorithm> mapAlgo{
            {"sha256", sha256Algorithm},
            {"sha384", sha384Algorithm},
            {"sha512", sha512Algorithm},
    };
    auto x = mapAlgo.find(strAlgo);
    if (x != end(mapAlgo)) {
        return x->second;
    }
    throw invalid_argument("Invalid algorithm: " + strAlgo);
}

/*******************************************************************************
 * Main function for the SRI project.
 * @param argc
 * @param argv
 * @return An integer 0 if all went well or another integer if there was an
 * error
 */
int main(int argc, char *argv[]) {
    // Both values from the CLI to pass to the SRI class
    string strHTMLFilePath;
    Algorithm algorithm;
    /***************************************************************************
     * Parse the command line arguments using TCLAP, inspired by
     * https://techkluster.com/c-plus-plus/3-ways-to-parse-command-line-arguments-in-c/.
     * Compilation solved according to
     * https://stackoverflow.com/questions/25213659/how-to-use-tclap-in-cmake-project.
     * Only TCLAP related method in this first try block.
     */
    try {
        // Description of this CLI
        TCLAP::CmdLine cmd(
                "Generate SRI in HTML tag according to https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                ' ',
                "0.0"
        );
        // The HTML file containing src tag(s) to process
        TCLAP::UnlabeledValueArg<string> inputArg(
                "input",
                "The HTML file containing src tag(s) to process",
                true,
                "",
                "HTML file"
        );
        cmd.add(inputArg);
        // The algorithm to use being an Enum sha256Algorithm, sha384Algorithm,
        // sha512Algorithm
        TCLAP::ValueArg<string> algorithmArg(
                "a",
                "algorithm",
                "The algorithm to use being sha256 or sha384 or sha512",
                false,
                "sha256",
                "algorithm"
        );
        cmd.add(algorithmArg);
        cmd.parse(argc, argv);

        // Get the value parsed by the inputArg
        strHTMLFilePath = inputArg.getValue();
        // Check if the argument is a valid file path
        if (!bIsFile(strHTMLFilePath)) {
            return wrongArguments(
                    "The file: " + strHTMLFilePath + " does not exist."
            );
        }

        // Check they match the enum Algorithm, if not exit
        try {
            algorithm = getEnumAlgorithm(
                    algorithmArg.getValue()
            );
        } catch (invalid_argument &e) {
            return wrongArguments(e.what());
        }

    } catch (TCLAP::ArgException &e) {
        return wrongArguments(
                "Error: " + e.error() + " for argument " + e.argId()
        );
    }


    // Turn HTML file into a string
    string strHTML = getStringFromLocalPath(strHTMLFilePath);
    SRI sri = SRI(algorithm);

    // Get the hash for all the src tags in the HTML file
    map<string, string> mapResHash;
    try {
        mapResHash = getSrcHash(strHTML, sri);
    } catch (CryptoPP::FileSource::OpenErr &e) {
        return errorMessageAndExit(e.what(), 3);
    }

    // Modify the HTML file with the SRI hash using regex
    for (const auto &pair: mapResHash) {
        // Remove potential existing integrity attribute
        strHTML = regex_replace(
                strHTML,
                regex(R"(\sintegrity=.*("|')(\s|$))"),
                " "
        );
        // Replace the src with the src and the hash
        strHTML = regex_replace(
                strHTML,
                regex(pair.first + "(\"|\')"),
                pair.first + "\" integrity=\"" + pair.second + "\""
        );
    }
    // Output the new HTML file
    cout << strHTML << endl;
    return 0;
}
