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
#include "HTMLFile.h"
#include <iostream>
#include <map>
// TCLAP for the CLI, it requires https://launchpad.net/ubuntu/+source/tclap
// Installed using apt-get install libtclap-dev
#include <tclap/CmdLine.h>
#include <tclap/UnlabeledValueArg.h>
#include <tclap/ValueArg.h>
#include <tclap/ArgException.h>
#include <cryptopp/files.h>


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
        if (!HTMLFile::bIsFile(strHTMLFilePath)) {
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
    string strHTML = HTMLFile::getStringFromLocalPath(strHTMLFilePath);

    SRI sri = SRI(algorithm);

    try {
        HTMLFile htmlFile(strHTMLFilePath.c_str(), sri);
        //mapResHash = getSrcHash(strHTML, sri);
        cout << htmlFile.resultingHTMLFile() << endl;
        return 0;
    } catch (CryptoPP::FileSource::OpenErr &e) {
        return errorMessageAndExit(e.what(), 3);
    }
}
