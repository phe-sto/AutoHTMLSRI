//
// Created by chrichri on 16/06/24.
//

#ifndef SRI_HTMLFILE_H
#define SRI_HTMLFILE_H

#include "SRI.h"

class HTMLFile {

public:
    /***************************************************************************
    * The constructor of the HTMLFile class. It requires a path to the HTML file
    * and a SRI instance to get the hash of the resources.
    * @param chFSPath The path to the HTML file
    * @param sri The SRI instance to get the hash of the resources
    * */
    HTMLFile(const char *chFSPath, SRI &sriParam);

    /***************************************************************************
     * mapResHash is public mainly for testing purposes
     */
    map<string, string> mapResHash;

    /***************************************************************************
    * Function to get the hash of all the src tags in the HTML file.
    * The parser is used according to https://developer.mozilla.org/fr/docs/Web/Security/Subresource_Integrity
    * It uses HTMLCXX to parse the HTML file and get the src tags.
    * If the resource is local, it uses the SRI class to get the hash.
    * If the resource is remote, it uses Curl to download the resource and then
    * get the hash.
    * */
    static map<string, string> getSrcHash(const string &strHTMLFilePath, SRI &sri);

    /***************************************************************************
    * Function to check if a file exists.
    * @param strFilePath The file strFilePath to check
    * @return A boolean true if the file exists, false otherwise
    */
    static bool bIsFile(const string &strFilePath);

    /***************************************************************************
    * Method to write the resulting HTML file with the SRI hash.
    * It uses regex to modify the HTML file with the SRI hash.
    * */
    string resultingHTMLFile();

    /***************************************************************************
    * Method to get the content of a file as a string.
    * Used to get the content of the HTML input.
    * @param strHTMLFilePath The path to the file to read
    * */
    static string getStringFromLocalPath(const string &strHTMLFilePath);

private:
    const char *chFSPath;
    SRI sri;


};


#endif //SRI_HTMLFILE_H
