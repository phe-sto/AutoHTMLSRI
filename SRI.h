/*******************************************************************************
 * SRI.h Header of the SRI hash class.
 *
 * Code under WTFPL, "Do What The Fuck You Want to Public License" feel free to
 * and please contribute.
 *
 * @author Christophe Brun
 * @version 0.0
 * @date 2024-06-15
 * @brief Header of the SRI hash class
 * @note C++17
 * */

#ifndef SRI_SRI_H
#define SRI_SRI_H

#include <string>
#include <cryptopp/cryptlib.h>

using namespace std;

/*******************************************************************************
 * List of the SRI compliant algorithm according to
 * https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity.
 * */
enum Algorithm {
    sha256Algorithm,
    sha384Algorithm,
    sha512Algorithm
};

class SRI {
/*******************************************************************************
 * Only constructor and getHash method are public
 * */
public:
    /***************************************************************************
     * Constructor
     * @param algorithm The algorithm to use, an enum Algorithm
     * */
    explicit SRI(Algorithm algorithm);

    /***************************************************************************
     * The method that returns the hash based on the algorithm
     * @param aString The string to hash
     * @return The hash as a string
     */
    string getHash(const char *chFSPath);

private:
    Algorithm algorithm;

    /***************************************************************************
     * @param aString The string to hash using sha256 algorithm from crypto++
     * @return The sha256 hash as a string
     * */
    static string getSha256Hash(const char *chFSPath);

    /***************************************************************************
     * @param aString The string to hash using sha512 algorithm from crypto++
     * @return The sha512 hash as a string
     * */
    static string getSha512Hash(const char *chFSPath);

    /***************************************************************************
     * @param aString The string to hash using sha348 algorithm from crypto++
     * @return The sha384 hash as a string
     * */
    static string getSha384Hash(const char *chFSPath);
};

#endif //SRI_SRI_H
