/*******************************************************************************
 * SRI.cpp - Implementation of the SRI class
 * The SRI class is a class that takes a aString and an algorithm and returns
 * a hash. The algorithm is a string that can be sha256 or sha384 or and sha512.
 * Only getHash is public and the other methods are private.
 * It uses the Crypto++ library to generate the hash in a safe way.
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
#include "SRI.h"
#include <string>

// For sha algorithms
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>

/*******************************************************************************
 * Extend CryptoPP::Base64Encoder with line break being false to make the
 * syntax more lightweight as it is 3 times in the above methods.
 * */
class NoLineBase64Encoder : public CryptoPP::Base64Encoder {
public:
    explicit NoLineBase64Encoder(CryptoPP::BufferedTransformation *attachment)
            : CryptoPP::Base64Encoder(attachment, false) {}

};

/*******************************************************************************
 * Extend class CryptoPP::FileSource with pump all file source is true
 * syntax more lightweight as it is 3 times in the above methods.
 * */
class PumpAllFileSource : public CryptoPP::FileSource {
public:
    PumpAllFileSource(
            const char *filename, CryptoPP::BufferedTransformation *attachment
    )
            : CryptoPP::FileSource(filename, true, attachment) {}

};

/*******************************************************************************
 * Constructor
 * @param algorithm The algorithm to use, an enum Algorithm
 * */
SRI::SRI(Algorithm algorithm) {
    this->algorithm = algorithm;

}

/*******************************************************************************
 * The method that returns the hash based on the algorithm.
 * The hash is a string formated with the algorithm followed by the hash as
 * expected in the HTML security attribute.
 * @param aString The string to hash
 * @return The hash as a string
 */
string SRI::getHash(const char *chFSPath) {
    string hash;

    switch (this->algorithm) {
        case sha256Algorithm: {
            hash = "sha256-" + getSha256Hash(chFSPath);
            break;
        }
        case sha384Algorithm: {
            hash = "sha384-" + getSha384Hash(chFSPath);
            break;
        }
        case sha512Algorithm: {
            hash = "sha512-" + getSha512Hash(chFSPath);
            break;
        }
    }
    return hash;
}

/*******************************************************************************
 * @param aString The string to hash using sha256 algorithm from crypto++
 * @return The sha256 hash as a string
 * */
string SRI::getSha256Hash(const char *chFSPath) {
    CryptoPP::SHA256 hash;
    string strDigest; // the result

    PumpAllFileSource fileSource(
            chFSPath,
            new CryptoPP::HashFilter(
                    hash,
                    new NoLineBase64Encoder(
                            new CryptoPP::StringSink(
                                    strDigest
                            )
                    )
            )
    );
    return strDigest;
}

/*******************************************************************************
 * @param aString The string to hash using sha348 algorithm from crypto++
 * @return The sha384 hash as a string
 * */
string SRI::getSha384Hash(const char *chFSPath) {
    CryptoPP::SHA384 hash;
    string strDigest; // the result

    PumpAllFileSource fileSource(
            chFSPath,
            new CryptoPP::HashFilter(
                    hash,
                    new NoLineBase64Encoder(
                            new CryptoPP::StringSink(
                                    strDigest
                            )
                    )
            )
    );
    return strDigest;
}

/*******************************************************************************
 * @param aString The string to hash using sha512 algorithm from crypto++
 * @return The sha512 hash as a string
 * */
string SRI::getSha512Hash(const char *chFSPath) {
    CryptoPP::SHA512 hash;
    string strDigest; // the result

    PumpAllFileSource fileSource(
            chFSPath,
            new CryptoPP::HashFilter(
                    hash,
                    new NoLineBase64Encoder(
                            new CryptoPP::StringSink(
                                    strDigest
                            )
                    )
            )
    );
    return strDigest;
}