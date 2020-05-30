using System;
using System.Collections;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;

namespace PksSigner
{
    /// <summary>
    ///  a copy from BC of "SignerUtils" with only ECDSA support
    /// </summary>
    static class PksSignerUtils
    {
        static readonly IDictionary algorithms = Platform.CreateHashtable();

        static PksSignerUtils()
        {
            const string noneWithEcdsa = "NONEwithECDSA";
            algorithms["NONEWITHECDSA"] = noneWithEcdsa;
            algorithms["ECDSAWITHNONE"] = noneWithEcdsa;

            const string sha1WithEcdsa = "SHA-1withECDSA";
            algorithms["ECDSA"] = sha1WithEcdsa;
            algorithms["SHA1/ECDSA"] = sha1WithEcdsa;
            algorithms["SHA-1/ECDSA"] = sha1WithEcdsa;
            algorithms["ECDSAWITHSHA1"] = sha1WithEcdsa;
            algorithms["ECDSAWITHSHA-1"] = sha1WithEcdsa;
            algorithms["SHA1WITHECDSA"] = sha1WithEcdsa;
            algorithms["SHA-1WITHECDSA"] = sha1WithEcdsa;
            algorithms[X9ObjectIdentifiers.ECDsaWithSha1.Id] = sha1WithEcdsa;
            algorithms[TeleTrusTObjectIdentifiers.ECSignWithSha1.Id] = sha1WithEcdsa;

            const string sha224WithEcdsa = "SHA-224withECDSA";
            algorithms["SHA224/ECDSA"] = sha224WithEcdsa;
            algorithms["SHA-224/ECDSA"] = sha224WithEcdsa;
            algorithms["ECDSAWITHSHA224"] = sha224WithEcdsa;
            algorithms["ECDSAWITHSHA-224"] = sha224WithEcdsa;
            algorithms["SHA224WITHECDSA"] = sha224WithEcdsa;
            algorithms["SHA-224WITHECDSA"] = sha224WithEcdsa;
            algorithms[X9ObjectIdentifiers.ECDsaWithSha224.Id] = sha224WithEcdsa;

            const string sha256WithEcdsa = "SHA-256withECDSA";
            algorithms["SHA256/ECDSA"] = sha256WithEcdsa;
            algorithms["SHA-256/ECDSA"] = sha256WithEcdsa;
            algorithms["ECDSAWITHSHA256"] = sha256WithEcdsa;
            algorithms["ECDSAWITHSHA-256"] = sha256WithEcdsa;
            algorithms["SHA256WITHECDSA"] = sha256WithEcdsa;
            algorithms["SHA-256WITHECDSA"] = sha256WithEcdsa;
            algorithms[X9ObjectIdentifiers.ECDsaWithSha256.Id] = sha256WithEcdsa;

            const string sha384WithEcdsa = "SHA-384withECDSA";
            algorithms["SHA384/ECDSA"] = sha384WithEcdsa;
            algorithms["SHA-384/ECDSA"] = sha384WithEcdsa;
            algorithms["ECDSAWITHSHA384"] = sha384WithEcdsa;
            algorithms["ECDSAWITHSHA-384"] = sha384WithEcdsa;
            algorithms["SHA384WITHECDSA"] = sha384WithEcdsa;
            algorithms["SHA-384WITHECDSA"] = sha384WithEcdsa;
            algorithms[X9ObjectIdentifiers.ECDsaWithSha384.Id] = sha384WithEcdsa;

            const string sha512WithEcdsa = "SHA-512withECDSA";
            algorithms["SHA512/ECDSA"] = sha512WithEcdsa;
            algorithms["SHA-512/ECDSA"] = sha512WithEcdsa;
            algorithms["ECDSAWITHSHA512"] = sha512WithEcdsa;
            algorithms["ECDSAWITHSHA-512"] = sha512WithEcdsa;
            algorithms["SHA512WITHECDSA"] = sha512WithEcdsa;
            algorithms["SHA-512WITHECDSA"] = sha512WithEcdsa;
            algorithms[X9ObjectIdentifiers.ECDsaWithSha512.Id] = sha512WithEcdsa;
        }

        public static ISigner GetSigner(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            algorithm = Platform.ToUpperInvariant(algorithm);

            string mechanism = (string)algorithms[algorithm] ?? algorithm;


            if (mechanism.Equals("NONEwithECDSA"))
            {
                return CreateEcdsaSigner(new NullDigest());
            }
            if (mechanism.Equals("SHA-1withECDSA"))
            {
                return CreateEcdsaSigner(new Sha1Digest());
            }
            if (mechanism.Equals("SHA-224withECDSA"))
            {
                return CreateEcdsaSigner(new Sha224Digest());
            }
            if (mechanism.Equals("SHA-256withECDSA"))
            {
                return CreateEcdsaSigner(new Sha256Digest());
            }
            if (mechanism.Equals("SHA-384withECDSA"))
            {
                return CreateEcdsaSigner(new Sha384Digest());
            }
            if (mechanism.Equals("SHA-512withECDSA"))
            {
                return CreateEcdsaSigner(new Sha512Digest());
            }
            
            throw new NotSupportedException($"Not supported signer algorithm: {algorithm}");
        }

        static DsaDigestSigner CreateEcdsaSigner(IDigest digest)
        {
            return new DsaDigestSigner(new PksEcdsaSigner(), digest);
        }
    }
}
