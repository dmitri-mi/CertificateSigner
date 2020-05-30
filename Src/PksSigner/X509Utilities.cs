using System.Collections;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Utilities.Collections;

namespace PksSigner
{
    /// <summary>
    /// a copy from BouncyCastle  with only limited functionality to support ECDSA,
    /// see Org.BouncyCastle.Crypto.Operators.X509Utilities
    /// </summary>
    static class X509Utilities
    {
        private static readonly IDictionary algorithms = Platform.CreateHashtable();
        private static readonly IDictionary exParams = Platform.CreateHashtable();
        private static readonly ISet noParams = new HashSet();

        static X509Utilities()
        {
            algorithms.Add("SHA1WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha1);
            algorithms.Add("ECDSAWITHSHA1", X9ObjectIdentifiers.ECDsaWithSha1);
            algorithms.Add("SHA224WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha224);
            algorithms.Add("SHA256WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha256);
            algorithms.Add("SHA384WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha384);
            algorithms.Add("SHA512WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha512);

            //
            // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
            // The parameters field SHALL be NULL for RSA based signature algorithms.
            //
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha1);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha224);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha256);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha384);
            noParams.Add(X9ObjectIdentifiers.ECDsaWithSha512);

        }

        internal static DerObjectIdentifier GetAlgorithmOid(string algorithmName)
        {
            algorithmName = Platform.ToUpperInvariant(algorithmName);

            if (algorithms.Contains(algorithmName))
            {
                return (DerObjectIdentifier)algorithms[algorithmName];
            }

            return new DerObjectIdentifier(algorithmName);
        }

        internal static AlgorithmIdentifier GetSigAlgID(DerObjectIdentifier sigOid, string algorithmName)
        {
            if (noParams.Contains(sigOid))
            {
                return new AlgorithmIdentifier(sigOid);
            }

            algorithmName = Platform.ToUpperInvariant(algorithmName);

            if (exParams.Contains(algorithmName))
            {
                return new AlgorithmIdentifier(sigOid, (Asn1Encodable)exParams[algorithmName]);
            }

            return new AlgorithmIdentifier(sigOid, DerNull.Instance);
        }
    }
}