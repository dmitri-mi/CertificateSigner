using Org.BouncyCastle.Crypto;

namespace PksSigner
{
    /// <summary>
    /// Pks (private key store) parameters used to sign with EC private key
    /// </summary>
    public class PksEcPrivateKey : AsymmetricKeyParameter // : ECKeyParameters
    {
        public string CertificateCommonName { get; }
        public string CertificateStoreName { get; }
        public string CertificateStoreLocation { get; }

        /// <summary>
        /// Defines the location of the certificate in the certificate store,
        /// so that the associated private key can be used to create the signature
        /// </summary>
        /// <param name="certificateCommonName">CN (common name) of the certificate to be found in certificate store</param>
        /// <param name="certificateStoreName">Example: "CA" or "MY"</param>
        /// <param name="certificateStoreLocation">Example: "LocalMachine", "User", "Service"</param>
        public PksEcPrivateKey(
            string certificateCommonName,
            string certificateStoreName,
            string certificateStoreLocation
        ) 
            : base(true)
        //: base("ECDSA", true, new ECDomainParameters())
        {
            CertificateCommonName    = certificateCommonName;
            CertificateStoreName     = certificateStoreName;
            CertificateStoreLocation = certificateStoreLocation;
        }

        public override int GetHashCode()
        {
            return
                (CertificateCommonName?.GetHashCode() ?? 0) ^
                (CertificateStoreName?.GetHashCode() ?? 0) ^
                (CertificateStoreLocation?.GetHashCode() ?? 0) ^
                base.GetHashCode();
        }

        public override bool Equals(object obj)
        {
            if (obj == this) return true;

            if (!(obj is PksEcPrivateKey other)) return false;

            return
                CertificateCommonName == other.CertificateCommonName &&
                CertificateStoreName == other.CertificateStoreName &&
                CertificateStoreLocation == other.CertificateStoreLocation &
                base.Equals(other);
        }
    }
}