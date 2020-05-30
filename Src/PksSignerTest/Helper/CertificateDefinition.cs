using System;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;

namespace CertificateIssuer
{
    public class CertificateDefinition
    {
        public X509Name Subject { get; set; }
        public GeneralName[] SubjectAltNames { get; set; }
        public SubjectPublicKeyInfo PublicKey { get; set; }
        public X509Certificate2 SigningCertificate { get; set; }
        public TimeSpan ExpireIn { get; set; } = TimeSpan.FromDays(14);
    }
}