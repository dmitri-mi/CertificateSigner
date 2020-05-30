using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using CertificateIssuer;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PksSignerTest
{
    [TestClass]
    public class CertificateIssuerTest
    {
        [TestMethod]
        public void CertificateIssuerShouldSucceedTest()
        {
            // // You can also extract publicKey from CSR:
            // Pkcs10CertificationRequest csr = ...;
            // SubjectPublicKeyInfo info = csr.GetCertificationRequestInfo().SubjectPublicKeyInfo;
            // string publicKeyBase64 = Convert.ToBase64String(info.GetDerEncoded());
            // 
            // but for testing we use the hardcoded value:
            //
            // some public key in base64 DER encoded, that will be used as public key of the new certificate,
            // it should be ECDSA with SHA256 for this example, since the signing Certificate is also ECDSA with SHA256 (OID 1.2.840.10045.4.3.2)
            const string publicKey = @"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhpFTpKgGDqfxSwp9WlPJMa2o3XR5x1xKAgC4CR2AFbSzGFAjCIkUKtBCUrA5Te6ydhxVduA3JFE2hzqy/6V6qA==";

            // This certificate should exist in the certificate store on LocalMachine in CA store with appropriate subject CN
            // This certificate should have an associated private key that may not be exportable.
            X509Certificate2 signingCert = FindBySubject("L2", StoreName.CertificateAuthority, StoreLocation.LocalMachine);

            var subject = new DistinguishedName
            {
                C="My custom cert",
                O = "My org",
                SubjectAltNames = new[] { "a.bc.com" }
            };

            var issuer = new EcdsaCertificateIssuer();

            string newCert = issuer.CreateCertificate(subject, publicKey, signingCert);

            Assert.IsNotNull(newCert);
        }

        private X509Certificate2 FindBySubject(string subjectName, StoreName storeName, StoreLocation storeLocation)
        {
            try
            {
                // Get a local private key for sigining the outer envelope 
                using (var certStore = new X509Store(storeName, storeLocation))
                {
                    certStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                    var cert = certStore
                        .Certificates
                        .Find(X509FindType.FindBySubjectName, subjectName, false)
                        .Cast<X509Certificate2>()
                        .OrderByDescending(x => x.NotAfter) // select one with the latest expiration date
                        .First(); // require at least one to be found

                    certStore.Close();

                    return cert;
                }
            }
            catch (Exception e)
            {
                throw new Exception(
                    $"Cannot find valid certificate by subject: {subjectName} store: {storeName} store-location: {storeLocation}",
                    e);
            }
        }
    }
}
