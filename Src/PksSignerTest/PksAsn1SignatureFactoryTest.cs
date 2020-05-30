using System;
using System.Collections;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using PksSigner;

namespace PksSignerTest
{
    [TestClass]
    public class PksAsn1SignatureFactoryTest
    {
        [TestMethod]
        public void CalculateSignatureShouldSucceed()
        {
            // The certificate should exist in the certificate store
            // on LocalMachine in CA store with appropriate subject CN
            // as it is defined in with the given "issuerSubject".
            // This certificate should have an associated private key that may not be exportable.
            const string issuerSubject = "L2";

            var privateKey = new PksEcPrivateKey(
                issuerSubject,
                "CA",
                "LocalMachine");

            const string algorithm = "SHA256withECDSA";

            ISignatureFactory signatureFactory = new PksAsn1SignatureFactory(algorithm, privateKey);

            // example of hash, real hash will be a longer byte array
            byte[] hash = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };


            IStreamCalculator calculator = signatureFactory.CreateCalculator();

            using (var stream = calculator.Stream)
            {
                stream.Write(hash, 0, hash.Length);
            }

            object result = calculator.GetResult();

            byte[] signature = ((IBlockResult) result).Collect(); // ASN.1 DER formatted signature
            
            Assert.IsNotNull(signature);
        }

        [TestMethod]
        public void CreateCertificateShouldSucceed()
        {
            // some public key in base64 DER encoded, that will be used as public key of the new certificate,
            // it should be ECDSA with SHA256 for this example, since the signing Certificate is also ECDSA with SHA256 (OID 1.2.840.10045.4.3.2)
            const string publicKey = @"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhpFTpKgGDqfxSwp9WlPJMa2o3XR5x1xKAgC4CR2AFbSzGFAjCIkUKtBCUrA5Te6ydhxVduA3JFE2hzqy/6V6qA==";

            // The certificate should exist in the certificate store
            // on LocalMachine in CA store with appropriate subject CN
            // as it is defined in with the given "issuerSubject".
            // This certificate should have an associated private key that may not be exportable.
            const string issuerSubject = "L2";

            var privateKey = new PksEcPrivateKey(
                issuerSubject,
                "CA",
                "LocalMachine");

            const string algorithm = "SHA256withECDSA";

            ISignatureFactory signatureFactory = new PksAsn1SignatureFactory(algorithm, privateKey);


            // signatureCalculatorFactory can be used for generating a new certificate with BouncyCastle
            var certificateGenerator = new X509V3CertificateGenerator();

            // ... set all other required fields of the X509V3CertificateGenerator
            certificateGenerator.SetSerialNumber(BigInteger.One);
            certificateGenerator.SetIssuerDN(ToX509Name(issuerSubject));
            certificateGenerator.SetSubjectDN(ToX509Name("My-new-cert", "My-org"));

            certificateGenerator.SetPublicKey(
                PublicKeyFactory.CreateKey(
                    SubjectPublicKeyInfo.GetInstance(Convert.FromBase64String(publicKey))));
            certificateGenerator.SetNotBefore(DateTime.Now.Subtract(TimeSpan.FromMinutes(10)));

            certificateGenerator.SetNotAfter(DateTime.Now.Add(TimeSpan.FromDays(14)));

            // finally run the generator for a new certificate:
            X509Certificate cert = certificateGenerator.Generate(signatureFactory);

            Assert.IsNotNull(cert);
        }

        private static X509Name ToX509Name(string cn, string organization = null)
        {
            IDictionary attrs = new Hashtable();
            IList ord = new ArrayList();

            if (cn != null)
            {
                attrs[X509Name.C] = cn;
                ord.Add(X509Name.C);
            }

            if (organization != null)
            {
                attrs[X509Name.O] = organization;
                ord.Add(X509Name.O);
            }

            var issuer = new X509Name(ord, attrs);

            return issuer;
        }
    }
}
