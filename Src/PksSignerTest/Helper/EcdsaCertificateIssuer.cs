using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using PksSigner;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CertificateIssuer
{
    public class EcdsaCertificateIssuer
    {
        /// <summary>
        /// Create new certificate that is signed with private key from signing certificate that resides
        /// in Windows certificate store on local machine in intermediate certificate authorities.
        /// The private key does NOT have to be exportable.
        /// </summary>
        /// <param name="subject"></param>
        /// <param name="publicKeyBase64DerEncoded"></param>
        /// <param name="signingCertificate"></param>
        /// <returns>Freshly created certificate in PEM format</returns>
        public string CreateCertificate(DistinguishedName subject, string publicKeyBase64DerEncoded, X509Certificate2 signingCertificate)
        {
            var definition = new CertificateDefinition
            {
                Subject = ToX509Name(subject),
                SubjectAltNames = ToSans(subject.SubjectAltNames),
                PublicKey = ToPublicKey(publicKeyBase64DerEncoded),
                SigningCertificate = signingCertificate
            };

            X509Certificate certificate = CreateCertificate(definition);

            return ToPem(certificate);
        }

        public X509Certificate CreateCertificate(CertificateDefinition definition)
        {
            var randomGenerator = new CryptoApiRandomGenerator();

            BigInteger serialNumber = CreateSerialNumber(randomGenerator);


            if (definition.SigningCertificate == null)
                throw new CertificateIssuerException("Cannot create certificate without signing certificate (null).");

            (AsymmetricCipherKeyPair caKeyPair, X509Name issuer) = GetSigningKeyPair(definition.SigningCertificate);

            var publicKeyForNewCert = PublicKeyFactory.CreateKey(definition.PublicKey);

            var certGen = new X509V3CertificateGenerator();

            certGen.SetSerialNumber(serialNumber);
            certGen.SetIssuerDN(issuer);
            certGen.SetSubjectDN(definition.Subject);
            certGen.SetPublicKey(publicKeyForNewCert);

            var now = DateTime.Now;

            certGen.SetNotBefore(now.Subtract(new TimeSpan(0, 0, 10, 0))); // start 10 min before now

            // add max 2 weeks from now but not more then L2 expiration date
            var certExpirationDate = now.Add(definition.ExpireIn);
            var signingCertificateNotAfter = definition.SigningCertificate.NotAfter;
            if (signingCertificateNotAfter < now)
            {
                throw new CertificateIssuerException(
                    "Cannot create derived certificate because signing certificate already expired. Signing certificate subject name: " +
                    definition.SigningCertificate?.SubjectName.Name);
            }

            if (certExpirationDate > signingCertificateNotAfter)
            {
                certExpirationDate = signingCertificateNotAfter;
            }

            certGen.SetNotAfter(certExpirationDate);


            // certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

            AddExtensionSubjectKeyIdentifier(certGen, publicKeyForNewCert);

            AddExtensionAuthorityKeyIdentifier(certGen, caKeyPair);

            AddExtensionSubjectAltNames(certGen, definition.SubjectAltNames);

            // var s = @"file:////my-CA.com/CertEnroll/my-CA.com_my-Dev%20L2%20CA.crt";
            // AddExtensionAuthorityInfo(certGen, s);

            // string certificateTemplateExtension = "IPSECIntermediateOffline";
            // AddExtensionCertificateTemplateName(certGen, certificateTemplateExtension);

            // var crl = @"file:////my-CA.com/CertEnroll/my-Dev%20L2%20CA.crl";
            // AddExtensionCrlDistributionPoints(certGen, crl);

            // other supported algorithms: 
            /* SHA1withECDSA
             * SHA224withECDSA
             * SHA256withECDSA
             * SHA384withECDSA
             * SHA512withECDSA
             * NONEwithECDSA
             */
            const string algorithm = "SHA256WITHECDSA";

            // This is the most interesting part where we use our custom signature factory that utilizes
            // the custom private key PksEcPrivateKey
            ISignatureFactory signatureFactory =
                new PksAsn1SignatureFactory(algorithm, caKeyPair.Private, new SecureRandom(randomGenerator));

            X509Certificate cert = certGen.Generate(signatureFactory);

            return cert;
        }

        private static BigInteger CreateSerialNumber(CryptoApiRandomGenerator randomGenerator)
        {
            // BigInteger serialNumber = BigIntegers.CreateRandomInRange(
            //     BigInteger.ValueOf(Int32.MaxValue).Add(BigInteger.One), 
            //     BigInteger.ValueOf(Int64.MaxValue), 
            //     new SecureRandom(randomGenerator));

            // set to 19 bytes as per NEM-1518, since cert has max 20 bytes for serial number
            var sizeInBits = 8 * 19;
            BigInteger serialNumber = new BigInteger(sizeInBits, new SecureRandom(randomGenerator));
            if (serialNumber.SignValue < 0) serialNumber = serialNumber.Negate(); // convert negative to positive
            return serialNumber;
        }

        private static void AddExtensionSubjectKeyIdentifier(X509V3CertificateGenerator certGen,
            AsymmetricKeyParameter publicKeyForNewCert)
        {
            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure(publicKeyForNewCert));
        }

        private static void AddExtensionAuthorityKeyIdentifier(X509V3CertificateGenerator certGen,
            AsymmetricCipherKeyPair caKeyPair)
        {
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(caKeyPair.Public));
        }

        private static void AddExtensionSubjectAltNames(X509V3CertificateGenerator certGen, GeneralName[] subjectAltNames)
        {
            if (subjectAltNames?.Length > 0)
            {
                certGen.AddExtension(X509Extensions.SubjectAlternativeName, false,
                    new DerSequence(subjectAltNames.Where(x => x.Name != null).ToArray<Asn1Encodable>()));
            }
        }

        private static void AddExtensionCrlDistributionPoints(X509V3CertificateGenerator certGen, string crl)
        {
            certGen.AddExtension(X509Extensions.CrlDistributionPoints, false,
                new CrlDistPoint(new[]
                {
                    new DistributionPoint(
                        new DistributionPointName(
                            DistributionPointName.FullName,
                            new GeneralNames(
                                new GeneralName(GeneralName.UniformResourceIdentifier, crl)
                            )
                        )
                        , null, null)
                }));
        }

        private static void AddExtensionCertificateTemplateName(X509V3CertificateGenerator certGen, string certificateTemplateExtension)
        {
            certGen.AddExtension(
                new DerObjectIdentifier("1.3.6.1.4.1.311.20.2"), // OID for Certificate Template Name
                false,
                new DerBmpString(certificateTemplateExtension)
            );
        }

        private static void AddExtensionAuthorityInfo(X509V3CertificateGenerator certGen, string authorityInfoAccess)
        {
            certGen.AddExtension(X509Extensions.AuthorityInfoAccess, false,
                new AuthorityInformationAccess(new AccessDescription(AccessDescription.IdADCAIssuers,
                    new GeneralName(GeneralName.UniformResourceIdentifier, authorityInfoAccess))));
        }

        private (AsymmetricCipherKeyPair keyPair, X509Name subject) GetSigningKeyPair(X509Certificate2 signingCert)
        {
            X509Certificate publicPartCertificate = new X509CertificateParser().ReadCertificate(signingCert.RawData);

            AsymmetricKeyParameter privateKey = ExtractPrivateKey(signingCert, publicPartCertificate);

            var keyPair = new AsymmetricCipherKeyPair(publicPartCertificate.GetPublicKey(), privateKey);

            return (keyPair, publicPartCertificate.SubjectDN);
        }

        private AsymmetricKeyParameter ExtractPrivateKey(X509Certificate2 signingCertificate, X509Certificate publicPartOfSigningCertificate)
        {
            if (!signingCertificate.HasPrivateKey)
                throw new CertificateIssuerException(
                    $"Certificate doesn't have the private key. Certificate DN: {signingCertificate.SubjectName.Name} , Serial number: {signingCertificate.SerialNumber}");

            string certSubjectCn = publicPartOfSigningCertificate.SubjectDN.GetValueList(X509Name.CN)
                .Cast<string>()
                .FirstOrDefault();

            var privateKey = new PksEcPrivateKey(
                certSubjectCn,
                "CA",
                "LocalMachine");

            return privateKey;
        }

        private static X509Name ToX509Name(DistinguishedName distinguishedName)
        {
            IDictionary attrs = new Hashtable();
            IList ord = new ArrayList();

            if (distinguishedName.C != null)
            {
                attrs[X509Name.C] = distinguishedName.C;
                ord.Add(X509Name.C);
            }

            if (distinguishedName.O != null)
            {
                attrs[X509Name.O] = distinguishedName.O;
                ord.Add(X509Name.O);
            }

            if (distinguishedName.L != null)
            {
                attrs[X509Name.L] = distinguishedName.L;
                ord.Add(X509Name.L);
            }

            if (distinguishedName.St != null)
            {
                attrs[X509Name.ST] = distinguishedName.St;
                ord.Add(X509Name.ST);
            }

            if (distinguishedName.E != null)
            {
                attrs[X509Name.E] = distinguishedName.E;
                ord.Add(X509Name.E);
            }

            var issuer = new X509Name(ord, attrs);

            return issuer;
        }

        private static GeneralName[] ToSans(string[] subjectAltNames)
        {
            return subjectAltNames?.Length > 0 ? subjectAltNames.Select(x => new GeneralName(GeneralName.DnsName, x)).ToArray() : null;
        }

        private static SubjectPublicKeyInfo ToPublicKey(string publicKey)
        {
            SubjectPublicKeyInfo subjectPki = SubjectPublicKeyInfo.GetInstance(Convert.FromBase64String(publicKey));
            return subjectPki;
            // var keyPair = CreateEcKeyPair();
            // return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
        }

        // converts bouncy castle objects of type
        // X509Certificate, X509Crl, AsymmetricCipherKeyPair, AsymmetricKeyParameter,
        // IX509AttributeCertificate, Pkcs10CertificationRequest, Asn1.Cms.ContentInfo 
        // to PEM format string
        private static string ToPem(object obj)
        {
            using (var mem = new MemoryStream())
            using (var writer = new StreamWriter(mem))
            {
                var pem = new PemWriter(writer);

                pem.WriteObject(obj);

                // force the pem write to flush it's data - kind of abnoxious you have to do that
                pem.Writer.Flush();

                // create a stream reader to read the data.
                using (var reader = new StreamReader(mem))
                {
                    mem.Position = 0;
                    string pemStr = reader.ReadToEnd();
                    return pemStr;
                }
            }
        }
    }
}
