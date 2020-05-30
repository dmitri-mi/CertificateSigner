using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CertificateSignerTest
{
    [TestClass]
    public class SignerTest
    {
        [TestMethod]
        public void ValidSignShouldSucceed()
        {
            // wrapper for unmanaged signer
            var signer = new CertificateSigner.SignerWrapper();

            // example of hash, real hash will be a longer byte array
            byte[] hash = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };

            byte[] signature = signer.Sign(
                hash,
                "L2",  // CN (common name) of the certificate in the store that has the associated private key
                "CA", // Logical store name, "CA" means Intermediate Certificate Authorities, use "MY" for personal
                "LocalMachine" // Store location
            );

            Assert.IsNotNull(signature);

            // // if the certificate's private key is ECDSA SHA-256 we should get the signature that is 64 bit,
            // // first 32 bit is R parameter, last 32 bit is S parameter
            // Assert.AreEqual(64, signature.Length);
        }
    }
}
