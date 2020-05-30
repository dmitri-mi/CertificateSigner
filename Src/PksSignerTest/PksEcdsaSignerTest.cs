using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using PksSigner;

namespace PksSignerTest
{
    [TestClass]
    public class PksEcdsaSignerTest
    {
        [TestMethod]
        public void ValidShouldSucceed()
        {
            // example of hash, real hash will be a longer byte array
            byte[] hash = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };

            ICipherParameters privateKey = new PksEcPrivateKey(
                "L2",
                "CA",
                "LocalMachine");


            var dsaSigner = new PksEcdsaSigner();

            dsaSigner.Init(true, privateKey); // init forSigning. this is how it is used in BouncyCastle DsaDigestSigner

            BigInteger[] signature = dsaSigner.GenerateSignature(hash);

            // for ECDSA "signature" contains two values R and S, where R=signature[0], S=signature[1]
            var r = signature[0];
            var s = signature[1];

            Assert.IsFalse(BigInteger.Zero.Equals(r), "r - shouldn't be zero");
            Assert.IsFalse(BigInteger.Zero.Equals(s), "s - shouldn't be zero");
        }
    }
}
