using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace PksSigner
{
    /// <summary>
    /// Signer that accesses private key store (PKS) and signs without exporting the private key explicitly
    /// </summary>
    internal class PksEcdsaSigner : IDsa
    {
        private PksEcPrivateKey _privateKey; // used for signing
        private ECDsaSigner _verifier;

        public virtual string AlgorithmName => "ECDSA";

        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            SecureRandom providedRandom = null;

            if (forSigning)
            {
                if (parameters is ParametersWithRandom rParam)
                {
                    providedRandom = rParam.Random;
                    parameters = rParam.Parameters;
                }

                _privateKey = parameters as PksEcPrivateKey ??
                              throw new InvalidKeyException("EC private key required for signing");
            }
            else
            {
                _verifier = new ECDsaSigner();
                _verifier.Init(false, parameters);
            }
        }

        public virtual BigInteger[] GenerateSignature(byte[] message)
        {
            var signer = new CertificateSigner.SignerWrapper();

            byte[] signature = signer.Sign(message, 
                _privateKey.CertificateCommonName,
                _privateKey.CertificateStoreName,
                _privateKey.CertificateStoreLocation);

            if(signature == null || signature.Length != 64)
                throw new Exception($"Invalid signature length, expected 64 but got: {signature?.Length}");

            /*
             * To prevent positive values from being misinterpreted as negative values,
             * you can add a zero-byte value to the end of the array.
             * END of the array since BigInteger interprets byte array as little-endian:
             *
             * The individual bytes in the value array should be in little-endian order,
             * from lowest-order byte to highest-order byte
             */

            BigInteger r = new BigInteger(1, signature, 0, 32);
            BigInteger s = new BigInteger(1, signature, 32, 32);

            return new[] { r, s };
        }

        public bool VerifySignature(byte[] message, BigInteger r, BigInteger s)
        {
            if (_verifier == null) throw new NotImplementedException();

            return _verifier.VerifySignature(message, r, s);
        }

        // Does not exist in BC 1.8.3.1, only after ver 1.8.4, which is defined in IDsaExt, 
        // and implemented in ECDsaSigner. GenerateSignature fails if key==null in BC ver 1.8.4 and up
        // if we derive this class from ECDsaSigner :
        //
        // public override BigInteger Order
        // {
        //     get { return key?.Parameters.N; }
        // }
    }
}