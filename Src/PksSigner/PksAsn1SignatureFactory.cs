using System;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PksSigner
{
    /// <summary>
    /// Signature factory that uses Cryptographic service provider without explicit access to private key.
    /// This class is needed solely because we cannot override the Signer that is created in the method
    /// IStreamCalculator CreateCalculator()
    /// </summary>
    internal class PksAsn1SignatureFactory : ISignatureFactory
    {
        private readonly AlgorithmIdentifier algID;
        private readonly string algorithm;
        private readonly AsymmetricKeyParameter privateKey;
        private readonly SecureRandom random;

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="algorithm">The name of the signature algorithm to use.</param>
        /// <param name="privateKey">The private key to be used in the signing operation.
        /// Notice that this can contain any parameters required for Signer to sign the data and
        /// not necessarily raw private key themselves.
        /// </param>
        public PksAsn1SignatureFactory(string algorithm, AsymmetricKeyParameter privateKey) : 
            this(algorithm, privateKey, null)
        {
        }

        /// <summary>
        /// Constructor which also specifies a source of randomness to be used if one is required.
        /// </summary>
        /// <param name="algorithm">The name of the signature algorithm to use.</param>
        /// <param name="privateKey">The private key to be used in the signing operation.</param>
        /// <param name="random">The source of randomness to be used in signature calculation.</param>
        public PksAsn1SignatureFactory(string algorithm, AsymmetricKeyParameter privateKey, SecureRandom random)
        {
            DerObjectIdentifier sigOid = X509Utilities.GetAlgorithmOid(algorithm);

            this.algorithm = algorithm;
            this.privateKey = privateKey;
            this.random = random;
            this.algID = X509Utilities.GetSigAlgID(sigOid, algorithm);
        }

        public Object AlgorithmDetails
        {
            get { return this.algID; }
        }

        public IStreamCalculator CreateCalculator()
        {
            // this is why we need this custom class, since we cannot override the Signer
            ISigner sig = PksSignerUtils.GetSigner(algorithm); 

            if (random != null)
            {
                sig.Init(true, new ParametersWithRandom(privateKey, random));
            }
            else
            {
                sig.Init(true, privateKey);
            }

            return new SigCalculator(sig);
        }
    }

    // a copy from BC
    internal class SigCalculator : IStreamCalculator
    {
        private readonly ISigner sig;
        private readonly Stream stream;

        internal SigCalculator(ISigner sig)
        {
            this.sig = sig;
            this.stream = new SignerBucket(sig);
        }

        public Stream Stream
        {
            get { return stream; }
        }

        public object GetResult()
        {
            return new SigResult(sig);
        }
    }

    // a copy from BC
    internal class SigResult : IBlockResult
    {
        private readonly ISigner sig;

        internal SigResult(ISigner sig)
        {
            this.sig = sig;
        }

        public byte[] Collect()
        {
            return sig.GenerateSignature();
        }

        public int Collect(byte[] destination, int offset)
        {
            byte[] signature = Collect();

            Array.Copy(signature, 0, destination, offset, signature.Length);

            return signature.Length;
        }
    }

    // a copy from BC
    internal class SignerBucket
        : Stream
    {
        protected readonly ISigner signer;

        public SignerBucket(
            ISigner signer)
        {
            this.signer = signer;
        }

        public override int Read(
            byte[] buffer,
            int offset,
            int count)
        {
            throw new NotImplementedException();
        }

        public override int ReadByte()
        {
            throw new NotImplementedException();
        }

        public override void Write(
            byte[] buffer,
            int offset,
            int count)
        {
            if (count > 0)
            {
                signer.BlockUpdate(buffer, offset, count);
            }
        }

        public override void WriteByte(
            byte b)
        {
            signer.Update(b);
        }

        public override bool CanRead
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override long Length
        {
            get { return 0; }
        }

        public override long Position
        {
            get { throw new NotImplementedException(); }
            set { throw new NotImplementedException(); }
        }

        public override void Flush()
        {
        }

        public override long Seek(
            long offset,
            SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(
            long length)
        {
            throw new NotImplementedException();
        }
    }
}
