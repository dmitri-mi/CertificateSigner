using System;
using System.Runtime.Serialization;

namespace CertificateIssuer
{
    [Serializable]
    public class CertificateIssuerException : Exception
    {
        public CertificateIssuerException()
        {
        }

        public CertificateIssuerException(string message) : base(message)
        {
        }

        public CertificateIssuerException(string message, Exception inner) : base(message, inner)
        {
        }

        protected CertificateIssuerException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}