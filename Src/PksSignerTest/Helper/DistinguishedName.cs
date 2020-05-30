namespace CertificateIssuer
{
    public class DistinguishedName
    {
        public string C { get; set; }
        public string O { get; set; }
        public string L { get; set; }
        public string St { get; set; }
        public string E { get; set; }

        /// <summary>
        /// This can be null or empty when SANs are not required
        /// </summary>
        public string[] SubjectAltNames { get; set; }
    }
}