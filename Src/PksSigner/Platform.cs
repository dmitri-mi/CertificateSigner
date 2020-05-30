using System.Collections;

namespace PksSigner
{
    /// <summary>
    /// a copy from BouncyCastle with only limited functionality
    /// </summary>
    internal static class Platform
    {
        public static IDictionary CreateHashtable()
        {
            return new Hashtable();
        }

        public static string ToUpperInvariant(string algorithmName)
        {
            return algorithmName.ToUpperInvariant();
        }
    }
}