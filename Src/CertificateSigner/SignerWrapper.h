#pragma once
using namespace System;

namespace CertificateSigner
{
	public ref class SignerWrapper
	{
	public:
		SignerWrapper();

		// returns a signature of the hash, using the private key associated with the certificate
		array<Byte>^ Sign(
			array<Byte>^ hash, 
			String^ certificateName, // CN of the certificate that has the private key
			String^ certificateStoreName, // // Logical store name, "CA" means Intermediate Certificate Authorities, "MY" means personal
			String^ certificateStoreLocation // "LocalMachine", "User", "Service"
			); 
	};
}




