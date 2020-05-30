#include <windows.h>

#include "SignerWrapper.h"

#include <string>
#include <msclr/marshal_cppstd.h>
#include "Sign.h"

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

CertificateSigner::SignerWrapper::SignerWrapper()
{
}

array<System::Byte>^ 
 CertificateSigner::SignerWrapper::Sign(
	array<System::Byte>^ hash,
	String^ certificateName,
	String^ certificateStoreName,
	String^ certificateStoreLocation
 )
{
	unsigned char* unmanagedHash = NULL;
	BYTE* pbSignature = NULL;
	DWORD cbSignature = 0;

	try
	{
		unmanagedHash = new BYTE[hash->Length];

		Runtime::InteropServices::Marshal::Copy(
			hash, 
			0, 
			IntPtr(const_cast<unsigned char*>(unmanagedHash)), 
			hash->Length);

		std::wstring certificateNameUnmanaged = msclr::interop::marshal_as<std::wstring>(certificateName);
		std::wstring::const_pointer pcwCertificateName = certificateNameUnmanaged.c_str();

		std::wstring certificateStoreNameUnmanaged = msclr::interop::marshal_as<std::wstring>(certificateStoreName);
		std::wstring::const_pointer pcwCertificateStoreName = certificateStoreNameUnmanaged.c_str();

		std::wstring certificateStoreLocationUnmanaged = msclr::interop::marshal_as<std::wstring>(certificateStoreLocation);
		std::wstring::const_pointer pcwCertificateStoreLocation = certificateStoreLocationUnmanaged.c_str();

		HRESULT signResult = Signer::Sign(
			unmanagedHash,
			hash->Length,
			pcwCertificateName,
			pcwCertificateStoreName,
			pcwCertificateStoreLocation,
			&pbSignature,
			&cbSignature
		);

		// on success
		if(cbSignature > 0 && pbSignature != NULL && !FAILED(signResult))
		{
			array<Byte>^ result = gcnew array<System::Byte>(cbSignature);

			Runtime::InteropServices::Marshal::Copy(
				IntPtr(static_cast<void*>(pbSignature)),
				result,
				0,
				cbSignature);

			return result;
		}
	}
	finally
	{
		if (unmanagedHash != NULL)  delete[] unmanagedHash;
	    if (NULL != pbSignature) Signer::ReleaseMemory(pbSignature);
	}
	
	return nullptr; // on failure
}