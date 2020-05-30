// from: https://github.com/Microsoft/Windows-classic-samples/blob/master/Samples/Win7Samples/security/cryptoapi/CertSign/CPP/Sign.cpp 

/****************************************************************

Title: Acquire a private key associated with a certificate and use it for signing

This example shows how to acquire private key associated with a certificate,
determine its type (CAPI or CNG) and used it to signed hashed message.
In addition it demonstrates creating hash using CAPI or CNG APIs
Please note: even though this sample shows CNG hash signed by CNG key and
CAPI hash signed by CAPI key, it is possible to use CNG key to sign CAPI hash

****************************************************************/

#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS

#include <windows.h>
#include <winerror.h>
#include <strsafe.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string>

#include "Sign.h"

System::String^ Signer::BuildErrorMessage(DWORD dwErrCode)
{
	LPWSTR pwszMsgBuf = NULL;
	
	FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,             // Location of message definition ignored
		dwErrCode,      // Message identifier for the requested message   
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),  // Language identifier for the requested message
		(LPWSTR)& pwszMsgBuf,     // Buffer that receives the formatted message
		0,                   // Size of output buffer not needed as allocate buffer flag is set
		NULL              // Array of insert values
	);

	System::String^ msg;

	if (NULL != pwszMsgBuf)
	{
		msg = System::String::Format(L"Error code: 0x{0:X8}, {1}.", 
				static_cast<unsigned long long>(dwErrCode),
				gcnew System::String(pwszMsgBuf));
		
		LocalFree(pwszMsgBuf);
	}
	else
	{
		msg = System::String::Format(L"Error code: 0x{0:X8} ({0})",
			static_cast<unsigned long long>(dwErrCode));
	}

	return msg;
}

void Signer::ThrowException(HRESULT hr, System::String^ errorMsg)
{
	System::String^ msg = errorMsg;
	if (hr != 0)
	{
		System::String^ errorCode = BuildErrorMessage(hr);
		msg = System::String::Format(L"{0} {1}.", errorCode, errorMsg);
	}
	System::Exception^ e = gcnew System::Exception(msg);
	throw e;
}

	//----------------------------------------------------------------------------
	// HrFindCertificateBySubjectName
	//
	//----------------------------------------------------------------------------
	HRESULT
		Signer::HrFindCertificateBySubjectName(
			/*[in]  */ LPCWSTR         wszStoreLocation, // by default, L"LocalMachine", but may be L"User", L"Service"
			/*[in]  */ LPCWSTR		   wszStore,   // the store name: L"CA", L"MY"
			/*[in]  */ LPCWSTR		   wszSubject, // Subject Common Name (CN)
			/*[out] */ PCCERT_CONTEXT* ppcCert
		)
	{
		HRESULT hr = S_OK;
		HCERTSTORE  hStoreHandle = NULL;  // The system store handle.

		try
		{
			*ppcCert = NULL;


			DWORD flags = CERT_SYSTEM_STORE_LOCAL_MACHINE; // default

			if (lstrcmpW(wszStoreLocation, L"LocalMachine") == 0)
			{
				flags = CERT_SYSTEM_STORE_LOCAL_MACHINE;
				// wprintf(L"Selected cert store LOCAL_MACHINE.\n");
			}
			else if (lstrcmpW(wszStoreLocation, L"User") == 0)
			{
				flags = CERT_SYSTEM_STORE_CURRENT_USER;
				// wprintf(L"Selected cert store User.\n");
			}
			else if (lstrcmpW(wszStoreLocation, L"Service") == 0)
			{
				flags = CERT_SYSTEM_STORE_CURRENT_SERVICE;
				// wprintf(L"Selected cert store Service.\n");
			}

			flags = flags | CERT_STORE_READONLY_FLAG;

			//-------------------------------------------------------------------
			// Open the certificate store to be searched.

			hStoreHandle = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,   // the store provider type
				0,            // the encoding type is not needed
				NULL,            // use the default HCRYPTPROV
				flags,                    // set the store location in a registry location
				wszStore                  // the store name: L"CA", L"MY" 
			);

			if (NULL == hStoreHandle)
			{
				hr = HRESULT_FROM_WIN32(GetLastError());
				ThrowException(hr, gcnew System::String("Failed to open certificate store"));
			}

			//-------------------------------------------------------------------
			// Get a certificate that has the specified Subject Common Name (CN)

			*ppcCert = CertFindCertificateInStore(
				hStoreHandle,
				X509_ASN_ENCODING,        // Use X509_ASN_ENCODING
				0,                         // No dwFlags needed
				CERT_FIND_SUBJECT_STR,     // Find a certificate with a
										   //  subject that matches the 
										   //  string in the next parameter
				wszSubject,                // The Unicode string to be found
										   //  in a certificate's subject
				NULL);                     // NULL for the first call to the
										   //  function; In all subsequent
										   //  calls, it is the last pointer
										   //  returned by the function
			if (NULL == *ppcCert)
			{
				hr = HRESULT_FROM_WIN32(GetLastError());

				ThrowException(hr,
					gcnew System::String("Failed to find certificate in store by subject: " +
					gcnew System::String(wszSubject))
				);
			}

		}
		finally
		{
		    if (NULL != hStoreHandle)
		    {
		    	CertCloseStore(hStoreHandle, 0);
		    }
		}

	

		return hr;
	}

	//----------------------------------------------------------------------------------------------------------------
	// 
	//  Function:   HrSignCNGHash()
	//
	// The caller must call LocalFree to release (*ppbSignature)
	//------------------------------------------------------------------------------------------------------------------
	HRESULT
		Signer::HrSignCNGHash(
			/*[in]  */ NCRYPT_KEY_HANDLE   hKey,
			/*[in]  */ void* pPaddingInfo,
			/*[in]  */ DWORD               dwFlag,
			/*[in]  */ const BYTE* pbHash,
			/*[in]  */ ULONG               cbHash,
			/*[out] */ BYTE** ppbSignature,
			/*[out] */ ULONG* pcbSignature
		)
	{
		HRESULT hr = S_OK;

		try {
			//initialize OUT parameters
			*ppbSignature = NULL;
			*pcbSignature = 0;

			//get a size of signature
			hr = NCryptSignHash(
				hKey,
				pPaddingInfo,
				(PBYTE)pbHash,
				cbHash,
				NULL,           //pbSignature
				0,              //The size, in bytes, of the pbSignature buffer
				pcbSignature,
				dwFlag);        //dwFlags

			if (FAILED(hr))
			{
				ThrowException(hr, gcnew System::String("Failed to get the size of the signature."));
			}

			// allocate buffer for signature
			*ppbSignature = (BYTE*)LocalAlloc(LPTR, *pcbSignature);
			if (NULL == *ppbSignature)
			{
				hr = HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);

				ThrowException(hr, gcnew System::String("Failed to allocate memory for the signature."));
			}

			hr = NCryptSignHash(
				hKey,
				pPaddingInfo,
				(PBYTE)pbHash,
				cbHash,
				*ppbSignature,
				*pcbSignature,
				pcbSignature,
				dwFlag); //dwFlags

			if (FAILED(hr))
			{
				ThrowException(hr, gcnew System::String("Failed to create the signature."));
			}

			hr = S_OK;

		}
		finally
		{
			if (FAILED(hr))
			{
				if (NULL != *ppbSignature)
				{
					LocalFree(*ppbSignature);
				}
				*ppbSignature = NULL;
				*pcbSignature = 0;
			}
		}

		return hr;
	}

	//----------------------------------------------------------------------------------------------------------------
	// 
	//  Function:   HrSignCAPI()
	//
	//------------------------------------------------------------------------------------------------------------------
	HRESULT
		Signer::HrSignCAPI(
			/*[in]  */ HCRYPTHASH  hHash,
			/*[in]  */ HCRYPTPROV  hProvider,
			/*[in]  */ DWORD       dwKeySpec,
			/*[out] */ PBYTE* ppbSignature,
			/*[out] */ DWORD* pcbSignature
		)
	{
		HRESULT hr = S_OK;

		try {
			//initialize OUT parameters
			*ppbSignature = NULL;
			*pcbSignature = 0;

			//get a size of signature
			if (!CryptSignHash(
				hHash,
				dwKeySpec,
				NULL,  //sDescription, not supported, must be NULL
				0,          //dwFlags
				NULL,    //pbSignature
				pcbSignature))
			{
				hr = HRESULT_FROM_WIN32(GetLastError());
				ThrowException(hr, gcnew System::String("Failed to get the size of the signature"));
			}

			//now allocate memory for signature object
			*ppbSignature = (BYTE*)LocalAlloc(LPTR, *pcbSignature);
			if (NULL == *ppbSignature)
			{
				hr = HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);
				ThrowException(hr, gcnew System::String("Failed to allocate memory for signature"));
			}

			//now sign it
			if (!CryptSignHash(
				hHash,
				dwKeySpec,
				NULL, //sDescription, not supported, must be NULL
				0,         //dwFlags
				*ppbSignature,
				pcbSignature))
			{
				hr = HRESULT_FROM_WIN32(GetLastError());
				ThrowException(hr, gcnew System::String("Failed to create signature from hash"));
			}

			//
			// Reverse bytes to Big Endian
			//

			//
			// TODO: Check if the keys is DSA, then Reverse R&S separately
			// at the middle of the buffer.
			//

			// works for non DSA keys only
			if (*pcbSignature > 1)
			{
				for (DWORD i = 0; i < (*pcbSignature) / 2; i++)
				{
					BYTE b = (*ppbSignature)[i];
					(*ppbSignature)[i] = (*ppbSignature)[*pcbSignature - i - 1];
					(*ppbSignature)[*pcbSignature - i - 1] = b;
				}
			}

			hr = S_OK;

		}
		finally
		{
				if (NULL != hHash)
				{
					CryptDestroyHash(hHash);
				}

				if (FAILED(hr))
				{
					if (NULL != *ppbSignature)
					{
						LocalFree(*ppbSignature);
					}
					*ppbSignature = NULL;
					*pcbSignature = 0;
				}
		}

		return hr;
	}

	
	//----------------------------------------------------------------------------------------------------------------
	// Sign - creates signature for the provided hash using the private key 
    // associated with the certificate located in certificate store
	//
	//----------------------------------------------------------------------------------------------------------------
	HRESULT
		__cdecl
		Signer::Sign(
			/* [in]  */ const BYTE* pbHash,        // hash
			/* [in]  */ DWORD cbHash,              // length of hash
			/* [in]  */ LPCWSTR pwszCName,         // example L"Test" - subject name string of certificate to be used in signing
			/* [in]  */ LPCWSTR pwszStoreName,     // example: L"MY" - certificate store name
			/* [in]  */ LPCWSTR pwszStoreLocation, // example: L"User" - certificate store location
			/* [out] */  BYTE** pbSignature,       // output signature
			/* [out] */  DWORD* cbSignature        // output length of signature
		)
	{
		HRESULT hr = S_OK; // success or failure error code

		//certificate to be used to sign data
		PCCERT_CONTEXT pCertContext = NULL;

		//choose what hash algorithm to use, default SHA1
		LPCWSTR pwszHashAlgName = L"SHA1";

		//variable that receives the handle of either the CryptoAPI provider or the CNG key
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = NULL;

		//handle to CSP; is being used with CAPI keys
		HCRYPTPROV hCSP = NULL;

		//handle to CNG private key; is being used with CNG keys only
		NCRYPT_KEY_HANDLE hCngKey = NULL;

		DWORD	dwCngFlags = 0;

		//TRUE if user needs to free handle to a private key
		BOOL fCallerFreeKey = TRUE;

		//key spec; will be used to determine key type
		DWORD dwKeySpec = 0;

		BCRYPT_PKCS1_PADDING_INFO PKCS1PaddingInfo = { 0 };
		BCRYPT_PKCS1_PADDING_INFO* pPKCS1PaddingInfo = NULL;
		PCCRYPT_OID_INFO pOidInfo = NULL;

		try {
			//-------------------------------------------------------------------
			// Find the test certificate to be validated and obtain a pointer to it

			hr = HrFindCertificateBySubjectName(
				pwszStoreLocation,
				pwszStoreName,
				pwszCName,
				&pCertContext
			);
			if (FAILED(hr))
			{
				ThrowException(hr, "Failed to find certificate in the cert store");
			}

			if (!CryptAcquireCertificatePrivateKey(
				pCertContext,
				CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
				NULL,                            //Reserved for future use and must be NULL
				&hCryptProvOrNCryptKey,
				&dwKeySpec,
				&fCallerFreeKey)) //user should free key if TRUE is returned
			{
				hr = HRESULT_FROM_WIN32(GetLastError());
				ThrowException(hr, "Failed to access private key context of the certificate");
			}


			//
			// check whether we have CNG or CAPI key
			//

			switch (dwKeySpec)
			{
			case CERT_NCRYPT_KEY_SPEC: //CNG key
			{
				hCngKey = (NCRYPT_KEY_HANDLE)hCryptProvOrNCryptKey;

				// TODO:
				// The production code must specify valid padding.
				// SAMPLE:
				//   This padding valid for RSA non PSS only:
				//

				pOidInfo = CryptFindOIDInfo(
					CRYPT_OID_INFO_OID_KEY,
					pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
					CRYPT_PUBKEY_ALG_OID_GROUP_ID
				);
				if (NULL != pOidInfo &&
					0 == lstrcmpW(pOidInfo->pwszCNGAlgid, L"RSA"))
				{
					PKCS1PaddingInfo.pszAlgId = pwszHashAlgName;
					pPKCS1PaddingInfo = &PKCS1PaddingInfo;
					dwCngFlags = BCRYPT_PAD_PKCS1;
				}

				hr = HrSignCNGHash(
					hCngKey,
					pPKCS1PaddingInfo,
					dwCngFlags,
					pbHash,
					cbHash,
					pbSignature,
					cbSignature
				);
				if (FAILED(hr))
				{
					ThrowException(hr, "Failed to sign hash (CNG)");
				}

				// wprintf(L"Signed message using CNG key.\n");
			}
			break;

			case AT_SIGNATURE: //CAPI key        
			case AT_KEYEXCHANGE:
			{
				//
				// Legacy (pre-Vista) key
				//

				hCSP = (HCRYPTPROV)hCryptProvOrNCryptKey;

				hr = HrSignCAPI(
					reinterpret_cast<HCRYPTHASH>(pbHash),
					hCSP,
					dwKeySpec,
					pbSignature,
					cbSignature
				);

				if (FAILED(hr))
				{
					ThrowException(hr, "Failed to sign hash (CAPI legacy)");
				}

				// wprintf(L"Successfully signed message using legacy CSP key.\n");
			}
			break;

			default:

			{
				// wprintf(L"Unexpected dwKeySpec returned from CryptAcquireCertificatePrivateKey.\n");
				ThrowException(hr,
					System::String::Format(L"{0} {1}",
						L"Unexpected dwKeySpec returned from CryptAcquireCertificatePrivateKey: ",
						dwKeySpec));
				break;
			}
			}


			// wprintf(L"Created a signature \n");

			hr = S_OK;

		}
		finally{

			//free CNG key or CAPI provider handle
			if (fCallerFreeKey)
			{
				switch (dwKeySpec)
				{
				case CERT_NCRYPT_KEY_SPEC: //CNG key
					NCryptFreeObject(hCngKey);
					break;

				case AT_SIGNATURE: //CAPI key        
				case AT_KEYEXCHANGE:
					CryptReleaseContext(hCSP, 0);
					break;
				default: // TODO : should throw an error 
					ThrowException(0,
						System::String::Format(L"{0} {1}",
							L"Cannot free memory allocated to private key, unknown key type: ",
							dwKeySpec));
				}
			}

			if (NULL != pCertContext)
			{
				CertFreeCertificateContext(pCertContext);
			}

			if (FAILED(hr))
			{
				if (NULL != pbSignature && NULL != *pbSignature)
				{
					LocalFree(*pbSignature);

					*pbSignature = NULL;

				}

				if (cbSignature != NULL)
				{
					*cbSignature = 0;
				}

				// ReportError(NULL, hr);
			}
		}

		return hr;
	}

	//----------------------------------------------------------------------------------------------------------------
    // Release the memory allocated by "Sign" method in pbSignature
    //
	//----------------------------------------------------------------------------------------------------------------
	void Signer::ReleaseMemory(BYTE* pbSignature)
	{
		if (NULL != pbSignature)
		{
			LocalFree(pbSignature);
		}
	}

