#pragma once
#include <windows.h>

class Signer
{
	static System::String^ BuildErrorMessage(DWORD dwErrCode);
	static void ThrowException(HRESULT hr, System::String^ errorMsg);

	static HRESULT
		Signer::HrFindCertificateBySubjectName(
			/*[in]  */ LPCWSTR         wszStoreLocation,
			/*[in]  */ LPCWSTR			wszStore,
			/*[in]  */ LPCWSTR			wszSubject,
			/*[out] */ PCCERT_CONTEXT* ppcCert
		);

	static HRESULT
		Signer::HrSignCNGHash(
			/*[in]  */ NCRYPT_KEY_HANDLE   hKey,
			/*[in]  */ void* pPaddingInfo,
			/*[in]  */ DWORD dwFlag,
			/*[in]  */ const BYTE* pbHash,
			/*[in]  */ ULONG cbHash,
			/*[out] */ BYTE** ppbSignature,
			/*[out] */ ULONG* pcbSignature
		);

	static HRESULT
		Signer::HrSignCAPI(
			/*[in]  */ HCRYPTHASH  hHash,
			/*[in]  */ HCRYPTPROV  hProvider,
			/*[in]  */ DWORD       dwKeySpec,
			/*[out] */ PBYTE* ppbSignature,
			/*[out] */ DWORD* pcbSignature
		);

public:
	static HRESULT
		__cdecl
		Sign(
			/* [in]  */ const BYTE* pbHash,        // hash
			/* [in]  */ DWORD cbHash,              // length of hash
			/* [in]  */ LPCWSTR pwszCName,         // example L"Test" - subject name string of certificate to be used in signing
			/* [in]  */ LPCWSTR pwszStoreName,     // example: L"MY" - certificate store name
			/* [in]  */ LPCWSTR pwszStoreLocation, // example: L"User" - certificate store location
			/* [out] */  BYTE** pbSignature,       // output signature
			/* [out] */  DWORD* cbSignature        // output length of signature
		);

	static void __cdecl ReleaseMemory(BYTE* pbSignature);
};