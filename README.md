# Cryptographic Signer
Create a signature using non-exportable private key in Windows certificate store.

This repo allows to create a cryptographic signature of the provided hash using the private key associated with the certificate that is located in Windows certificate store. The most important part is that the private key is "non-exportable", thus it is not retrieved by the code but only a context to the private key is found and used for signing. 

The signing part is done using NCrypt library (C/C++) code and there is a wrapper that compiles it into C++\CLI managed class that can be called from C#.

The certificate should exist in Certificate Store with the assoicated private key. For example, you may have a .p12 file that contains a certificate with the private key.You should then import it into the certificate store. Notice that the private key can be marked as non-exportable and the code still works correctly.

This was tested on Visual Studio 2019 compiled as x64 platform and running on Windows 10. The test certificate was associated with the key that was ECDSA_P256.
