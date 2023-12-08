#include <windows.h>
#include <bcrypt.h>
#include <iostream>

#pragma comment(lib, "bcrypt.lib")

static NTSTATUS EncryptPassword(PUCHAR password, PUCHAR& hash, DWORD& hashSize, PUCHAR secret, DWORD secretSize)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	NTSTATUS status = 0;
	DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
	PBYTE pbHashObject = NULL;
	DWORD passwordSize = strlen((char*)password);

	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (!(((NTSTATUS)(status)) >= 0))
	{
		std::cerr << "BCryptOpenAlgorithmProvider failed with status: " << std::hex << status << std::endl;
		goto Cleanup;
	}

	status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
	if (!(((NTSTATUS)(status)) >= 0))
	{
		std::cerr << "BCryptGetProperty failed with status: " << std::hex << status << std::endl;
		goto Cleanup;
	}

	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject)
	{
		std::cerr << "Memory allocation failed" << std::endl;
		goto Cleanup;
	}

	status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, secret, secretSize, 0);
	if (!(((NTSTATUS)(status)) >= 0))
	{
		std::cerr << "BCryptCreateHash failed with status: " << std::hex << status << std::endl;
		goto Cleanup;
	}

	status = BCryptHashData(hHash, password, passwordSize, 0);
	if (!(((NTSTATUS)(status)) >= 0))
	{
		std::cerr << "BCryptHashData failed with status: " << std::hex << status << std::endl;
		goto Cleanup;
	}

	status = BCryptGetProperty(hHash, BCRYPT_HASH_LENGTH, (PBYTE)&hashSize, sizeof(DWORD), &cbData, 0);
	if (!(((NTSTATUS)(status)) >= 0))
	{
		std::cerr << "BCryptGetProperty failed with status: " << std::hex << status << std::endl;
		goto Cleanup;
	}

	hash = (PUCHAR)malloc(hashSize);
	status = BCryptFinishHash(hHash, hash, hashSize, NULL);
	if (status == STATUS_INVALID_PARAMETER)
	{
		std::cerr << "One or more parameters are not valid. This includes the case where cbOutput is not the same size as the hash. " << std::hex << status << std::endl;
		goto Cleanup;
	}
	else if (status == STATUS_INVALID_HANDLE)
	{
		std::cerr << "The hash handle in the hHash parameter is not valid. " << std::hex << status << std::endl;
		goto Cleanup;
	}


Cleanup:
	if (hAlg)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}
	if (hHash)
	{
		BCryptDestroyHash(hHash);
	}
	if (pbHashObject)
	{
		HeapFree(GetProcessHeap(), 0, pbHashObject);
	}
	return status;
}

static NTSTATUS ValidatePassword(PUCHAR inputPassword, PUCHAR storedHash, ULONG hashSize, PUCHAR secret, DWORD secretSize)
{
	PUCHAR inputHash;
	ULONG inputHashSize;
	NTSTATUS status = EncryptPassword(inputPassword, inputHash, inputHashSize, secret, secretSize);

	if (!(((NTSTATUS)(status)) >= 0))
	{
		std::cerr << "EncryptPassword failed with status: " << std::hex << status << std::endl;
		return status;
	}

	if (inputHashSize != hashSize)
	{
		std::cerr << "Hash size mismatch" << std::endl;
		return STATUS_INVALID_PARAMETER;
	}

	if (memcmp(inputHash, storedHash, hashSize) == 0)
	{
		std::cout << "Password is valid" << std::endl;
		return 1;
	}
	else
	{
		std::cout << "Password is invalid" << std::endl;
		return STATUS_INVALID_PARAMETER;
	}
}


int main()
{
	UCHAR password[] = "password";
	UCHAR secret[] = "top_secret";

	PUCHAR hash = nullptr;

	NTSTATUS status = 0;
	DWORD hashSize = 0;

	status = EncryptPassword(password, hash, hashSize, secret, sizeof(UCHAR) * ARRAYSIZE(secret));
	if (status == 0)
	{
		std::cout << "Hash: ";
		for (int i = 0; i < hashSize; i++)
		{
			std::cout << std::hex << (int)hash[i];
		}
		std::cout << std::endl;
	}
	status = ValidatePassword(password, hash, hashSize, secret, sizeof(UCHAR) * ARRAYSIZE(secret));

	delete[] hash;
	return status;
}