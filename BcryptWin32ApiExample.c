#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

static NTSTATUS EncryptPassword(PUCHAR password, PUCHAR* hash, DWORD* hashSize, PUCHAR secret, DWORD secretSize)
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
		printf_s("BCryptOpenAlgorithmProvider failed with status: 0x%x\n", status);
		goto Cleanup;
	}

	status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
	if (!(((NTSTATUS)(status)) >= 0))
	{
		printf_s("BCryptGetProperty failed with status: 0x%x\n", status);
		goto Cleanup;
	}

	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject)
	{
		printf_s("HeapAlloc failed\n");
		goto Cleanup;
	}

	status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, secret, secretSize, 0);
	if (!(((NTSTATUS)(status)) >= 0))
	{
		printf_s("BCryptCreateHash failed with status: 0x%x\n", status);
		goto Cleanup;
	}

	status = BCryptHashData(hHash, password, passwordSize, 0);
	if (!(((NTSTATUS)(status)) >= 0))
	{
		printf_s("BCryptHashData failed with status: 0x%x\n", status);
		goto Cleanup;
	}

	status = BCryptGetProperty(hHash, BCRYPT_HASH_LENGTH, (PBYTE)hashSize, sizeof(DWORD), &cbData, 0);
	if (!(((NTSTATUS)(status)) >= 0))
	{
		printf_s("BCryptGetProperty failed with status: 0x%x\n", status);
		goto Cleanup;
	}

	*hash = (PUCHAR)malloc(*hashSize);
	status = BCryptFinishHash(hHash, *hash, *hashSize, NULL);
	if (status == STATUS_INVALID_PARAMETER)
	{
		printf_s("BCryptFinishHash failed with status: 0x%x\n", status);
		printf_s("Error code: STATUS_INVALID_PARAMETER\n");
		goto Cleanup;
	}
	else if (status == STATUS_INVALID_HANDLE)
	{
		printf_s("BCryptFinishHash failed with status: 0x%x\n", status);
		printf_s("Error code: STATUS_INVALID_HANDLE\n");
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
	NTSTATUS status = EncryptPassword(inputPassword, &inputHash, &inputHashSize, secret, secretSize);

	if (!(((NTSTATUS)(status)) >= 0))
	{
		printf_s("EncryptPassword failed with status: 0x%x\n", status);
		return status;
	}

	if (inputHashSize != hashSize)
	{
		printf_s("Hash size mismatch\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (memcmp(inputHash, storedHash, hashSize) == 0)
	{
		printf_s("Password is valid\n");
		return 1;
	}
	else
	{
		printf_s("Password is invalid\n");
		return STATUS_INVALID_PARAMETER;
	}
}


int main()
{
	UCHAR password[] = "password";
	UCHAR secret[] = "top_secret";

	PUCHAR hash = NULL;

	NTSTATUS status = 0;
	DWORD hashSize = 0;

	status = EncryptPassword(password, &hash, &hashSize, secret, sizeof(UCHAR) * ARRAYSIZE(secret));
	if (status == 0)
	{
		printf_s("Hash: ");
		for (int i = 0; i < hashSize; i++)
		{
			printf_s("%02x", hash[i]);
		}
		printf_s("\n");
	}
	status = ValidatePassword(password, hash, hashSize, secret, sizeof(UCHAR) * ARRAYSIZE(secret));

	free(hash);
	return status;
}