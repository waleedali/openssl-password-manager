// openssl-password-manager.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <conio.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <Windows.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

using namespace std;

static const unsigned char key_data[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

typedef enum _operation_modes {
	ECB = 0,
	CTR,
	CBC
} OPERATION_MODES;

static unsigned int op_mode = ECB;

typedef struct _user_data {
	unsigned int operationmode;
	string encrypted_password;
} USER_DATA;

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(const unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx, unsigned int operation_mode, unsigned char *iv)
{
	int i, nrounds = 5;
	unsigned char key[32];
  
	/*
	* Gen key & IV for AES. A SHA1 digest is used to hash the supplied key material.
	* nrounds is the number of times the we hash the material. 
	*/
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) {
	printf("Key size is %d bits - should be 256 bits\n", i);
	return -1;
	}

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_CIPHER_CTX_init(d_ctx);

	switch (operation_mode)
	{
	case ECB:
		EVP_EncryptInit_ex(e_ctx, EVP_aes_128_ecb(), NULL, key, NULL);
		EVP_DecryptInit_ex(d_ctx, EVP_aes_128_ecb(), NULL, key, NULL);
		break;
	case CTR:
		EVP_EncryptInit_ex(e_ctx, EVP_aes_128_ctr(), NULL, key, iv);
		EVP_DecryptInit_ex(d_ctx, EVP_aes_128_ctr(), NULL, key, iv);
		break;
	case CBC:
		EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
		EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
		break;
	default:
		printf("This operation mode is not supported");
		return -1;
	}

	return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = (unsigned char *)malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  /* update ciphertext with the final remaining bytes */
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* because we have padding ON, we must allocate an extra cipher block size of memory */
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = (unsigned char *)malloc(p_len + AES_BLOCK_SIZE);
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}


string GetCurrentOpMode(){
	if (ECB == op_mode)
		return "ECB";
	else if (CTR == op_mode)
		return "CTR";
	else 
		return "CBC";
}

void SetStdinEcho(bool enable = true)
{
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if( !enable )
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode );

#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

vector<string> &split(const string &s, char delim, vector<string> &elems) {
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}


vector<string> split(const string &s, char delim) {
    vector<string> elems;
    split(s, delim, elems);
    return elems;
}

int ReadAndProcessFile(const string &username, const string &password)
{
	string line;
	map<string, USER_DATA> user_data_map;
	ifstream myfile ("secureduserdata.dat");
	if (myfile.is_open())
	{
		while (getline (myfile,line))
		{
			//cout << line << '\n';
			vector<string> data = split(line, ';');
			if(data.size() != 3 || atoi(data[0].c_str()) > CBC)
				continue;
			USER_DATA ud;
			ud.operationmode = atoi(data[0].c_str());
			ud.encrypted_password = data[2];
			user_data_map.insert(pair<string, USER_DATA>(data[1], ud));
		}
		myfile.close();
	}

	map<string, USER_DATA>::iterator it = user_data_map.find(username);
	if (it == user_data_map.end())
	{
		cout << "\nusername not found.\n";
		return 0;
	}

	/* "opaque" encryption, decryption ctx structures that libcrypto uses to record
		status of enc/dec operations */
	EVP_CIPHER_CTX en, de;

	/* 8 bytes to salt the key_data during key generation. This is an example of
		compiled in salt. We just read the bit pattern created by these two 4 byte 
		integers on the stack as 64 bits of contigous salt material - 
		ofcourse this only works if sizeof(int) >= 4 */
	unsigned int salt[] = {12345, 54321};
	unsigned char *iv = (unsigned char *)malloc(32);

	/* gen key and iv. init the cipher ctx object */
	if (aes_init(key_data, 32, (unsigned char *)&salt, &en, &de, it->second.operationmode, iv)) {
		printf("Couldn't initialize AES cipher\n");
		return -1;
	}

	//string cipher_str = it->second.encrypted_password.substr(33);
	string cipher_str = it->second.encrypted_password;
	int len = cipher_str.size();
	char *plaintext;
	unsigned char *ciphertext = (unsigned char *)cipher_str.c_str(); 
	plaintext = (char *)aes_decrypt(&de, ciphertext, &len);

	free(plaintext);
	free(iv);
	return 0;
}

int ProcessAndWriteToFile(const string &username, const string &password)
{
	ofstream output_file;


	/*TODO: check if the username already exist in the file */


	/* "opaque" encryption, decryption ctx structures that libcrypto uses to record
		status of enc/dec operations */
	EVP_CIPHER_CTX en, de;

	/* 8 bytes to salt the key_data during key generation. This is an example of
		compiled in salt. We just read the bit pattern created by these two 4 byte 
		integers on the stack as 64 bits of contigous salt material - 
		ofcourse this only works if sizeof(int) >= 4 */
	unsigned int salt[] = {12345, 54321};
	unsigned char *ciphertext;
	unsigned char *iv = (unsigned char *)malloc(32);
	int len;

	/* gen key and iv. init the cipher ctx object */
	if (aes_init(key_data, 32, (unsigned char *)&salt, &en, &de, op_mode, iv)) {
		printf("Couldn't initialize AES cipher\n");
		return -1;
	}

	len = password.size() + 1;

	ciphertext = aes_encrypt(&en, (unsigned char *)password.c_str(), &len);

	/* the file is stored in the formate of:
	   operation_mode username encrypted_password */
	output_file.open ("secureduserdata.dat", ios::out | ios::app);
	string chipher_str((char*)ciphertext);
	//output_file << endl << op_mode << ";" << username << ";" << iv << chipher_str;
	output_file << endl << op_mode << ";" << username << ";" << chipher_str;
	output_file.close();

	free(ciphertext);
	free(iv);

	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	string username, password;
	char input_ch;
	char currentmenu = '1';


	string menu1 =  "Please select an option: \n" 
		"1- Enter a new username an password \n"
		"2- Verify the existance of a username and password \n"
		"3- Change the AES operation mode (current: " + GetCurrentOpMode() + ") \n"
		"4- Exit \n"
		"Enter Selection: "; 

	string menu2 = "\nPlease select the AES operation mode: \n"
				"1- Electronic codebook (ECB) \n"
				"2- Counter (CTR) \n"
				"3- Cipher-block chaining (CBC)\n"
				"4- Back \n"
				"Enter Selection: ";

	cout << menu1;

	while (1)
	{
		input_ch = _getche();

		switch (input_ch)
		{
		case '1':
			/* get the username and password from the user */
			cout << "\nEnter a username: ";
			/* TODO: should be restricted to alphabet only to prevent injecting the ';' char */
			getline(std::cin, username);
			cout << "Enter a password: ";
			SetStdinEcho(false);
			getline(std::cin, password);
			SetStdinEcho(true);

			ProcessAndWriteToFile(username, password);

			cout << "\nThank you. Your account infomation has been stored \n";
			break;
		case '2':
			/* get the username and password from the user */
			cout << "\nEnter a username: ";
			/* TODO: should be restricted to alphabet only to prevent injecting the ';' char */
			getline(std::cin, username);
			cout << "Enter a password: ";
			SetStdinEcho(false);
			getline(std::cin, password);
			SetStdinEcho(true);
			ReadAndProcessFile(username, password);
			break;
		case '3':
			cout << menu2;
			break;
		case '4':
			return 0;
			break;
		default:
			cout << "\nPlease enter a selection from the above list (1, 2, 3 or 4): \n";
		}
	}




 // /* encrypt and decrypt each input string and compare with the original */
 // for (i = 0; input[i]; i++) {
 //   char *plaintext;
 //   unsigned char *ciphertext;
 //   int olen, len;
 //   
 //   /* The enc/dec functions deal with binary data and not C strings. strlen() will 
 //      return length of the string without counting the '\0' string marker. We always
 //      pass in the marker byte to the encrypt/decrypt functions so that after decryption 
 //      we end up with a legal C string */
 //   olen = len = strlen(input[i])+1;
 //   
 //   ciphertext = aes_encrypt(&en, (unsigned char *)input[i], &len);
	//printf("ciphertext: %s", ciphertext);
 //   plaintext = (char *)aes_decrypt(&de, ciphertext, &len);

 //   if (strncmp(plaintext, input[i], olen)) 
 //     printf("FAIL: enc/dec failed for \"%s\"\n", input[i]);
 //   else 
 //     printf("OK: enc/dec ok for \"%s\"\n", plaintext);
 //   
 //   free(ciphertext);
 //   free(plaintext);
 // }

 // EVP_CIPHER_CTX_cleanup(&en);
 // EVP_CIPHER_CTX_cleanup(&de);

  return 0;
}

