#include <stdio.h>
#include <Windows.h>

unsigned char * encrypt(unsigned char *, int, int);

unsigned char * encrypt(unsigned char * data, int dataLen, int xor_key) 
{
	unsigned char * output = (unsigned char *)malloc(sizeof(unsigned char) * dataLen+1);

	for (int i = 0; i < dataLen; i++)
		output[i] = data[i] ^ xor_key;

	return output;
}

int main(void)
{
	unsigned char clear[] =
	// paste shellcode blob here
	"";

	size_t sc_len = sizeof(clear)-1; // auto sized char arrays are 1 byte larger by default
	unsigned char * out = encrypt(clear, sc_len, 0x53); // key of 0x53
	printf("\"");
	for (int i = 0; i < sc_len; i++)
	{
		if ( !(i%22) && i!=0 )
			printf("\"\n\"");
		printf("\\x%02x", out[i]);	
	}
	printf("\";");

	return 0;
}