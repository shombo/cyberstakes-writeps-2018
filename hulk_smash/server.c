#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

#define DWORD unsigned int

DWORD recvUntilNull(char * buffer)
{
	char *tmp = buffer;
	int totalBytes = 0;
	char  tmpLocal[2] = {0};

	do
	{
		if (read(0, tmpLocal, 1) != -1) 
		{
			*tmp++ = tmpLocal[0];
			totalBytes++;
		}
		else break;
	} while (tmpLocal[0] != 0x00);

	return totalBytes;
}

// expects the following:
// |"HELLO" | size | word |
// https://xkcd.com/1354/ ;)
DWORD doHeartbeat()
{
	char recvBuf[300] = {0};
	int heartbeatSize = 0;
	signed int bytesRecv;

	bytesRecv = read(0, recvBuf, 9);

	// check our header
	if(0 != strstr(recvBuf,"HELLO"))
	{
		// get the recv size
		bytesRecv = read(0, (char *)&heartbeatSize, 4);

		// get the word to echo - buffer overflow
		recvUntilNull(recvBuf);

		// echo the word back
		write(1, recvBuf, heartbeatSize);
		
		return 0;
	}

	return 1;
}

void serverFunc()
{
	while(!doHeartbeat());
}

int main()
{
	serverFunc();
	return 0;
}

