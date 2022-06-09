#include <iostream>
#include <WS2tcpip.h>
#include <winsock2.h>
#include <stdlib.h>

#pragma comment (lib, "ws2_32.lib")

using namespace std;


#define DEFAULT_PORT 1234
#define MAX_PACKET_SIZE 1400
#define CHAT_SIZE 100
#define RECEIVE_TIMEOUT 2000


#define TYP_NONE 0
#define TYP_CHAT 1
#define TYP_FILE 2
#define TYP_ACK	 10
#define TYP_NAK	 11
#define TYP_PART 99


int port = DEFAULT_PORT;
int packet_size = MAX_PACKET_SIZE;

SOCKET out = INVALID_SOCKET;
sockaddr_in sockserver;
int serverLength = sizeof(sockserver);

SOCKET in = INVALID_SOCKET;

sockaddr_in server_client; // Use to hold the client information (port / ip address)
int clientLength = sizeof(server_client); // The size of the client information


typedef struct _header_info {
	int type;
	int count; // pocet paketov
	int totalsize; //celkova dlzka dat
	char data;
} HEADER_INFO, * PHEADER_INFO;

typedef struct _header_data {
	int type;
	int id; // cislo paketu
	int size; // dlzka data
	char crc;
	char data;
} HEADER_DATA, * PHEADER_DATA;


// --------------------------------------------------------------------------
//   FUNKCIE PRE SERVERA
// --------------------------------------------------------------------------


char crc(char* buf, int buflen) {
	char mycrc = 0;
	for (int i = 0; i < buflen; ++i)
		mycrc ^= buf[i];
	return mycrc;
}

int send_ACK(int flag = true) {
	char packet[MAX_PACKET_SIZE];
	PHEADER_INFO h = (PHEADER_INFO)packet;
	h->type = flag ? TYP_ACK : TYP_NAK;
	h->count = 1;
	h->totalsize = 0;
	int sendOk = sendto(in, packet, sizeof(HEADER_INFO), 0, (sockaddr*)&server_client, clientLength);

	return sendOk;
}

void recv_chat(PHEADER_INFO h) {
	char packet[MAX_PACKET_SIZE];

	int bytesIn = recvfrom(in, packet, sizeof(packet), 0, (sockaddr*)&server_client, &clientLength);

	if (bytesIn == SOCKET_ERROR)
	{
		cout << "Error receiving from client " << WSAGetLastError() << endl;
		return;
	}

	PHEADER_DATA d = (PHEADER_DATA)packet;

	if (d->crc != crc(&d->data, d->size)) {
		send_ACK(false);
		cout << "\nchyba crc ->NAK\n";
		return;
	}

	send_ACK();
	char* msg = &d->data;
	cout << "\nCHAT>" << msg << "\n";
}

void recv_file(PHEADER_INFO h) {
	char fname[256];
	strcpy(fname, "tmp\\");
	strcat(fname, &h->data);

	int totalbytes = 0, totalpackets = 0;

	FILE* f = fopen(fname, "wb");
	if (f == NULL) {
		cout << "\nerror opening file for write\n";
		return;
	}

	char packet[MAX_PACKET_SIZE];
	PHEADER_DATA d;
	int bytesIn;
	for (int i = 0; i < h->count;) {
		bytesIn = recvfrom(in, packet, sizeof(packet), 0, (sockaddr*)&server_client, &clientLength);

		if (bytesIn == SOCKET_ERROR) {
			cout << "\nsocket error\n";
			fclose(f);
			return; //chyba Winsock
		}

		d = (PHEADER_DATA)packet;
		if (bytesIn > sizeof(HEADER_DATA) && d->type == TYP_PART && d->id == i) {
			if (d->crc != crc(&d->data, d->size)) {
				//chybne crc
				send_ACK(false);
			}
			else {
				send_ACK();
				fwrite(&d->data, d->size, 1, f);
				totalbytes += d->size;
				++totalpackets;
				cout << "\ndoslo " << d->size << "bytov\n";
				++i;
				continue;
			}
			
		}
		else  if (bytesIn > sizeof(HEADER_DATA) && d->type != TYP_PART) {
			cout << "\nchybny typ paketu\n";
			fclose(f);
			return;
		}
		else if (bytesIn > sizeof(HEADER_DATA) && d->type == TYP_PART && d->id < i) {
			send_ACK();
		} else {
			send_ACK(false);
		}
	}
	fclose(f);
	char fullname[1000];
	_fullpath(fullname, fname, sizeof(fullname));
	cout << "\nkoniec prenosu\nzapisane " << totalbytes << "bytov, pocet fragmentov:" << totalpackets << ", subor:" << fullname << "\n";
}

void server() {

	WSADATA data;
	WORD version = MAKEWORD(2, 2);

	// Start WinSock
	int wsOk = WSAStartup(version, &data);
	if (wsOk != 0)
	{
		// Not ok! Get out quickly
		cout << "Can't start Winsock! " << wsOk;
		return;
	}

	char _buf[100];
	cout << "zadajte port:";
	cin.getline(_buf, sizeof(_buf));
	int _newport = atoi(_buf);
	if (_newport > 0)
		port = _newport;

	// Create a socket, notice that it is a user datagram socket (UDP)
	in = socket(AF_INET, SOCK_DGRAM, 0);

	// Create a server hint structure for the server
	sockaddr_in serverHint;
	serverHint.sin_addr.S_un.S_addr = ADDR_ANY; // Us any IP address available on the machine
	serverHint.sin_family = AF_INET; // Address format is IPv4
	serverHint.sin_port = htons(port); // Convert from little to big endian

	// Try and bind the socket to the IP and port
	if (bind(in, (sockaddr*)&serverHint, sizeof(serverHint)) == SOCKET_ERROR)
	{
		cout << "Can't bind socket! " << WSAGetLastError() << endl;
		return;
	}

	char buf[MAX_PACKET_SIZE];
	cout << "server listening on port " << port;
	// Enter a loop
	while (true)
	{
		ZeroMemory(&server_client, clientLength); // Clear the client structure
		ZeroMemory(buf, sizeof(buf)); // Clear the receive buffer

		// Wait for message
		int bytesIn = recvfrom(in, buf, sizeof(buf), 0, (sockaddr*)&server_client, &clientLength);

		if (bytesIn == SOCKET_ERROR)
		{
			cout << "Error receiving from client " << WSAGetLastError() << endl;
			continue;
		}


		// Display message and client info
		char clientIp[256]; // Create enough space to convert the address byte array
		ZeroMemory(clientIp, 256); // to string of characters

		// Convert from byte array to chars
		inet_ntop(AF_INET, &server_client.sin_addr, clientIp, 256);

		// Display the message / who sent it
		cout << "\nMessage recv from " << clientIp  << endl;

		PHEADER_INFO h = (PHEADER_INFO)buf;
		switch (h->type) {
		case TYP_CHAT:
			send_ACK();
			recv_chat(h);
			break;


		case TYP_FILE:
			send_ACK();
			recv_file(h);
			break;
		}
	}

	// Close socket
	closesocket(in);

	// Shutdown winsock
	WSACleanup();

}



// --------------------------------------------------------------------------
//   FUNKCIE PRE KLIENTA
// --------------------------------------------------------------------------

int waitForACK() {
	char packet[MAX_PACKET_SIZE];
	int bytesIn = recvfrom(out, packet, sizeof(packet), 0, (sockaddr*)&sockserver, &serverLength);

	if (bytesIn == SOCKET_ERROR)
	{
		cout << "Error receiving from client " << WSAGetLastError() << endl;
		return TYP_NONE;
	}

	if (bytesIn < sizeof(HEADER_INFO)) {
		cout << "paket prilis kratky " << bytesIn << "\n";
		return TYP_NONE;
	}

	PHEADER_INFO h = (PHEADER_INFO)packet;
	if (h->type != TYP_ACK && h->type != TYP_NAK)
		return TYP_NONE;
	return h->type;
}

int client_send(char* packet, int len) {
	int sendOk = sendto(out, packet, len, 0, (sockaddr*)&sockserver, sizeof(sockserver));

	if (sendOk == SOCKET_ERROR)
	{
		cout << "That didn't work! " << WSAGetLastError() << endl;
		return false;
	}

	int result = waitForACK();
	if (result == TYP_ACK)
		return true;
	if (result == TYP_NONE) {
		return false;
	}

	//typ-nak - opakujem
	sendOk = sendto(out, packet, len, 0, (sockaddr*)&sockserver, sizeof(sockserver));

	if (sendOk == SOCKET_ERROR)
	{
		cout << "That didn't work! " << WSAGetLastError() << endl;
		return false;
	}
	result = waitForACK();
	if (result == TYP_ACK)
		return true;
	return false;
}

void chat(char *msg) {
	//char msg[100];
	char packet[MAX_PACKET_SIZE];
	int sendOk;

	//cin >> msg;
	if (strlen(msg) > 0) {
		PHEADER_INFO h = (PHEADER_INFO)packet;

		h->type = TYP_CHAT;
		h->count = 1;
		h->totalsize = strlen(msg);

		sendOk = client_send(packet, sizeof(HEADER_INFO));

		if (!sendOk)
			return;//neuspesne odoslanie 

		//packet[0] = TYP_CHAT;
		//packet[1] = 1; // posleme jediny packet s textom

		PHEADER_DATA d = (PHEADER_DATA)packet;
		d->type = TYP_PART;
		d->id = 1;
		d->size = strlen(msg) + 1;
		d->crc = crc(msg, d->size);

		//packet[0] = TYP_PART;
		//packet[1] = 1; // poradove cislo
		//packet[2] = strlen(msg)+1;

		strcpy(&d->data, msg);

		//sendOk = sendto(out, packet, sizeof(HEADER_DATA) + d->size - 1, 0, (sockaddr*)&sockserver, sizeof(sockserver));
		sendOk = client_send(packet, sizeof(HEADER_DATA) + d->size-1); //odosle paket a pocka na potvrdenie
		if (!sendOk)
		{
			cout << "That didn't work! " << WSAGetLastError() << endl;
		}
		return;
	}

}

void chyba(char* msg) {
	//char msg[100];
	char packet[MAX_PACKET_SIZE];
	int sendOk;

	//cin >> msg;
	if (strlen(msg) > 0) {
		PHEADER_INFO h = (PHEADER_INFO)packet;

		h->type = TYP_CHAT;
		h->count = 1;
		h->totalsize = strlen(msg);

		sendOk = client_send(packet, sizeof(HEADER_INFO));

		if (!sendOk)
			return;//neuspesne odoslanie 

		//packet[0] = TYP_CHAT;
		//packet[1] = 1; // posleme jediny packet s textom

		PHEADER_DATA d = (PHEADER_DATA)packet;
		d->type = TYP_PART;
		d->id = 1;
		d->size = strlen(msg) + 1;
		d->crc = crc(msg, d->size) + 1;                       // takto simuluem chybu ze dam mu zlu CRC

		//packet[0] = TYP_PART;
		//packet[1] = 1; // poradove cislo
		//packet[2] = strlen(msg)+1;

		strcpy(&d->data, msg);

		//sendOk = sendto(out, packet, sizeof(HEADER_DATA) + d->size - 1, 0, (sockaddr*)&sockserver, sizeof(sockserver));
		sendOk = client_send(packet, sizeof(HEADER_DATA) + d->size - 1); //odosle paket a pocka na potvrdenie
		if (!sendOk)
		{
			cout << "That didn't work! " << WSAGetLastError() << endl;
		}
		return;
	}
}

void sendfile(char *msg) {
	//char msg[100];
	char packet[MAX_PACKET_SIZE];
	int sendOk;

	//cin >> msg;
	if (strlen(msg) > 0) {
		FILE* f = fopen(msg, "rb");
		if (f == NULL) {
			cout << "\nsubor sa nenasiel\n";
			return;
		}

		fseek(f, 0, FILE_END);
		int flength = ftell(f);
		fseek(f, 0, FILE_BEGIN);

		PHEADER_INFO h = (PHEADER_INFO)packet;

		h->type = TYP_FILE;
		h->totalsize = flength;
		strcpy(&h->data, msg);

		int fragsize = packet_size - sizeof(HEADER_DATA);
		h->count = flength / fragsize + (flength % fragsize ? 1 : 0);

		//packet[0] = TYP_CHAT;
		//packet[1] = 1; // posleme jediny packet s textom
		//sendOk = sendto(out, packet, sizeof(HEADER_INFO), 0, (sockaddr*)&sockserver, sizeof(sockserver));
		sendOk = client_send(packet, sizeof(HEADER_INFO)+strlen(msg));
		if (!sendOk) {
			fclose(f);
			return;
		}

		char datapacket[MAX_PACKET_SIZE];
		PHEADER_DATA d = (PHEADER_DATA)datapacket;

		for (int i = 0; i < h->count; ++i) {
			d->type = TYP_PART;
			d->id = i;

			d->size = fread(&d->data, 1, fragsize, f);
			d->crc = crc(&d->data, d->size);

			//packet[0] = TYP_PART;
			//packet[1] = 1; // poradove cislo
			//packet[2] = strlen(msg)+1;


			//sendOk = sendto(out, packet, strlen(msg) + 2, 0, (sockaddr*)&sockserver, sizeof(sockserver));
			if (!client_send(datapacket, sizeof(HEADER_DATA) + d->size - 1))
				break;
		}

		fclose(f);
	}

}

void client() {

	char cmd[100];
	char packet[MAX_PACKAGE_NAME];

	WSADATA data;

	WORD version = MAKEWORD(2, 2);

	// Start WinSock
	int wsOk = WSAStartup(version, &data);
	if (wsOk != 0)
	{
		// Not ok! Get out quickly
		cout << "Can't start Winsock! " << wsOk;
		return;
	}

	// Create a hint structure for the server


	while (1) {
		cout << ">";
		//cin >> cmd;
		cin.getline(cmd, sizeof(cmd));

		if (!strnicmp(cmd, "PORT", 4)) {
			//cin >> cmd;
			memmove(cmd, &cmd[5], sizeof(cmd) - 5);
			if (out != INVALID_SOCKET) {
				cout << "\nsocket je aktivny\n";
			}
			else {
				int _param = atoi(cmd);
				if (_param > 0) {
					port = _param;
					cout << "\nport nastaveny na " << port << "\n";
				}
				else {
					cout << "\nchybne nastavenie portu\n";
				}
			}
		}
		else if (!strnicmp(cmd, "FRAG", 4)) {
			int _param = atoi(&cmd[5]);
			if (_param > sizeof(HEADER_INFO) && _param > sizeof(HEADER_DATA)) {
				packet_size = _param;
			}
			else {
				cout << "\nneplatne nastavenie\n";
			}
		}
		else if (!strnicmp(cmd, "SERVER", 6)) {
			char ip[100];
			memmove(ip, &cmd[7], sizeof(cmd)-7);

			if (strlen(ip) == 0 || atoi(ip) == 0) {
				strcpy(ip, "127.0.0.1");
				cout << "\nip nezadane, pouzije sa 127.0.0.1\n";
			}
			else {
				cout << "\nip nastavene na " << ip << "\n";
			}

			sockserver.sin_family = AF_INET; // AF_INET = IPv4 addresses
			sockserver.sin_port = htons(port); // Little to big endian conversion
			inet_pton(AF_INET, ip, &sockserver.sin_addr); // Convert from string to byte array

			// Socket creation, note that the socket type is datagram
			out = socket(AF_INET, SOCK_DGRAM, 0);

			if (out == 0) {
				cout << "\nneuspech pri otvarani socketu.\n";
			}

			unsigned int timeout = RECEIVE_TIMEOUT;

			setsockopt(out, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
		}
		else if (!strnicmp(cmd, "CHAT", 4)) {
			chat(&cmd[5]);
		}
		else if (!strnicmp(cmd, "FILE", 4)) {
			//char _fname[100];
			//cin >> _fname;

			sendfile(&cmd[5]);

		}
		else if (!strnicmp(cmd, "CHYBA", 5))
		{
			chyba(&cmd[5]);
		}
		else if (!strnicmp(cmd, "QUIT", 4)) {
			break;
		}
		else if(strlen(cmd) != 0) {
			cout << "\nneznamy prikaz\n";
		}
	}
	// Close the socket
	if (out != INVALID_SOCKET) {
		closesocket(out);
		out = INVALID_SOCKET;
	}

	// Close down Winsock
	WSACleanup();

}


void main() {
	char temp[100];

	cout << "Vyberte co potrebujete: " << endl;
	cout << "Server: 1" << endl;
	cout << "Klient: 2" << endl;
	int pick;

	cin.getline(temp, sizeof(temp));
	pick = atoi(temp);

	if (pick == 1) {
		server();
	}
	else if (pick == 2) {
		client();
	}

	return;
}