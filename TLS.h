#ifndef TLS_h
#define TLS_h
#include <WiFiUdp.h>

#include <ESP8266WiFi.h>
#include <string.h>

class TLS
{

public:
	TLS();
	static void parse(uint8_t* searchstr, WiFiClient client, uint8_t* result, int parseLength, int padding);
	static int intConvert(uint8_t *result, int parseLength);
	static void connectWiFi(const char* id, const char* pass);
	static String hexValue(uint8_t ch);
	static bool charScan(const uint8_t* value, WiFiClient client);
	static unsigned long sendNTPpacket(IPAddress& address, WiFiUDP udp, const int NTP_PACKET_SIZE);
	static void client_hello(uint8_t* buffer);
	static void client_key_exchange(uint8_t *buffer, const char* id, int id_size);
	static int array_copy(uint8_t *main, int startaddr, uint8_t *extra, int extralen);
	static byte packetBuffer[];

};

#endif