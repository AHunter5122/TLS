#include "TLS.h"
#include <ESP8266WiFi.h>
#include <string.h>
#include <WiFiUdp.h>

TLS::TLS()
{

  return;
}

void TLS::connectWiFi(const char* id, const char* pass){

  Serial.println();
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(id);
  
  WiFi.begin(id, pass);
  
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.println("WiFi connected");  
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
  
}    

void TLS::parse(uint8_t* searchstr, WiFiClient client, uint8_t* result, int parseLength, int padding){
  uint8_t buffer[parseLength];
  if (TLS::charScan(searchstr, client)){

    for (int i =0; i < padding; i++){
      client.read();
    }
    for(int i =0; i < parseLength; i ++){
      if(client.available()){
        uint8_t line = client.read();
        buffer[i] = line;
      }
      else{
        Serial.print("Client unavailable");
        Serial.println(i);
        break;
      }
    }
    memmove(result, buffer, sizeof(buffer));
    
  
  }
  
  
}

int TLS::intConvert(uint8_t *result, int parseLength){

  int j =0;
  for (int i = parseLength-1; i >= 0; i--){
    j = j + (pow(256.0, (double)(parseLength-i-1)))*result[i];
  }

  return j;
}

bool TLS::charScan(const uint8_t* value, WiFiClient client){
      
      
      int bufferSize = sizeof(value)-1;
      uint8_t certificateBuffer[bufferSize];
      int bufferIndex = 0;
      int chainFlag =0;
      bool found = false;
      
      while(client.available() && bufferIndex!= bufferSize){
        const uint8_t line = client.read();
        if (line == value[bufferIndex]){
          certificateBuffer[bufferIndex] = line;
          bufferIndex++;
        }
        else{
          bufferIndex=0;
        }
        if (bufferIndex == bufferSize){
          return true;
        }
        
      }

      return false;
}

unsigned long TLS::sendNTPpacket(IPAddress& address, WiFiUDP udp, const int NTP_PACKET_SIZE)
{
  Serial.println("sending NTP packet...");
  // set all bytes in the buffer to 0
  memset(packetBuffer, 0, NTP_PACKET_SIZE);
  
  // Initialize values needed to form NTP reques
  packetBuffer[0] = 0b11100011;   // LI, Version, Mode
  packetBuffer[1] = 0;     // Stratum, or type of clock
  packetBuffer[2] = 6;     // Polling Interval
  packetBuffer[3] = 0xEC;  // Peer Clock Precision
  
  // 8 bytes of zero for Root Delay & Root Dispersion
  packetBuffer[12]  = 49;
  packetBuffer[13]  = 0x4E;
  packetBuffer[14]  = 49;
  packetBuffer[15]  = 52;

  // all NTP fields have been given values, now
  // you can send a packet requesting a timestamp:
  udp.beginPacket(address, 123); //NTP requests are to port 123
  udp.write(packetBuffer, NTP_PACKET_SIZE);
  udp.endPacket();
}

String TLS::hexValue(uint8_t ch){
  char buf[5];
  if ((int)ch < 16){
    sprintf(buf, "0%x ", ch);
  }
  else{
    sprintf(buf, "%x ", ch);
  }
  
  return buf;
}

int TLS::array_copy(uint8_t *main, int startaddr, uint8_t *extra, int extralen){
  for(int i=startaddr; i <startaddr+extralen; i++){
    *(main+i) = *(extra+i-startaddr);
  }
  return startaddr+extralen;

}

void TLS::client_hello(uint8_t* buffer){
  uint8_t content[] = "\x16";
  uint8_t tls_version[] = "\x03\x03";
  uint8_t hello[] = "\x01";
  uint8_t unixtime[] = "\x4e\x24\x3b\x32";
  uint8_t client_random[29];
  uint8_t ciphers_compressions[] = "\x00\x00\x02\x00\x8c\x01\x00";
  uint8_t extensions[] = "\x00\xc5\x00\x00\x00\x00\x00\x23\x00\x00\x00\x0d\x00\x04\x00\x02\x04\x00\x00\x0f\x00\x01\x01\x00\x15\x00\xa8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
  uint8_t inner[] = "\x00\x00\x00";
  uint8_t outer[] = "\x00\x00";

  randomSeed(analogRead(A0));
  
  for (int i=0; i < 29; i++){
    client_random[i] = (uint8_t)random(255);
   }

  uint32_t innerlength = uint32_t(sizeof(tls_version)-1+sizeof(unixtime)-1+sizeof(client_random)-1+sizeof(ciphers_compressions)-1+sizeof(extensions)-1);
  uint16_t outerlength = innerlength+4;
  inner[0] = (uint8_t)(innerlength & 0xff0000);
  inner[1] = (uint8_t)(innerlength & 0xff00);
  inner[2] = (uint8_t)(innerlength & 0xff);
  outer[0] = (uint8_t)(outerlength & 0xff00);
  outer[1] = (uint8_t)(outerlength & 0xff);
  Serial.println(innerlength);

  Serial.println(outerlength);
  int index = 0;
  index = TLS::array_copy(buffer, index, content, (int)(sizeof(content)-1));
  index = TLS::array_copy(buffer, index, tls_version, (int)(sizeof(tls_version)-1));
  index = TLS::array_copy(buffer, index, outer, (int)(sizeof(outer)-1));
  index = TLS::array_copy(buffer, index, hello, (int)(sizeof(hello)-1));
  index = TLS::array_copy(buffer, index, inner, (int)(sizeof(inner)-1));
  index = TLS::array_copy(buffer, index, tls_version, (int)(sizeof(tls_version)-1));
  index = TLS::array_copy(buffer, index, unixtime, (int)(sizeof(unixtime)-1));
  index = TLS::array_copy(buffer, index, client_random, (int)(sizeof(client_random)-1));
  index = TLS::array_copy(buffer, index, ciphers_compressions, (int)(sizeof(ciphers_compressions)-1));
  index = TLS::array_copy(buffer, index, extensions, (int)(sizeof(extensions)-1));
  return;

}

void TLS::client_key_exchange(uint8_t *buffer, const char* id, int id_size){
  uint8_t *psk_id;
  psk_id = (uint8_t*) malloc(id_size);
  for(int i=0; i < id_size; i++){
    psk_id[i]=(uint8_t)id[i];
  }
  uint8_t content[] = "\x16";
  uint8_t tls_version[] = "\x03\x03";
  uint8_t key_exchange[] = "\x10";
  uint8_t psk_id_size[] = "\x00\x00\x00";
  uint8_t outer[] = "\x00\x00";
  uint16_t outerlength = (uint16_t)(sizeof(key_exchange)-1+id_size+sizeof(psk_id_size)-1);
  uint32_t psklength = (uint32_t)(id_size);

  outer[0] = (uint8_t)(outerlength & 0xff00);
  outer[1] = (uint8_t)(outerlength & 0xff);
  psk_id_size[0] = (uint8_t)(psklength & 0xff0000);
  psk_id_size[1] = (uint8_t)(psklength & 0xff00);
  psk_id_size[2] = (uint8_t)(psklength & 0xff);

  int index = 0;
  index = TLS::array_copy(buffer, index, content, (int)(sizeof(content)-1));
  index = TLS::array_copy(buffer, index, tls_version, (int)(sizeof(tls_version)-1));
  index = TLS::array_copy(buffer, index, outer, (int)(sizeof(outer)-1));
  index = TLS::array_copy(buffer, index, key_exchange, (int)(sizeof(key_exchange)-1));
  index = TLS::array_copy(buffer, index, psk_id_size, (int)(sizeof(psk_id_size)-1));
  index = TLS::array_copy(buffer, index, psk_id, (int)(sizeof(psk_id)-1));
}


//uint8_t packet[] = "\x16\x03\x03\x00\xf0\x01\x00\x00\xec\x03\x03\x4e\x24\x3b\x32\xaf\x37\xd2\x95\xee\x3c\x95\xc2\xf1\xb9\x21\xae\x3f\x6f\xbe\x37\x64\xa7\xcb\x6f\xb8\x00\xe9\x4e\x52\x40\x46\xae\x00\x00\x02\x00\x8c\x01\x00\x00\xc2\x00\x00\x00\x00\x00\x23\x00\x00\x00\x0d\x00\x04\x00\x02\x04\x00\x00\x0f\x00\x01\x01\x00\x15\x00\xa8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";