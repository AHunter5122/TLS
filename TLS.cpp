#include "TLS.h"
#include <ESP8266WiFi.h>
#include <string.h>
#include <WiFiUdp.h>
#include "sha256.h"

TLS::TLS()
{

  return;
}

bool TLS::connectWiFi(const char* id, const char* pass){

  Serial.println();
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(id);
  int timer = 0;
  WiFi.begin(id, pass);
  
  while (WiFi.status() != WL_CONNECTED) {
    timer++;
    delay(500);
    Serial.print(".");
    if(timer > 120){
      WiFi.disconnect();
      Serial.println();
      Serial.println("WiFi timed out");
      return false;
    }

  }
  Serial.println("");
  Serial.println("WiFi connected");  
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
  return true;
  
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
  for(int i =0; i < id_size; i++){
    Serial.println(TLS::hexValue(psk_id[i]));
  }
  uint8_t content[] = "\x16";
  uint8_t tls_version[] = "\x03\x03";
  uint8_t outer[] = "\x00\x00";
  uint8_t key_exchange[] = "\x10";
  uint8_t psk_outer[] = "\x00\x00\x00";
  uint8_t psk_inner[] = "\x00\x00";
  uint16_t outerlength = (uint16_t)(sizeof(key_exchange)-1+id_size+sizeof(psk_outer)-1+sizeof(psk_inner)-1);
  uint32_t psk_outer_length = (uint32_t)((int)id_size+2);
  uint16_t psk_inner_length = (uint16_t)(id_size);

  outer[0] = (uint8_t)(outerlength & 0xff00);
  outer[1] = (uint8_t)(outerlength & 0xff);
  psk_outer[0] = (uint8_t)(psk_outer_length & 0xff0000);
  psk_outer[1] = (uint8_t)(psk_outer_length & 0xff00);
  psk_outer[2] = (uint8_t)(psk_outer_length & 0xff);
  psk_inner[0] = (uint8_t)(psk_inner_length & 0xff00);
  psk_inner[1] = (uint8_t)(psk_inner_length & 0xff);

  int index = 0;
  index = TLS::array_copy(buffer, index, content, (int)(sizeof(content)-1));
  index = TLS::array_copy(buffer, index, tls_version, (int)(sizeof(tls_version)-1));
  index = TLS::array_copy(buffer, index, outer, (int)(sizeof(outer)-1));
  index = TLS::array_copy(buffer, index, key_exchange, (int)(sizeof(key_exchange)-1));
  index = TLS::array_copy(buffer, index, psk_outer, (int)(sizeof(psk_outer)-1));
  index = TLS::array_copy(buffer, index, psk_inner, (int)(sizeof(psk_inner)-1));
  index = TLS::array_copy(buffer, index, psk_id, id_size);
}
void TLS::change_cipher_spec(uint8_t* buffer, int bufferSize){
  uint8_t content[] = "\x14\x03\x03\x00\x01\x01";
  //TLS::check_memory(buffer, 6);
  int index = 0;
  index = TLS::array_copy(buffer, index, content, (int)(sizeof(content)-1));

}

bool TLS::check_memory(uint8_t** buffer, int bufferSize){
  if(sizeof(buffer) <= bufferSize+1){
    uint8_t* test = NULL;
    test = (uint8_t*) realloc(*buffer, bufferSize);
    if(test!=NULL){
      *buffer = test;
      Serial.println("reallocated");
      
    }
    else{
      free(buffer);
      Serial.println("Error reallocating memory");
      return false;
    }
  }
  return true;
  
}

int TLS::array_copy(uint8_t *main, int startaddr, uint8_t *extra, int extralen){
  for(int i=startaddr; i <startaddr+extralen; i++){
    *(main+i) = *(extra+(i-startaddr));
  }
  return startaddr+extralen;

}
void TLS::hmac256(uint8_t* secret, int secretSize, uint8_t* data, int dataSize, uint8_t* temp){
  // double ms;
  delay(1000);
  //ms = millis();
  Sha256.initHmac(secret,secretSize);

  for (int i=0; i < dataSize; i++){
    Sha256.write(data[i]);
  }

  uint8_t* result = Sha256.resultHmac();
  printHash(result);
  Serial.println("done");
  // Serial.print("Hash took ");
  // Serial.print((millis() - ms));
  // Serial.println(" ms");
  memcpy(temp, result, 32);
  Serial.println();
  
}


void TLS::PRF(uint8_t* secret, char* label, uint8_t* seed, int  secretSize, int labelSize, int seedSize, int iterations){
  uint8_t* data = (uint8_t* )malloc((labelSize+seedSize));
  uint8_t* temp = (uint8_t* )malloc(32);
  uint8_t* fulldata = (uint8_t* )malloc((32+labelSize+seedSize));
  uint8_t* cache = (uint8_t* )malloc(96);

  int addr = 0;

  for(int i =0; i < labelSize; i++){
    data[i] = (uint8_t)label[i];
  }

  TLS::array_copy(data, labelSize, seed, seedSize);

  TLS::hmac256(secret, secretSize, data, (seedSize+labelSize), temp);
  addr = TLS::array_copy(cache, addr, temp, 32);
  
  for(int i = 0; i < iterations; i++){
    TLS::array_copy(fulldata, 0, temp, (32+labelSize+seedSize));
    TLS::array_copy(fulldata, 32, data, (labelSize+seedSize));
    
    TLS::hmac256(secret, secretSize, fulldata, 32+labelSize+seedSize, temp);
    
    addr = TLS::array_copy(cache, addr, temp, 32);
  }
  Serial.println();
  Serial.println("cache:");
  for(int i =0; i < 96; i ++){
    Serial.print(TLS::hexValue(cache[i]));
  }
  Serial.println();
  free(temp);
  free(fulldata);
  free(cache);
  free(data);
}

void TLS::printHash(uint8_t* hash) {
  int i;
  for (i=0; i<32; i++) {
    Serial.print(TLS::hexValue(hash[i]));
  }
  Serial.println();

}

uint8_t* TLS::preMasterSecret(const char* psk, int pskSize){
  uint8_t* pms = (uint8_t* )malloc(4+pskSize+pskSize);
  uint8_t outer[2];
  uint16_t length = (uint16_t)pskSize;
  int zero = 0;
  outer[0] = (uint8_t)(length & 0xff00);
  outer[1] = (uint8_t)(length & 0xff);

  TLS::array_copy(pms, 0, outer, 2);
  for(int i = 2; i < pskSize+2; i++){
    pms[i] = (uint8_t)zero;
  }

  TLS::array_copy(pms, 2+pskSize, outer, 2);

  for(int i = 0; i < pskSize; i++){
    *(pms+(i+pskSize+4)) = (uint8_t)*(psk+i);
  }

  Serial.println("pre-master secret:");
  for (int i = 0; i < 4+pskSize+pskSize; i++){
    Serial.print(TLS::hexValue(pms[i]));
  }
  Serial.println("end secret");
  return pms;
}