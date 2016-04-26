#include "TLS.h"
#include <ESP8266WiFi.h>
#include <string.h>
#include <WiFiUdp.h>
#include "sha256.h"
#include <vector>
#include "aes.h"
//#include <AES.h>
TLS::TLS()
{

  return;
}

//connects the client to the specified AP, where id = SSID, and pass = password
//this function is intended to be used in a while loop which checks the value of 
//WL_CONNECTED so that the device can restart the process if it gets interrupted
//rather than just timing out.
void TLS::connectWiFi(const char* id, const char* pass){

  Serial.println();
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(id);
  int timer = 0; //connection timeout: causes the device to reconnect. 
  WiFi.begin(id, pass);
  
  //waiting for ~55 seconds to connect, before disconnecting
  while (WiFi.status() != WL_CONNECTED) {
    timer++;
    delay(500);
    Serial.print(".");
    if(timer > 110){
      WiFi.disconnect();
      Serial.println();
      Serial.println("WiFi timed out");
      return;
    }

  }
  Serial.println("");
  Serial.println("WiFi connected");  
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
  return;
  
}    

//simply calls functions below in the correct order to facilitate a TLS handshake
bool TLS::handshake(const char* psk_value, const char* psk_id, WiFiClient client){
  uint8_t hellopacket[246] = {0};
  uint8_t keypacket[18] = {0};
  uint8_t cipherspecpacket[6] = {0};
  uint8_t finishedmessage[17] = {0};

  std::vector<uint8_t> messages;
  std::vector<uint8_t> serverRandom;
  std::vector<uint8_t> clientRandom;
  std::vector<uint8_t>masterSecret;
  std::vector<uint8_t> pms;
  std::vector<uint8_t>::const_iterator it;
  
  messages.reserve(400);
  serverRandom.reserve(32);
  clientRandom.reserve(32);
  masterSecret.reserve(48);
  pms.reserve((4+(2*(int)strlen(psk_id))));
  
  bool received = true;
  
  while(received){
    Serial.println(1);
    TLS::client_hello(hellopacket, clientRandom);
    Serial.println(2);
    TLS::client_key_exchange(keypacket, psk_id, (int)strlen(psk_id));
    Serial.println(3);
    TLS::change_cipher_spec(cipherspecpacket, 5);
    Serial.println(4);
    TLS::preMasterSecret(psk_value, 32, pms); 
    Serial.println(5);
    TLS::masterSecret(pms, clientRandom, serverRandom, psk_id, (int)strlen(psk_id), masterSecret);
    Serial.println(6);
    TLS::insertClientPacket(hellopacket, sizeof(hellopacket), messages);
    delay(100);
    Serial.println(7);
    TLS::sendPacket(hellopacket, sizeof(hellopacket), client);
    Serial.println(8);
    received = TLS::receivePacket(messages, client);
    Serial.println(9);
    TLS::getServerRandom(messages, serverRandom);
    Serial.println(10);
    TLS::insertClientPacket(keypacket, sizeof(keypacket), messages); 
    Serial.println(11);
    TLS::sendPacket(keypacket, sizeof(keypacket), client);
    Serial.println(12);
    received = TLS::receivePacket(messages, client);
    Serial.println(13);
    TLS::sendPacket(cipherspecpacket, sizeof(cipherspecpacket), client);
    Serial.println(14);
    TLS::client_finished(masterSecret, messages, finishedmessage);
    Serial.println(15);
    TLS::sendPacket(finishedmessage, sizeof(finishedmessage), client);
    Serial.println(16);
    TLS::receivePacket(messages,client);
    Serial.println(17);
    break;
  }
  messages.clear();
  serverRandom.clear();
  clientRandom.clear();
  pms.clear();
  if(received){
    Serial.println("Handshake done!");
    return true;
  }
  else{
    Serial.println("handshake failed");
    return false;
  }
  
}

//sends the specified packet to the connected server via TCP
void TLS::sendPacket(uint8_t* packet, int packetSize, WiFiClient client){
  Serial.println("Sending packet");
  client.write(const_cast<uint8_t *>(packet), packetSize);

}

//Similar to the TLS handshake function, but for application data:
//this function calls the functions to create the application data packet
//and then sends the data
void TLS::sendAppData(char* data, int dataSize, WiFiClient client,  const char* key){
  //uint8_t appdata[5+dataSize];
  uint8_t *appdata = (uint8_t* )malloc((5+dataSize+(16-(dataSize % 16))));
  TLS::applicationData(appdata, data, dataSize, key);
  
  Serial.println("Application data:");
  // for(int i =0; i < sizeof(appdata); i++){
  //   Serial.print(TLS::hexValue(appdata[i]));
  // }
  delay(1);
  Serial.println();
  TLS::sendPacket(appdata, sizeof(appdata), client);
}

//waits for server response and saves it in a vector
bool TLS::receivePacket(std::vector<uint8_t>& v, WiFiClient client){
  Serial.println("receiving packet");
  for (int i =0; i < 60; i++){
    delay(100);
    if(client.available() != 0){
      break;
    }
    else if(i == 59){
      Serial.println("Client timed out. No packet received.");
      return false;
    }
  }

  int received = 0;
  int vSize = (int)v.capacity();
  while(client.available() != 0){
    delay(1);
    if (received < vSize){
      v.push_back(client.read());
    }
    else{
      v.reserve(20);
      vSize += 20;
    }

    received++;
  }
  v.resize(v.size());
  return true;
}




//for sending of NTP packets: very unsecure, so not used at the moment
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

//inserts a packet into the "messages" vector. This is done because all TLS handshake
//messages must be concatenated and hashed for part of the handshake
void TLS::insertClientPacket(uint8_t* packet, int packetSize, std::vector<uint8_t>& allPackets){
  for (int i = 0; i < packetSize; i++){
    allPackets.push_back(*(packet+i));
  }
}

//utility function, mostly for debugging; used to get the hexadecimal value
//of some unsigned char
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

//basically memcpy, but returns the last index written to, so that the function
//can be called again and again when multiple arrays are being added into one larger array
int TLS::array_copy(uint8_t *main, int startaddr, uint8_t *extra, int extralen){
  for(int i=startaddr; i <startaddr+extralen; i++){
    *(main+i) = *(extra+(i-startaddr));
  }
  return startaddr+extralen;

}

//mostly for debugging; prints out content of an array of unsigned chars
void TLS::printHex(uint8_t* data, int dataSize) {
  int i;
  for (i=0; i<dataSize; i++) {
    Serial.print(TLS::hexValue(data[i]));
  }
  Serial.println();

}

//the Pseudo-Random Function (PRF). Creates the specified amount of data by using a CBC-style
//algorithm (see RFC 5246 for specific details)
void TLS::PRF(uint8_t* secret, const char* label, uint8_t* seed, int  secretSize, int labelSize, int seedSize, int quantity, std::vector<uint8_t>& cache){
  int iterations = ceil((float)quantity/32.0);
  int remaining = quantity % 32;

  uint8_t* data = (uint8_t* )malloc((labelSize+seedSize));
  uint8_t* temp = (uint8_t* )malloc(32);
  uint8_t* fulldata = (uint8_t* )malloc((32+labelSize+seedSize));
  uint8_t* buffer = (uint8_t* )malloc(quantity+remaining);

  int addr = 0;

  for(int i =0; i < labelSize; i++){
    data[i] = (uint8_t)label[i];
  }

  TLS::array_copy(data, labelSize, seed, seedSize);

  TLS::hmac256(secret, secretSize, data, (seedSize+labelSize), temp);
  addr = TLS::array_copy(buffer, addr, temp, 32);
  
  for(int i = 0; i < iterations; i++){
    TLS::array_copy(fulldata, 0, temp, (32+labelSize+seedSize));
    TLS::array_copy(fulldata, 32, data, (labelSize+seedSize));
    
    TLS::hmac256(secret, secretSize, fulldata, 32+labelSize+seedSize, temp);
    
    addr = TLS::array_copy(buffer, addr, temp, 32);
  }

  free(temp);
  free(fulldata);
  free(data);

  

  //TLS::array_copy(cache, 0, buffer, quantity);
  for(int i = 0; i < quantity; i ++){
    cache.push_back(*(buffer+i));
  }
  free(buffer);
  

}

//takes a seret and some data, creates a hash and populates the provided array.
void TLS::hmac256(uint8_t* secret, int secretSize, uint8_t* data, int dataSize, uint8_t* temp){
  // double ms;
  //ms = millis();
  Sha256.initHmac(secret,secretSize);

  for (int i=0; i < dataSize; i++){
    Sha256.write(data[i]);
  }

  uint8_t* result = Sha256.resultHmac();
  // printHex(result, 32);
  // Serial.println("done");
  memcpy(temp, result, 32);
  Serial.println();
  
}

//given a Server Hello packet, extracts the server_random field for use in the Master Secret
void TLS::getServerRandom(std::vector<uint8_t>& packet, std::vector<uint8_t>& sRand){
  if(packet.size()>41){
    for(int i = 11; i < 43; i++){
      sRand.push_back(packet[i]);
    }
  }
}

//basically concatenates client random and server random, before applying the PRF
//to the result alongside the premaster secret and label
void TLS::masterSecret(std::vector<uint8_t>& pms, std::vector<uint8_t>& cRand, std::vector<uint8_t>& sRand, const char* label, int labelSize, std::vector<uint8_t>& masterSecret){
  uint8_t* secret = new uint8_t [pms.size()];
  uint8_t* cRandArray = new uint8_t [cRand.size()];
  uint8_t* sRandArray = new uint8_t [sRand.size()];
  uint8_t* csRandArray = new uint8_t [(cRand.size()+sRand.size())];

  memcpy(secret, &pms.front(), pms.size());
  memcpy(cRandArray, &cRand.front(), cRand.size());
  memcpy(sRandArray, &sRand.front(), sRand.size());

  int addr = TLS::array_copy(csRandArray, 0, cRandArray, cRand.size());
  TLS::array_copy(csRandArray, addr, sRandArray, sRand.size());

  TLS::PRF(secret, label, csRandArray, (int)pms.size(), labelSize, (int)(cRand.size()+sRand.size()), 48, masterSecret);
  
  delete secret;
  delete cRandArray;
  delete sRandArray;
  delete csRandArray;
  
}

//builds the pre-master secret from the PSK
//it is composed like so: 
//length of PSK(2 bytes) + N zeroes +length again + psk
void  TLS::preMasterSecret(const char* psk, int pskSize, std::vector<uint8_t>& pms){
  

  uint8_t outer[2];
  uint16_t length = (uint16_t)pskSize;
  int zero = 0;
  outer[0] = (uint8_t)(length & 0xff00);
  outer[1] = (uint8_t)(length & 0xff);

  //TLS::array_copy(pms, 0, outer, 2);
  pms.push_back(outer[0]);
  pms.push_back(outer[1]);

  for(int i = 0; i < pskSize; i++){
    pms.push_back((uint8_t)zero);
  }

  pms.push_back(outer[0]);
  pms.push_back(outer[1]);

  for(int i = 0; i < pskSize; i++){
    pms.push_back((uint8_t)*(psk+i));
  }

  //return pms;
}



//simple sha256 hash, as opposed to the hmac hash. This is mainly used
//to hash all messages at the end of the handshake
//in order to sign the "finished" message
void TLS::sha256Hash(std::vector<uint8_t>& messages, uint8_t* buffer){


  Sha256.init();

  for (int i =0; i < messages.size(); i++){
    Sha256.write(messages[i]);
    //Serial.print(TLS::hexValue(messages[i]));
  }

  uint8_t* sharesult = Sha256.result();

  TLS::array_copy(buffer, 0, sharesult, 32);

  
}


//PACKET BUILDERS - These functions take an array turn it into some type of packet.

/*Builds the client hello packet. Specifics follow:

*/
void TLS::client_hello(uint8_t* buffer, std::vector<uint8_t>& cRand){
  uint8_t content[] = "\x16"; //Content type: 22 (handshake)
  uint8_t tls_version[] = "\x03\x03"; //TLS version: 1.2
  uint8_t hello[] = "\x01"; //message type: 1 (hello)
  uint8_t unixtime[] = "\x4e\x24\x3b\x32"; //placeholder time
  uint8_t client_random[28]; //client random - constructed later
  uint8_t ciphers_compressions[] = "\x00\x00\x02\x00\xae\x01\x00"; //no compression methods, cipher suite =
  uint8_t extensions[] = "\x00\xc5\x00\x00\x00\x00\x00\x23\x00\x00\x00\x0d\x00\x04\x00\x02\x04\x00\x00\x0f\x00\x01\x01\x00\x15\x00\xa8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
  uint8_t inner[] = "\x00\x00\x00";
  uint8_t outer[] = "\x00\x00";

  randomSeed(analogRead(A0));
  
  for (int i=0; i < 4; i++){
    cRand.push_back(*(unixtime+i));
   }

  for (int i=0; i < 28; i++){
    client_random[i] = (uint8_t)random(255);
    cRand.push_back(*(client_random+i));
   }


  uint32_t innerlength = uint32_t(sizeof(tls_version)-1+sizeof(unixtime)-1+sizeof(client_random)-1+sizeof(ciphers_compressions)-1+sizeof(extensions)-1);
  uint16_t outerlength = innerlength+4;
  inner[0] = (uint8_t)(innerlength & 0xff0000);
  inner[1] = (uint8_t)(innerlength & 0xff00);
  inner[2] = (uint8_t)(innerlength & 0xff);
  outer[0] = (uint8_t)(outerlength & 0xff00);
  outer[1] = (uint8_t)(outerlength & 0xff);

  int index = 0;
  index = TLS::array_copy(buffer, index, content, (int)(sizeof(content)-1));
  index = TLS::array_copy(buffer, index, tls_version, (int)(sizeof(tls_version)-1));
  index = TLS::array_copy(buffer, index, outer, (int)(sizeof(outer)-1));
  index = TLS::array_copy(buffer, index, hello, (int)(sizeof(hello)-1));
  index = TLS::array_copy(buffer, index, inner, (int)(sizeof(inner)-1));
  index = TLS::array_copy(buffer, index, tls_version, (int)(sizeof(tls_version)-1));
  index = TLS::array_copy(buffer, index, unixtime, (int)(sizeof(unixtime)-1));
  index = TLS::array_copy(buffer, index, client_random, (int)(sizeof(client_random)));
  index = TLS::array_copy(buffer, index, ciphers_compressions, (int)(sizeof(ciphers_compressions)-1));
  index = TLS::array_copy(buffer, index, extensions, (int)(sizeof(extensions)-1));
  return;

}

void TLS::client_key_exchange(uint8_t *buffer, const char* id, int id_size){
  uint8_t *psk_id = (uint8_t* )malloc(id_size);
  for(int i=0; i < id_size; i++){
    psk_id[i]=(uint8_t)id[i];
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
  free(psk_id);
}
void TLS::change_cipher_spec(uint8_t* buffer, int bufferSize){
  uint8_t content[] = "\x14\x03\x03\x00\x01\x01";
  //TLS::check_memory(&buffer, 6);
  int index = 0;
  index = TLS::array_copy(buffer, index, content, (int)(sizeof(content)-1));

}

void TLS::client_finished(std::vector<uint8_t>& secret, std::vector<uint8_t>& messages, uint8_t* buffer){
  uint8_t* seed = (uint8_t* )malloc(32);
  std::vector<uint8_t> cache;
  cache.reserve(12);
  uint8_t cacheArray[12];
  uint8_t mSecret[48];
  memcpy(mSecret, &secret.front(), secret.size());
  TLS::sha256Hash(messages, seed);

  TLS::PRF(mSecret, "client_finished", seed, secret.size(), 15, 32, 12, cache);

  memcpy(cacheArray, &cache.front(), cache.size());

  uint8_t content[] = "\x16";
  uint8_t tls_version[] = "\x03\x03";
  uint8_t outer[] = "\x00\x00";

  uint16_t outerlength = (uint16_t)(cache.size());


  outer[0] = (uint8_t)(outerlength & 0xff00);
  outer[1] = (uint8_t)(outerlength & 0xff);
  int index = 0;
  index = TLS::array_copy(buffer, index, content, (sizeof(content)-1));
  index = TLS::array_copy(buffer, index, tls_version, (sizeof(tls_version)-1));
  index = TLS::array_copy(buffer, index, outer, (sizeof(outer)-1));
  index = TLS::array_copy(buffer, index, cacheArray, sizeof(cacheArray));
  free(seed);

}

void TLS::applicationData(uint8_t *buffer, char* data, int dataSize, const char* key){
  
  Serial.println("appdata start");
  uint8_t content[] = "\x16";
  uint8_t tls_version[] = "\x03\x03";
  uint8_t outer[] = "\x00\x00";

  uint8_t convertedKey[16];
  int paddingLength = (16-(dataSize % 16));
  uint8_t dataBuffer[dataSize+paddingLength];
  uint8_t paddedData[dataSize+paddingLength];
  uint8_t iv[] = {0x00};
  Serial.println("variables set");
  for (int i = 0; i < dataSize+paddingLength; i++){
    if(i >= dataSize){
      paddedData[i] = '\x00';
    }
    else{
      paddedData[i] = (uint8_t)*(data+i);
    }
  }
  Serial.println("paddedData made");
  for (int i =0; i < 16; i++){
    convertedKey[i] = (uint8_t)*(key+i);
  }
  Serial.println("key converted");

  Serial.println("paddeddadasize:");
  Serial.println(sizeof(paddedData));
  Serial.println(sizeof(dataBuffer));
  aes::AES128_CBC_encrypt_buffer(dataBuffer, paddedData, sizeof(paddedData), convertedKey, iv);

  uint16_t outerlength = (uint16_t)(dataSize+paddingLength);
  outer[0] = (uint8_t)(outerlength & 0xff00);
  outer[1] = (uint8_t)(outerlength & 0xff);
  int index = 0;
  index = TLS::array_copy(buffer, index, content, (sizeof(content)-1));
  index = TLS::array_copy(buffer, index, tls_version, (sizeof(tls_version)-1));
  index = TLS::array_copy(buffer, index, outer, (sizeof(outer)-1));
  for(int i = i; i < sizeof(dataBuffer); i++){
    buffer[i+index] = *(dataBuffer+i);
  }
  TLS::printHex(buffer, sizeof(dataBuffer));


}

