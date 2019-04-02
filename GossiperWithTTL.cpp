#include "libpcap/pcap.h"
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <iostream>
#include <algorithm>
#include <string.h>
#include <string>
#include <vector>
#include <ctime>
#define Goss_TYPE 514         // 0x0202
class Gossiper;

// разбить на потоки
// неправильно сохраняется МАС
using namespace std;

Gossiper *Goss;

class Gossiper
{
  private:
    const int N = 2;                    // количество получателей
    const int TTL = 4;
    char errbuf[PCAP_ERRBUF_SIZE];      // буфер ошибок
    pcap_t *handle;                     // идентификатор устройства
    vector <uint8_t*> Goss_list;        // буфер MAC адресов
    uint8_t PersonalMAC[6];
    uint8_t MulticastMAC[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x30};
    u_char* CopyPacket(const u_char*, u_char*, int);
    void AddInList(u_char*);
    void NewPacket();
    void SendPacket(const u_char*, int);
  public:
    Gossiper();
    void Hear();
    void SendStartPacker();
    bool CompareMAC(uint8_t*, uint8_t*);
    void FilterMAC(const u_char*, int);
};

Gossiper::Gossiper()
{
  cout << "Find device..." << endl;
  char *dev = pcap_lookupdev(errbuf);       // считываем прослушиваемое устройство

  if (dev == NULL) {
    fprintf(stderr, "%s\n", errbuf);
    throw;
  }
  printf("Device: %s\n", dev);

  cout << "Open session..." << endl;
  handle = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);    // открываем сессию для прослушивания устройства
  if (handle == NULL) {
    printf("Error opening! %s\n", errbuf);
    throw;
  }
  // enter MAC
  int s;
  struct ifreq ifr;        // структура для извлечения МАС

  if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1){
    cout << "Error open socket!" << endl;
    throw;
  }

  memset(&ifr, 0, sizeof(ifr));
  strcpy(ifr.ifr_name, dev);


  if (ioctl(s, SIOCGIFHWADDR, ifr) == -1){
    cout << "Error while getting MAC!" << endl;
    throw;
  }

  for (int i = 0; i < 6; i++)
    PersonalMAC[i] = (uint8_t) ifr.ifr_hwaddr.sa_data[i];
}

u_char* Gossiper::CopyPacket(const u_char *packet, u_char* dest, int len)
{
  u_char *mess = new u_char[len];

  for (int i = 0; i < len; i++)
    if (i < 5)
      mess[i] = dest[i];
    else{
      if (i == 14)
        mess[i] = (u_short)packet[i] - 1;
      else
        mess[i] = packet[i];
    }
  return mess;
}

void Gossiper::SendPacket(const u_char *packet, int len)
{
  if (!Goss_list.size()){
    cout << "Empty" << endl;
    return;
    }

  struct ether_header *eth = (struct ether_header *) packet;

  int num_dest = N > Goss_list.size() ? Goss_list.size() : N;
  random_shuffle(Goss_list.begin(), Goss_list.end() - 1);

  for (int i = 0; i < num_dest; i++){
    if(CompareMAC(Goss_list[i], eth->ether_dhost))
      continue;

    const u_char *out = CopyPacket(packet, Goss_list[i], len);

    cout << "Send message." << endl;
    pcap_sendpacket(handle, out, len);
  }
}

void Gossiper::AddInList(u_char *mac)
{
  cout << "Add in list" << endl;
  uint8_t insert[6];
  for (int i = 0; i < 6; i++)
    insert[i] = reinterpret_cast<uint8_t>(mac[i]);
  Goss_list.push_back(insert);
}

bool Gossiper::CompareMAC(uint8_t *first, uint8_t *second)
{
  for (int i = 0; i < 6; i++)
    if (first[i] != second[i])
      return false;
  return true;
}

void Gossiper::FilterMAC(const u_char *packet, int len)
{
  struct ether_header *eth;
  eth = (struct ether_header *) (packet);

  if (CompareMAC(eth->ether_dhost, MulticastMAC))
    AddInList(eth->ether_shost);

  if (CompareMAC(eth->ether_dhost, PersonalMAC))
    if (packet[14] != 0)
      SendPacket(packet, len);
}

void Gossiper::NewPacket()
{
  uint8_t packet[64];

  for (int i = 0; i < 64; i++){
    if(i > 5 && i < 12)
      packet[i] = PersonalMAC[i - 6];
    if(i == 12 || i == 13)
      packet[i] = 2;
    if(i == 14)
      packet[i] = TTL;
    if(i > 14)
      packet[i] = rand()%5;
  }

  cout << "Send message." << endl;
  SendPacket(packet, 64);
}

void Gossiper::SendStartPacker()
{
  uint8_t packet[64];

  for (int i = 0; i < 64; i++){
    if(i < 6)
      packet[i] = MulticastMAC[i];
    if(i > 5 && i < 12)
      packet[i] = PersonalMAC[i - 6];
    if(i == 12 || i == 13)
      packet[i] = 2;
    if(i == 14)
      packet[i] = 4;   // можно удалить
     if(i > 14)
      packet[i] = rand()%5;
  }
  cout << "Send start message..." << endl;
  pcap_sendpacket(handle, packet, 64);
}

static void Callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) // обработка приходящего пакета
{
  Goss->FilterMAC(packet, pkthdr->caplen);
}

void Gossiper::Hear()
{
  int timer = clock();
  cout << "Start listening..." << endl;

  while(true){
    pcap_loop(handle, 1, Callback, NULL); // функция-цикл для последовательной обработки сообщений
    if((clock() - timer)/CLOCKS_PER_SEC > 1){
      timer = clock();
      NewPacket();
    }
  }
}

int main(int argc, char const *argv[])
{
  try{
    Goss = new Gossiper();
    Goss->SendStartPacker();
    Goss->Hear();
  }catch(int i){
    return 1;
  }
  return 0;
}
