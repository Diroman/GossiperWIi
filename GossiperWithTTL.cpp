#include "libpcap/pcap.h"
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <iostream>
#include <string.h>
#include <string>
#include <vector>
#define Goss_TYPE 514         // 0x0202
class Gossiper;
// функция формирования пакетов

using namespace std;

Gossiper *Goss;

void handle_ethernet(const u_char* packet)
{
  int i;
  struct ether_header *eth;

  eth = (struct ether_header *) packet;

  cout << "Source: ";
  for(i = 0; i < 5; i++){
    printf("%02x:", eth->ether_shost[i]);
  }
  printf("%02x\tDest: ", eth->ether_shost[i]);
  for(i = 0; i < 5; i++){
    printf("%02x:", eth->ether_dhost[i]);
  }
  printf("%02x", eth->ether_dhost[i]);
  cout << '\n';

};

class Gossiper
{
  private:
    const int N = 2;                    // задержка в секундах
    const int TTL = 4;                  // количество получателей
    char errbuf[PCAP_ERRBUF_SIZE];      // буфер ошибок
    pcap_t *handle;                     // идентификатор устройства
    vector <uint8_t*> Goss_list;        // буфер MAC адресов
    uint8_t PersonalMAC[6];
    uint8_t MulticastMAC[6] = {1, 0, 94, 0, 0, 48};
    u_char* CopyPacket(const u_char*, u_char*, int, bool*);
    void AddInList(u_char*);
    void SendPacket(const u_char*, int);
  public:
    Gossiper();
    void Hear();
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

  cout << "Start listening..." << endl;
}

u_char* Gossiper::CopyPacket(const u_char *packet, u_char* dest, int len, bool *f)
{
  u_char *mess = new u_char[len];

  for (int i = 0; i < len; i++)
    if (i < 5)
      mess[i] = dest[i];
    else{
      if (i == 14){
        if ((u_short)packet[i] == 0){
          f = new bool(false);
          return mess;
        }
        mess[i] = (u_short)packet[i] - 1;
      }else
        mess[i] = packet[i];
    }
  return mess;
}

void Gossiper::SendPacket(const u_char *packet, int len)
{
  bool *f = new bool(true);
  struct ether_header *eth;
  eth = (struct ether_header *) packet;

  for (int i = 0; i < Goss_list.size(); i++){
    if(CompareMAC(Goss_list[i], eth->ether_dhost))
      continue;
    const u_char *out = CopyPacket(packet, Goss_list[i], len, f);
    if (!*f)
      return;
    pcap_sendpacket(handle, out, len);
  }
}

void Gossiper::AddInList(u_char *mac)
{
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
  eth = (struct ether_header *) packet;

  if (eth->ether_type != Goss_TYPE)
    return;

  if (CompareMAC(eth->ether_dhost, MulticastMAC))
    AddInList(eth->ether_shost);

  if (CompareMAC(eth->ether_dhost, PersonalMAC))
    if (packet[15] != 0)
      SendPacket(packet, len);
}

static void Callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) // обработка приходящего пакета
{
  Goss->FilterMAC(packet, pkthdr->caplen);
}

void Gossiper::Hear()
{
  while(true)
    pcap_loop(handle, 1, Callback, NULL); // функция-цикл для последовательной обработки сообщений
}

int main(int argc, char const *argv[])
{
  try{
    Goss = new Gossiper();
    Goss->Hear();
  }catch(int i){
    return 1;
  }
  return 0;
}
