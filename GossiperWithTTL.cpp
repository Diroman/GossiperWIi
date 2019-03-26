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
#define Goss_TYPE 0x0202

// функция для проверки МАС адреса и типа пакетов
// функция формирования пакетов

// получить пакет родителем, отправить информацию о новом получателе

using namespace std;

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
    char *dev;                          // прослушиваемое устройство
    char errbuf[PCAP_ERRBUF_SIZE];      // буфер ошибок
    pcap_t *handle;                     // идентификатор устройства
    bpf_u_int32 maskp;                  // маска подсети
	  bpf_u_int32 ip;                     // ip
    vector <uint8_t[6]> Goss_list;      // буфер MAC адресов
    uint8_t PersonalMAC[6];
    uint8_t MulticastMAC[6] = {1, 0, 94, 0, 0, 48};
    static void AddInList(u_char*);
    static void SendPacket(u_char*);
  public:
    Gossiper();
    void Hear();
    static void Callback(u_char*, const struct pcap_pkthdr*, const u_char*);
    static bool CompareMAC(uint8_t*, uint8_t*);
    static bool FilterMAC(struct ether_header*);
};

Gossiper::Gossiper()
{
  cout << "Find device..." << endl;
  dev = pcap_lookupdev(errbuf);       // считываем прослушиваемое устройство

  if (dev == NULL) {
    fprintf(stderr, "%s\n", errbuf);
    throw;
  }
  printf("Device: %s\n", dev);
  pcap_lookupnet(dev, &ip, &maskp, errbuf);

  cout << "Open session" << endl;
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

void Gossiper::AddInList(u_char *mac)
{
  uint8_t insert[6];
  for (int i = 0; i < 6; i++)
    insert[i] = static_cast<uint8_t>(mac[i]);
  Goss_list.push_back(insert);
}

bool Gossiper::CompareMAC(uint8_t *first, uint8_t *second)
{
  for (int i = 0; i < 6; i++)
    if (first[i] != second[i])
      return false;
  return true;
}

bool Gossiper::FilterMAC(struct ether_header *eth)
{
  if (CompareMAC(eth->ether_dhost, MulticastMAC)){

  }
  cout << "Filter" << endl;
  return true;
}

void Gossiper::Callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) // обработка приходящего пакета
{
  struct ether_header *eth;
  eth = (struct ether_header *) packet;

  FilterMAC(eth);

}

void Gossiper::Hear()
{
  while(true)
    pcap_loop(handle, 1, Callback, NULL); // функция-цикл для последовательной обработки сообщений
}

int main(int argc, char const *argv[])
{
  try{
    Gossiper Goss = Gossiper();
    Goss.Hear();
  }catch(int i){
    return 1;
  }
  return 0;
}
