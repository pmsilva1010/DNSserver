/* 
    Pedro Silva - 2007183130
    Tempo despendido: 44h
*/

#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ipc.h> 
#include <sys/types.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/fcntl.h>
#include <semaphore.h>
#include <errno.h>
#include <sys/mman.h>
#include <time.h>

#define CONFIG_FILE "config.txt"
#define LOCAL_DNS "localdns.txt"

// Structs
//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated messages
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
//Structure of a Query
struct QUERY
{
    unsigned char *name;
    struct QUESTION *ques;
};

//Estrutura do ficheiro de configuraçao
typedef struct{
    int flag; // 0-maintenance off ! 1-maintenance on
    sem_t ready;
	int threads;
	char local_domain[100];
	char name_pipe[100];
    int nr_domains;
    char domains[][100];
} config;

typedef struct{
    char hora_arranque[128], last_update[128];
    int pedidos_totais, pedidos_recusados, local_resolv, ext_resolv;
} Estatisticas;

struct stat statbuf;

typedef struct sPedido{
    unsigned short id;
    unsigned char *name;
    int sockfd;
    struct sockaddr_in dest;
    struct sPedido *Prox;
} PEDIDO;

typedef PEDIDO *FILA;

//Variaveis globais
int pConfiguracao, pEstatistica;
int shmid, fdsrc, fd_named_pipe;
config* memShared;
char* local;
time_t rawtime;
struct tm * timeinfo;
pthread_t *pool;
FILA fila_p, fila_n;
sem_t mutex_p, cond_p, mutex_n, cond_n;
Estatisticas est;

//Funcoes
void convertName2RFC (unsigned char*,unsigned char*);
unsigned char* convertRFC2Name (unsigned char*,unsigned char*,int*);
void sendReply(unsigned short, unsigned char*, int, int, struct sockaddr_in);

void cleanup();
void maintenance();
void gConfiguracao();
void gEstatisticas();
void load_configs();
void *work(void *idp);
void inicializa(FILA*);
void inserir(FILA*,unsigned short,unsigned char*, int, struct sockaddr_in);
void apagar(FILA*);
int check_ldomain(unsigned char*);
int valida(unsigned char*);
char *strdelc(char *, char);
void handle_maintenance();

