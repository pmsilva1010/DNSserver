/* 
	Pedro Silva - 2007183130
	Tempo despendido: 44h
*/
	
#include "dnsserver.h"

int main( int argc , char *argv[])
{
	unsigned char buf[65536], *reader;
	int sockfd, stop;
	struct DNS_HEADER *dns = NULL;
	
	struct sockaddr_in servaddr,dest;
	socklen_t len;

	inicializa(&fila_p);
	inicializa(&fila_n);
	
	// Check arguments
	if(argc <= 1) {
		printf("Usage: dnsserver <port>\n");
		exit(1);
	}
	
	// Get server UDP port number
	int port = atoi(argv[1]);
	
	if(port <= 0) {
		printf("Usage: dnsserver <port>\n");
		exit(1);
	}
	
	
	// ****************************************
	// Create socket & bind
	// ****************************************
	
	// Create UDP socket
    sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
 
	if (sockfd < 0) {
         printf("ERROR opening socket.\n");
		 exit(1);
	}

	// Prepare UDP to bind port
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servaddr.sin_port=htons(port);
	
	// Bind application to UDP port
	int res = bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
	
	if(res < 0) {
         printf("Error binding to port %d.\n", servaddr.sin_port);
		 
		 if(servaddr.sin_port <= 1024) {
			 printf("To use ports below 1024 you may need additional permitions. Try to use a port higher than 1024.\n");
		 } else {
			 printf("Please make sure this UDP port is not being used.\n");
		 }
		 exit(1);
	}
	/****** END UDP SOCKET CREATION ******************************/
	/****** Tratamento de Sinais **********/
	signal(SIGINT,cleanup);
	signal(SIGTSTP,maintenance);
	/***************************/

	/****** Criacao da memoria partilhada ************************/
	shmid = shmget(IPC_PRIVATE, sizeof(config), IPC_CREAT|0777);
  	memShared = (config*) shmat(shmid, NULL, 0);
  	/*************************/
  	//SEM
  	sem_init(&memShared->ready,1,0);

	/********* Criacao de Processos **********************/
	pConfiguracao=fork();
	if(pConfiguracao==0){
		gConfiguracao();
	}

	pEstatistica=fork();
	if(pEstatistica==0){
		gEstatisticas();
	}
	/***************************/

	/******** Semaforos para sync das threads *************/
	sem_init(&mutex_p, 0, 1);
    sem_init(&cond_p, 0, 0);
    sem_init(&mutex_n, 0, 1);
    sem_init(&cond_n, 0, 0);

	/********** Criacao da pool de threads ****************/
	sem_wait(&memShared->ready);
	
	pool=malloc(sizeof(pthread_t)*memShared->threads);
	int id[memShared->threads],i;

	for(i=0;i<memShared->threads;i++){
		id[i]=i;
		pthread_create(&pool[i],NULL,work,&id[i]);
	}

	sem_post(&memShared->ready);


	/********** Mapear localdns em memoria *********************/
	if((fdsrc=open(LOCAL_DNS,O_RDONLY))<0){		//Open file
		fprintf(stderr, "[%d][Main] Error openning localdns.txt file: %s\n",getpid(),strerror(errno));
		cleanup();
	}
	if(fstat (fdsrc,&statbuf)<0){		//Get size
		fprintf(stderr, "[%d][Main] Error getting the file size: %s\n",getpid(),strerror(errno));
		cleanup();
	}
	if((local=mmap(0,statbuf.st_size, PROT_READ,MAP_SHARED, fdsrc,0))==(caddr_t)-1){
		fprintf(stderr, "[%d][Main] Error maping the file: %s\n",getpid(),strerror(errno));
		cleanup();
	}

	/********** Criacao do named PIPE para estatisticas ********/
	if(mkfifo(memShared->name_pipe, O_CREAT|O_EXCL|0600)<0 && (errno|=EEXIST)){
  		perror("Cannot create pipe: ");
  		cleanup();
  	}
  	if((fd_named_pipe=open(memShared->name_pipe, O_WRONLY))<0){
  		perror("Cannot open pipe for writing: ");
  		cleanup();
  	}
  
	char horaServidor[128];

  	time ( &rawtime );
  	timeinfo = localtime ( &rawtime );
  	sprintf(horaServidor,"%d:%d:%d",timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec);

  	strcpy(est.hora_arranque,horaServidor);
  	est.pedidos_totais=0;
  	est.pedidos_recusados=0;
  	est.local_resolv=0;
  	est.ext_resolv=0;

  	write(fd_named_pipe,&est,sizeof(Estatisticas));
  	/***********************************************************/

	// ****************************************
	// Receive questions
	// ****************************************
	
	while(1) {
		// Receive questions
		len = sizeof(dest);
		printf("\n\n-- Wating for DNS message --\n\n");
		if(recvfrom (sockfd,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , &len) < 0) {
			printf("Error while waiting for DNS message. Exiting...\n");
			exit(1);
		}
		
		printf("DNS message received\n");
	 
		// Process received message
		dns = (struct DNS_HEADER*) buf;
		//qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
		reader = &buf[sizeof(struct DNS_HEADER)];
	 
		printf("\nThe query %d contains: ", ntohs(dns->id));
		printf("\n %d Questions.",ntohs(dns->q_count));
		printf("\n %d Answers.",ntohs(dns->ans_count));
		printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
		printf("\n %d Additional records.\n\n",ntohs(dns->add_count));
		
		// We only need to process the questions
		// We only process DNS messages with one question
		// Get the query fields according to the RFC specification
		struct QUERY query;
		if(ntohs(dns->q_count) == 1) {
			// Get NAME
			query.name = convertRFC2Name(reader,buf,&stop);
			reader = reader + stop;
			
			// Get QUESTION structure
			query.ques = (struct QUESTION*)(reader);
			reader = reader + sizeof(struct QUESTION);
			
			// Check question type. We only need to process A records.
			if(ntohs(query.ques->qtype) == 1) {
				printf("A record request.\n\n");
			} else {
				printf("NOT A record request!! Ignoring DNS message!\n");
				continue;
			}
			
		} else {
			printf("\n\nDNS message must contain one question!! Ignoring DNS message!\n\n");
			continue;
		}
		
		// Received DNS message fulfills all requirements.
		
		// ****************************************
		// Print received DNS message QUERY
		// ****************************************
		printf(">> QUERY: %s\n", query.name);
		printf(">> Type (A): %d\n", ntohs(query.ques->qtype));
		printf(">> Class (IN): %d\n\n", ntohs(query.ques->qclass));

		if(check_ldomain(query.name)==1){
			inserir(&fila_p,dns->id,query.name,sockfd,dest);
			sem_post(&cond_p);
		}
		else{
			inserir(&fila_n,dns->id,query.name,sockfd,dest);
			sem_post(&cond_n);
		}
		
		est.pedidos_totais++;
		write(fd_named_pipe,&est,sizeof(Estatisticas));
		// ****************************************
		// Example reply to the received QUERY
		// (Currently replying 10.0.0.2 to all QUERY names)
		// ****************************************
		//sendReply(dns->id, query.name, inet_addr("10.0.0.2"), sockfd, dest);
	}
	
    return 0;
}

/******* Codigo meu ******************************/
void cleanup(){
	char opcao[2];

	printf("\n[%d][Main] Are you sure you want to terminate the server? [y : n]\n",getpid());
	scanf("%s",opcao);

	if(opcao[0]=='y'){
		kill(pConfiguracao,SIGKILL); 	// Terminate 
		kill(pEstatistica,SIGKILL);		//  processes
		sem_destroy(&memShared->ready);	// End semaphore
		shmctl(shmid, IPC_RMID, NULL);	// Clear shared memory
		free(pool);						// Remove threads pool
		sem_destroy(&mutex_p);			// Destroy the
    	sem_destroy(&cond_p);			//  thread
   	 	sem_destroy(&mutex_n);			//  sync
    	sem_destroy(&cond_n);			//  semaphores
		munmap(local,statbuf.st_size); 	// Unmap localdns 
		close(fdsrc);				 	//  file
		close(fd_named_pipe);			// Close
		unlink(memShared->name_pipe);	//  named pipe
		free(fila_p);					// Elimina as
		free(fila_n);					//  listas de pedidos
		printf("[%d][Main] Terminating the server!\n",getpid());
		
		exit(0);
	}
	else if(opcao[0]=='n'){
		printf("[%d][Main] Resuming server!\n",getpid());
	}
	else
		printf("[%d][Main] Invalid option! Resuming server!\n",getpid());
}

void maintenance(){
	if(memShared->flag==0){
		printf("[%d][Main] Entering maintenance mode\n", getpid());
		kill(pConfiguracao,SIGUSR1);
	}
	else{
		printf("[%d][Main] Exiting maintenance mode\n", getpid());
		kill(pConfiguracao,SIGUSR1);
		while(memShared->flag==1){

		}
	}	
}

void gConfiguracao(){
	signal(SIGINT,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	printf("[%d][Confiuration Manager] Configuration Manager is up!\n", getpid());

	memShared->flag=0;
	load_configs();

	sem_post(&memShared->ready);

	signal(SIGUSR1,handle_maintenance);
	
	while(1){

	}
}

void gEstatisticas(){
	signal(SIGINT,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	printf("[%d][Statistics Manager] Statistics Manager is up!\n",getpid());
	Estatisticas est;

	while((fd_named_pipe=open(memShared->name_pipe, O_RDONLY|O_NONBLOCK))<0){
  		printf("[%d][Statistics Manager] PIPE NOT OPEN YET\n",getpid());
  		sleep(1);
  	}
 
	while(1){
		sleep(30);
		while(read(fd_named_pipe,&est,sizeof(Estatisticas))>0){
			time ( &rawtime );
  			timeinfo = localtime ( &rawtime );
  			strcpy(est.last_update,asctime (timeinfo));
		}

		printf("------Statistics-------\n");
  		printf("Server started at: %s\nTotal requests: %d\nRequests denied: %d\nLocal domain solved: %d\nExternal domain solved: %d\nLast update at: %s"
  			,est.hora_arranque,est.pedidos_totais,est.pedidos_recusados,est.local_resolv,est.ext_resolv,est.last_update);
  		printf("-----------------------\n");
	}
}

void load_configs(){
	char nome[100],igual[3],dados[100];
	memShared->nr_domains=0;
	//Ler o ficheiro de configuraçao
	FILE *f;
	if((f=fopen(CONFIG_FILE,"r"))!=NULL){
		fscanf(f,"%s %s %s", nome,igual,dados);
		memShared->threads=atoi(dados);
		fscanf(f,"%s %s %s", nome,igual,dados);
		strcpy(memShared->local_domain,dados);
		fscanf(f,"%s %s %s", nome,igual,dados);
		strcpy(memShared->name_pipe,dados);
		fscanf(f,"%s %s", nome,igual);
		while(fscanf(f,"%s",dados)!=EOF){
			strdelc(dados,';');
			strcpy(memShared->domains[memShared->nr_domains],dados);
			memShared->nr_domains++;
		}
	}
	else
		printf("[%d][Configuration Manager] Error opening the configuration file!\n",getpid());

	fclose(f);
}

void *work(void *idp){
	int id=*((int*) idp);
	
	while(1){
		if(sem_trywait(&cond_p)==0){			//pedidos prioritarios
			sem_wait(&mutex_p);
			
			PEDIDO Tmp=*fila_p;
			apagar(&fila_p);

			sem_post(&mutex_p);

			char * sub;
			if((sub=strstr(local,(char *) Tmp.name))!=NULL){
				int query=strlen((char *) Tmp.name),i;
				char aux[15+1];

				sub=sub+query+1;
				for(i=0;sub[i]!='\n';i++){
					aux[i]=sub[i];
				}
				aux[i]='\0';
				sendReply(Tmp.id, Tmp.name, inet_addr(aux), Tmp.sockfd, Tmp.dest);
				est.local_resolv++;
			}
			else{
				printf("[Thread %d][Main] IP Not found!\n",id);
				sendReply(Tmp.id, Tmp.name, inet_addr("0.0.0.0"), Tmp.sockfd, Tmp.dest);
				est.pedidos_recusados++;
			}
			write(fd_named_pipe,&est,sizeof(Estatisticas));
		}
		else if(sem_trywait(&cond_n)==0){		//pedidos normais
			sem_wait(&mutex_n);
			
			PEDIDO Tmp=*fila_n;
			apagar(&fila_n);

			sem_post(&mutex_n);

			if(memShared->flag==1){
				printf("[Thread %d][Main] Server on maintenance\n",id);
				sendReply(Tmp.id, Tmp.name, inet_addr("0.0.0.0"), Tmp.sockfd, Tmp.dest);
				est.pedidos_recusados++;
			}
			else{
				if(valida(Tmp.name)==1){
					printf("[Thread %d][Main] The domain %s is valid!\n",id,Tmp.name);

					int pipefd[2];
					pipe(pipefd);
					char buffer[1024]="\0";
		
					char* dig_param[] = { "dig" ,"+short", (char *) Tmp.name, NULL };
		
					pid_t p_aux=fork();
					if (p_aux==0){
						close(pipefd[0]);    // close reading end in the child
	    				dup2(pipefd[1], 1);  // send stdout to the pipe   	
						close(pipefd[1]);

						execvp(dig_param[0], dig_param);
					}
					else{			
					    close(pipefd[1]);  					// close the write end of the pipe in the parent
					    read(pipefd[0], buffer, sizeof(buffer));
					    close(pipefd[0]);

					    int cmp=strlen(buffer);
					    buffer[cmp-1]='\0';

					    if(cmp<=0){
					    	printf("[Thread %d][Main] IP Not found!\n",id);
					    	sendReply(Tmp.id, Tmp.name, inet_addr("0.0.0.0"), Tmp.sockfd, Tmp.dest);
					    	est.pedidos_recusados++;
					    }
					    else{
					    	sendReply(Tmp.id, Tmp.name, inet_addr(buffer), Tmp.sockfd, Tmp.dest);
					    	est.ext_resolv++;
				    	}
					}
				}
				else{
					printf("[Thread %d][Main] The domain %s is not valid!\n",id,Tmp.name);
					sendReply(Tmp.id, Tmp.name, inet_addr("0.0.0.0"), Tmp.sockfd, Tmp.dest);
					est.pedidos_recusados++;
				}
			}
			write(fd_named_pipe,&est,sizeof(Estatisticas));	
		}
	}
}

void inicializa(FILA* Fila){		//Incializa uma fila
	*Fila=NULL;
}

void inserir(FILA* Fila, unsigned short id,unsigned char *name, int sockfd, struct sockaddr_in dest){		//Insere dados numa fila
	if(*Fila==NULL){
		*Fila=(FILA) malloc (sizeof(PEDIDO));
		if(*Fila==NULL) return;
		(*Fila)->id=id;
		(*Fila)->name=name;
		(*Fila)->sockfd=sockfd;
		(*Fila)->dest=dest;
		(**Fila).Prox=NULL;
	}
	else{
		inserir(&(**Fila).Prox,id,name,sockfd,dest);
	}
}

void apagar(FILA* Fila){		//Apaga o 1º elemento da fila
	PEDIDO *Tmp=*Fila;

	if(*Fila==NULL)  //Nao existem elementos
		return;

	*Fila=(*Fila)->Prox;
	free(Tmp);
}

int check_ldomain(unsigned char* name){
	int ldomain=strlen(memShared->local_domain);
	int query=strlen((char *)name);

	if(query<ldomain)
		return 0;

	char aux[ldomain+1];
	
	strncpy(aux,(char *) name+(query-ldomain), ldomain);
	aux[ldomain]='\0';

	if(strcmp(memShared->local_domain,aux)==0)
		return 1;
	else
		return 0;
}

int valida(unsigned char* name){
	int i,ldomain,query;

	for(i=0;i<memShared->nr_domains;i++){
		if(strstr((char*) name,memShared->domains[i])!=NULL){	// verifica se o dominio existe na query
			ldomain=strlen(memShared->domains[i]);
			query=strlen((char *)name);
			char aux[ldomain+1];
			
			strncpy(aux,(char *) name+(query-ldomain), ldomain);
			aux[ldomain]='\0';

			if(strcmp(memShared->domains[i],aux)==0)
				return 1;
		}
	}

	return 0;
}

char *strdelc(char *s, char ch){
	int i,j;

	for(i=j=0;s[i]!='\0';i++){
		if(s[i]!=ch)
			s[j++]=s[i];
	}
	s[j]='\0';
	return s;
}

void handle_maintenance(){
	if(memShared->flag==0){
		memShared->flag=1;
		printf("[%d][Configuration Manager] Maintenance mode ON\n",getpid());
	}
	else{
		load_configs();
		memShared->flag=0;
		printf("[%d][Configuration Manager] Maintenance mode OFF\n",getpid());
	}
}

/******* Fim do meu codigo ***********************/
 
/**
	sendReply: this method sends a DNS query reply to the client
	* id: DNS message id (required in the reply)
	* query: the requested query name (required in the reply)
	* ip_addr: the DNS lookup reply (the actual value to reply to the request)
	* sockfd: the socket to use for the reply
	* dest: the UDP package structure with the information of the DNS query requestor (includes it's IP and port to send the reply)
**/
void sendReply(unsigned short id, unsigned char* query, int ip_addr, int sockfd, struct sockaddr_in dest) {
		unsigned char bufReply[65536], *rname;
		char *rip;
		struct R_DATA *rinfo = NULL;
		
		//Set the DNS structure to reply (according to the RFC)
		struct DNS_HEADER *rdns = NULL;
		rdns = (struct DNS_HEADER *)&bufReply;
		rdns->id = id;
		rdns->qr = 1;
		rdns->opcode = 0;
		rdns->aa = 1;
		rdns->tc = 0;
		rdns->rd = 0;
		rdns->ra = 0;
		rdns->z = 0;
		rdns->ad = 0;
		rdns->cd = 0;
		rdns->rcode = 0;
		rdns->q_count = 0;
		rdns->ans_count = htons(1);
		rdns->auth_count = 0;
		rdns->add_count = 0;
		
		// Add the QUERY name (the same as the query received)
		rname = (unsigned char*)&bufReply[sizeof(struct DNS_HEADER)];
		convertName2RFC(rname , query);
		
		// Add the reply structure (according to the RFC)
		rinfo = (struct R_DATA*)&bufReply[sizeof(struct DNS_HEADER) + (strlen((const char*)rname)+1)];
		rinfo->type = htons(1);
		rinfo->_class = htons(1);
		rinfo->ttl = htonl(3600);
		rinfo->data_len = htons(sizeof(ip_addr)); // Size of the reply IP address

		// Add the reply IP address for the query name 
		rip = (char *)&bufReply[sizeof(struct DNS_HEADER) + (strlen((const char*)rname)+1) + sizeof(struct R_DATA)];
		memcpy(rip, (struct in_addr *) &ip_addr, sizeof(ip_addr));
		
		// Send DNS reply
		printf("\nSending Answer... ");
		if( sendto(sockfd, (char*)bufReply, sizeof(struct DNS_HEADER) + (strlen((const char*)rname) + 1) + sizeof(struct R_DATA) + sizeof(ip_addr),0,(struct sockaddr*)&dest,sizeof(dest)) < 0) {
			printf("FAILED!!\n");
		} else {
			printf("SENT!!!\n");
		}
}

/**
	convertRFC2Name: converts DNS RFC name to name
**/
u_char* convertRFC2Name(unsigned char* reader,unsigned char* buffer,int* count) {
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    while(*reader!=0) {
        if(*reader>=192) {
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        } else {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0) {
            *count = *count + 1;
        }
    }
 
    name[p]='\0';
    if(jumped==1) {
        *count = *count + 1;
    }
 
    for(i=0;i<(int)strlen((const char*)name);i++) {
        p=name[i];
        for(j=0;j<(int)p;j++) {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0';
    return name;
}

/**
	convertName2RFC: converts name to DNS RFC name
**/
void convertName2RFC(unsigned char* dns,unsigned char* host) {
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) {
        if(host[i]=='.') {
            *dns++ = i-lock;
            for(;lock<i;lock++) {
                *dns++=host[lock];
            }
            lock++;
        }
    }
    *dns++='\0';
}