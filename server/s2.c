#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <stdbool.h>
#include "../prf/prf.h"


#define PORT "6666"  // the port users will be connecting to
#define KEY_SIZE 32
#define BACKLOG 1     // how many pending connections queue will hold
#define BLOCK_SIZE 64
#define DIGEST_SIZE SHA256_DIGEST_LENGTH

struct header{
int opcode; //1=Up 2=Dwn 3=Data 4=Ack 5=Error 0=Crt
char name[30];
struct stat mystat;
unsigned int block;
size_t Payload;
int ecode;
};



void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{
unsigned char key[KEY_SIZE], ct[256], pt[KEY_SIZE];
   unsigned char iv[BLOCK_SIZE];     
        
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();
        
       

unsigned char *auth_key=NULL;
unsigned char *integrity_key=NULL;

//------------------------------SERVER SETUP CODE---------------------------//

    int newfd, new_fd=0;  
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; 
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv,numbytes;
int sz, sd;


    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; 

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }


    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((newfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(newfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(newfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(newfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); 

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(newfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; 
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");


        sin_size = sizeof their_addr;
        new_fd = accept(newfd, (struct sockaddr *)&their_addr, &sin_size);


        if (new_fd == -1) {
            perror("accept");
            
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);

        printf("server: got connection from %s\n", s);


//------------------------------SERVER SETUP CODE---------------------------//






int fp;
int i;
FILE *f, *r;
int counter;
unsigned char replybuf[sizeof(struct header)];
unsigned char sendbuf[sizeof(struct header) + 8192 +64];
struct header rep_header;

//--------------------------------------Certificate--------------------------------------------//
FILE *cert; //Certificate Pointer
struct header cert_header; //Header for Certificate Packet

cert=fopen("server-certificate.crt","r");//Open Certificate

cert_header.opcode=0;//Build Header
strcpy(cert_header.name,"server-certificate.crt");//Build Header

if(stat(cert_header.name,&cert_header.mystat)<0)//Cert Details
perror("Boo");

memcpy(sendbuf,&cert_header,sizeof(struct header));//Build Packet: Add Header
if(!fread(sendbuf+sizeof(struct header), cert_header.mystat.st_size, sizeof(char),cert))//Build Packet: Add Payload
	perror("Cert no read");

            if (send(new_fd, sendbuf, sizeof(struct header)+cert_header.mystat.st_size, 0) == -1) //Send Certificate
                perror("send");
else
{

if(recv(new_fd,replybuf,sizeof(struct header),0)==-1) //Get Reply Header
perror("recv");

memcpy(&rep_header,replybuf,sizeof(struct header));
if(rep_header.opcode==4) //Check for Acknowledgement
printf("Certificate Validated");

else if(rep_header.opcode=5)
{printf("Validation failed");return 0;}



}
int size1;
//Receive Key
if(recv(new_fd,ct,256,0)==-1) 
perror("recv");
printf("\n");
size1 = rsa_decrypt(pt, ct, "./server-private.key");
  //      for(i = 0 ; i < size1; i++){
    

//            printf("%d ", pt[i]);
  //      }

if(generate_auth_key(pt,&auth_key)==0)
printf("\nAuth Key generated succesfully\n");


if(generate_integrity_key(pt,&integrity_key)==0)
printf("\nIntegrity Key generated succesfully\n");
//--------------------------------------Certificate--------------------------------------------//






//--------------------------------------Initial Request--------------------------------------------//
struct header req_header;

if(recv(new_fd,replybuf,sizeof(struct header),0)==-1) //Get Request Header
perror("recv");
memcpy(&req_header,replybuf,sizeof(struct header));


//printf("Got Request %d", req_header.opcode);


if(req_header.opcode==2)// Download 
{
	if(access(req_header.name,F_OK) != -1){
//Send ACK

						if(stat(req_header.name,&rep_header.mystat)<0)//File Details
						perror("Boo");








						rep_header.opcode=4;
						memcpy(sendbuf,&rep_header,sizeof(struct header));//Build Packet
						if (send(new_fd, sendbuf, sizeof(struct header), 0) == -1) //Send Reply
				                perror("send");

					      }
	else{
//Send error


						rep_header.opcode=5; rep_header.ecode=7;
//Set error code//				
						memcpy(sendbuf,&rep_header,sizeof(struct header));//Build Packet
						if (send(new_fd, sendbuf, sizeof(struct header), 0) == -1) //Send Reply
				                perror("send");
printf("\nNo File by this name.\n");return 0;

	    }



//Putting full send code here














//--------------------------------------File Transfer--------------------------------------------//

struct header file_header; //Header for data transfer

file_header.opcode=3;//Build Header
strcpy(file_header.name,req_header.name);//Build Header

file_header.block=0;

f=fopen(file_header.name,"r");//File to be sent
if(stat(file_header.name,&file_header.mystat)<0)//File Details ????////Becomes Redunadant this should be sent in up/dwn request
perror("Boo");

//store size in variable and use to calculate payload

while (file_header.mystat.st_size>ftell(f)) { //Loop through blocks till entire file is sent

if(file_header.mystat.st_size-ftell(f)<8192) //Adjust payload length for last block
file_header.Payload = file_header.mystat.st_size-ftell(f);



if(file_header.block==0) //Initialise payload to 8192
file_header.Payload=8192;

if(file_header.mystat.st_size < 8192)
file_header.Payload=file_header.mystat.st_size;


file_header.block++; //Block Counter



if(!fread(sendbuf+sizeof(struct header)+BLOCK_SIZE, file_header.Payload, sizeof(char), f)) //Build Packet : Add Payload
	perror("");
printf("\nFile read till:%d\nSending Block:%d\n",ftell(f),file_header.block);


memcpy(sendbuf+BLOCK_SIZE,&file_header,sizeof(struct header)); //Build Packet : Add Header

//Encryption Here
 if(!RAND_bytes(iv, BLOCK_SIZE)){
                printf("Error in generating IV");
        }

encrypt_ctr(sendbuf+BLOCK_SIZE,sizeof(struct header)+file_header.Payload , sendbuf+BLOCK_SIZE, integrity_key, iv);//Encrypt Header + Payload
memcpy(sendbuf,iv,BLOCK_SIZE); //Add IV

while(1){ //Loop to send block and wait till acknowledgement
//counter=0;
            if (send(new_fd, sendbuf, sizeof(struct header)+8192+BLOCK_SIZE, 0) == -1) //Send block
                perror("send");


            else{


			if(recv(new_fd,replybuf,sizeof(struct header),0)==-1) //Get Reply
			perror("recv");

			memcpy(&rep_header,replybuf,sizeof(struct header));


			if(rep_header.opcode==4) //Proceed to next block after succesful acknowledgement
			break;
/*
			else{
				 //Some error
				counter++; //Update no of times current block is sent
				if(counter==10)
				break; //Abandon block if 10 tries attempted
			    }

*/
		}

	}
//if(counter==10) //Abort sending operation
//{
//printf("\nIncorrect Data sent more than 10 times\n"); 
//break;
//}



}




//--------------------------------------File Transfer Ends--------------------------------------------//



//--------------------------------------Hash--------------------------------------------//
close(fp);
close(f);

unsigned char digest[DIGEST_SIZE];

int hasher= calc_hash(req_header.name, digest);
printf("\n%d\n",hasher);

printf("\nGenerated Hash:\n");
for(i=0;i<DIGEST_SIZE;i++)
printf("%d",digest[i]);


if(!RAND_bytes(iv, BLOCK_SIZE)){
                printf("Error in generating IV");
        }
memcpy(sendbuf,iv,BLOCK_SIZE);
memcpy(sendbuf+BLOCK_SIZE,digest,DIGEST_SIZE); 

encrypt_ctr(sendbuf+BLOCK_SIZE, DIGEST_SIZE,sendbuf+BLOCK_SIZE, auth_key, iv);







if (send(new_fd, sendbuf,BLOCK_SIZE+ DIGEST_SIZE, 0) == -1) //Send Hash
                perror("send");


            else{


			if(recv(new_fd,replybuf,sizeof(struct header),0)==-1) //Get Reply
			perror("recv");

			memcpy(&rep_header,replybuf,sizeof(struct header));


			if(rep_header.opcode==4)
{close(new_fd);
 
close(newfd);



printf("\nFile Sent\n"); 
   return 0;}

else
{
close(new_fd);
 
close(newfd);



printf("\nData Corruptded FIle Send Failed\n"); 
   return 0;
}
//--------------------------------------Hash Ends--------------------------------------------//

}

return 0;
}











//Putting full send code here

 

else if(req_header.opcode==1)// Upload
{
	if(access(req_header.name,F_OK) != -1){
//Send ACK

						if(stat(req_header.name,&rep_header.mystat)<0)//File Details
						perror("Boo");








						rep_header.opcode=5;//file already exists
						memcpy(sendbuf,&rep_header,sizeof(struct header));//Build Packet
						if (send(new_fd, sendbuf, sizeof(struct header), 0) == -1) //Send Reply
				                perror("send");
printf("\nFile already exists\n");
return 0;
					      }
	else{
//Send error


						rep_header.opcode=4; //rep_header.ecode=7;
//Set error code//				
						memcpy(sendbuf,&rep_header,sizeof(struct header));//Build Packet
						if (send(new_fd, sendbuf, sizeof(struct header), 0) == -1) //Send Reply
				                perror("send");
//printf("No File");return 0;

sz=req_header.mystat.st_size;
	    }









//putting full receive code here









//-------------------------------------------------File Transfer-----------------------------------------------------------------//

struct header file_header; //File Header



//struct data *tmp;

int sp=0;

counter=0;

r=fopen(req_header.name,"w+");//open file to append

while (sz>0){

	if ((numbytes = recv(new_fd, sendbuf, sizeof(struct header) + 8192 + BLOCK_SIZE, MSG_WAITALL)) == -1) 
        perror("recv");

	memcpy(iv,sendbuf,BLOCK_SIZE);//Extract IV


        decrypt_ctr( sendbuf+BLOCK_SIZE, sizeof(struct header) + 8192 , sendbuf+BLOCK_SIZE, integrity_key, iv) ;

	memcpy(&file_header,sendbuf+BLOCK_SIZE,sizeof(struct header));//Extract Header

	
	sd=fwrite(sendbuf+sizeof(struct header)+BLOCK_SIZE,1,file_header.Payload,r);
	counter=0;//Reset counter for next block
	sp=sp + sd;
	sz=sz-sd;//size from request header
	printf("\nBytes written this time:%d\nTotal bytes written:%d\nGot Block %d\n",sd,sp,file_header.block);


//Send Ack
	rep_header.opcode=4;
	memcpy(replybuf,&rep_header,sizeof(struct header));//Build repply packet
	if (send(new_fd,replybuf,sizeof(struct header), 0) == -1)
        perror("send");



}












//-------------------------------------------------File Transfer Ends-----------------------------------------------------------------//



 
//--------------------------------------Hash--------------------------------------------//

fclose(r);

unsigned char digest[DIGEST_SIZE];
unsigned char rdigest[DIGEST_SIZE];

int hasher= calc_hash(req_header.name, digest);
printf("\n%d\n",hasher);


if ((numbytes = recv(new_fd, sendbuf,BLOCK_SIZE+ DIGEST_SIZE, 0)) == -1) 
        perror("recv");

	memcpy(iv,sendbuf,BLOCK_SIZE);//Extract IV


decrypt_ctr( sendbuf+BLOCK_SIZE, DIGEST_SIZE , sendbuf+BLOCK_SIZE, auth_key, iv) ;
	memcpy(rdigest,sendbuf+BLOCK_SIZE,DIGEST_SIZE);//Get Hash

bool matches=true;
for(i=0;i<DIGEST_SIZE;i++)
if(rdigest[i]!=digest[i])
{
matches=false;
break;
}

printf("\nReceived Hash\n");
for(i=0;i<DIGEST_SIZE;i++)
printf("%d",rdigest[i]);

printf("\nSelf Generated Hash\n");
for(i=0;i<DIGEST_SIZE;i++)
printf("%d",digest[i]);

//printf("\n%d",DIGEST_SIZE);

if(matches)
{
	rep_header.opcode=4;
	memcpy(replybuf,&rep_header,sizeof(struct header));//Build repply packet
	if (send(new_fd,replybuf,sizeof(struct header), 0) == -1)
        perror("send");
printf("\nCorrect file received\n");
}

else
{
	rep_header.opcode=5;
	memcpy(replybuf,&rep_header,sizeof(struct header));//Build repply packet
	if (send(new_fd,replybuf,sizeof(struct header), 0) == -1)
        perror("send");
printf("\nIncorrect file received\n");
remove(req_header.name);
}
//--------------------------------------Hash Ends--------------------------------------------//


//close(r);





   return 0;
}














































//putting full receive code here


























 

else 
return 0;
//--------------------------------------Initial Request--------------------------------------------//




}
