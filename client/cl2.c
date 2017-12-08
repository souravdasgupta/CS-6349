#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "client.h"
#include "/home/utsav/Downloads/CS-6349-master/prf/prf.h"

#define PORT "6666" // the port client will be connecting to 
#define KEY_SIZE 32
#define MAXDATASIZE 9000 // max number of bytes we can get at once
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



// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
int fp;
unsigned char key[KEY_SIZE], *ct = NULL, pt[KEY_SIZE];
   unsigned char iv[BLOCK_SIZE];  
        
        
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();
        
        if(!RAND_bytes(key, KEY_SIZE)){
                printf("Error in generating random key");
        }

unsigned char *auth_key=NULL;
unsigned char *integrity_key=NULL;

//-------------------------------------------------Initial Setup-----------------------------------------------------------------//

FILE *rf = fopen("a.txt","w");
    int new_fd, numbytes;  
    char buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

FILE *o;
    if (argc != 2) {
        fprintf(stderr,"usage: client hostname\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((new_fd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(new_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(new_fd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); 


//-------------------------------------------------Initial Setup-----------------------------------------------------------------//








int sd;

int i;
FILE *f, *r;
int counter;
unsigned char replybuf[sizeof(struct header)];
unsigned char sendbuf[sizeof(struct header) + 8192 + BLOCK_SIZE];
struct header rep_header;

//-------------------------------------------------Certificate-----------------------------------------------------------------//
struct header cert_header; //Header for Certificate Packet

if ((numbytes = recv(new_fd, sendbuf, sizeof(struct header) + 1359, MSG_WAITALL)) == -1) //Get certificate
        perror("recv");


memcpy(&cert_header,sendbuf,sizeof(struct header)); //Certificate Header



r=fopen("server.crt","w");
sd=fwrite(sendbuf+sizeof(struct header),1,cert_header.mystat.st_size,r);//Write certificate to file. Call validation code

fclose(r);
//printf("Cert recd %d\n",sd);
int validated=validate_certificate("./CA_certificate.crt","./server.crt");


if(validated==1){
rep_header.opcode=4;
printf("Certificate Validated");}
else{
printf("Validation failed");
rep_header.opcode=5;
rep_header.ecode=17;
}

memcpy(replybuf,&rep_header,sizeof(struct header)); //Buid reply packet
if (send(new_fd,replybuf,sizeof(struct header), 0) == -1) //Send reply
                perror("send");

if(validated!=1)
return 0;

//Key Generation and Sending code goes here
int size1;
size1 = rsa_encrypt(key, KEY_SIZE, &ct, "./server.crt");
        if(ct == NULL || size1 == 0){
                printf("Encryption failed\n");
                return -1;
        }

if (send(new_fd,ct,size1, 0) == -1) //Send key
                perror("send");



if(generate_auth_key(key,&auth_key)==0)
printf("\n\nAuth Key generated succesfully\n");


if(generate_integrity_key(key,&integrity_key)==0)
printf("\nIntegrity Key generated succesfully\n");


//-------------------------------------------------Certificate Ends-----------------------------------------------------------------//



//--------------------------------------Initial Request--------------------------------------------//
int sz;
printf("\n1: Upload  2: Download\n");
int choice;
scanf("%d",&choice);
char inputname[30];

if(choice!=1 && choice!=2)
{printf("Incorrect Input"); return 0;}

printf("\nEnter File Name\n");
scanf("%s",inputname);

if(strlen(inputname)>30)
{printf("\nFile Name over 30 characters not supported\n"); close(new_fd); return 0;}



//printf("\n%d\n",choice);

struct header req_header;

strcpy(req_header.name,inputname);


if(choice==2) //Download
{
req_header.opcode=2;

if(access(req_header.name,F_OK) != -1)
{printf("\nFile already present.\n");close(new_fd);return 0;}
else
{
memcpy(sendbuf,&req_header,sizeof(struct header));

if (send(new_fd, sendbuf, sizeof(struct header), 0) == -1) //Send Reply
				                perror("send");


	if ((numbytes = recv(new_fd, replybuf, sizeof(struct header), 0)) == -1) 
        perror("recv");


memcpy(&rep_header,replybuf,sizeof(struct header));

if(rep_header.opcode!=4)
{printf("\nNo file by this name on server.\n");close(new_fd);return 0;}

else {sz=rep_header.mystat.st_size;};

//putting full receive code here









//-------------------------------------------------File Transfer-----------------------------------------------------------------//

struct header file_header; //File Header



//struct data *tmp;

int sp=0;

counter=0;

r=fopen(req_header.name,"w+");

while (sz>0){

	if ((numbytes = recv(new_fd, sendbuf, sizeof(struct header) + 8192 + BLOCK_SIZE, MSG_WAITALL)) == -1) 
        perror("recv");

	memcpy(iv,sendbuf,BLOCK_SIZE);//Extract IV
//Decrypt code goes here


//printf("\nCipher Packet:\n");
//for(i=0;i<sizeof(struct header) + 8192;i++)
//printf("%c",sendbuf[i+BLOCK_SIZE]);


decrypt_ctr( sendbuf+BLOCK_SIZE, sizeof(struct header) + 8192 , sendbuf+BLOCK_SIZE, integrity_key, iv) ;
//printf("\nDe-Cipher Packet:\n");
//for(i=0;i<sizeof(struct header) + 8192;i++)
//printf("%c",sendbuf[i+BLOCK_SIZE]);
	memcpy(&file_header,sendbuf+64,sizeof(struct header));//Extract Header


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
//printf("\n%d\n",hasher);


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

printf("\nRecieved Hash\n");
for(i=0;i<DIGEST_SIZE;i++)
printf("%d",rdigest[i]);

printf("\nGenerated Hash\n");
for(i=0;i<DIGEST_SIZE;i++)
printf("%d",digest[i]);

//printf("%d",DIGEST_SIZE);

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
printf("\nIncorrect file recieved\n");
remove(req_header.name);
}
//--------------------------------------Hash Ends--------------------------------------------//


//close(r);


}


 close(new_fd);  return 0;
}














































//putting full receive code here








































else if(choice==1)//Upload
{
//strcpy(req_header.name,"output2.txt");
if(access(req_header.name,F_OK) != -1)
{
req_header.opcode=1;



if(stat(req_header.name,&req_header.mystat)<0)//File Details
						perror("Boo");

memcpy(sendbuf,&req_header,sizeof(struct header));

if (send(new_fd, sendbuf, sizeof(struct header), 0) == -1) //Send Upload request
				                perror("send");


	if ((numbytes = recv(new_fd, replybuf, sizeof(struct header), 0)) == -1) 
        perror("recv");


memcpy(&rep_header,replybuf,sizeof(struct header));

if(rep_header.opcode!=4)
{printf("Server already has file with same name.\n");close(new_fd);return 0;}

else {sz=req_header.mystat.st_size;};
}
else
{printf("\nNo such file found\n");close(new_fd);return 0;}



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

//sleep(10);

}




//--------------------------------------File Transfer Ends--------------------------------------------//



//--------------------------------------Hash--------------------------------------------//
close(fp);
close(f);

unsigned char digest[DIGEST_SIZE];

int hasher= calc_hash(req_header.name, digest);
//printf("\n%d\n",hasher);

printf("\nGenerated Hash\n");
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
 
close(new_fd);



printf("\nFile Sent\n"); 
   return 0;}

else
{
close(new_fd);
 
close(new_fd);



printf("\nData Corruptded FIle Send Failed\n"); 
   return 0;
}
//--------------------------------------Hash Ends--------------------------------------------//

}
close(new_fd);
return 0;

































//Putting full send code here





}
































else 
{printf("Incorrect choice");return 0;}
//--------------------------------------Initial Request Ends--------------------------------------------//






}
