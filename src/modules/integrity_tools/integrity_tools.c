/****************************************************************************
 *
 *   Copyright (c) 2012-2022 PX4 Development Team. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name PX4 nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

 /**
 * @file integrity_tools
 * Minimal application example for PX4 autopilot
 *
 * @author Example User <mail@example.com>
 */

#include "integrity_tools.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "sha3.h"

#define XSTR(x) #x
#define STR(x) XSTR(x)




// void HMACList_init(void){

// }

__EXPORT void HMACList_add(const char* filename, int filenameLen){


   hmac_list item = {"",""};

   if(filenameLen > 40){
      PX4_INFO("File name is too long to store\n");
      return;
   }

   ssize_t size;
   int fd = open(filename, O_RDONLY | O_BINARY);
   char *key = STR(HMAC_KEY);
   PX4_INFO("key: %s\n",key);

   size = lseek(fd, 0, SEEK_END);

   char* buf = malloc(sizeof(char)*(size + strlen(key)));
   lseek(fd, 0, SEEK_SET);
   if( (size = read(fd, (char *)buf, size))<0){
      PX4_INFO("unvalid file: %s \n", filename);
      return;
   }

   strncpy(buf+size,key,strlen(key));

   PX4_INFO("File size is %ld\n", size);
	int result = sha3_hash(item.filehash, (int)out_length, (uint8_t *) buf, (int)size, hash_bit, 0);

   strncpy(item.filename, filename, filenameLen);
   PX4_INFO("hash of %s is %s, result is %d\n",item.filename,item.filehash,result);

   close(fd);

   char* keyfile = malloc(sizeof(char)*(filenameLen+2));

   strncpy(keyfile, filename, filenameLen);
   strncpy(keyfile+filenameLen,"h\0",2);
   PX4_INFO("hash file stored at %s\n", keyfile);
   fd = open((const char *) keyfile, O_WRONLY | O_BINARY|O_CREAT,0600);
   if(write(fd, (void *)&item, sizeof(hmac_list))<0){
      PX4_INFO("write failed BY %d \n", errno);
   };

   close(fd);

}

//buf: sizeof(struct HMAC_list)
void HMAC_get(const char* filename, int filenameLen, void *buf){
   hmac_list item;
   ssize_t size;

   //파일명 길이 검사
   if(filenameLen > 40){
      PX4_INFO("File name is too long to store\n");
      return;
   }

   //HMAC 파일 불러오기
   char* keyfile = malloc(sizeof(char)*(filenameLen+1));
   strncpy(keyfile, filename, filenameLen);
   strncpy(keyfile+filenameLen,"h",1);

   int fd = open((const char *) keyfile, O_WRONLY | O_BINARY);

   lseek(fd, 0, SEEK_SET);
   if( (size = read(fd, (char *)&item, sizeof(hmac_list)))<0){
      PX4_INFO("unvalid file: %s \n", keyfile);
      return;
   }

   strncpy(buf, (char *)item.filehash, out_length);

   close(fd);
}

int HMAC_file(const char* filename, int filenameLen, void *hmac_buf){
   if(filenameLen > 40){
      PX4_INFO("File name is too long to store\n");
      return -1;
   }

   //파일 및 키 불러오기
   int fd = open(filename, O_RDONLY | O_BINARY);
   char *key = STR(HMAC_KEY);
   PX4_INFO("key: %s\n",key);

   //파일 크기 구하기
   ssize_t size;
   size = lseek(fd, 0, SEEK_END);

   //파일 열기
   char *buf = malloc(sizeof(char)*(size + strlen(key)));
   lseek(fd, 0, SEEK_SET);
   if( (size = read(fd, buf, size))<0){
      PX4_INFO("unvalid file: %s ", filename);
      return -1;
   }

   //파일이름+키 함치기
   strncpy(buf+size,key,strlen(key));

   PX4_INFO("File size is %ld\n", size);
	int result = sha3_hash(hmac_buf, (int)out_length, (uint8_t *) buf, (int)size, hash_bit, 0);

   close(fd);
   return result;

}
__EXPORT bool HMAC_verify(const char* filename, int filenameLen){

   // 파일 해시화
   char hmac_file[out_length] , hmac[out_length];
   HMAC_file(filename, filenameLen, hmac_file);
   HMAC_get(filename, filenameLen, hmac);

   if(!strncmp(hmac, hmac_file, out_length)){
      PX4_INFO("verification success\n");
      return 1;
   }
   else {
      PX4_INFO("verification failed\n");
      return 0;
   }


}

__EXPORT bool user_verify(const char* id, const char* pw){
   if(!strcmp(id, "sju0924") && !strcmp(pw, "1234")){
      PX4_INFO("login success, %s", id);
      return 1;
   }
   else{
      return 0;
   }
}
int integrity_tools_main(int argc, char *argv[])
{
   if (argc < 2) {
		PX4_INFO("Hello Sky!");
	}

	else if (argc == 2) {
      //HMACList_init()
      HMACList_add(argv[1],strlen(argv[1]) );
   }

   return OK;
}
