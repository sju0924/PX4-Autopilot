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
#include "sha3.h"

#define XSTR(x) #x
#define STR(x) XSTR(x)




// void HMACList_init(void){

// }

__EXPORT void HMACList_add(const char* filename, int filenameLen){


   struct HMAC_list item;

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
      PX4_INFO("unvalid file\n");
      return;
   }

   strncpy(buf+size,key,strlen(key));

   PX4_INFO("File size is %d\n", size);
	int result = sha3_hash(item.filehash, (int)out_length, (uint8_t *) buf, (int)size, hash_bit, SHAKE);

   strncpy(item.filename, filename, filenameLen);
   PX4_INFO("hash of ");
   PX4_INFO("%s",item.filename);
   PX4_INFO("is");
   PX4_INFO("%s",item.filehash);
   PX4_INFO("result: %d\n", result);

   close(fd);

   char* keyfile = malloc(sizeof(char)*(filenameLen+1));

   strncpy(keyfile, filename, filenameLen);
   strncpy(keyfile+filenameLen,"h",1);

   fd = open((const char *) keyfile, O_WRONLY | O_BINARY);
   write(fd, (void *)&item, sizeof(struct HMAC_list));

   close(fd);

}

int integrity_tools_main(int argc, char *argv[])
{
   if (argc < 2) {
		PX4_INFO("Hello Sky!");
	}

	else if (!strcmp(argv[1], "dataman")) {
      //HMACList_init()
      HMACList_add("/fs/microsd/dataman",strlen("/fs/microsd/dataman") );
   }

   return OK;
}
