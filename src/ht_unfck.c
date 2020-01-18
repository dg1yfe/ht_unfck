/*
 ============================================================================
 Name        : ht_unfck.c
 Author      : 
 Version     :
 Copyright   : GPL
 Description :
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <libgen.h>

#define FI2_NAME_MAXLEN 1024

struct etq_meta_S{
	char 	 magic[4];
	uint32_t zero;
} __attribute__((packed));

struct fi2_meta_S{
	char 	 magic[4];
	uint32_t data_len;
	uint16_t type;
	uint16_t scrambled;
	uint8_t  md5[16];
	uint16_t name_len;
} __attribute__((packed));


enum ht_parser_state_E{ HTS_ETQHEAD, HTS_FI2HEAD, HTS_FI2NAME, HTS_FI2CONTENT,
	HTS_SKIP_FI2_DATA, HTS_SKIP};

struct fi2_descramble_S{
	char * keyword;
	int  key_len;
	int  s_len;
	int  k_pos;
};


void descrable_init(struct fi2_descramble_S * desc_state, char * key, size_t data_len){
	desc_state->key_len = strlen(key);
	desc_state->keyword = key;
	desc_state->s_len = (data_len >> 3) & 7;
	desc_state->k_pos = data_len % desc_state->key_len;

	if(desc_state->s_len == 0){
		desc_state->s_len = 3;
	}
}


void descramble(struct fi2_descramble_S * desc_state, char * buf, size_t datalen){
	size_t count;
	count = datalen;
	while(count > 0){
		*buf -= desc_state->keyword[desc_state->k_pos];
		buf++;
		desc_state->k_pos = (desc_state->k_pos + desc_state->s_len) % desc_state->key_len;
		count--;
	};
}


int main(int argc, char **argv){
	FILE * f_in;
	FILE * f_out;
	char * name;
	int files;
	size_t rpos;
	size_t chunk_remaining_bytes;
	int err;
	struct etq_meta_S * etq_head_p;
	struct fi2_meta_S fi2_head;
	char   chunk_name[FI2_NAME_MAXLEN];
	char key[] = "Decrypt error in file \x27%s\x27. Please contact the programmer.\n";
	struct fi2_descramble_S desc_state;

	enum ht_parser_state_E state;

	char buf[4096];
	size_t read_bytes;
	size_t to_read;

	if(argc != 2){
		printf("HAM-Trainer unf*ck\n"
				"Usage: ht_unfck <etq file>\n");
		exit(0);
	}

	files = 0;
	name = argv[1]+1;
	name[strlen(name)-1]=0;
	printf("Opening: %s\n",name);
	f_in = fopen(name,"rb");
	if(f_in == NULL){
		perror("Error opening file.");
		exit(0);
	}

	rpos  = 0;
	state = HTS_ETQHEAD;

	while(!feof(f_in)){
		switch(state){
			case HTS_ETQHEAD:{
				to_read = sizeof(struct etq_meta_S);
				read_bytes = fread(buf,1,to_read, f_in);
				rpos += read_bytes;
				if(read_bytes != to_read){
					err = ferror(f_in);
					perror("Error reading ETQ header:");
					return EXIT_FAILURE;
				}
				etq_head_p = (struct etq_meta_S *) buf;
				if(strncmp(etq_head_p->magic,"ETQ1",4) != 0){
					fprintf(stderr, "This is no etq1 file.\n");
					return EXIT_FAILURE;
				}
				if(etq_head_p->zero != 0){
					fprintf(stderr, "Warning: Header 'zero' is not zero.\n");
				}
				state = HTS_FI2HEAD;
				break;
			}
			case HTS_FI2HEAD:{
				size_t excess_len;
				to_read = sizeof(fi2_head);
				read_bytes = fread(buf,1,to_read, f_in);
				if(read_bytes != to_read){
					if(feof(f_in))
						break;
					err = ferror(f_in);
					perror("Error reading FI2 header: ");
					return EXIT_FAILURE;
				}
				memcpy(&fi2_head, buf, sizeof(fi2_head));
				fi2_head.data_len = ntohl(fi2_head.data_len);
				fi2_head.scrambled = ntohs(fi2_head.scrambled);
				fi2_head.type = ntohs(fi2_head.type);
				fi2_head.name_len = ntohs(fi2_head.name_len);
				excess_len = sizeof(fi2_head) - 8 + fi2_head.name_len;
				if(strncmp(fi2_head.magic,"FI1\0",4) == 0){
					fprintf(stderr, "FI1 chunks not (yet) implemented, skipping.\n");
					state = HTS_SKIP;
					break;
				}
				if(strncmp(fi2_head.magic,"FI2\0",4) != 0){
					fprintf(stderr, "This is no FI2 chunk at %zu.\n", rpos);
					state = HTS_SKIP;
					break;
				}
				if(fi2_head.name_len > FI2_NAME_MAXLEN){
					printf("Chunk name exceeds maxlen, increase it and recompile.\n");
					printf("Skipping chunk.\n");
					fseek(f_in, fi2_head.name_len, SEEK_CUR);
					rpos += fi2_head.name_len;
					state = HTS_SKIP_FI2_DATA;
					break;
				}
				if(fi2_head.data_len < excess_len ){
					printf("Invalid chunk size (smaller than chunk header.)\n");
					state = HTS_SKIP;
					break;
				}
				fi2_head.data_len -= excess_len;
				rpos += read_bytes;
				state = HTS_FI2NAME;
				break;
			}
			case HTS_SKIP_FI2_DATA:{
				// skip this chunk
				fseek(f_in, fi2_head.data_len, SEEK_CUR);
				rpos += fi2_head.data_len;
				state = HTS_FI2HEAD;
				break;
			}
			case HTS_FI2NAME:{
				char md5_str[33];
				char * dname;
				char * bname;
				int k;

				to_read = fi2_head.name_len;
				memset(chunk_name,0,sizeof(chunk_name));
				read_bytes = fread(chunk_name,1,to_read, f_in);
				if(read_bytes != to_read){
					err = ferror(f_in);
					perror("Error reading FI2 chunk name:");
					return EXIT_FAILURE;
				}
				dname = dirname(chunk_name);
				bname = basename(chunk_name);
				if(*dname != '.'){
					mkdir(dname, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
				}
				f_out = fopen(chunk_name,"wb");
				if(f_out == NULL){
					printf("Error opening %s for writing.\nSkipping...\n", chunk_name);
					state = HTS_SKIP_FI2_DATA;
				}
				rpos += read_bytes;
				chunk_remaining_bytes = fi2_head.data_len;

				memset(md5_str,0,sizeof(md5_str));
				for(k=0;k<16;k++){
					char hex_str[3];
					sprintf(hex_str, "%02x", fi2_head.md5[k]);
					strncat(md5_str,hex_str,2);
				}
				printf( "Found Entry:\n"
					    " Name     : %s\n"
						" Size     : %lu\n"
						" MD5      : 0x%s\n"
						" Type     : %u\n"
						" Scrambled: %u\n",
						chunk_name,
						(unsigned long) fi2_head.data_len,
						md5_str,
						fi2_head.type, fi2_head.scrambled);
				files++;
				if(fi2_head.scrambled){
					descrable_init(&desc_state, key, fi2_head.data_len);
				}
				state = HTS_FI2CONTENT;
				break;
			}
			case HTS_FI2CONTENT:{
				size_t written;
				to_read = chunk_remaining_bytes < sizeof(buf) ? chunk_remaining_bytes : sizeof(buf);
				read_bytes = fread(buf,1,to_read, f_in);
				rpos += read_bytes;
				chunk_remaining_bytes -= read_bytes;
				if(read_bytes != to_read){
					err = ferror(f_in);
					printf("Error reading FI2 data at %zu: \n", read_bytes);
					perror("");
					return EXIT_FAILURE;
				}
				if(fi2_head.scrambled == 1){
					descramble(&desc_state, buf, read_bytes);
				}
				written = fwrite(buf,1,read_bytes,f_out);
				if(written != read_bytes){
					err = ferror(f_out);
					printf("Error writing data to %s at %zu: \n", chunk_name, written );
					perror("");
					return EXIT_FAILURE;
				}
				if(chunk_remaining_bytes == 0){
					fclose(f_out);
					state = HTS_FI2HEAD;
				}
				break;
			}
			case HTS_SKIP:{
				return EXIT_FAILURE;
				break;
			}
		}
	}
	fclose(f_in);
	printf("Processed %u files.\n", files);

	return EXIT_SUCCESS;
}
