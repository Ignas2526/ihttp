#ifndef _INC_IHTTP

#define _INC_IHTTP

#define IHTTP_VERSION "1.1.007"
/*
Windows
_WIN32   Both 32 bit and 64 bit
_WIN64   64 bit only

Unix (Linux, *BSD, Mac OS X)
See this related question on some of the pitfalls of using this check.

unix
__unix
__unix__

Mac OS X
__APPLE__
__MACH__
Both are defined; checking for either should work.

Linux
http://www.faqs.org/docs/Linux-HOWTO/GCC-HOWTO.html

__linux__
FreeBSD

http://www.freebsd.org/doc/en/books/porters-handbook/porting-versions.html
__FreeBSD__
*/

#if (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32)
	#define WIN32
#elif (defined(__APPLE__) || defined(__MACH__)) && !defined(MAC_OS)
	#define MAC_OS
#elif defined(__unix__) || defined(__linux__) || defined(__FreeBSD__)
	#define LINUX
#endif

#ifdef WIN32
	#include <winsock2.h> //ws2_32.lib
	#include <ws2tcpip.h>
	#define WIN32_LEAN_AND_MEAN
	#include <windows.h>
	#define http_error() WSAGetLastError()
	typedef SOCKET ihttp_socket_t;

#else //some type of unix
  #define _XOPEN_SOURCE 500
	#include <unistd.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <sys/time.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <sys/select.h>
	#include <fcntl.h>
	
	typedef int ihttp_socket_t;
	
	#define closesocket close
	
	#define INVALID_SOCKET -1
	#define SOCKET_ERROR   -1

	
	#include <errno.h>
	#define http_error() errno
#endif

#include <stdlib.h> 
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <limits.h>

#ifdef LINUX
	#include <linux/limits.h>
	#include <sys/time.h>
#endif

#ifdef MAC_OS
	#include <mach-o/dyld.h>
#endif

#ifndef IHTTP_SOMAXCONN
	// The number of pending connections queue will hold for listen(2).
	// Some large value, it will be clipped to internal max.
	#define IHTTP_SOMAXCONN 65535
#endif

#define WORKER_THREAD_COUNT 8
#define SOCKET_QUEUE_SIZE 16

#define IHTTP_REQUEST_HEADERS_SIZE 4096
#define IHTTP_MAX_REQUEST_LINE_LENGTH 512
#define IHTTP_MAX_REQUEST_HEADER_COUNT 30
#define IHTTP_SEND_RECV_TIMEOUT_SEC 3

#define IHTTP_QUEUE_HIGH_LOAD 70

#define IHTTP_HLOAD_SEND_RECV_TIMEOUT_SEC 1


#define IHTTP_MAX_POST_SIZE 5*1024*1024 // 5MB
#define IHTTP_DEFAULT_DATA_SIZE 1024

//#define DEV

#define HTTP_ERR	0x00
#define HTTP_GET	0x01
#define HTTP_POST	0x02

#define HTTP_200	200
#define HTTP_400	400
#define HTTP_403	403
#define HTTP_404	404
#define HTTP_409	409
#define HTTP_500	500


struct http_name_value_pair {
  char* name; int name_len;
  char* value; int value_len;
};
struct http_thread_arg_url {
  char *value; int value_len;//Url value
};

struct HTTP_THREAD {
	int thread_id;
	int queue_load;
	unsigned long long int request_time;
	ihttp_socket_t socket;
  
	struct {
		// Holds data of the header
		char *data_header; // data buffer
		unsigned int data_header_i; // current place in the data
		unsigned int data_header_len; // recieved data length
		
		// Holds non-header data, such as post
		char *data; // data buffer
		unsigned int data_i; // current place in data
		unsigned int data_len; // recieved data length
		unsigned int data_alloc; // currently allocated
		
		int header_i;
		struct http_name_value_pair header[32];

		int cookie_len; int cookie_alloc;
		struct http_name_value_pair *cookie;
	} request;
	
	struct {
	  char *data;
		unsigned int data_i;
		unsigned int data_len;
		unsigned int data_alloc;
		
		int header_i;
		struct http_name_value_pair header[32];
	} response;

  char method;//HTTP Request Method
  char *uri; int uri_len;//HTTP Request url
  char *version; int version_len;//HTTP Request Version
  
  int post_len; int post_alloc;
  struct http_name_value_pair *post;
  
  int url_count;
  struct http_thread_arg_url url[32];
  
	int send_file;
  char *file_path; int file_path_len;
	
	int status_code;
	
};

struct IHTTP_SERVER {
	int program_terminate;

	char *root_path;
	int root_path_len;
	
	ihttp_socket_t socket_queue[SOCKET_QUEUE_SIZE];
	// socket_queue_start and socket_queue_count must be volatile
	volatile int socket_queue_start;
	volatile int socket_queue_count;

	struct ihttp_listener_st *listeners;
	int listeners_count;
	
};

struct ihttp_listener_st {
		// sockaddr_storage is a general type. It can hold both sockaddr_in and sockaddr_in6
		struct sockaddr_storage *addr;
		socklen_t addr_len;
		ihttp_socket_t socket;
};

struct IHTTP_DATA {
	struct IHTTP_SERVER *server;
	struct HTTP_THREAD *thread;

	pthread_mutex_t *server_mutex;
	int thread_id;
	void (*thread_function)(struct IHTTP_DATA *);
	void *arg;
};






struct IHTTP_DATA *ihttp_init(void (*thread_function)(struct IHTTP_DATA *));

// Initialize create socket and bind it: WSAStartup(), socket(), bind()
// Returns 0 on the error, r<0 on ihttp error and r>0 on WSA error.
int ihttp_add_listener(char *node, char *service, struct IHTTP_DATA *ihttp);

// Closes the socket that is used to listen for connections. Safe to be called multiple times on the same ihttp
void ihttp_close_connection(struct IHTTP_DATA *ihttp);

// Convers integer to char. return - buf > 0, no error, is the digit length.
char *ihttp_utoc(unsigned int digit, char *buf);

// Converts char to unsigned int. returns 0 on failiure and 1 on success.
int ihttp_ctou(unsigned int *out, char *c, int clen);

int ihttp_main (struct IHTTP_DATA *ihttp);

void *ihttp_thread(void *arg);


//HTTP response header and response status line manipulation functions
// Each word in the header name must start with capital letter, remaining letters should be lowercase, e.g. Connection, Accept-Charset.
void http_set_status(struct HTTP_THREAD *http, char *value, int value_len);//set status line
void http_add_header(struct HTTP_THREAD *http, char *name, int name_len, char *value, int value_len);//add header without replacing, can be useful to add multiple headers with the same name
void http_set_header(struct HTTP_THREAD *http, char *name, int name_len, char *value, int value_len);//add new or replace existing header
void http_rem_header(struct HTTP_THREAD *http, char *name, int name_len);//remove header


void http_sig_handle(int signal);

#endif