#include "ihttp.h"

//pthread_mutex_t http_server_mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ihttp_added_cond  = PTHREAD_COND_INITIALIZER;
pthread_cond_t ihttp_removed_cond  = PTHREAD_COND_INITIALIZER;
//pthread_mutex_t     ihttp_resume_mutex = PTHREAD_MUTEX_INITIALIZER;

// TODO IMPORTANT: send returns the numbe of bytes sent. Swith to bytes_recvd, bytes_sent
// TODO close() on UNIXes and  closesocket on windows

const char http_err400[] = "HTTP/1.1 400 Bad Request\r\nConnection: Close\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 11\r\n\r\nBad Request";
const int http_err400_len = sizeof(http_err400) - 1;

const char http_err403[] = "HTTP/1.1 403 Forbidden\r\nConnection: keep-alive\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 17\r\n\r\nAccess Forbidden!";
const int http_err403_len = sizeof(http_err403) - 1;

const char http_err404[] = "HTTP/1.1 404 Not Found\r\nConnection: keep-alive\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 15\r\n\r\nPage Not Found!";
const int http_err404_len = sizeof(http_err404) - 1;

const char http_err409[] = "HTTP/1.1 409 Conflict\r\nConnection: keep-alive\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 9\r\n\r\nConflict!";
const int http_err409_len = sizeof(http_err404) - 1;

const char http_err500[] = "HTTP/1.1 500 Internal Error\r\nConnection: keep-alive\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 13\r\n\r\nServer Error!";
const int http_err500_len = sizeof(http_err500) - 1;

struct IHTTP_DATA *ihttp_init(void (*thread_function)(struct IHTTP_DATA *))
{
	#ifdef WIN32
		WSADATA wsaData;
		// Request Winsock V 2.0
		if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) return -1; // Winsock dll not found
		if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) return -2; // Winsock version is lower than 2.0
	#endif

	struct IHTTP_DATA *ihttp;
	
	ihttp = malloc(sizeof(struct IHTTP_DATA) * WORKER_THREAD_COUNT);
	if (ihttp == NULL) return NULL;
	ihttp->server = malloc(sizeof(struct IHTTP_SERVER));
	if (ihttp->server == NULL) return NULL;
	
	ihttp->server_mutex = malloc(sizeof(pthread_mutex_t));//seems to crash without this
	if (ihttp->server_mutex == NULL) return NULL;
	pthread_mutex_init(ihttp->server_mutex, NULL);
	
	ihttp->server->socket_queue_start = 0;
	ihttp->server->socket_queue_count = 0;
	
	/*
		0.0.0.0 will listen on all available IP adresses
		127.0.0.1 will listen only localy
	 */
	//strcpy(ihttp->server->host, "0.0.0.0");
	//ihttp->server->port = 8080;
	
	/* exec path on other unixes
	 int mib[4];
	 mib[0] = CTL_KERN;
	 mib[1] = KERN_PROC;
	 mib[2] = KERN_PROC_PATHNAME;
	 mib[3] = -1;
	 char buf[1024];
	 size_t cb = sizeof(buf);
	 sysctl(mib, 4, buf, &cb, NULL, 0);
	 */
	//getcwd(ihttp->server->root_path,128);//TODO: handle return
	ihttp->server->root_path = malloc(256);
#if defined(WIN32)
	ihttp->server->root_path_len = GetModuleFileName(NULL, ihttp->server->root_path, 256);
	if (!ihttp->server->root_path_len) return NULL;
	
	int i;
	for (i = ihttp->server->root_path_len; i > 0; i--) {if (ihttp->server->root_path[i] == '\\') break;}
	ihttp->server->root_path_len = i + 1;
#elif defined(MAC_OS)
	char *root_path_tmp = malloc(256); uint32_t root_path_tmp_len = 256;
	if (root_path_tmp == NULL) return NULL;
	
	if (_NSGetExecutablePath(root_path_tmp, &root_path_tmp_len) != 0) {free(root_path_tmp); return NULL;}
	ihttp->server->root_path_len = strlen(root_path_tmp);
	
	int i;
	for (i = ihttp->server->root_path_len; i > 0; i--) { if (root_path_tmp[i] == '/') break;}
	ihttp->server->root_path_len = i + 1;
	
	if (ihttp->server->root_path_len >= (256 - 1)) {free(root_path_tmp); return NULL;} // prevent overflow
	root_path_tmp[ihttp->server->root_path_len] = 0;
	
	if (!realpath(root_path_tmp, ihttp->server->root_path)) {free(root_path_tmp); return NULL;}
	free(root_path_tmp);
	
	ihttp->server->root_path_len = strlen(ihttp->server->root_path);
	if (ihttp->server->root_path_len >= (256 - 2)) return NULL; // prevent overflow
	
	ihttp->server->root_path[ihttp->server->root_path_len] = '/';
	ihttp->server->root_path[ihttp->server->root_path_len + 1] = 0;
	ihttp->server->root_path_len += 1;
#elif defined(LINUX)
	// TODO: ADD SUPPORT FOR char dest[PATH_MAX];
	char path[PATH_MAX];
	pid_t pid = getpid();
	sprintf(path, "/proc/%d/exe", pid);
	int len = readlink(path, ihttp->server->root_path, 256 - 2);
	if(len == -1)
		perror("readlink");
	
	int i;
	for (i = len; i > 0; i--) { if (ihttp->server->root_path[i] == '/') break;}
	ihttp->server->root_path_len = i + 1;
#endif
	
	ihttp->server->listeners = NULL;
	ihttp->server->listeners_count = 0;
	//printf("PATH: (%d) %.*s\n", ihttp->server->root_path_len, ihttp->server->root_path_len, ihttp->server->root_path);
	
	ihttp->thread = malloc(sizeof(struct HTTP_THREAD) * WORKER_THREAD_COUNT);
	
	// Initialize threads
	for (int i = 0; i < WORKER_THREAD_COUNT; i++) {
		ihttp->thread[i].thread_id = i;
		ihttp->thread[i].socket = INVALID_SOCKET;
		ihttp->thread[i].request.data_header = malloc(IHTTP_REQUEST_HEADERS_SIZE);
		if (ihttp->thread[i].request.data_header == NULL) {puts("Error, malloc()"); return NULL;}
		
		ihttp->thread[i].request.data = malloc(IHTTP_DEFAULT_DATA_SIZE);
		if (ihttp->thread[i].request.data == NULL) {puts("Error, malloc()"); return NULL;}
		ihttp->thread[i].request.data_alloc = IHTTP_DEFAULT_DATA_SIZE;
		
		ihttp->thread[i].post = malloc(sizeof(struct http_name_value_pair) * 16);
		if (ihttp->thread[i].post == NULL) {puts("Error, malloc()"); return NULL;}
		ihttp->thread[i].post_len = 0;
		ihttp->thread[i].post_alloc = 16;
		
		ihttp->thread[i].request.cookie = malloc(sizeof(struct http_name_value_pair) * 8);
		if (ihttp->thread[i].request.cookie == NULL) {puts("Error, malloc()"); return NULL;}
		ihttp->thread[i].request.cookie_len = 0;
		ihttp->thread[i].request.cookie_alloc = 8;
		
		ihttp->thread[i].response.data = malloc(4096);
		if (ihttp->thread[i].response.data == NULL) {puts("Error, malloc()"); return NULL;}
		ihttp->thread[i].response.data_alloc = 4096;
		
		for (int j = 0; j < 32; j++) {
			ihttp->thread[i].response.header[j].name = ihttp->thread[i].response.header[j].value = NULL;
			ihttp->thread[i].response.header[j].name_len = ihttp->thread[i].response.header[j].value_len = 0;
		}
		
		ihttp->thread[i].file_path = malloc(384);
		if (ihttp->thread[i].file_path == NULL) {puts("Error, malloc()"); return NULL;}
		
		memcpy(ihttp->thread[i].file_path, ihttp->server->root_path, ihttp->server->root_path_len);
		ihttp->thread[i].send_file=1;
	}
	
	ihttp->thread_id = 0;
	ihttp->thread_function = thread_function;
	for (int i = 1; i < WORKER_THREAD_COUNT; i++) {//Fill data
		ihttp[i].server = ihttp->server;
		ihttp[i].thread = &ihttp->thread[i];
		ihttp[i].server_mutex = ihttp->server_mutex;
		ihttp[i].thread_id = i;
		ihttp[i].thread_function = thread_function;
	}
	return ihttp;
}

char *ihttp_utoc(unsigned int digit, char *buf)
{
	unsigned int divisor = 1;
	char *out;
	out = buf;
	while ((digit / divisor) > 9) {divisor *= 10;}
	do {*out++ = 48 + ((digit / divisor) % 10); divisor /= 10;} while(divisor);
	return out;
}

int ihttp_ctou(unsigned int *out, char *c, int clen)
{
	int dm=0;unsigned int t=UINT_MAX,t2=1;int i,i2,l=-1,t3;
	
	do{t/=10;dm++;}while(t);/*find number of digits in the MAX*/
	i=clen-1;
	/*overflow,underflow test*/
	if(dm<clen||!clen){/*if number has no digits, or has more digits than the MAX*/
		return 0;
	}else if(dm==clen){/*if number has as much digits as the MAX, do thorough validation*/
		i2=0;
		t2 *= pow(10,clen-1);
		t=UINT_MAX;
		do{t3=(t/t2)%10-(c[i2]-48);if(t3>0)break;if(t3<0)return 0;t2/=10;i2++;}while(i2<clen);
		t2=1;
	}
	*out=0;
	do{t3=(c[i]-48);if(t3<0||t3>9) return 0; *out+=t3*t2;t2*=10;i--;}while(i>l);
	return 1;
}

void ihttp_close_connection(struct IHTTP_DATA *ihttp)
{
	//TODO
	/*
	if (ihttp->server->server_socket != INVALID_SOCKET) {
		for (int thid = 0; thid < WORKER_THREAD_COUNT; thid++) {
			if (ihttp->thread[thid].socket != INVALID_SOCKET) {
				closesocket(ihttp->thread[thid].socket);
			}
		}
		closesocket(ihttp->server->server_socket);
#ifdef WIN32
		WSACleanup();
#endif
		ihttp->server->server_socket = INVALID_SOCKET;
	}*/
}

/*
	Function that does URL decoding a.k.a. percent decoding
	with suppot for decoding literal + into space.
	encoded: a%20b+a
	decoded: a b a
 */
void ihttp_decode(char *data, int *len)
{
	int i = 0, j = 0;
	
	while (j < *len) {
		// Literal + should be decoded into space https://www.w3.org/TR/html4/interact/forms.html#h-17.13.4.1
		if (data[j] == '+') {data[i++] = ' '; j++; continue;}
		if (data[j] != '%') {data[i++] = data[j++]; continue;}
		
		char chr = 0;
		
		// There must be at least 2 characters after %
		if ((*len - j) < 3) {
			data[i] = '%';
			data[++i] = data[++j];
			return;
		}
		
		j++;
		if (data[j] >= '0' && data[j] <= '9') chr = data[j] - '0';
		else if (data[j] >= 'A' && data[j] <= 'F') chr = data[j] - 'A' + 10;
		else if (data[j] >= 'a' && data[j] <= 'f') chr = data[j] - 'a' + 10;
		else {j--; goto SKIP;}
		chr <<= 4;
		
		j++;
		if (data[j] >= '0' && data[j] <= '9') chr += data[j] - '0';
		else if (data[j] >= 'A' && data[j] <= 'F') chr += data[j] - 'A' + 10;
		else if (data[j] >= 'a' && data[j] <= 'f') chr += data[j] - 'a' + 10;
		else {j -= 2; goto SKIP;}
		
		data[i] = chr;
		
		++j;
		++i;
		continue;
		
	SKIP:
		data[i] = '%';
		data[++i] = data[++j];
		data[++i] = data[++j];
		continue;
	}
	
	*len = i;
	return;
}

/*
	Returns 1 if character is reserved URI character.
	Based on RFC 3986 section-2.2
	
	reserved = gen-delims / sub-delims
	gen-delims = ":" / "/" / "?" / "#" / "[" / "]" / "@"
	sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
 */
int ihttp_is_reseved_uri_char(char chr)
{
	if (chr == ':' || chr == '/' || chr == '?' || chr == '#' || chr == '[' || chr == ']' || chr == '@' ||
		chr == '!' || chr == '$' || chr == '&' || chr == '\'' || chr == '(' || chr == ')' || chr == '*' ||
		chr == '+' || chr == ',' || chr == ';' || chr == '=')
		return 1;
	else
		return 0;
}

/*
	Function that parses the query string in the URL and
	the POST of type application/x-www-form-urlencoded.
 
	The HTTP spec doesn't specify at all how the key-value pairs should be parsed
 
	IHTTP Spec:
 * The order of query stings is preserved
 * special characters out of the order are ignored and discarded
 a=b& is key 'a'; val 'b'
 a=b&= is key 'a'; val 'b'
 a=&== is key 'a'; val ''
 * keys without values will be empty
 a= is key 'a'; val ''
 a is key 'a'; val '';
	Flow:
	1. skip reserved chars
	2. First non-reserved char start matching key value until first =
	3. start matching value until &
	4. go to #1
 */
// TODO: merge same key values
int ihttp_parse_query_string(char *data, int data_len, struct http_name_value_pair **name_value_pair, int *struct_len, int *struct_alloc)
{
	int i = 0, start_pos = 0;
	while (i < data_len) {
		// Skip reserved chars
		while (i < data_len && ihttp_is_reseved_uri_char(data[i])) i++;
		
		// If we're at the end of the data, we're done.
		if (i >= data_len) break;
		
		// If we ran out of space in post field, allocate more
		if (*struct_len >= *struct_alloc) {
			*struct_alloc += 16;
			struct http_name_value_pair *tmp_name_value_pair;
			tmp_name_value_pair = realloc(*name_value_pair, *struct_alloc * sizeof(struct http_name_value_pair));
			
			if (tmp_name_value_pair != NULL) {
				*name_value_pair = tmp_name_value_pair;
			} else {
				puts("Error, realloc()");
				return 0;
			}
		}
		
		// Start matching key (name)
		start_pos = i;
		(*name_value_pair)[*struct_len].name = &data[start_pos];
		
		// Keep matching name untill first = or &
		while (i < data_len && data[i] != '=' && data[i] != '&') i++;
		
		(*name_value_pair)[*struct_len].name_len = i - start_pos;
		
		ihttp_decode((*name_value_pair)[*struct_len].name, &(*name_value_pair)[*struct_len].name_len);
		
		(*name_value_pair)[*struct_len].value = NULL;
		(*name_value_pair)[*struct_len].value_len = 0;
		
		// Case when name is followed by & and there's no value
		if (data[i] == '&') {
			(*struct_len)++;
			continue;
		}
		
		// If we're at the end of the data, we're done.
		if (++i >= data_len) {
			(*struct_len)++;
			break;
		}
		
		// Start matching value
		start_pos = i;
		(*name_value_pair)[*struct_len].value = &data[start_pos];
		
		// Keep matching name untill first &
		while (i < data_len && data[i] != '&') i++;
		
		(*name_value_pair)[*struct_len].value_len = i - start_pos;
		
		ihttp_decode((*name_value_pair)[*struct_len].value, &(*name_value_pair)[*struct_len].value_len);
		
		(*struct_len)++;
		continue;
	}
	return 1;
}

/*
	Ensures that response data is big enough to hold the required length
 */
int ihttp_require_response_length(int length, struct IHTTP_DATA *ihttp)
{
	int new_length = ihttp->thread->response.data_i + length;
	if (new_length > ihttp->thread->response.data_alloc) {
		char *tmp_data = realloc(ihttp->thread->response.data, new_length);
		if (tmp_data == NULL) {
			return 0;
		}
		ihttp->thread->response.data = tmp_data;
		ihttp->thread->response.data_alloc = new_length;
	}
	return 1;
}

/*
	Recieves data from the socket.
	Will recieve at least 1 byte, at most buffer_len bytes.
*/
int ihttp_recieve(ihttp_socket_t socket, char *buffer, int buffer_len, int bytes_to_recieve)
{
	return recv(socket, buffer, buffer_len, 0);
	
}
/*
	Recieves data from the socket.
	Will recieve exactly buffer_len bytes.
*/
int ihttp_recieve_all(ihttp_socket_t socket, char *buffer, int buffer_len)
{
	// If recv returns 0 either the client closed the connection or there's no data
	int bytes_recvd_total = 0, bytes_recvd = 0;
	while (bytes_recvd_total < buffer_len) {
		if ((bytes_recvd = recv(socket, &buffer[bytes_recvd_total], (buffer_len - bytes_recvd_total), 0)) <= 0) return bytes_recvd;
		bytes_recvd_total += bytes_recvd;
	}
	return bytes_recvd_total;
}

/*
	Sends data to the socket.
	Will send buffer_len bytes of data.
*/
int ihttp_send(ihttp_socket_t socket, const char *buffer, int buffer_len)
{
	// If send returns 0 either the client closed the connection or there's no data
	int bytes_sent_total = 0, bytes_sent = 0;
	while (bytes_sent_total < buffer_len) {
		if ((bytes_sent = send(socket, &buffer[bytes_sent_total], buffer_len, 0)) <= 0) return bytes_sent;
		bytes_sent_total += bytes_sent;
	}
	return bytes_sent_total;
}


int ihttp_add_listener(char *node, char *service, struct IHTTP_DATA *ihttp)
{
	struct addrinfo hints, *res = NULL, *ai;

	memset(&hints, 0, sizeof(hints));
	// use AF_INET, AF_INET6 to force IPv4 or IPv6
	hints.ai_family = AF_UNSPEC; // use IPv4 or IPv6, whichever
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;

	if (getaddrinfo(node, service, &hints, &res) != 0) {
		puts("failed to resolve the listening address");
		return 1;
	} else if (res == NULL) {
		puts("failed to resolve the listening address: getaddrinfo returned an empty list");
		return 1;
	}
	/* listen to the returned addresses */
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		//TODO: check if we're listening to this already
		//TODO: freeaddrinfo
		// Add addr to the listeners list
		ihttp->server->listeners_count++;
		
		ihttp->server->listeners = realloc(ihttp->server->listeners, ihttp->server->listeners_count * sizeof(struct ihttp_listener_st));
		if (ihttp->server->listeners == NULL) {
			//freeaddrinfo(res);
			return 1;
		}

		struct ihttp_listener_st *listener = &ihttp->server->listeners[ihttp->server->listeners_count - 1];

		listener->addr = malloc(sizeof(struct sockaddr_storage));
		if (listener->addr == NULL) {
			//freeaddrinfo(res);
			return 1;
		}
		
		memcpy(listener->addr, ai->ai_addr, ai->ai_addrlen);

		listener->addr_len = ai->ai_addrlen;

#ifdef SOCK_CLOEXEC
		listener->socket = socket(ai->ai_addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
#else
		listener->socket = socket(ai->ai_addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
#endif

		if (listener->socket == INVALID_SOCKET) {
			//freeaddrinfo(res);
			return http_error();
		}

		if (fcntl(listener->socket, F_SETFD, FD_CLOEXEC) == -1) {
			return http_error();
		}

		{
			int flag = 1;
			if (setsockopt(listener->socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) != 0)
				//freeaddrinfo(res);
				return http_error();
    }

		// Attempt to some socket flags that should improve performance.
		#ifdef TCP_DEFER_ACCEPT
		{
			int flag = 1;
			if (setsockopt(listener->socket, IPPROTO_TCP, TCP_DEFER_ACCEPT, &flag, sizeof(flag)) != 0)
				//freeaddrinfo(res);
				return http_error();
		}
		#endif

		#ifdef TCP_FASTOPEN
		{
			int flag;
			#ifdef __APPLE__
				/* In OS X, the option value for TCP_FASTOPEN must be 1 if is's enabled */
				flag = 1;
			#else
				flag = 4096;
			#endif
			if (setsockopt(listener->socket, IPPROTO_TCP, TCP_FASTOPEN, (const void *)&flag, sizeof(flag)) != 0)
				//freeaddrinfo(res);
				return http_error();
		}
		#endif

		if (bind(listener->socket, (struct sockaddr *)listener->addr, listener->addr_len) != 0) {
			close(listener->socket);
			//goto SERVER_ERROR;
    }
	}
	//freeaddrinfo(res);
	return 0;
	 
//SERVER_ERROR:
	//ihttp_close_connection(ihttp);
	//freeaddrinfo(res);
	//return http_error();
}

const char *get_ip_str(const struct sockaddr *sa, char *s, socklen_t len)
{
	switch(sa->sa_family) {
		case AF_INET:
			return inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s, len);
		case AF_INET6:
			return inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), s, len);
		default:
			return NULL;
	}
}
uint16_t get_port_int(const struct sockaddr *sa)
{
	switch(sa->sa_family) {
		case AF_INET:
			return ntohs(((struct sockaddr_in *)sa)->sin_port);
		case AF_INET6:
			return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
		default:
			return 0;
	}
}


int ihttp_main(struct IHTTP_DATA *ihttp)
{
	/*
		Initialize WSA – WSAStartup().
		Create a socket – socket().
		Bind the socket – bind().
		Listen on the socket – listen().
		Accept a connection – accept(), connect().
		Send and receive data – recv(), send(), recvfrom(), sendto().
		Disconnect – close()/closesocket().
	 */
	struct IHTTP_SERVER *server = ihttp->server;

	if (server->listeners_count == 0) {
		puts("No listeners");
		return 0;
	}
	pthread_t threads[WORKER_THREAD_COUNT];
	
	pthread_attr_t http_pth_attr; // thread attribute
	pthread_attr_init(&http_pth_attr);
	pthread_attr_setdetachstate(&http_pth_attr, PTHREAD_CREATE_DETACHED);
	
	for (int i = 0; i < WORKER_THREAD_COUNT; i++) {
		int rc = pthread_create(&threads[i], &http_pth_attr, ihttp_thread, (void *)&ihttp[i]);
		if (rc) {printf("Error, pthread_create(): %d\n", rc); break;}
	}
	
	// TODO: add termination support, move socket_set to ihttp to allow for listener removal
	//server->program_terminate = 0;
	
	fd_set socket_set, socket_set_tmp;
	FD_ZERO(&socket_set);
	FD_ZERO(&socket_set_tmp);

	ihttp_socket_t max_socket_id = server->listeners[0].socket;
	for (int i = 0; i < server->listeners_count; i++) {
		struct ihttp_listener_st *listener = &server->listeners[i];

		// Start listening for incoming connections
		if (listen(listener->socket, IHTTP_SOMAXCONN) != 0) {
			printf("Error, listen(): %u\n", http_error()); goto SERVER_ERROR;
		}
		FD_SET(listener->socket, &socket_set);

		if (listener->socket > max_socket_id) max_socket_id = listener->socket;
	}

	while (1) {
		socket_set_tmp = socket_set;
		if (select(max_socket_id + 1, &socket_set_tmp, NULL, NULL, NULL) <= 0) {
			// -1 select() error, 0 timeout error, should not happen in this config
			goto SERVER_ERROR;
		}

		for (int i = 0; i < server->listeners_count; i++) {
			struct ihttp_listener_st *listener = &server->listeners[i];
			if (!FD_ISSET(listener->socket, &socket_set_tmp)) continue;
			
			struct sockaddr_storage addr; socklen_t addr_len;
			ihttp_socket_t client_socket = accept(listener->socket, (struct sockaddr *)&addr, &addr_len);
			if (client_socket == INVALID_SOCKET) continue;
			if (fcntl(client_socket, F_SETFD, FD_CLOEXEC) == -1) continue;
			
			char address[INET6_ADDRSTRLEN]; //INET6_ADDRSTRLEN will always be larger than INET_ADDRSTRLEN
			int port;

			if ((get_ip_str((struct sockaddr *)&addr, (char *)&address, INET6_ADDRSTRLEN)) == NULL) {
				close(client_socket);
				puts("error get_ip_str");
				continue;
			}
			if ((port = get_port_int((struct sockaddr *)&addr)) == 0) {
				close(client_socket);
				puts("error port");
				continue;
			}

			//inform user of socket number - used in send and receive commands
			printf("New connection , socket fd is %d , ip is : %s , port : %d \n", client_socket, address, port);
        
			//if (server->program_terminate) break;

			// If socket queue is full, wait till there's a free spot
			while (server->socket_queue_count == SOCKET_QUEUE_SIZE) {
				pthread_cond_wait(&ihttp_removed_cond, ihttp->server_mutex);
			}
			int i = (server->socket_queue_start + server->socket_queue_count) % SOCKET_QUEUE_SIZE;
			server->socket_queue[i] = client_socket;

			server->socket_queue_count++;

			pthread_mutex_unlock(ihttp->server_mutex);
	
			// The pthread_cond_signal should come after pthread_mutex_unlock, although both ways work.
			pthread_cond_signal(&ihttp_added_cond);
		}
	}
	
SERVER_ERROR:
	ihttp_close_connection(ihttp);
	return 0;
}

void *ihttp_thread(void *arg)
{
	struct IHTTP_DATA *ihttp = arg;
	
IHTTP_THREAD_START:
	pthread_mutex_lock(ihttp->server_mutex);
	// If socket queue is empty, wait till there's something in it
	while (ihttp->server->socket_queue_count == 0) {
		pthread_cond_wait(&ihttp_added_cond, ihttp->server_mutex);
	}

	ihttp->thread->queue_load = ihttp->server->socket_queue_count * 100 / SOCKET_QUEUE_SIZE;

	ihttp->server->socket_queue_count--;
	ihttp->thread->socket = ihttp->server->socket_queue[ihttp->server->socket_queue_start];
	ihttp->server->socket_queue_start = (ihttp->server->socket_queue_start + 1) % SOCKET_QUEUE_SIZE;

	pthread_mutex_unlock(ihttp->server_mutex);
	
	// The pthread_cond_signal should come after pthread_mutex_unlock, although both ways work.
	pthread_cond_signal(&ihttp_removed_cond);
	
	struct timeval tp;
	gettimeofday(&tp, NULL);
	ihttp->thread->request_time = (unsigned long long)tp.tv_sec * 1000 + (unsigned long long)tp.tv_usec / 1000;

	// Disable SIGPIPE signal emission, which is emitted when we encounter EPIPE error in send()
#if 0
	{
		int set = 1;
		setsockopt(ihttp->thread->socket, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
	}
#endif
	
	// Set socket condition that at least a single byte must arrive in a 3 second period
	{
		int timeout_sec = IHTTP_SEND_RECV_TIMEOUT_SEC;
		if (ihttp->thread->queue_load > IHTTP_QUEUE_HIGH_LOAD) {
			timeout_sec = IHTTP_HLOAD_SEND_RECV_TIMEOUT_SEC;
		}

		#ifdef WIN32
			DWORD timeout = timeout_sec * 1000;
		#else
			const struct timeval timeout = {.tv_sec = timeout_sec, .tv_usec = 0};
		#endif
		setsockopt(ihttp->thread->socket, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout, sizeof(timeout));

		setsockopt(ihttp->thread->socket, SOL_SOCKET, SO_SNDTIMEO, (void *)&timeout, sizeof(timeout));
	}
	ihttp->thread->request.data_header_len = 0;
	
IHTTP_THREAD_HTTP_CONTINUE:

	ihttp->thread->request.data_header_i = 0;
	
	ihttp->thread->request.data_i = 0;
	ihttp->thread->request.data_len = 0;
	
	ihttp->thread->method = HTTP_ERR;
	ihttp->thread->uri_len = 0;
	ihttp->thread->version_len = 0;
	
	ihttp->thread->request.header_i = 0;
	memset(ihttp->thread->request.header, 0, sizeof(struct http_name_value_pair) * IHTTP_MAX_REQUEST_HEADER_COUNT);
	
	ihttp->thread->post_len = 0;
	memset(ihttp->thread->post, 0, sizeof(struct http_name_value_pair) * 16);
	
	ihttp->thread->request.cookie_len = 0;
	memset(ihttp->thread->request.cookie, 0, sizeof(struct http_name_value_pair) * 8);
	
	ihttp->thread->url_count = 0;
	memset(ihttp->thread->url, 0, sizeof(struct http_thread_arg_url) * 32);
	
	ihttp->thread->file_path_len = ihttp->server->root_path_len;
	
	ihttp->thread->response.header_i = 0;
	for (int j = 0; j < 32; j++) {
		ihttp->thread->response.header[j].name_len = ihttp->thread->response.header[j].value_len = 0;
	}
	
	ihttp->thread->response.data_i = 0;
	ihttp->thread->response.data_len = 0;
	
	ihttp->thread->status_code = HTTP_200;
	
	// Find all header field names, its values and where HTTP header ends
	// Recieve HTTP request line (first line)
	{
		int state = 1, i = 0;
		for (;;) {
			// We expect for the HTTP request line (first line) to be no longer than IHTTP_MAX_REQUEST_LINE_LENGTH
			if (ihttp->thread->request.data_header_len > IHTTP_MAX_REQUEST_LINE_LENGTH) goto HTTP_THREAD_ERR;
			int bytes_left = IHTTP_MAX_REQUEST_LINE_LENGTH - ihttp->thread->request.data_header_len;
			int bytes_recvd = recv(ihttp->thread->socket, &ihttp->thread->request.data_header[ihttp->thread->request.data_header_len], bytes_left, 0);
			
			// if recv retuned 0 or -1, there was an error or no data
			if (bytes_recvd <= 0) goto IHTTP_THREAD_RESET_CLOSE;
			ihttp->thread->request.data_header_len += bytes_recvd;
			while (i < ihttp->thread->request.data_header_len) {
				// Find the method, get to the end of the first space
				if (state == 1 && ihttp->thread->request.data_header[i] == ' ') {
					if (i == 4 && memcmp(ihttp->thread->request.data_header, ((char[]){'P','O','S','T'}), 4) == 0) {
						ihttp->thread->method = HTTP_POST;
					} else if (i == 3 && memcmp(ihttp->thread->request.data_header, ((char[]){'G','E','T'}), 3) == 0) {
						ihttp->thread->method = HTTP_GET;
					}
					i++;
					ihttp->thread->request.data_header_i = i;
					state = 2;
					
				// Find the URI
				} else if (state == 2 && ihttp->thread->request.data_header[i] == ' ') {
					// get rid of the first / in url
					if (ihttp->thread->request.data_header[ihttp->thread->request.data_header_i] == '/') ihttp->thread->request.data_header_i++;
					ihttp->thread->uri = &ihttp->thread->request.data_header[ihttp->thread->request.data_header_i];
					ihttp->thread->uri_len = i - ihttp->thread->request.data_header_i;
					i++;
					ihttp->thread->request.data_header_i = i;
					state = 3;
					
				// Find the HTTP version
				} else if (ihttp->thread->request.data_header[i] == '\r') {
					if ((i + 1) < ihttp->thread->request.data_header_len && ihttp->thread->request.data_header[i + 1] == '\n') {
						ihttp->thread->version = &ihttp->thread->request.data_header[ihttp->thread->request.data_header_i];
						ihttp->thread->version_len = i - ihttp->thread->request.data_header_i;
						i += 2;
						ihttp->thread->request.data_header_i = i;
						goto IHTTP_THREAD_REQUEST_LINE_DONE;
					} else {
						break;
					}
				} else {
					i++;
				}
			}
		}
		
	IHTTP_THREAD_REQUEST_LINE_DONE:
		if (ihttp->thread->method == HTTP_ERR || ihttp->thread->version_len == 0) goto HTTP_THREAD_ERR; //Top header must be full

		// TODO: Acording to the standard, header names are case insensitive. Lowercase header names.
		// TODO: Support header spec fully! https://www.jmarshall.com/easy/http/#headerlines
		// TODO: more thorough header checking: check for colon (name: something OK; name : something NOT OK)
		/* parsing name, but do not discard SP before colon, see
		 * http://www.mozilla.org/security/announce/2006/mfsa2006-33.html */
		for (;;) { // Recieve remaining header fields
			while (i < ihttp->thread->request.data_header_len) {
				if (ihttp->thread->request.header_i == IHTTP_MAX_REQUEST_HEADER_COUNT) {puts("max 32 headers");goto HTTP_THREAD_ERR;} // only up to 32 headers
				if (ihttp->thread->request.header[ihttp->thread->request.header_i].name_len == 0) { // first, find header name
					if (ihttp->thread->request.data_header[i] == ' ') {
						ihttp->thread->request.header[ihttp->thread->request.header_i].name = &ihttp->thread->request.data_header[ihttp->thread->request.data_header_i];
						ihttp->thread->request.header[ihttp->thread->request.header_i].name_len = i - ihttp->thread->request.data_header_i - 1;//-1 to exclude :
						i++;
						ihttp->thread->request.data_header_i = i;
					} else if (ihttp->thread->request.data_header[i] == '\r') { // simplified \r\n\r\n detection, \r\n\r
						ihttp->thread->request.data_header_i += 2;
						
						goto IHTTP_THREAD_REQUEST_HEADERS_DONE;
					} else {
						i++;
					}
				} else {
					if (ihttp->thread->request.data_header[i] == '\r') {
						if ((i + 1) < ihttp->thread->request.data_header_len && ihttp->thread->request.data_header[i + 1] == '\n') {
							ihttp->thread->request.header[ihttp->thread->request.header_i].value = &ihttp->thread->request.data_header[ihttp->thread->request.data_header_i];
							ihttp->thread->request.header[ihttp->thread->request.header_i].value_len = i - ihttp->thread->request.data_header_i;
							ihttp->thread->request.header_i++;
							i += 2;
							ihttp->thread->request.data_header_i = i;
						} else {
							break;
						}
					} else {
						i++;
					}
				}
			}
			
			// TODO: if header is too large 413 Entity Too Large
			if (ihttp->thread->request.data_header_len > IHTTP_REQUEST_HEADERS_SIZE) goto HTTP_THREAD_ERR;
			int bytes_left = IHTTP_REQUEST_HEADERS_SIZE - ihttp->thread->request.data_header_len;
			int bytes_recvd = recv(ihttp->thread->socket, &ihttp->thread->request.data_header[ihttp->thread->request.data_header_len], bytes_left, 0);
			
			// If we get here, we need more data. if recv is less than 1 it means that it failed
			if (bytes_recvd <= 0) goto IHTTP_THREAD_RESET_CLOSE;
			ihttp->thread->request.data_header_len += bytes_recvd;
		}
	}
IHTTP_THREAD_REQUEST_HEADERS_DONE:
	
	// Process uri
	// TODO: parse quey string. Accoding to spec it starts after first ? and ends before # or end of sting ihttp_parse_query_string
	{
		int len = 0, len2 = 0;
		ihttp->thread->url[ihttp->thread->url_count].value = ihttp->thread->uri;
		while (len < ihttp->thread->uri_len) {
			if (ihttp->thread->uri[len] == '/') {
				ihttp->thread->url[ihttp->thread->url_count].value_len = len2;
				ihttp->thread->url_count++;
				if (ihttp->thread->url_count == 32) goto HTTP_THREAD_ERR;//only up to 32 urls
				len++; len2 = 0;
				ihttp->thread->url[ihttp->thread->url_count].value = &ihttp->thread->uri[len];
			} else {
				len2++;
				len++;
			}
		}
		ihttp->thread->url[ihttp->thread->url_count].value_len = len2; ihttp->thread->url_count++;
	}
	
	/* Parse POST data */
	if (ihttp->thread->method == HTTP_POST) {
		//Find Content-Length header
		unsigned int post_len = 0;
		for (int i = 0; i < ihttp->thread->request.header_i; i++) {
			if (ihttp->thread->request.header[i].name_len == 14 && memcmp(ihttp->thread->request.header[i].name, ((char[]){'C','o','n','t','e','n','t','-','L','e','n','g','t','h'}), 14) == 0) {
				ihttp_ctou(&post_len, ihttp->thread->request.header[i].value, ihttp->thread->request.header[i].value_len);
				break;
			}
		}
		// According to the spec, "Content-Length: 0" is valid.
		// If equals to 0, then there's no post
		if (post_len) {
			if (post_len > IHTTP_MAX_POST_SIZE) goto HTTP_THREAD_ERR;
			
			// Reallocate data if there's not enough
			if (post_len > ihttp->thread->request.data_alloc) {
				char *tmp_data = realloc(ihttp->thread->request.data, post_len);
				if (tmp_data == NULL) {puts("Error, realloc()"); goto HTTP_THREAD_ERR;}
				ihttp->thread->request.data = tmp_data;
				ihttp->thread->request.data_alloc = post_len;
			}
			
			// Copy, if any, POST data from the header data
			int extra_post_data_len = ihttp->thread->request.data_header_len - ihttp->thread->request.data_header_i;
			if (extra_post_data_len <= post_len) {
				memcpy(ihttp->thread->request.data, &ihttp->thread->request.data_header[ihttp->thread->request.data_header_i], extra_post_data_len);
				ihttp->thread->request.data_header_i += extra_post_data_len;
				ihttp->thread->request.data_len = extra_post_data_len;
				
				// Handle case when (extra_post_data_len > post_len)
			} else {
				memcpy(ihttp->thread->request.data, &ihttp->thread->request.data_header[ihttp->thread->request.data_header_i], post_len);
				ihttp->thread->request.data_header_i = ihttp->thread->request.data_header_len;
				ihttp->thread->request.data_len = post_len;
			}
			
			
			// Recieve remaining post data if any (post size - current post length)
			int bytes_left = post_len - ihttp->thread->request.data_len;
			
			while (bytes_left > 0) {
				int bytes_recvd = recv(ihttp->thread->socket, &ihttp->thread->request.data[ihttp->thread->request.data_len], bytes_left, 0);
				if (bytes_recvd <= 0) {printf("Error, recv():%u\n", http_error()); goto IHTTP_THREAD_RESET_CLOSE;}
				ihttp->thread->request.data_len += bytes_recvd;
				bytes_left -= bytes_recvd;
			}
			
			if (ihttp_parse_query_string(&ihttp->thread->request.data[ihttp->thread->request.data_i],
										 ihttp->thread->request.data_len - ihttp->thread->request.data_i,
										 &ihttp->thread->post, &ihttp->thread->post_len, &ihttp->thread->post_alloc) == 0)
				goto HTTP_THREAD_ERR;
		}
	}
	
	/* Parse Cookie Header*/
	/* Based on rfc6265
		
		The OWS (optional whitespace) rule is used where zero or more linear whitespace characters MAY appear:
		OWS = *( [ obs-fold ] WSP )
	 ; "optional" whitespace
		obs-fold = CRLF
	 
	 
		cookie-header = "Cookie:" OWS cookie-string OWS
	 cookie-string = cookie-pair *( ";" SP cookie-pair )
	 cookie-pair       = cookie-name "=" cookie-value
	 */
	{
		//Find Cookie header
		for (int head_i = 0; head_i < ihttp->thread->request.header_i; head_i++) {
			if (ihttp->thread->request.header[head_i].name_len == 6 && memcmp(ihttp->thread->request.header[head_i].name, ((char[]){'C','o','o','k','i','e'}), 6) == 0) {
				// Parse Cookie header value
				// TODO: fix overflow. Maximim of 6 cookies possible
				int i = 0;
				while (1) {
					// Skip any space
					while (i < ihttp->thread->request.header[head_i].value_len && ihttp->thread->request.header[head_i].value[i] == ' ') i++;
					
					// Read Name
					ihttp->thread->request.cookie[ihttp->thread->request.cookie_len].name = &ihttp->thread->request.header[head_i].value[i];
					
					while (i < ihttp->thread->request.header[head_i].value_len && ihttp->thread->request.header[head_i].value[i] != '=') i++;
					
					ihttp->thread->request.cookie[ihttp->thread->request.cookie_len].name_len = &ihttp->thread->request.header[head_i].value[i] - ihttp->thread->request.cookie[ihttp->thread->request.cookie_len].name;
					
					// Cookie name can't be empty
					if (!ihttp->thread->request.cookie[ihttp->thread->request.cookie_len].name_len) goto HTTP_THREAD_ERR;
					
					if (++i >= ihttp->thread->request.header[head_i].value_len) break;
					
					// Read Value
					ihttp->thread->request.cookie[ihttp->thread->request.cookie_len].value = &ihttp->thread->request.header[head_i].value[i];
					
					while (i < ihttp->thread->request.header[head_i].value_len && ihttp->thread->request.header[head_i].value[i] != ';') i++;
					
					ihttp->thread->request.cookie[ihttp->thread->request.cookie_len].value_len = &ihttp->thread->request.header[head_i].value[i] - ihttp->thread->request.cookie[ihttp->thread->request.cookie_len].value;
					
					ihttp->thread->request.cookie_len++;
					if (++i >= ihttp->thread->request.header[head_i].value_len) break;
				}
			}
		}
	}
	
#ifdef DEV
	printf("Method    %d\n", (int)ihttp->thread->method);
	printf("uri (%d)   %.*s\n", ihttp->thread->uri_len,ihttp->thread->uri_len, ihttp->thread->uri);
	printf("HTTP_Version (%d)   %.*s\n", ihttp->thread->version_len, ihttp->thread->version_len, ihttp->thread->version);
	
	printf("header_i: %d.\n", ihttp->thread->request.header_i);
	for (int l2 = 0; l2 < ihttp->thread->request.header_i; l2++)
		printf("  #%d %.*s    %.*s\n", l2, ihttp->thread->request.header[l2].name_len, ihttp->thread->request.header[l2].name,
			   ihttp->thread->request.header[l2].value_len, ihttp->thread->request.header[l2].value);
	
	printf("url_count: %d.\n",ihttp->thread->url_count);
	for (int l2 = 0; l2 < ihttp->thread->url_count; l2++)
		printf("  #%d (%d) %.*s\n", l2, ihttp->thread->url[l2].value_len, ihttp->thread->url[l2].value_len, ihttp->thread->url[l2].value);
	
	printf("POST (len:%d  alloc:%d)\n", ihttp->thread->post_len, ihttp->thread->post_alloc);
	for (int l2 = 0; l2 < ihttp->thread->post_len; l2++)
		printf("  #%d (%d)%.*s    (%d)%.*s\n", l2, ihttp->thread->post[l2].name_len, ihttp->thread->post[l2].name_len,
			   ihttp->thread->post[l2].name, ihttp->thread->post[l2].value_len, ihttp->thread->post[l2].value_len, ihttp->thread->post[l2].value);
	
	printf("Cookie (len:%d  alloc:%d)\n", ihttp->thread->request.cookie_len, ihttp->thread->request.cookie_alloc);
	for (int l2 = 0; l2 < ihttp->thread->request.cookie_len; l2++)
		printf("  #%d (%d)%.*s    (%d)%.*s\n", l2, ihttp->thread->request.cookie[l2].name_len, ihttp->thread->request.cookie[l2].name_len,
			   ihttp->thread->request.cookie[l2].name, ihttp->thread->request.cookie[l2].value_len, ihttp->thread->request.cookie[l2].value_len, ihttp->thread->request.cookie[l2].value);
	printf("----------------------\n");
#endif
	
	
	/*Initialize response headers*/
	char *tmp_value = realloc(ihttp->thread->response.header[0].value, sizeof("HTTP/1.1 200 OK") - 1);
	if (tmp_value == NULL) goto HTTP_THREAD_ERR;
	ihttp->thread->response.header[0].value = tmp_value;
	ihttp->thread->response.header[0].value_len = sizeof("HTTP/1.1 200 OK") - 1;
	
	memcpy(ihttp->thread->response.header[0].value, ((char[]){'H','T','T','P','/','1','.','1',' ','2','0','0',' ','O','K'}), sizeof("HTTP/1.1 200 OK") - 1);
	
	ihttp_add_header(ihttp->thread, "Connection", sizeof("Connection") - 1, "keep-alive", sizeof("keep-alive") - 1);
	ihttp_add_header(ihttp->thread, "Content-Type", sizeof("Content-Type") - 1, "text/html; charset=utf-8", sizeof("text/html; charset=utf-8") - 1);
	
	ihttp->thread_function(ihttp);
	
	if (ihttp->thread->status_code == HTTP_200) {
		char *http_header = NULL;
		http_header = malloc(256);
		if (http_header == NULL) goto HTTP_THREAD_ERR;
		
		int http_header_alloc = 256; int http_header_i = 0;
		
		for (int i = 0; i < 32; i++) {
			if (ihttp->thread->response.header[i].name_len == 0 && ihttp->thread->response.header[i].value_len == 0) continue;
			// Only allocate more memory if there's not enough (tmp_buff_len+name_len+" : "+value_len+\r\n)>allocated
			if ((http_header_i + (ihttp->thread->response.header[i].name_len + 2 + ihttp->thread->response.header[i].value_len + 2)) > http_header_alloc) {
				http_header_alloc += 256;
				char *tmp_http_header;
				tmp_http_header = realloc(http_header, http_header_alloc);
				if (tmp_http_header == NULL) goto HTTP_THREAD_ERR;
				http_header = tmp_http_header;
			}
			
			if (ihttp->thread->response.header[i].name_len) {//Status line has no name
				memcpy(&http_header[http_header_i], ihttp->thread->response.header[i].name, ihttp->thread->response.header[i].name_len);
				http_header_i += ihttp->thread->response.header[i].name_len;
				memcpy(&http_header[http_header_i], ((char[]){':',' '}), 2);
				http_header_i += 2;
			}
			
			memcpy(&http_header[http_header_i], ihttp->thread->response.header[i].value, ihttp->thread->response.header[i].value_len);
			http_header_i += ihttp->thread->response.header[i].value_len;
			memcpy(&http_header[http_header_i], ((char[]){'\r','\n'}), 2);
			http_header_i += 2;
		}
		
		// Only allocate more memory if there's not enough
		if ((http_header_i + sizeof("Content-Length: XXXXXXXXXX\r\n\r\n") - 1) > http_header_alloc) {
			http_header_alloc += 256;
			char *tmp_http_header;
			tmp_http_header = realloc(http_header, http_header_alloc);
			if (tmp_http_header == NULL) {puts("Error, realloc()"); goto HTTP_THREAD_ERR;}
			http_header = tmp_http_header;
		}
		
		// File
		if (ihttp->thread->send_file == 0) {
			FILE *fp;
			int bytes_sent;
			ihttp->thread->send_file = 1;
			fp = fopen(ihttp->thread->file_path, "rb");
			if (fp != NULL) {
				long fsize;
				fseek(fp, 0, SEEK_END); fsize = ftell(fp); fseek(fp, 0, SEEK_SET);
				memcpy(&http_header[http_header_i], ((char[]){'C','o','n','t','e','n','t','-','L','e','n','g','t','h',':',' '}), sizeof("Content-Length: ") - 1);
				http_header_i += sizeof("Content-Length: ") - 1;
				http_header_i += (ihttp_utoc(fsize, &http_header[http_header_i]) - &http_header[http_header_i]);
				memcpy(&http_header[http_header_i], ((char[]){'\r','\n','\r','\n'}), sizeof("\r\n\r\n") - 1);
				http_header_i += sizeof("\r\n\r\n") - 1;
				

				bytes_sent = ihttp_send(ihttp->thread->socket, http_header, http_header_i);
				if (bytes_sent == SOCKET_ERROR) {
					fclose(fp);
					// Skip errors that happen when client had closed the connection
					if (http_error() != EPIPE && http_error() != ECONNRESET)
						printf("Error, send(): %u.\n", http_error());
					goto IHTTP_THREAD_RESET_CLOSE;
				}
				
				ihttp_require_response_length(2048, ihttp);
				int file_length;
				while ((file_length = fread(ihttp->thread->response.data, sizeof(char), 2048, fp)) != 0) {
					bytes_sent = ihttp_send(ihttp->thread->socket, ihttp->thread->response.data, file_length);
					if (bytes_sent == SOCKET_ERROR) {
						fclose(fp);
						// Skip errors that happen when client had closed the connection
						if (http_error() != EPIPE && http_error() != ECONNRESET)
							printf("Error, send(): %u.\n", http_error());
						goto IHTTP_THREAD_RESET_CLOSE;
					}
					if (file_length < 2048) break;
				}
				fclose(fp);
				free(http_header);
				goto IHTTP_CONTINUE_CONNECTION;
			}
			ihttp->thread->status_code = HTTP_404;
			
			// Regular data
		} else {
			int bytes_sent;
			memcpy(&http_header[http_header_i], ((char[]){'C','o','n','t','e','n','t','-','L','e','n','g','t','h',':',' '}), sizeof("Content-Length: ") - 1);
			http_header_i += sizeof("Content-Length: ") - 1;
			http_header_i += (ihttp_utoc(ihttp->thread->response.data_i, &http_header[http_header_i]) - &http_header[http_header_i]);
			memcpy(&http_header[http_header_i], ((char[]){'\r','\n','\r','\n'}), sizeof("\r\n\r\n") - 1);
			http_header_i += sizeof("\r\n\r\n") - 1;
			
			bytes_sent = ihttp_send(ihttp->thread->socket, http_header, http_header_i);
			if (bytes_sent == SOCKET_ERROR) {
				// Skip errors that happen when client had closed the connection
				if (http_error() != EPIPE && http_error() != ECONNRESET)
					printf("Error, send(): %u.\n", http_error());
				goto IHTTP_THREAD_RESET_CLOSE;
			}
			bytes_sent = ihttp_send(ihttp->thread->socket, ihttp->thread->response.data, ihttp->thread->response.data_i);
			if (bytes_sent == SOCKET_ERROR) {
				// Skip errors that happen when client had closed the connection
				if(http_error() != EPIPE && http_error() != ECONNRESET)
					printf("Error, send(): %u.\n", http_error());
				goto IHTTP_THREAD_RESET_CLOSE;
			}
			
			free(http_header);
			goto IHTTP_CONTINUE_CONNECTION;
		}
	}
	
	switch(ihttp->thread->status_code) {
		default:
		case HTTP_200:
			goto IHTTP_CONTINUE_CONNECTION;
			break;
		case HTTP_400:
		{
			int bytes_sent = ihttp_send(ihttp->thread->socket, http_err400, http_err400_len);
			if (bytes_sent == SOCKET_ERROR) {
				// Skip errors that happen when client had closed the connection
				if(http_error() != EPIPE && http_error() != ECONNRESET)
					printf("Error, send(): %u\n", http_error());
				goto IHTTP_THREAD_RESET_CLOSE;
			}
			break;
		}
		case HTTP_403:
		{
			int bytes_sent = ihttp_send(ihttp->thread->socket, http_err403, http_err403_len);
			if (bytes_sent == SOCKET_ERROR) {
				// Skip errors that happen when client had closed the connection
				if(http_error() != EPIPE && http_error() != ECONNRESET)
					printf("Error, send(): %u\n", http_error());
				goto IHTTP_THREAD_RESET_CLOSE;
			}
			break;
		}
		case HTTP_404:
		{
			printf("HTTP 404 uri (%d) %.*s\n", ihttp->thread->uri_len, ihttp->thread->uri_len, ihttp->thread->uri);
			int bytes_sent = ihttp_send(ihttp->thread->socket, http_err404, http_err404_len);
			if (bytes_sent == SOCKET_ERROR) {
				// Skip errors that happen when client had closed the connection
				if(http_error() != EPIPE && http_error() != ECONNRESET)
					printf("Error, send(): %u\n", http_error());
				goto IHTTP_THREAD_RESET_CLOSE;
			}
			break;
		}
		case HTTP_409:
		{
			int bytes_sent = ihttp_send(ihttp->thread->socket, http_err409, http_err409_len);
			if (bytes_sent == SOCKET_ERROR) {
				// Skip errors that happen when client had closed the connection
				if(http_error() != EPIPE && http_error() != ECONNRESET)
					printf("Error, send(): %u\n", http_error());
				goto IHTTP_THREAD_RESET_CLOSE;
			}
			break;
		}
		case HTTP_500:
		{
			int bytes_sent = ihttp_send(ihttp->thread->socket, http_err500, http_err500_len);
			if (bytes_sent == SOCKET_ERROR) {
				// Skip errors that happen when client had closed the connection
				if(http_error() != EPIPE && http_error() != ECONNRESET)
					printf("Error, send(): %u\n", http_error());
				goto IHTTP_THREAD_RESET_CLOSE;
			}
			break;
		}
	}
	
IHTTP_CONTINUE_CONNECTION:
	// HTTP Pipelining and persistent connections.
	//If there's any data left, copy it to the beginning and go to start.
	if (ihttp->thread->request.data_header_len > ihttp->thread->request.data_header_i) {
		int remaining_header_len = ihttp->thread->request.data_header_len - ihttp->thread->request.data_header_i;
		memcpy(ihttp->thread->request.data_header, &ihttp->thread->request.data_header[ihttp->thread->request.data_header_i], remaining_header_len);
		ihttp->thread->request.data_header_len = remaining_header_len;
		goto IHTTP_THREAD_HTTP_CONTINUE;
	}
	// Block and try to recieve more data.
	int bytes_recvd = recv(ihttp->thread->socket, ihttp->thread->request.data_header, 4, 0);
	
	// if recv returned 0 or less, connection failed
	if (bytes_recvd < 1) {
		goto IHTTP_THREAD_RESET_CLOSE;
	} else {
		ihttp->thread->request.data_header_len = bytes_recvd;
		goto IHTTP_THREAD_HTTP_CONTINUE;
	}
	
IHTTP_THREAD_RESET_CLOSE:
	// Reset memory of POST back to original
	if (ihttp->thread->post_alloc != 16) {
		void *tmp_alloc;
		ihttp->thread->post_alloc = 16;
		tmp_alloc = realloc(ihttp->thread->post, ihttp->thread->post_alloc * sizeof(struct http_name_value_pair));
		if (tmp_alloc != NULL) {
			ihttp->thread->post = tmp_alloc;
		} else {puts("Error, realloc()");}
	}
	
	// Reset memory of request.data back to IHTTP_DEFAULT_DATA_SIZE
	if (ihttp->thread->request.data_alloc != IHTTP_DEFAULT_DATA_SIZE) {
		void *tmp_alloc;
		ihttp->thread->request.data_alloc = IHTTP_DEFAULT_DATA_SIZE;
		tmp_alloc = realloc(ihttp->thread->request.data, IHTTP_DEFAULT_DATA_SIZE);
		if (tmp_alloc) {
			ihttp->thread->request.data = tmp_alloc;
		} else {puts("Error, realloc()");}
	}
	
	// Reset memory of response.data back to original
	if (ihttp->thread->response.data_alloc != 4096) {
		void *tmp_alloc;
		ihttp->thread->response.data_alloc = 4096;
		tmp_alloc = realloc(ihttp->thread->response.data, ihttp->thread->response.data_alloc);
		if (tmp_alloc) {
			ihttp->thread->response.data = tmp_alloc;
		} else {puts("Error, realloc()");}
	}
	for (int hid = 0; hid < 32; hid++) {
		if (ihttp->thread->response.header[hid].name != NULL) {
			free(ihttp->thread->response.header[hid].name);
			ihttp->thread->response.header[hid].name = NULL;
		}
		if (ihttp->thread->response.header[hid].value != NULL) {
			free(ihttp->thread->response.header[hid].value);
			ihttp->thread->response.header[hid].value = NULL;
		}
	}
	
	#ifdef WIN32
	closesocket(ihttp->thread->socket);
	#else
	close(ihttp->thread->socket);
	#endif
	ihttp->thread->socket = INVALID_SOCKET;
	
	//pthread_mutex_lock(ihttp->server_mutex);
	//pthread_mutex_unlock(ihttp->server_mutex);
	//return NULL;
	goto IHTTP_THREAD_START;
HTTP_THREAD_ERR:
	send(ihttp->thread->socket, http_err400, http_err400_len, 0);
	goto IHTTP_THREAD_RESET_CLOSE;
	//HTTP_PROGRAM_TERMINATE:
	/*	pthread_mutex_lock(ihttp->server_mutex);
	 ihttp->server->program_terminate = 1;
	 pthread_mutex_unlock(ihttp->server_mutex);
	 raise(SIGTERM);
	 return NULL;*/
}

// Set response status
int ihttp_set_response_status(struct HTTP_THREAD *ihttp_thread, int ihttp_status_code)
{
	if (ihttp_status_code == HTTP_200 || ihttp_status_code == HTTP_400 || ihttp_status_code == HTTP_403 ||
		ihttp_status_code == HTTP_404 || ihttp_status_code == HTTP_409 || ihttp_status_code == HTTP_500) {
		ihttp_thread->response.status = ihttp_status_code;
		return 1;
	}
	
	/**/
	return 0;
}

//add header without replacing
void ihttp_add_header(struct HTTP_THREAD *ihttp_thread, char *name, int name_len, char *value, int value_len)
{
	for (int i = 0; i < 32; i++) {
		//empty name and value mean empty header
		if (ihttp_thread->response.header[i].value_len != 0 || ihttp_thread->response.header[i].name_len != 0) continue;
		void *tmp_alloc = realloc(ihttp_thread->response.header[i].name, name_len);
		if (tmp_alloc == NULL) return;
		
		ihttp_thread->response.header[i].name = tmp_alloc;
		ihttp_thread->response.header[i].name_len = name_len;
		memcpy(ihttp_thread->response.header[i].name, name, name_len);
		tmp_alloc = realloc(ihttp_thread->response.header[i].value, value_len);
		if (tmp_alloc == NULL) return;
		
		ihttp_thread->response.header[i].value = tmp_alloc;
		ihttp_thread->response.header[i].value_len = value_len;
		memcpy(ihttp_thread->response.header[i].value, value, value_len);
		break;
	}
	return;
}

void ihttp_set_header(struct HTTP_THREAD *ihttp_thread, char *name, int name_len, char *value, int value_len)//add new or replace existing header
{
	void *tmp_alloc; int i = 0;
	for (i=0; i<32; i++) {//same name header
		if (ihttp_thread->response.header[i].name_len == name_len && memcmp(ihttp_thread->response.header[i].name, name, name_len) == 0) goto SET_ONLY_VALUE;
	}
	
	for (i=1; i<32; i++) {//new empty header
		if (ihttp_thread->response.header[i].value_len == 0 && ihttp_thread->response.header[i].name_len == 0) goto SET_BOTH;
	}
	//same named header nor empty header was found
	return;
SET_BOTH:
	tmp_alloc = realloc(ihttp_thread->response.header[i].name, name_len);
	if (tmp_alloc == NULL) return;
	ihttp_thread->response.header[i].name = tmp_alloc;
	ihttp_thread->response.header[i].name_len = name_len;
	memcpy(ihttp_thread->response.header[i].name, name, name_len);
	
SET_ONLY_VALUE:
	tmp_alloc = realloc(ihttp_thread->response.header[i].value, value_len);
	if (tmp_alloc == NULL) return;
	ihttp_thread->response.header[i].value = tmp_alloc;
	ihttp_thread->response.header[i].value_len = value_len;
	memcpy(ihttp_thread->response.header[i].value, value, value_len);
	return;
}

void ihttp_rem_header(struct HTTP_THREAD *ihttp_thread, char *name, int name_len)//remove header
{
	for (int i=0; i<32; i++) {
		if (ihttp_thread->response.header[i].name_len != name_len || memcmp(ihttp_thread->response.header[i].name, name, name_len) != 0) continue;
		ihttp_thread->response.header[i].name_len = 0;
		ihttp_thread->response.header[i].value_len = 0;
		break;
	}
	return;
}
