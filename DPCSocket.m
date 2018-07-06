//
//  DPCSocket.m
//  DPCSocket v2.0
//
//  Created by weifu Deng on 2018/4/26.
//  Copyright © 2018年 Digital Power Inc. All rights reserved.
//

/*socket编程:<sys/socket.h> <arpa/inet.h> <netinet/in.h>
 TCP: SOCK_STREAM, 面向连接的，采用数据流方式传输数据，会重发一切
 错误数据，因此可以保证数据的完整性和正确性。
 (面向连接，数据流，传输控制，差错检查，错误重传)
 UDP: SOCK_DGRAM, 无连接的，采用数据报方式传输数据。数据有可能丢失。
 (无连接，数据报)
 
 TCP 的编程步骤：SOCK_STREAM
 server:
 1. socket()获取一个sockfdsrv。 AF_INET, SOCK_STREAM, 0
 2. 准备地址。
 struct sockaddr_in AF_INET, htons(端口号)
 INADD_ANY/inet_addr(点分十进制)
 3. bind()绑定。 //记得param2类型转换
 int bind(int sockfd, const struct sockaddr* addr, int len);
 4. listen()监听。 sockfdsrv,  backlog(long of waiting queue)
 int listen(int sockfd, int backlog);
 5. accept()等待连接。 返回用于交互的socket描述符
 int accept(int sockfd, struct sockaddr* addr, int* len);
 [out]addr [in/out]len
 6. recv()接收消息。
 int recv(int sockfd, void* buf, int len, int flags);
 flags:
 7. send()发送信息。
 int send(int sockfd, void* buf, int len, int flags);
 8. close()关闭连接。 sockfdsrv;
 
 client:
 1. socket()获取一个sockfdc, AF_INET, SOCK_STREAM, 0
 2. 准备地址。
 struct sockaddr_in AF_INET, htons(端口号)
 inet_addr(点分十进制)
 3. connect()连接服务器
 int connect(int sock, const struct sockaddr* srvaddr, int len);
 4. send()发送信息
 5. recv()接收消息
 6. close()关闭连接。 sockfdc
 
 注：socket获得的sockfd用于监听，accept返回的sockfd用于读写通信。
 
 UDP编程过程：SOCK_DGRAM
 server:
 1. socket()创建套接字
 2. 准备地址
 3. bind()绑定
 4. recvfrom()接收信息
 int recvfrom(int sock, void* buf, int size, int flags,
 struct sockaddr *from, int *len);
 flags:一般置0  from[out] len[in/out]
 5. sendto 发信息
 int sendto(int sock, void* buf, int size, int flags,
 const struct sockaddr *to, int len);
 6. close()关闭套接字
 
 client:
 1. socket()创建套接字
 2. 准备接收方地址 sturct sockaddr_in
 3. sendto()发信息
 4. recvfrom()收信息
 5. close()关闭套接字
*/

#import "DPCSocket.h"

@interface DPCSocket (){
}

@property (nonatomic, assign) dp_socket mySocket;
@property (nonatomic, assign) sa_family_t myFamily;
@property (nonatomic, assign) uint8_t myType;

@end


@implementation DPCSocket
@synthesize mySocket;
@synthesize myFamily;

static void dp_cslog(const char *fmt,...){
    NSDate *date = [NSDate date];
    NSDateFormatter *forMatter = [[NSDateFormatter alloc] init];
    [forMatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    
    printf("%s [DPCSocket] ", [[forMatter stringFromDate:date] UTF8String]);
    va_list args;
    va_start (args, fmt);
    vprintf(fmt, args);
    va_end (args);
    printf("\n");
}

#pragma mark - public
+ (NSString *)formatIPv4Address:(struct in_addr *)ipv4addr{
    NSString *address = nil;
    char dstStr[INET_ADDRSTRLEN] = {0};
    if(inet_ntop(AF_INET, ipv4addr, dstStr, INET_ADDRSTRLEN) != NULL){
        address = [NSString stringWithUTF8String:dstStr];
    }
    
    return address;
}

+ (NSString *)formatIPv6Address:(struct in6_addr *)ipv6addr{
    NSString *address = nil;
    char dstStr[INET6_ADDRSTRLEN] = {0};
    if(inet_ntop(AF_INET6, ipv6addr, dstStr, INET6_ADDRSTRLEN) != NULL){
        address = [NSString stringWithUTF8String:dstStr];
    }
    
    return address;
}

+ (NSString *)getAddressByhostName:(NSString *)hostName{
    NSString *hostAddr = nil;
    
    struct addrinfo hints;
    struct addrinfo *res, *cur;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;//AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_DEFAULT;
    hints.ai_protocol = IPPROTO_IP;   // IP协议
    
    int status = getaddrinfo(hostName.UTF8String, NULL, &hints, &res);//http 8000
    if (status != 0) {
        dp_cslog("getaddrinfo error: %s(%d)", strerror(status), status);
        return nil;
    }
    
    for (cur = res; cur; cur = cur->ai_next) {
        if (cur->ai_family == AF_INET) {
            hostAddr = [DPCSocket formatIPv4Address:&((struct sockaddr_in *)cur->ai_addr)->sin_addr];
        }
        else if (cur->ai_family == AF_INET6){
            hostAddr = [DPCSocket formatIPv6Address:&((struct sockaddr_in6 *)cur->ai_addr)->sin6_addr];
        }
    }
    
    freeaddrinfo(res);
    return hostAddr;
}

+ (sa_family_t)localFamily{
    sa_family_t ifamily = AF_UNSPEC;
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    
    if (getifaddrs(&interfaces) == 0) {  // 0 表示获取成功
        temp_addr = interfaces;
        while (temp_addr != NULL) {
            // Check if interface is en0 which is the wifi connection on the iPhone
            if ((strcmp(temp_addr->ifa_name, "en0") == 0) ||        //"en0" wifi
                (strcmp(temp_addr->ifa_name, "pdp_ip0")) == 0) {    //"pdp_ip0" 蜂窝网络
                if (temp_addr->ifa_addr->sa_family == AF_INET){
                    struct sockaddr_in *ipv4 = (struct sockaddr_in *)temp_addr->ifa_addr;
                    if ([DPCSocket formatIPv4Address:&ipv4->sin_addr])
                        ifamily = AF_INET;
                }
                else if (temp_addr->ifa_addr->sa_family == AF_INET6){
                    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)temp_addr->ifa_addr;
                    NSString *ipv6Addr = [DPCSocket formatIPv6Address:&ipv6->sin6_addr];
                    if (ipv6Addr)   {
                        ifamily = AF_INET6;
                        if (![ipv6Addr isEqualToString:@""] &&
                            ![ipv6Addr.uppercaseString hasPrefix:@"FE80"]) {
                            break;
                        }
                    }
                }
            }
            temp_addr = temp_addr->ifa_next;
        }
    }
    
    freeifaddrs(interfaces);
    return ifamily;
}

+ (void)logSocketInfo:(dp_socket)socket logFlag:(NSString *)flag{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof (struct sockaddr_storage);
    if (getsockname(socket, (struct sockaddr *) &addr, (socklen_t*)&addr_len) == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
            dp_cslog("log socket[%s]: ipv4 host: %s port: %d",
                     flag.UTF8String,
                     [[DPCSocket formatIPv4Address:&ipv4->sin_addr] UTF8String],
                     ntohs(ipv4->sin_port));
        }
        else if (addr.ss_family == AF_INET6){
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;
            dp_cslog("log socket[%s]: ipv6 host: %s port: %d",
                     flag.UTF8String,
                     [[DPCSocket formatIPv6Address:&ipv6->sin6_addr] UTF8String],
                     ntohs(ipv6->sin6_port));
        }
    }
}

+ (void)logSockaddrInfo:(struct sockaddr_storage *)ipaddr logFlag:(NSString *)flag{
    if (ipaddr->ss_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)ipaddr;
        dp_cslog("log socket[%s]: ipv4 host: %s port: %d",
                 flag.UTF8String,
                 [[DPCSocket formatIPv4Address:&ipv4->sin_addr] UTF8String],
                 ntohs(ipv4->sin_port));
    }
    else if (ipaddr->ss_family == AF_INET6){
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)ipaddr;
        dp_cslog("log socket[%s]: ipv6 host: %s port: %d",
                 flag.UTF8String,
                 [[DPCSocket formatIPv6Address:&ipv6->sin6_addr] UTF8String],
                 ntohs(ipv6->sin6_port));
    }
}

- (void)freeSockaddr:(struct sockaddr_storage **)ipaddr{
    if (*ipaddr) {
        free(*ipaddr);
        *ipaddr = NULL;
    }
}

- (struct sockaddr_storage *)creatLocalSockaddr:(uint16_t)iport{
    if (iport <= 0x400 ) {
        dp_cslog("%s: illegal parameter", __func__);
        return NULL;
    }
    
    struct sockaddr_storage pladdr = {0};
    if (self.myFamily == AF_INET) {
        struct sockaddr_in *sockaddr4 = (struct sockaddr_in *)&pladdr;
        sockaddr4->sin_len         = sizeof(struct sockaddr_in);
        sockaddr4->sin_family      = AF_INET;
        sockaddr4->sin_port        = htons(iport);
        sockaddr4->sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else if (self.myFamily == AF_INET6){
        struct sockaddr_in6 *sockaddr6 = (struct sockaddr_in6 *)&pladdr;
        sockaddr6->sin6_len       = sizeof(struct sockaddr_in6);
        sockaddr6->sin6_family    = AF_INET6;
        sockaddr6->sin6_port      = htons(iport);
        sockaddr6->sin6_addr      = in6addr_any;
    }
    else{
        dp_cslog("%s: protocol not supported", __func__);
        return NULL;
    }
    
    struct sockaddr_storage * pLocalAddr = (struct sockaddr_storage *)malloc(sizeof(struct sockaddr_storage));
    if (!pLocalAddr) {
        dp_cslog("%s: malloc failed", __func__);
        return NULL;
    }
    
    memset(pLocalAddr, 0, sizeof(struct sockaddr_storage));
    memcpy(pLocalAddr, &pladdr, sizeof(struct sockaddr_storage));
    
    return pLocalAddr;
}

- (struct sockaddr_storage *)creatRemoteSockaddr:(NSString *)rhostName port:(uint16_t)iport{
    if (!rhostName) {
        dp_cslog("%s: illegal parameter", __func__);
        return NULL;
    }
    
    struct sockaddr_storage praddr = {0};
    struct addrinfo hints;
    struct addrinfo *res, *cur;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_DEFAULT;
    hints.ai_protocol = IPPROTO_IP;   // IP协议
    
    int status = getaddrinfo([rhostName UTF8String], "8000", &hints, &res);
    if (status != 0) {
        dp_cslog("%s: %s(%d)", __func__, strerror(status), status);
        return NULL;
    }
    
    BOOL bflag = NO;
    for (cur = res; cur; cur = cur->ai_next) {
        if (cur->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)&praddr;
            memcpy(ipv4, (struct sockaddr_in *)cur->ai_addr, sizeof(struct sockaddr_in));
            ipv4->sin_port = htons(iport);
            
            bflag = YES;
        }
        else if (cur->ai_family == AF_INET6){
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&praddr;
            memcpy(ipv6, (struct sockaddr_in6 *)cur->ai_addr, sizeof(struct sockaddr_in6));
            ipv6->sin6_port = htons(iport);
            
            bflag = YES;
        }
    }
    freeaddrinfo(res);
    
    if (!bflag) {
        dp_cslog("%s: protocol not supported", __func__);
        return NULL;
    }
    
    struct sockaddr_storage *pRemoteAddr = (struct sockaddr_storage *)malloc(sizeof(struct sockaddr_storage));
    if (!pRemoteAddr) {
        dp_cslog("%s: malloc failed", __func__);
        return NULL;
    }
    
    memset(pRemoteAddr, 0, sizeof(struct sockaddr_storage));
    memcpy(pRemoteAddr, &praddr, sizeof(struct sockaddr_storage));
    
    return pRemoteAddr;
}

- (BOOL)bindSocketAddr:(struct sockaddr *)ipaddr{
    if (!ipaddr) {
        dp_cslog("%s: illegal parameter", __func__);
        return NO;
    }
    
    int iret = bind(self.mySocket, ipaddr, ipaddr->sa_len);
    if (iret == SOCKET_ERROR) {
        dp_cslog("%s: %s(%d)", __func__, strerror(errno), errno);
        return NO;
    }
    
    return YES;
}

#pragma mark -upd methods
- (BOOL)recvfromDataBuff:(char *)pdata lenOfData:(uint32_t *)ilen remoteAddr:(struct sockaddr *)raddr timeout:(uint32_t)timeout{//ms
    
    if (self.myType == SOCK_STREAM) {
        dp_cslog("tcp unsupported recvfrom");
        return NO;
    }
    
    uint32_t originalSize = *ilen;
    if (!pdata || !raddr ) {
        dp_cslog("%s: illegal parameter", __func__);
        return NO;
    }
    
    socklen_t addrLen = 0;
    if (self.myFamily == AF_INET) {
        addrLen = sizeof(struct sockaddr_in);
    }
    else if (self.myFamily  == AF_INET6) {
        addrLen = sizeof(struct sockaddr_in6);
    }
    else{
        dp_cslog("%s: unknown ifamily", __func__);
        return NO;
    }
    
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(self.mySocket, &readfds);
    int irslt = select(self.mySocket + 1, &readfds, NULL, NULL, &tv);
    if (irslt == 0 ){
        //dp_cslog("%s: timeout", __func__);
        return NO;
    }
    else if (irslt < 0) {
        dp_cslog("%s: irslt(%d) error[%s(%d)]", __func__, irslt, strerror(errno), errno);
        return NO;
    }
    
    if (FD_ISSET (self.mySocket, &readfds)){
        *ilen = (uint32_t)recvfrom(self.mySocket, pdata, originalSize, 0, raddr, &addrLen);
        if (*ilen <= 0){
            dp_cslog("%s: %s(%d)", __func__, strerror(errno), errno);
            return NO;
        }
        
        if ((*ilen) + 1 >= originalSize){
            dp_cslog("%s: received a message that was too large", __func__);
            return NO;
        }
        
        pdata[*ilen]=0;
        
        return YES;
    }
    
    return NO;
}

- (BOOL)sendtoData:(char *)pdata lenOfData:(uint32_t)ilen remoteAddr:(struct sockaddr *)raddr{
    if (self.myType == SOCK_STREAM) {
        dp_cslog("tcp unsupported sendto");
        return NO;
    }
    
    if (!pdata || !raddr){
        dp_cslog("%s: illegal parameter", __func__);
        return NO;
    }
    
    ssize_t iret = sendto(self.mySocket, pdata, ilen, 0, raddr, raddr->sa_len);
    if (iret != ilen) {
        dp_cslog("%s: %s(%d)", __func__, strerror(errno), errno);
        return NO;
    }
    
    return YES;
}

- (BOOL)setBroadcast{
    if (self.myFamily == AF_INET6) {
        dp_cslog("ipv6 unsupported broadcast");
        return NO;
    }
    
    const int optval = 1;
    int rlst = setsockopt(self.mySocket, SOL_SOCKET, SO_BROADCAST, (char*)&optval, sizeof(optval));
    if(rlst == SOCKET_ERROR){
        dp_cslog("%s: %s(%d)", __func__, strerror(errno), errno);
        return NO;
    }
    
    return YES;
}

#pragma mark -tcp methods
- (BOOL)setListenMaxCount:(uint32_t)imax{
    
    if (self.myType == SOCK_DGRAM) {
        dp_cslog("udp unsupported listen");
        return NO;
    }
    
    int iret = listen(self.mySocket, imax);
    if (iret == SOCKET_ERROR) {
        dp_cslog("%s error: %s(%d)", __func__, strerror(errno), errno);
        return NO;
    }
    
    return YES;
}

- (dp_socket)getAcceptedSocket{
    if (self.myType == SOCK_DGRAM) {
        dp_cslog("udp unsupported accept");
        return INVALID_SOCKET;
    }
    
    struct sockaddr client = {0};
    socklen_t addrLen = sizeof(socklen_t);
    dp_socket rwfd = accept(self.mySocket, &client, &addrLen);
    if (rwfd == SOCKET_ERROR){
        dp_cslog("%s error: %s(%d)", __func__, strerror(errno), errno);
    }
    
    return rwfd;
}

- (BOOL)connect2RemoteAddr:(struct sockaddr *)raddr timeout:(uint32_t)timeout{//ms
    if (self.myType == SOCK_DGRAM) {
        dp_cslog("udp unsupported connect");
        return NO;
    }
    
    /*
     *1.设置成非阻塞模式来控制链接超时
     *2.成功链接后再设为阻塞模式
     */
    //1.设置非阻塞
    int status = SOCKET_ERROR;
    int flags = fcntl(self.mySocket, F_GETFL,0);
    fcntl(self.mySocket, F_SETFL, flags | O_NONBLOCK);
    
    status = connect(self.mySocket, raddr, raddr->sa_len);
    if (status == SOCKET_ERROR){
        if (errno == EINPROGRESS){
            //it is in the connect process
            fd_set fdwrite;
            int error;
            int len = sizeof(int);
            
            struct timeval tv;
            tv.tv_sec = timeout / 1000;
            tv.tv_usec = (timeout % 1000) * 1000;
            
            FD_ZERO(&fdwrite);
            FD_SET(self.mySocket, &fdwrite);
            
            int ret = select(self.mySocket + 1, NULL, &fdwrite, NULL, &tv);
            if (ret <= 0) {//err
                dp_cslog("%s error: %s(%d)", __func__, strerror(errno), errno);
                return NO;
            }
            
            //判断是否链接成功
            getsockopt(self.mySocket, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
            if (error != 0) {
                dp_cslog("%s error: %s(%d)", __func__, strerror(error), error);
                return NO;
            }
        }
        else{
            dp_cslog("%s error: %s(%d)", __func__, strerror(errno), errno);
            return NO;
        }
    }
    
    //2.连接成功后设置阻塞模式
    flags = fcntl(self.mySocket, F_GETFL,0);
    flags &= ~ O_NONBLOCK;
    fcntl(self.mySocket,F_SETFL, flags);
    
    return TRUE;
}

- (int32_t)recvDataBuff:(char *)pdata lenOfBuff:(uint32_t)ilen timeout:(uint32_t)timeout{//ms
    int ret;
    uint32_t rlen = 0;
    ssize_t len;
    fd_set    readfds;
    
    if (self.myType == SOCK_DGRAM) {
        dp_cslog("udp unsupported recv");
        return SOCKET_ERROR;
    }
    
    while (rlen < ilen){
        struct timeval tv;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;
        
        FD_ZERO(&readfds);
        FD_SET(self.mySocket, &readfds);
        
        ret = select(self.mySocket + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {// err
            dp_cslog("%s error: %s(%d)", __func__, strerror(errno), errno);
            return SOCKET_ERROR;
        }
        else if (ret == 0){// time out
            //dp_cslog("%s error:recv timeout", __func__);
            return 0;
        }
        
        if (FD_ISSET(self.mySocket, &readfds)){  //测试isocket是否可读
            len = recv(self.mySocket, pdata + rlen, ilen - rlen, 0);
            if (len <= 0) {//err
                dp_cslog("%s error: %s(%d)", __func__, strerror(errno), errno);
                return SOCKET_ERROR;
            }
            else{
                rlen += len;
            }
        }
    }
    
    return rlen;
}

- (int32_t)sendData:(char *)pdata lenOfData:(uint32_t)ilen{
    int32_t wlen = 0;
    ssize_t len;
    
    if (self.myType == SOCK_DGRAM) {
        dp_cslog("udp unsupported send");
        return SOCKET_ERROR;
    }
    
    while (wlen < ilen){
        len = send(self.mySocket, pdata + wlen, ilen - wlen, 0);
        if (len <= 0) {
            dp_cslog("%s error: %s(%d)", __func__, strerror(errno), errno);
            return SOCKET_ERROR;
        }
        else {
            wlen += len;
        }
    }
    
    return wlen;
}

#pragma mark - circle
- (instancetype)initWithType:(uint8_t)itype{
    if (itype != SOCK_STREAM && itype != SOCK_DGRAM) {
        dp_cslog("DPCSocket init error: unsupported socket type");
        return nil;
    }
    
    self = [super init];
    if (self) {
        self.myType = itype;
        self.myFamily = [DPCSocket localFamily];
        self.mySocket = [self creatSocket:itype];
        if (self.mySocket == INVALID_SOCKET) {
            self = nil;
        }
    }
    
    return self;
}

- (void)dealloc{
    [self closeSocket];
}

#pragma mark - pri
- (void)closeSocket{
    if (self.mySocket != INVALID_SOCKET) {
        shutdown(self.mySocket, SHUT_RDWR);
        close(self.mySocket);
        self.mySocket = INVALID_SOCKET;
    }
}

//SOCK_STREAM(TCP), SOCK_DGRAM(UDP)
- (dp_socket)creatSocket:(uint8_t)itype{
    if (itype != SOCK_STREAM && itype != SOCK_DGRAM) {
        dp_cslog("%s: itype not supported", __func__);
        return INVALID_SOCKET;
    }
    int nosigpipe = 1;
    int reuseOn = 1;
    int status = INVALID_SOCKET;
    int isocket = INVALID_SOCKET;
    
    if (self.myFamily == AF_INET6) {
        isocket = socket(AF_INET6, itype, 0);
    }
    else if (self.myFamily == AF_INET){
        isocket = socket(AF_INET, itype, 0);
    }
    else{
        dp_cslog("%s: protocol not supported", __func__);
        return INVALID_SOCKET;
    }
    
    /*!
     *屏蔽SIGPIPE信号,等同于signal(SIGPIPE,SIG_IGN);
     *SIGPIPE信号
     *在linux下写socket的程序的时候，如果尝试send到一个disconnected socket上，就会让底层抛出一个SIGPIPE信号。
     *该信号的缺省处理方法是退出进程。
     */
    status = setsockopt(isocket, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
    if (status == SOCKET_ERROR) {
        dp_cslog("%s: shielded signal sigpipe failed", __func__);
        close(isocket);
        return INVALID_SOCKET;
    }
    
    //地址复用，解决端口被占用问题
    status = setsockopt(isocket, SOL_SOCKET, SO_REUSEADDR, &reuseOn, sizeof(reuseOn));
    if (status == SOCKET_ERROR) {
        dp_cslog("%s: enabling address reuse failed", __func__);
        close(isocket);
        return INVALID_SOCKET;
    }
    
    return isocket;
}

@end
