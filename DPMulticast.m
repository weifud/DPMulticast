//
//  DPMulticast.m
//  DPMulticast
//
//  Created by weifu Deng on 2018/4/26.
//  Copyright © 2018年 Digital Power Inc. All rights reserved.
//

/*
 多播（组播):主机之间一对一组的通讯模式，也就是增加了同一个组的主机能够接受到此组内的全部数据，网络中的交换机和路由器仅仅向有需求者复制并转发其所需数据。主机能够向路由器请求增加或退出某个组。网络中的路由器和交换机有选择的复制并传输数据，即仅仅将组内传输数据给那些增加组的主机。这样既能一次将传输数据给多个有须要（增加组）的主机，又能保证不影响其它不须要（未增加组）的主机的其它通讯。
 多播的优点：
 1）须要同样数据流的client增加同样的组共享一条数据流。节省了server的负载。具备广播所具备的长处。
 2）因为组播协议是依据接受者的须要对数据流进行复制转发。所以服务端的服务总带宽不受客户接入端带宽的限制。
    IP协议同意有2亿6千多万个组播，所以其提供的服务能够很丰富。
 3）此协议和单播协议一样同意在Internet宽带网上传输。
 
 多播的缺点：
 1）与单播协议相比没有纠错机制。发生丢包错包后难以弥补。但能够通过一定的容错机制和QOS加以弥补。
 2）现行网络尽管都支持组播的传输。但在客户认证、QOS等方面还须要完好，这些缺点在理论上都有成熟的解决方式，仅仅是须要逐步推广应用到现存网络其中。
 
 多播的地址是特定的，D类地址用于多播。D类IP地址就是多播IP地址，即224.0.0.0至239.255.255.255之间的IP地址，并被划分为局部连接多播地址、预留多播地址和管理权限多播地址3类：
 局部多播地址：在224.0.0.0～224.0.0.255之间，这是为路由协议和其他用途保留的地址，路由器并不转发属于此范围的IP包。
 预留多播地址：在224.0.1.0～238.255.255.255之间，可用于全球范围（如Internet）或网络协议。
 管理权限多播地址：在239.0.0.0～239.255.255.255之间，可供组织内部使用，类似于私有IP地址，不能用于Internet，可限制多播范围。
 
 使用多播
 只有类型为 SOCK_DGRAM 和 SOCK_RAW 的 AF_INET6 和 AF_INET 套接字支持 IP 多播。IP 多播仅在接口驱动程序支持多播的子网中受到支持。
 
 发送 IPv4 多播数据报
 要发送多播数据报，请在 224.0.0.0 到 239.255.255.255 的范围中指定一个 IP 多播地址作为 sendto(3SOCKET) 调用的目标地址。
 
 缺省情况下，发送 IP 多播数据报时其生存时间 (time-to-live, TTL) 值为 1。此值可以阻止将数据报转发到单个子网之外。使用套接字选项 IP_MULTICAST_TTL，可以将后续多播数据报的 TTL 设置为 0 到 255 之间的任何值。此功能用于控制多播的范围。
 
 u_char ttl;
 setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,sizeof(ttl))
 TTL 为 0 的多播数据报不能在任何子网中传输，但是在发送主机属于目标组并且发送套接字上未禁用多播回送的情况下可以进行本地传送。如果有一个或多个多播路由器连接到第一跃点子网，则 TTL 大于 1 的多播数据报可以传送到多个子网。为了提供有意义的范围控制，多播路由器支持 TTL 阈值概念。这些阈值会阻止低于特定 TTL 值的数据报遍历某些子网。这些阈值将针对具有以下初始 TTL 值的多播数据报强制实施相应约定：
 0 限定在同一主机
 1 限定在同一子网
 32 限定在同一站点
 64 限定在同一地区
 128 限定在同一洲
 255 范围不受限制
 站点和地区并未严格定义，站点可以根据实际情况再分为更小的管理单元。
 应用程序可以选择以上列出的 TTL 值以外的初始 TTL 值。例如，应用程序可以通过发送多播查询来对网络资源执行扩展环搜索，即第一个 TTL 值为 0，然后逐渐增大 TTL 的值，直到收到回复为止。
 
 多播路由器不转发任何目标地址在 224.0.0.0 与 224.0.0.255（包括 224.0.0.0 和 224.0.0.255）范围之间的多播数据报，而不管其 TTL 值是多少。此地址范围是为使用路由协议以及其他低级拓扑搜索或维护协议（如网关搜索和组成员关系报告）而保留的。
 
 即使主机拥有多个具有多播功能的接口，每个多播传输也是通过单个网络接口发送的。如果主机还用作多播路由器且 TTL 值大于 1，则多播可以转发到源接口之外的接口。可以使用套接字选项覆盖来自给定套接字的后续传输的缺省设置：
 struct in_addr addr;
 setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr))
 其中 addr 是所需传出接口的本地 IP 地址。通过指定地址 INADDR_ANY 恢复到缺省接口。使用 SIOCGIFCONF ioctl 获取接口的本地 IP 地址。要确定接口是否支持多播，请使用 SIOCGIFFLAGS ioctl 获取接口标志并测试是否设置了 IFF_MULTICAST 标志。此选项主要用于多播路由器以及其他专门针对 Internet 拓扑的系统服务。
 
 如果将多播数据报发送到发送主机本身所属的组，则缺省情况下，本地传送的 IP 层将回送此数据报的副本。另一套接字选项可为发送主机提供针对是否回送后续数据报的显式控制：
 
 u_char loop;
 setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop))
 其中 loop 为 0 即为禁用回送，为 1 即为启用回送。此选项通过消除因接收应用程序自己的传输内容而产生的开销，可提高单台主机上只有一个实例的应用程序的性能。对于可以在一台主机上具有多个实例或者其发送主机不属于目标组的应用程序，不应使用此选项。
 
 如果发送主机属于其他接口的目标组，则发送初始 TTL 值大于 1 的多播数据报可以传送到其他接口上的发送主机。回送控制选项不会影响此类传送。
 
 接收 IPv4 多播数据报
 主机必须成为一个或多个 IP 多播组的成员，才能接收 IP 多播数据报。进程可以使用以下套接字选项请求主机加入多播组：
 
 struct ip_mreq mreq;
 setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))
 其中 mreq 为以下结构：
 struct ip_mreq {
    struct in_addr imr_multiaddr;      // multicast group to join
    struct in_addr imr_interface;      // interface to join on
}
每个成员关系都与单个接口关联。可以在多个接口上加入同一组。将 imr_interface 地址指定为 INADDR_ANY 以选择缺省的多播接口。还可以通过指定主机的本地地址之一来选择特定的具有多播功能的接口。

要删除成员关系，请使用：
struct ip_mreq mreq;
setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq))
其中 mreq 包含用于添加成员关系的那些值。关闭套接字或中止保存套接字的进程将删除与此套接字关联的成员关系。可以有多个套接字请求成为特定组的成员，并且直到删除最后一个请求，主机才不再是此组的成员。

如果任一套接字请求成为数据报目标组的成员，则内核 IP 层将接受传入的多播包。给定套接字是否接收多播数据报取决于此套接字的关联目标端口和成员关系，或者取决于原始套接字的协议类型。要接收发送到特定端口的多播数据报，请将其绑定到本地端口，同时不指定本地地址，如使用 INADDR_ANY。

如果在 bind(3SOCKET) 之前存在以下内容，则可以将多个进程绑定到同一 SOCK_DGRAM UDP 端口：
int one = 1;
setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))
在这种情况下，每个目标为共享端口的传入多播或广播 UDP 数据报将传送到所有绑定到此端口的套接字。为了向后兼容，此传送不适用于传入的单播数据报。无论单播数据报的目标端口绑定有多少套接字，此类数据报永远都不会传送到多个套接字。 SOCK_RAW 套接字不要求 SO_REUSEADDR 选项共享单一 IP 协议类型。

可以在 <netinet/in.h> 中找到与多播相关的新套接字选项所需的定义。所有 IP 地址均以网络字节顺序传递。

发送 IPv6 多播数据报
要发送 IPv6 多播数据报，请在 ff00::0/8 范围中指定一个 IP 多播地址作为 sendto(3SOCKET) 调用的目标地址。

缺省情况下，IP 多播数据报的发送跃点限制为 1，此值可以阻止将数据报转发到单个子网之外。使用套接字选项 IPV6_MULTICAST_HOPS，可以将后续多播数据报的跃点限制设置为 0 到 255 之间的任何值。此功能用于控制多播的范围：

uint_l;
setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,sizeof(hops))
不能在任何子网中传输跃点限制为 0 的多播数据报，但是在以下情况下可以在本地范围内传送数据报：

发送主机属于目标组
启用了发送套接字上的多播回送

如果第一跃点子网连接到一个或多个多播路由器，则可以将跃点限制大于 1 的多播数据报传送到多个子网。与 IPv4 多播地址不同，IPv6 多播地址包含明确的范围信息，此信息在地址的第一部分进行编码。定义的范围如下，其中未指定 X：
ffX1::0/16 节点－本地范围，限定在同一节点
ffX2::0/16 链路－本地范围
ffX5::0/16 站点－本地范围
ffX8::0/16 组织－本地范围
ffXe::0/16 全局范围

应用程序可独立于多播地址范围，使用不同的跃点限制值。例如，应用程序可以通过发送多播查询来对网络资源执行扩展环搜索，即第一个跃点限制值为 0，然后逐渐增大跃点限制值，直到收到回复为止。

即使主机拥有多个具有多播功能的接口，每个多播传输也是通过单个网络接口发送的。如果主机还用作多播路由器且跃点限制值大于 1，则多播可以转发到源接口之外的接口。可以使用套接字选项覆盖来自给定套接字的后续传输的缺省设置：

uint_t ifindex;
ifindex = if_nametoindex ("hme3");
setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex))
其中，ifindex 是所需传出接口的接口索引。通过指定值 0 恢复到缺省接口。

如果将多播数据报发送到发送主机本身所属的组，则缺省情况下，本地传送的 IP 层将回送此数据报的副本。另一套接字选项可为发送主机提供针对是否回送后续数据报的显式控制：

uint_t loop;
setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop))
其中，loop 为 0 即为禁用回送，为 1 即为启用回送。此选项通过消除因接收应用程序自己的传输内容而产生的开销，可提高单台主机上只有一个实例的应用程序（如路由器或邮件守护进程）的性能。对于可以在一台主机上具有多个实例的应用程序（如会议程序）或者其发送主机不属于目标组的应用程序（如时间查询程序），不应使用此选项。

如果发送主机属于其他接口的目标组，则发送初始跃点限制值大于 1 的多播数据报可以传送到其他接口上的发送主机。回送控制选项不会影响此类传送。

接收 IPv6 多播数据报
主机必须成为一个或多个 IP 多播组的成员，才能接收 IP 多播数据报。进程可以使用以下套接字选项请求主机加入多播组：

struct ipv6_mreq mreq;
setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq))
其中 mreq 为以下结构：
struct ipv6_mreq {
    struct in6_addr    ipv6mr_multiaddr;    // IPv6 multicast addr
    unsigned int       ipv6mr_interface;    // interface index
}
每个成员关系都与单个接口关联。可以在多个接口上加入同一组。将 ipv6_interface 指定为 0 以选择缺省的多播接口。为主机的其中一个接口指定接口索引以选择此具有多播功能的接口。

要离开组，请使用：
struct ipv6_mreq mreq;
setsockopt(sock, IPPROTO_IPV6, IP_LEAVE_GROUP, &mreq, sizeof(mreq))
其中 mreq 包含用于添加成员关系的那些值。当关闭套接字或中止保存套接字的进程时，此套接字将删除关联的成员关系。可以有多个套接字请求成为特定组的成员。直到删除最后一个请求，主机才不再是此组的成员。

如果任一套接字已请求成为数据报目标组的成员，则内核 IP 层将接受传入的多播包。多播数据报是否传送到特定的套接字取决于与此套接字关联的目标端口和成员关系，或者取决于原始套接字的协议类型。要接收发送到特定端口的多播数据报，请将其绑定到本地端口，同时不指定本地地址，如使用 INADDR_ANY。

如果在 bind(3SOCKET) 之前存在以下内容，则可以将多个进程绑定到同一 SOCK_DGRAM UDP 端口：

int one = 1;
setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))
在这种情况下，所有绑定到此端口的套接字将接收每个目标为共享端口的传入多播 UDP 数据报。为了向后兼容，此传送不适用于传入的单播数据报。无论单播数据报的目标端口绑定有多少套接字，此类数据报永远都不会传送到多个套接字。 SOCK_RAW 套接字不要求 SO_REUSEADDR 选项共享单一 IP 协议类型。

可以在 <netinet/in.h> 中找到与多播相关的新套接字选项所需的定义。所有 IP 地址均以网络字节顺序传递。
 */

#import "DPMulticast.h"
#import <net/if.h>

static void dp_mtlog(const char *fmt,...){
    NSDate *date = [NSDate date];
    NSDateFormatter *forMatter = [[NSDateFormatter alloc] init];
    [forMatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    
    printf("%s [DPMulticast] ", [[forMatter stringFromDate:date] UTF8String]);
    va_list args;
    va_start (args, fmt);
    vprintf(fmt, args);
    va_end (args);
    printf("\n");
}

@interface DPMulticast(){
    uint32_t _recvBuffSize;
    uint32_t _recvTimeout;
    char *_recvBuff;
    struct sockaddr_storage *_recvAddr;
}

@property (nonatomic, strong) DPCSocket *dpSocket;
@property (nonatomic, strong) NSValue *mltAddrValue;

@end

@implementation DPMulticast
@synthesize delegate;

- (instancetype)init{
    self = [super init];
    if (self) {
        self.dpSocket = [[DPCSocket alloc] initWithType:SOCK_DGRAM];
        if (!self.dpSocket) {
            self = nil;
        }
    }
    
    return self;
}

- (void)dealloc{
    [self freeMemory];
}

- (void)freeMemory{
    _recvBuffSize = 0;
    _recvTimeout = 0;
    if (_recvBuff) {
        free(_recvBuff);
        _recvBuff = NULL;
    }
    
    if (_recvAddr) {
        free(_recvAddr);
        _recvAddr = NULL;
    }
}

#pragma mark - public
/**
 设置ipv4阈值或ipv6跃点
 */
- (BOOL)multicastSetIPv4TTLorIPv6Hop:(uint8_t)ttlhop{
    if (self.dpSocket.myFamily == AF_INET){
        int rlst = setsockopt(self.dpSocket.mySocket, IPPROTO_IP, IP_MULTICAST_TTL, &ttlhop,sizeof(ttlhop));
        if(rlst != SOCKET_ERROR){
            return YES;
        }
    }
    else if (self.dpSocket.myFamily == AF_INET6) {
        int rlst = setsockopt(self.dpSocket.mySocket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttlhop, sizeof(ttlhop));
        if(rlst != SOCKET_ERROR){
            return YES;
        }
    }

    dp_mtlog("multicastSetIPv4TTLorIPv6Hop: %s(%d)", strerror(errno), errno);
    return NO;
}


/**
 设置组播的默认网络接口，从给定的网络接口发送数据,其他接口会忽略该socket的数据
 (主机可以拥有多个具有多播功能的接口，每个多播传输也是通过单个网络接口发送的。只有一个接口可以不用指定)
 */
- (BOOL)multicastIFSet{
    if (self.dpSocket.myFamily == AF_INET) {
        struct in_addr ipv4Addr = {0};
        ipv4Addr.s_addr = htonl(INADDR_ANY);//使用系统默认的网卡发送组播数据
        int rlst = setsockopt(self.dpSocket.mySocket, IPPROTO_IP, IP_MULTICAST_IF, &ipv4Addr, sizeof(ipv4Addr));
        if(rlst != SOCKET_ERROR){
            return YES;
        }
    }
    else if (self.dpSocket.myFamily == AF_INET6) {
        uint8_t ifindex;
        ifindex = if_nametoindex ("en0");//获取指定接口index，接口不存在对应接口则返回0（默认接口）,en0 wifi
        int rlst = setsockopt(self.dpSocket.mySocket, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex));
        if(rlst != SOCKET_ERROR){
            return YES;
        }
    }
    
    dp_mtlog("multicastIFSet: %s(%d)", strerror(errno), errno);
    return NO;
}

/**
 当发送方也加入了组播组时，设置发送方是否接收回送数据
 NO 即为禁用回送，YES 即为启用回送
 */
- (BOOL)multicastLoopSet:(BOOL)bloop{
    uint8_t iloop = bloop ? 1 : 0;
    if (self.dpSocket.myFamily == AF_INET) {
        int rlst = setsockopt(self.dpSocket.mySocket, IPPROTO_IP, IP_MULTICAST_LOOP, &iloop, sizeof(iloop));
        if(rlst != SOCKET_ERROR){
            return YES;
        }
    }
    else if (self.dpSocket.myFamily == AF_INET6) {
        int rlst = setsockopt(self.dpSocket.mySocket, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &iloop, sizeof(iloop));
        if(rlst != SOCKET_ERROR){
            return YES;
        }
    }
    
    dp_mtlog("multicastLoopSet: %s(%d)", strerror(errno), errno);
    return NO;
}

- (BOOL)multicastSetIPAddr:(NSString *)ipaddr port:(uint16_t)port{
    struct sockaddr_storage *mltAddr = [self.dpSocket creatRemoteSockaddr:ipaddr port:port];
    if (mltAddr) {
        self.mltAddrValue = [NSValue valueWithBytes:mltAddr objCType:@encode(struct sockaddr_storage)];
        [self.dpSocket freeSockaddr:&mltAddr];
        
        struct sockaddr_storage mltAddr1 = {0};
        [self.mltAddrValue getValue:&mltAddr1];
        
        return YES;
    }
    
    dp_mtlog("multicastSetIPAddr: creat remote address failed");
    
    return NO;
}

- (BOOL)multicastBindPort:(uint16_t)port{
    struct sockaddr_storage *locAddr = [self.dpSocket creatLocalSockaddr:port];
    if (locAddr) {
        return [self.dpSocket bindSocketAddr:(struct sockaddr *)locAddr];
    }
    
    dp_mtlog("multicastSetIPAddr: creat local address failed");
    return NO;
}

- (BOOL)multicastAdd2Group{
    struct sockaddr_storage mltAddr = {0};
    [self.mltAddrValue getValue:&mltAddr];
    
    if (self.dpSocket.myFamily == AF_INET) {
        struct sockaddr_in *ipv4Addr = (struct sockaddr_in *)&mltAddr;
        struct ip_mreq mreq = {0};
        mreq.imr_multiaddr.s_addr = ipv4Addr->sin_addr.s_addr;//inet_addr(gAddr.UTF8String);//要加入的组播组地址
        mreq.imr_interface.s_addr = htonl(INADDR_ANY); //使用默认的接口来收发组播数据;
        int rlst = setsockopt(self.dpSocket.mySocket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
        if(rlst != SOCKET_ERROR){
            return YES;
        }
    }
    else if (self.dpSocket.myFamily == AF_INET6) {
        struct sockaddr_in6 *ipv6Addr = (struct sockaddr_in6 *)&mltAddr;
        struct ipv6_mreq mreq = {0};
        mreq.ipv6mr_multiaddr = ipv6Addr->sin6_addr;
        mreq.ipv6mr_interface = if_nametoindex ("en0");
        int rlst = setsockopt(self.dpSocket.mySocket, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
        if(rlst != SOCKET_ERROR){
            return YES;
        }
    }
    
    dp_mtlog("multicastAdd2Group: %s(%d)", strerror(errno), errno);
    return NO;
}

- (BOOL)multicastDrop4Group{
    struct sockaddr_storage mltAddr = {0};
    [self.mltAddrValue getValue:&mltAddr];
    
    if (self.dpSocket.myFamily == AF_INET) {
        struct sockaddr_in *ipv4Addr = (struct sockaddr_in *)&mltAddr;
        struct ip_mreq mreq = {0};
        mreq.imr_multiaddr.s_addr = ipv4Addr->sin_addr.s_addr;
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        int rlst = setsockopt(self.dpSocket.mySocket, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
        if(rlst != SOCKET_ERROR){
            return YES;
        }
    }
    else if (self.dpSocket.myFamily == AF_INET6) {
        struct sockaddr_in6 *ipv6Addr = (struct sockaddr_in6 *)&mltAddr;
        struct ipv6_mreq mreq = {0};
        mreq.ipv6mr_multiaddr = ipv6Addr->sin6_addr;
        mreq.ipv6mr_interface = if_nametoindex ("en0");//"en0" wifi
        int rlst = setsockopt(self.dpSocket.mySocket, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq));
        if(rlst != SOCKET_ERROR){
            return YES;
        }
    }
    
    dp_mtlog("multicastDrop4Group: %s(%d)", strerror(errno), errno);
    return NO;
}

- (BOOL)multicastSendData:(NSData *)data{
    if (!data) {
        dp_mtlog("multicastSendData: data is nil");
        return NO;
    }
    
    struct sockaddr_storage mltAddr = {0};
    [self.mltAddrValue getValue:&mltAddr];
    return [self.dpSocket sendtoData:(char *)data.bytes
                           lenOfData:(uint32_t)data.length
                          remoteAddr:(struct sockaddr *)&mltAddr];
}

- (BOOL)multicastSetRecvbuff:(uint32_t)buffSize timeout:(uint32_t)timeout{
    [self freeMemory];
    _recvBuff = (char *)malloc(buffSize);
    _recvAddr = (struct sockaddr_storage *)malloc(sizeof(struct sockaddr_storage));
    if (_recvBuff && _recvAddr) {
        _recvBuffSize = buffSize;
        _recvTimeout = timeout;
        return YES;
    }
    
    [self freeMemory];
    
    dp_mtlog("multicastSetRecvbuff: crear buff failed");
    
    return NO;
}

- (BOOL)multicastRecvData{
    if (_recvBuffSize > 0) {
        uint32_t irlen = _recvBuffSize;
        memset(_recvBuff, 0, _recvBuffSize);
        memset(_recvAddr, 0, sizeof(struct sockaddr_storage));
        
        BOOL brslt = [self.dpSocket recvfromDataBuff:_recvBuff
                                           lenOfData:&irlen
                                          remoteAddr:(struct sockaddr *)_recvAddr
                                             timeout:_recvTimeout];
        if (brslt && self.delegate) {
            NSData *recvData = [[NSData alloc] initWithBytes:_recvBuff length:irlen];
            NSValue *rAddrValue = [NSValue valueWithBytes:_recvAddr objCType:@encode(struct sockaddr)];
            [self.delegate multicastRecvData:recvData fromAddr:rAddrValue];
            return YES;
        }
    }
    
    return NO;
}

@end
