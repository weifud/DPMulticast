//
//  DPCSocket.h
//  DPCSocket v2.0
//  Support ipv6
//
//  Created by weifu Deng on 2018/4/26.
//  Copyright © 2018年 Digital Power Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <ifaddrs.h>
#import <unistd.h>
#import <netdb.h>
#import <sys/fcntl.h>
#import <sys/errno.h>
#import <sys/time.h>
#import <netinet/in.h>
#import <arpa/inet.h>

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

typedef int dp_socket;//Socket

@interface DPCSocket : NSObject

@property (nonatomic, assign, readonly) dp_socket mySocket;
@property (nonatomic, assign, readonly) sa_family_t myFamily;//AF_INET,AF_INET6

+ (NSString *)formatIPv4Address:(struct in_addr *)ipv4addr;
+ (NSString *)formatIPv6Address:(struct in6_addr *)ipv6addr;
+ (sa_family_t)localFamily;
+ (NSString *)getAddressByhostName:(NSString *)hostName;

+ (void)logSocketInfo:(dp_socket)socket logFlag:(NSString *)flag;
+ (void)logSockaddrInfo:(struct sockaddr_storage *)ipaddr logFlag:(NSString *)flag;

#pragma mark -socket methods
/**
 创建套接字实例

 @param itype SOCK_STREAM(TCP), SOCK_DGRAM(UDP)
 @return 套接字实例
 */
- (instancetype)initWithType:(uint8_t)itype;
- (void)freeSockaddr:(struct sockaddr_storage **)ipaddr;
- (struct sockaddr_storage *)creatLocalSockaddr:(uint16_t)iport;
- (struct sockaddr_storage *)creatRemoteSockaddr:(NSString *)rhostName port:(uint16_t)iport;
- (BOOL)bindSocketAddr:(struct sockaddr *)ipaddr;

#pragma mark -upd methods
- (BOOL)recvfromDataBuff:(char *)pdata lenOfData:(uint32_t *)ilen remoteAddr:(struct sockaddr *)raddr timeout:(uint32_t)timeout;//ms
- (BOOL)sendtoData:(char *)pdata lenOfData:(uint32_t)ilen remoteAddr:(struct sockaddr *)raddr;//ms
- (BOOL)setBroadcast;//ipv6 unsupported broadcast

#pragma mark -tcp methods
- (BOOL)setListenMaxCount:(uint32_t)imax;
- (dp_socket)getAcceptedSocket;
- (BOOL)connect2RemoteAddr:(struct sockaddr *)raddr timeout:(uint32_t)timeout;//ms
- (int32_t)recvDataBuff:(char *)pdata lenOfBuff:(uint32_t)ilen timeout:(uint32_t)timeout;//ms
- (int32_t)sendData:(char *)pdata lenOfData:(uint32_t)ilen;
@end
