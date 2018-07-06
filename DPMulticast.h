//
//  DPMulticast.h
//  DPMulticast
//
//  Created by weifu Deng on 2018/4/26.
//  Copyright © 2018年 Digital Power Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "DPCSocket.h"

@protocol DPMulticastDelegate <NSObject>
- (void)multicastRecvData:(NSData *)rData fromAddr:(NSValue *)rAddrValue;//(struct sockaddr *)
@end

@interface DPMulticast : NSObject
@property (nonatomic, weak) id<DPMulticastDelegate> delegate;

/**
 设置阈值(存活时间)或跃点

 @param ttlhop 阈值或跃点
 @return YES/NO
 */
- (BOOL)multicastSetIPv4TTLorIPv6Hop:(uint8_t)ttlhop;

/**
 设置收发数据网络接口

 @return YES/NO
 */
- (BOOL)multicastIFSet;

/**
 设置是否接收换回数据

 @param bloop YES/NO
 @return YES/NO
 */
- (BOOL)multicastLoopSet:(BOOL)bloop;

/**
 设置组播组地址和端口

 @param ipaddr 组播组地址
 @param port 组播组端口
 @return YES/NO
 */
- (BOOL)multicastSetIPAddr:(NSString *)ipaddr port:(uint16_t)port;

/**
 绑定本地接收端口

 @param port 本地接收端口
 @return YES/NO
 */
- (BOOL)multicastBindPort:(uint16_t)port;

/**
 加入组播组

 @return YES/NO
 */
- (BOOL)multicastAdd2Group;

/**
 离开组播组

 @return YES/NO
 */
- (BOOL)multicastDrop4Group;

/**
 发送组播数据

 @param data 要发送的数据
 @return YES/NO
 */
- (BOOL)multicastSendData:(NSData *)data;

/**
 设置接收缓冲区

 @param buffSize 缓冲区大小
 @return YES/NO
 */
- (BOOL)multicastSetRecvbuff:(uint32_t)buffSize timeout:(uint32_t)timeout;//ms

/**
 接收广播数据
 */
- (BOOL)multicastRecvData;

@end
