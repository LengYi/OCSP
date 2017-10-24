//
//  OCSPManager.h
//  OCSPAY
//
//  Created by ice on 2017/10/23.
//  Copyright © 2017年 ice. All rights reserved.
//

#import <Foundation/Foundation.h>

#pragma mark - CertStatusItem
@interface CertStatusItem : NSObject

@property(nonatomic, strong) NSString *appName;
@property(nonatomic, strong) NSString *certID;
@property(nonatomic, strong) NSString *commonName;
@property(nonatomic, assign) NSInteger certStatus;
@property(nonatomic, strong) NSString *thisUpdate;
@property(nonatomic, strong) NSString *revokedTime;
@property(nonatomic, assign) NSInteger revocationReason;
@property(nonatomic, strong) NSString *expiresTime;

@property(nonatomic, strong) NSString *filePath;

- (NSString *)certStatusToString;
- (NSString *)revocationReasonToString;

@end

typedef void (^CertRevocationCompleteHandle)(CertStatusItem *statusItem,NSError *error);

#pragma mark - OCSPManager
@interface OCSPManager : NSObject

+ (OCSPManager *)shareInstance;

- (void)checkRevocationWtihPath:(NSString *)filePath completeHandle:(CertRevocationCompleteHandle)completeHandle;
@end
