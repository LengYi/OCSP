//
//  OCSPManager.m
//  OCSPAY
//
//  Created by ice on 2017/10/23.
//  Copyright © 2017年 ice. All rights reserved.
//

#import "OCSPManager.h"
#import "SecBase64.h"
#import "SecCFRelease.h"
#import "SecOCSPResponse.h"

#pragma mark - CertStatusItem
@implementation CertStatusItem

- (NSString *)certStatusToString{
    switch (self.certStatus) {
        case CS_Good:
            return @"Good";
        case CS_Revoked:
            return @"Revoked";
        case CS_Unknown:
            return @"Unknown";
        default:
            break;
    }
    
    return @"Unknown";
}

- (NSString *)revocationReasonToString{
    switch (self.revocationReason) {
        case kSecRevocationReasonUnrevoked:
            return @"Unrevoked";
            break;
        case kSecRevocationReasonUndetermined:
            return @"Undetermined";
            break;
        case kSecRevocationReasonUnspecified:
            return @"Unspecified";
            break;
        case kSecRevocationReasonKeyCompromise:
            return @"KeyCompromise";
            break;
        case kSecRevocationReasonCACompromise:
            return @"CACompromise";
            break;
        case kSecRevocationReasonAffiliationChanged:
            return @"AffiliationChanged";
            break;
        case kSecRevocationReasonCessationOfOperation:
            return @"CessationOfOperation";
            break;
        case kSecRevocationReasonCertificateHold:
            return @"CertificateHold";
            break;
        case kSecRevocationReasonRemoveFromCRL:
            return @"RemoveFromCRL";
            break;
        case kSecRevocationReasonPrivilegeWithdrawn:
            return @"PrivilegeWithdrawn";
            break;
        case kSecRevocationReasonAACompromise:
            return @"AACompromise";
            break;
        default:
            break;
    }
    return @"Undetermined";
}

- (NSString *)description{
    return [NSString stringWithFormat:@"appName:%@ \nCommonName:%@ \nthisUpdate:%@ \ncertStatus:%@ \nrevokeDate:%@ \nreovcationReason: %@",self.appName,self.commonName,self.thisUpdate, [self certStatusToString],self.revokedTime,[self revocationReasonToString]];
}

@end



#pragma mark - OCSPManager

@implementation OCSPManager

+ (OCSPManager *)shareInstance{
    static OCSPManager *manager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        if (!manager) {
            manager = [[OCSPManager alloc] init];
        }
    });
    
    return manager;
}

- (void)checkRevocationWtihPath:(NSString *)filePath completeHandle:(CertRevocationCompleteHandle)completeHandle{
    NSDictionary *dict = [self mobileProvisionWithURL:[NSURL URLWithString:filePath]];
    NSArray *certificates = [self getCertificatesFromMoileProvision:dict];
    NSDate *expirationDate = [dict objectForKey:@"ExpirationDate"];
    NSString *expirationDateStr = [self stringFormDate:expirationDate];
    
    if ([certificates count] > 0){
        CFErrorRef error = NULL;
        SecCertificateRef certificateRef = (__bridge SecCertificateRef)(certificates[0]);
        // 解析获取证书序列号,原始证书序列号 Mac钥匙串->搜索证书->右键显示简介->细节->签发者名称->序列号(值为10进制)
        CFDataRef serialNumberData = SecCertificateCopySerialNumber(certificateRef, &error);
        const UInt8 *byte = CFDataGetBytePtr(serialNumberData);
        CFIndex len = CFDataGetLength(serialNumberData);
        
        NSMutableString *serialNumberMutableStr = [[NSMutableString alloc]init];
        for (CFIndex n = 0; n < len; n++) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", byte[n]);
            NSString *ddd = [[NSString alloc]initWithBytes:hex length:2 encoding:NSUTF8StringEncoding];
            [serialNumberMutableStr appendString:ddd];
        }
        // 证书序列号16进制字符串->2进制数字
        long long d = strtoll([serialNumberMutableStr UTF8String],NULL,16);
        NSString *serialNumberStr = [NSString stringWithFormat:@"%lld",d];
        
        // 解析获取验证证书需要请求的域名地址
        NSString *authorityInfoAccessURI = [self authorityInfoAccessURI:certificateRef];
        if (serialNumberData && !error){
            // 获取证书名称
            CFStringRef commonName = NULL;
            SecCertificateCopyCommonName(certificateRef,&commonName);
            // 拼接请求url
            NSString *urlString = [self ocspURLStringWithSerialNumber:serialNumberData authorityInfoAccessURI:authorityInfoAccessURI];
            // 发送证书验证请求
            NSData *data = [self checkRevocationFromOCSPServer:urlString];
            // 解析验证请求结果
            if (data) {
                SecOCSPSingleResponseRef singleResponse = createOCSPSingleReqonseData((__bridge CFDataRef)(data));
                if (singleResponse){
                    CertStatusItem *item = [[CertStatusItem alloc]init];
                    const char *thisUpdate = cfabsoluteTimeToStringLocal(singleResponse->thisUpdate);
                    const char *nextUpdate = cfabsoluteTimeToStringLocal(singleResponse->nextUpdate);
                    const char *revokeDate = cfabsoluteTimeToStringLocal(singleResponse->revokedTime);
                    
                    NSString *appName = [[filePath lastPathComponent]stringByDeletingPathExtension];
                    appName = [appName stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
                    item.appName = appName;
                    item.thisUpdate = [NSString stringWithUTF8String:thisUpdate];
                    item.revocationReason = singleResponse->crlReason;
                    item.certStatus = singleResponse->certStatus;
                    item.commonName = (__bridge_transfer NSString *)(commonName);
                    item.certID = serialNumberStr;
                    item.expiresTime = expirationDateStr;
                    item.filePath = filePath;
                    
                    if (item.certStatus == 0) {
                        item.revokedTime = @"";
                    }else
                    {
                        item.revokedTime = [NSString stringWithUTF8String:revokeDate];
                    }
                    
                    free((void *)thisUpdate);
                    free((void *)nextUpdate);
                    free((void *)revokeDate);
                    free(singleResponse);
                    
                    completeHandle(item,nil);
                }else{
                    NSError *error = [NSError errorWithDomain:@"RevocationDomain" code:-1 userInfo:[NSDictionary dictionaryWithObjectsAndKeys:filePath,@"FilePath", nil]];
                    completeHandle(nil,error);
                }
            }else{
                NSError *error = [NSError errorWithDomain:@"RevocationDomain" code:-1 userInfo:[NSDictionary dictionaryWithObjectsAndKeys:filePath,@"FilePath", nil]];
                completeHandle(nil,error);
            }
            
        }else{
            NSError *error = [NSError errorWithDomain:@"RevocationDomain" code:-1 userInfo:[NSDictionary dictionaryWithObjectsAndKeys:filePath,@"FilePath", nil]];
            completeHandle(nil,error);
        }
        
        if (serialNumberData) {
            free((void *)serialNumberData);
        }
    }else{
        NSError *error = [NSError errorWithDomain:@"RevocationDomain" code:-1 userInfo:[NSDictionary dictionaryWithObjectsAndKeys:filePath,@"FilePath", nil]];
        completeHandle(nil,error);
    }
}

// 解析mobileprovision证书数据
- (NSDictionary *)mobileProvisionWithURL:(NSURL *)url{
    NSURL *URL = url;
    NSData *fileData = nil;
    
    if ([[URL pathExtension] isEqualToString:@"app"]){
        fileData = [NSData dataWithContentsOfURL:[URL URLByAppendingPathComponent:@"embedded.mobileprovision"]];
    }else if ([[URL pathExtension] isEqualToString:@"ipa"]){
        NSTask *unzipTask = [NSTask new];
        [unzipTask setLaunchPath:@"/usr/bin/unzip"];
        [unzipTask setStandardOutput:[NSPipe pipe]];
        [unzipTask setArguments:@[@"-p", [URL path], @"Payload/*.app/embedded.mobileprovision" ]];
        [unzipTask launch];
        [unzipTask waitUntilExit];
        
        fileData = [[[unzipTask standardOutput] fileHandleForReading] readDataToEndOfFile];
    }else{
        fileData = [NSData dataWithContentsOfURL:URL];
    }
    
    if (fileData) {
        CMSDecoderRef decoder = NULL;
        CMSDecoderCreate(&decoder);
        CMSDecoderUpdateMessage(decoder, fileData.bytes, fileData.length);
        CMSDecoderFinalizeMessage(decoder);
        CFDataRef dataRef = NULL;
        CMSDecoderCopyContent(decoder, &dataRef);
        NSData *data = (NSData *)CFBridgingRelease(dataRef);
        CFRelease(decoder);
        
        if (data) {
            NSDictionary *propertyList = [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL];
            return propertyList;
        }
    }
    return NULL;
}

// 解析DeveloperCertificates数组值
- (NSArray *)getCertificatesFromMoileProvision:(NSDictionary *)dict{
     NSMutableArray *array = [[NSMutableArray alloc] init];
     id value = [dict objectForKey:@"DeveloperCertificates"];
    if ([value isKindOfClass:[NSArray class]]) {
        for (NSData *data in value){
            SecCertificateRef certificateRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)data);
            if (certificateRef) {
                [array addObject:(__bridge_transfer id)(certificateRef)];
            }
        }
    }
    return array;
}

- (NSString *)authorityInfoAccessURI:(SecCertificateRef)certificateRef
{
    NSString *uri = nil;
    
    CFErrorRef error = NULL;
    NSString *key = (__bridge NSString *)(kSecOIDAuthorityInfoAccess);
    NSArray *array = @[key];
    NSDictionary *cerDict = CFBridgingRelease(SecCertificateCopyValues(certificateRef,(__bridge CFArrayRef)(array),&error));
    NSDictionary *oscpURIDict = [cerDict objectForKey:key];
    if (oscpURIDict) {
        NSArray *values = [oscpURIDict objectForKey:@"value"];
        for (NSDictionary *value in values) {
            NSString *label = [value objectForKey:@"label"];
            if ([label isKindOfClass:[NSString class]] && [label isEqualToString:@"URI"]) {
                uri = [value objectForKey:@"value"];
            }
        }
    }
    
    return uri;
}

// 拼接证书验证请求的实际地址
- (NSString *)ocspURLStringWithSerialNumber:(CFDataRef)serialNumberData authorityInfoAccessURI:(NSString *)authorityInfoAccessURI
{
    if (!authorityInfoAccessURI) {
        authorityInfoAccessURI = @"http://ocsp.apple.com/ocsp-wwdr01";
    }
    
    NSString *authorityInfoAccessURL = [NSString stringWithFormat:@"%@%@",authorityInfoAccessURI,@"/ME4wTKADAgEAMEUwQzBBMAkGBSsOAwIaBQAEFADrDMz0cWy6RiOj1S%2BY1D32MKkdBBSIJxcJqbYYYIvs67r2R1nFUlSjtwII"];
    const char *urlString = [authorityInfoAccessURL UTF8String];
    CFURLRef cfUrl = CFURLCreateWithBytes(NULL, (const UInt8 *)urlString, strlen(urlString), kCFStringEncodingUTF8, NULL);
    CFURLRef url = createGetURL(cfUrl, serialNumberData);
    NSURL *nsurl = (__bridge_transfer NSURL *)url;
    CFReleaseSafe(cfUrl);
    return [nsurl absoluteString];
}

CFURLRef createGetURL(CFURLRef responder, CFDataRef request) {
    CFURLRef getURL = NULL;
    CFMutableDataRef base64Request = NULL;
    CFStringRef base64RequestString = NULL;
    CFStringRef peRequest = NULL;
    CFIndex base64Len;
    
    base64Len = SecBase64Encode(NULL, CFDataGetLength(request), NULL, 0);
    /* Don't bother doing all the work below if we know the end result will
     exceed 255 bytes (minus one for the '/' separator makes 254). */
    if (base64Len + CFURLGetBytes(responder, NULL, 0) > 254)
        return NULL;
    
    require(base64Request = CFDataCreateMutable(kCFAllocatorDefault,
                                                base64Len), errOut);
    CFDataSetLength(base64Request, base64Len);
    SecBase64Encode(CFDataGetBytePtr(request), CFDataGetLength(request),
                    (char *)CFDataGetMutableBytePtr(base64Request), base64Len);
    require(base64RequestString = CFStringCreateWithBytes(kCFAllocatorDefault,
                                                          CFDataGetBytePtr(base64Request), base64Len, kCFStringEncodingUTF8,
                                                          false), errOut);
    require(peRequest = CFURLCreateStringByAddingPercentEscapes(
                                                                kCFAllocatorDefault, base64RequestString, NULL, CFSTR("+/="),
                                                                kCFStringEncodingUTF8), errOut);
#if 1
    CFStringRef urlString = CFURLGetString(responder);
    CFStringRef fullURL;
    //    if (CFStringHasSuffix(urlString, CFSTR("/"))) {
    fullURL = CFStringCreateWithFormat(kCFAllocatorDefault, NULL,
                                       CFSTR("%@%@"), urlString, peRequest);
    //    } else {
    //        fullURL = CFStringCreateWithFormat(kCFAllocatorDefault, NULL,
    //                                           CFSTR("%@/%@"), urlString, peRequest);
    //    }
    getURL = CFURLCreateWithString(kCFAllocatorDefault, fullURL, NULL);
    CFRelease(fullURL);
#else
    getURL = CFURLCreateWithString(kCFAllocatorDefault, peRequest, responder);
#endif
    
errOut:
    CFReleaseSafe(base64Request);
    CFReleaseSafe(base64RequestString);
    CFReleaseSafe(peRequest);
    
    return getURL;
}

// 发送证书验证请求
- (NSData *)checkRevocationFromOCSPServer:(NSString *)urlString{
    NSURL *url  = [NSURL URLWithString:urlString];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setValue:@"securityd (unknown version) CFNetwork/672.1.15 Darwin/14.0.0" forHTTPHeaderField:@"User-Agent"];
    [request setValue:@"application/ocsp-response" forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"no-cache" forHTTPHeaderField:@"Cache-Control"];
    //    NSOperationQueue *queue = [[NSOperationQueue alloc]init];
    
    NSError *error = nil;
    NSURLResponse *urlRespone = nil;
    NSData  *data = [NSURLConnection sendSynchronousRequest:request returningResponse:&urlRespone error:&error];
    return data;
}

SecOCSPSingleResponseRef createOCSPSingleReqonseData(CFDataRef data){
    SecOCSPResponseRef ocspResponse = SecOCSPResponseCreate(data,0);
    SecAsn1OCSPSingleResponse **responses;
    for (responses = ocspResponse->responseData.responses; *responses; ++responses) {
        SecAsn1OCSPSingleResponse *resp = *responses;
        SecOCSPSingleResponseRef singleResponse = SecOCSPSingleResponseCreate(resp,ocspResponse->coder);
        SecOCSPResponseFinalize(ocspResponse);
        return singleResponse;
    }
    return NULL;
}

const char *cfabsoluteTimeToStringLocal(CFAbsoluteTime abstime)
{
    CFDateRef cfDate = CFDateCreate(kCFAllocatorDefault, abstime);
    CFDateFormatterRef dateFormatter = CFDateFormatterCreate(kCFAllocatorDefault, CFLocaleCopyCurrent(), kCFDateFormatterFullStyle, kCFDateFormatterLongStyle);
    CFDateFormatterSetFormat(dateFormatter, CFSTR("yyyy-MM-dd HH:mm:ss"));
    CFStringRef newString = CFDateFormatterCreateStringWithDate(kCFAllocatorDefault, dateFormatter, cfDate);
    
    char buffer[1024] = {0,};
    char *time_string = NULL;
    size_t sz;
    
    CFStringGetCString(newString, buffer, 1024, kCFStringEncodingUTF8);
    sz = strnlen(buffer, 1024);
    time_string = (char *)malloc(sz);
    strncpy(time_string, buffer, sz+1);
    
    CFRelease(dateFormatter);
    CFRelease(cfDate);
    CFRelease(newString);
    
    return time_string;
}

- (NSString *)stringFormDate:(NSDate *)date{
    //    NSTimeZone *zone = [NSTimeZone systemTimeZone];
    //    NSInteger interval = 8 * 60 * 60; //改成北京时间
    //    NSDate *localDate = [date dateByAddingTimeInterval:interval];
    
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc]init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    NSString *dataFormString = [dateFormatter stringFromDate:date];
    
    return dataFormString;
}

@end
