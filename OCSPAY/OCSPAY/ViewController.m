//
//  ViewController.m
//  OCSPAY
//
//  Created by ice on 2017/10/23.
//  Copyright © 2017年 ice. All rights reserved.
//

#import "ViewController.h"
#import "OCSPManager.h"

typedef enum __APPStatus{
    kAppStatusStop,
    kAPPStatusWaiting,
    kAppStatusChecking
    
} APPStatus;

@interface ViewController ()
@property (nonatomic,strong) NSMutableString *logString;
@property (nonatomic,assign) APPStatus status;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    id value = [[NSUserDefaults standardUserDefaults]objectForKey:@"FilePath"];
    if ([value isKindOfClass:[NSString class]]) {
        self.filePathField.stringValue  = value;
    }
    
    _status = kAPPStatusWaiting;
}

// 打开文件浏览选择框,选择文件
- (IBAction)fileBrowserOnClicked:(id)sender {
    
    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel setCanChooseFiles:YES];
    [openPanel setCanChooseDirectories:YES];
    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setAllowsOtherFileTypes:NO];
    [openPanel setAllowedFileTypes:@[ @"app",@"ipa", @"mobileprovision" ]];
    
    if ([openPanel runModal] == NSOKButton) {
        NSString *fileNameOpened = [[[openPanel URLs] objectAtIndex:0] path];
        self.filePathField.stringValue = fileNameOpened;
    }
}

// 开始查询证书状态
- (IBAction)startCheckAction:(id)sender {
    // 记录历史
    [[NSUserDefaults standardUserDefaults] setObject:self.filePathField.stringValue forKey:@"FilePath"];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    __weak typeof(self) weakSelf = self;
    if (_status != kAppStatusChecking) {
        _status = kAppStatusChecking;
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [weakSelf refreshResultView:nil];
            weakSelf.msgLabel.stringValue = @"检查中...";
            weakSelf.startBtn.enabled = NO;
            weakSelf.browseBtn.enabled = NO;
        });
        
        dispatch_async(dispatch_queue_create("check", NULL), ^{
            [weakSelf checkRevocationCompletionHandler:^(CertStatusItem *statusItem,NSError *error) {
                // 主线程刷新界面
                dispatch_async(dispatch_get_main_queue(), ^{
                    [weakSelf refreshResultView:statusItem];
                    [weakSelf.msgLabel setStringValue:@"检查结束"];
                    _status = kAPPStatusWaiting;
                    weakSelf.startBtn.enabled = YES;
                    weakSelf.browseBtn.enabled = YES;
                });
            }];
        });
    }
}

- (void)checkRevocationCompletionHandler:(void (^)(CertStatusItem *statusItem,NSError *error))handler{
    NSString *filePath = self.filePathField.stringValue;
    if ([filePath hasSuffix:@".ipa"] || [filePath hasSuffix:@".app"] || [filePath hasSuffix:@".mobileprovision"]) {
        filePath = [filePath stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
        filePath = [NSString stringWithFormat:@"file:///%@",filePath];
        NSLog(@"%@",filePath);
        
        [[OCSPManager shareInstance] checkRevocationWtihPath:filePath
                                              completeHandle:^(CertStatusItem *statusItem, NSError *error) {
                                                  handler(statusItem,error);
                                              }];
    }
}

- (void)refreshResultView:(CertStatusItem *)statusItem{
    if (!_logString) {
        _logString = [[NSMutableString alloc] init];
    }
    
    if (statusItem){
        [_logString appendFormat:@"应用名: %@ \n",statusItem.appName];
        [_logString appendFormat:@"公司名称: %@ \n",statusItem.commonName];
        [_logString appendFormat:@"证书ID: %@ \n",statusItem.certID];
        [_logString appendFormat:@"查询时间: %@ \n",statusItem.thisUpdate];
        [_logString appendFormat:@"证书状态: %@ \n",[statusItem certStatusToString]];
        
        if (statusItem.certStatus != 0) {
            [_logString appendFormat:@"撤销时间: %@ \n",statusItem.revokedTime];
            [_logString appendFormat:@"撤销原因: %@ \n",[statusItem revocationReasonToString]];
        }
        [_logString appendString:@"\n"];
        
        [_logString appendFormat:@"查询请求地址: %@ \n",statusItem.requestUrl];
    }else
    {
        [_logString setString:@""];;
    }
    
    self.resultLogView.string = _logString;
}

@end
