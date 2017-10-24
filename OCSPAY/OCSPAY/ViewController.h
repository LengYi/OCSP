//
//  ViewController.h
//  OCSPAY
//
//  Created by ice on 2017/10/23.
//  Copyright © 2017年 ice. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "IRTextFieldDrag.h"

@interface ViewController : NSViewController

@property (weak) IBOutlet IRTextFieldDrag *filePathField;
@property (unsafe_unretained) IBOutlet NSTextView *resultLogView;
@property (weak) IBOutlet NSTextField *msgLabel;
@property (weak) IBOutlet NSButton *startBtn;
@property (weak) IBOutlet NSButton *browseBtn;

- (IBAction)fileBrowserOnClicked:(id)sender;

- (IBAction)startCheckAction:(id)sender;

@end

