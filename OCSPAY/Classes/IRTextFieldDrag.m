//
//  IRTextFieldDrag.m
//  TBPackaging
//
//  Created by Esteban Bouza on 01/12/12.
//

#import "IRTextFieldDrag.h"

@implementation IRTextFieldDrag

- (void)awakeFromNib {
    [self registerForDraggedTypes:@[NSFilenamesPboardType]];
}

- (BOOL)performDragOperation:(id <NSDraggingInfo>)sender
{
    NSPasteboard *pboard = [sender draggingPasteboard];
    
    if ( [[pboard types] containsObject:NSURLPboardType] ) {
        NSArray *files = [pboard propertyListForType:NSFilenamesPboardType];
        if (files.count <= 0) {
            return NO;
        }
        self.stringValue = [files objectAtIndex:0];
        [self selectText:self];
        [[self currentEditor] setSelectedRange:NSMakeRange([[self stringValue] length], 0)];
    }
    return YES;
}


// Source: http://www.cocoabuilder.com/archive/cocoa/11014-dnd-for-nstextfields-drag-drop.html
- (NSDragOperation)draggingEntered:(id <NSDraggingInfo>)sender {
    
    if (!self.isEnabled) return NSDragOperationNone;
    
    NSPasteboard *pboard;
    NSDragOperation sourceDragMask;
    
    sourceDragMask = [sender draggingSourceOperationMask];
    pboard = [sender draggingPasteboard];
    
    if ( [[pboard types] containsObject:NSColorPboardType] ) {
        if (sourceDragMask & NSDragOperationCopy) {
            return NSDragOperationCopy;
        }
    }
    if ( [[pboard types] containsObject:NSFilenamesPboardType] ) {
        if (sourceDragMask & NSDragOperationCopy) {
            return NSDragOperationCopy;
        }
    }
    
    return NSDragOperationNone;
}

// Dragging bug in Apple Mac OS SDK: http://stackoverflow.com/questions/9534543/weird-behavior-dragging-from-stacks-to-status-item-doesnt-work
- (void)draggingEnded:(id<NSDraggingInfo>)sender {
    if (NSPointInRect([sender draggingLocation], self.frame)) {
        [self performDragOperation:sender];
    }
}

@end
