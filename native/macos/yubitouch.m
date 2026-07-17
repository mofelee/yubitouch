#import <Cocoa/Cocoa.h>
#include <stdlib.h>
#include <string.h>

static NSPanel *YTPanel;
static NSImageView *YTIconView;
static NSTextField *YTTitleLabel;
static NSTextField *YTSubtitleLabel;
static unsigned long long YTGeneration;

static void YTSetApplicationIcon(NSApplication *application) {
    NSString *path = [NSBundle.mainBundle pathForResource:@"YubiTouch-1024" ofType:@"png"];
    if (path != nil) {
        NSImage *icon = [[NSImage alloc] initWithContentsOfFile:path];
        if (icon != nil) {
            application.applicationIconImage = icon;
        }
    }
}

static void YTOnMain(dispatch_block_t block) {
    if ([NSThread isMainThread]) {
        block();
    } else {
        dispatch_async(dispatch_get_main_queue(), block);
    }
}

static NSTextField *YTLabel(NSRect frame, CGFloat size, NSFontWeight weight, NSColor *color) {
    NSTextField *label = [[NSTextField alloc] initWithFrame:frame];
    label.bezeled = NO;
    label.drawsBackground = NO;
    label.editable = NO;
    label.selectable = NO;
    label.font = [NSFont systemFontOfSize:size weight:weight];
    label.textColor = color;
    label.lineBreakMode = NSLineBreakByTruncatingTail;
    return label;
}

static void YTBuildPanel(void) {
    if (YTPanel != nil) {
        return;
    }
    NSRect frame = NSMakeRect(0, 0, 344, 104);
    YTPanel = [[NSPanel alloc] initWithContentRect:frame
                                         styleMask:NSWindowStyleMaskBorderless | NSWindowStyleMaskNonactivatingPanel
                                           backing:NSBackingStoreBuffered
                                             defer:NO];
    YTPanel.level = NSStatusWindowLevel;
    YTPanel.opaque = NO;
    YTPanel.backgroundColor = [NSColor clearColor];
    YTPanel.hasShadow = YES;
    YTPanel.hidesOnDeactivate = NO;
    YTPanel.collectionBehavior = NSWindowCollectionBehaviorCanJoinAllSpaces |
                                 NSWindowCollectionBehaviorFullScreenAuxiliary |
                                 NSWindowCollectionBehaviorTransient;

    NSView *content = [[NSView alloc] initWithFrame:frame];
    content.wantsLayer = YES;
    content.layer.cornerRadius = 8.0;
    content.layer.backgroundColor = NSColor.windowBackgroundColor.CGColor;
    content.layer.borderColor = NSColor.separatorColor.CGColor;
    content.layer.borderWidth = 1.0;
    YTPanel.contentView = content;

    YTIconView = [[NSImageView alloc] initWithFrame:NSMakeRect(20, 28, 48, 48)];
    YTIconView.imageScaling = NSImageScaleProportionallyUpOrDown;
    [content addSubview:YTIconView];

    YTTitleLabel = YTLabel(NSMakeRect(86, 52, 238, 28), 20, NSFontWeightSemibold, NSColor.labelColor);
    [content addSubview:YTTitleLabel];
    YTSubtitleLabel = YTLabel(NSMakeRect(86, 27, 238, 22), 13, NSFontWeightRegular, NSColor.secondaryLabelColor);
    [content addSubview:YTSubtitleLabel];
}

static void YTPositionPanel(void) {
    NSScreen *screen = NSScreen.mainScreen;
    if (screen == nil) {
        return;
    }
    NSRect visible = screen.visibleFrame;
    NSRect frame = YTPanel.frame;
    frame.origin.x = NSMaxX(visible) - NSWidth(frame) - 24;
    frame.origin.y = NSMaxY(visible) - NSHeight(frame) - 24;
    [YTPanel setFrame:frame display:YES];
}

static NSImage *YTSymbol(NSString *name, NSColor *color) {
    NSImage *image = [NSImage imageWithSystemSymbolName:name accessibilityDescription:nil];
    NSImageSymbolConfiguration *configuration = [NSImageSymbolConfiguration configurationWithPointSize:36 weight:NSFontWeightSemibold];
    configuration = [configuration configurationByApplyingConfiguration:[NSImageSymbolConfiguration configurationWithHierarchicalColor:color]];
    return [image imageWithSymbolConfiguration:configuration];
}

static void YTShow(NSString *symbol, NSColor *color, NSString *title, NSString *subtitle) {
    YTBuildPanel();
    YTGeneration++;
    YTIconView.image = YTSymbol(symbol, color);
    YTTitleLabel.stringValue = title;
    YTSubtitleLabel.stringValue = subtitle;
    YTPositionPanel();
    [YTPanel orderFrontRegardless];
}

static void YTHideAfter(NSTimeInterval delay, unsigned long long generation) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (generation == YTGeneration) {
            [YTPanel orderOut:nil];
        }
    });
}

void YTInitializeApplication(void) {
    @autoreleasepool {
        if (![NSThread isMainThread]) {
            return;
        }
        NSApplication *application = [NSApplication sharedApplication];
        [application setActivationPolicy:NSApplicationActivationPolicyAccessory];
        YTSetApplicationIcon(application);
        [application finishLaunching];
    }
}

void YTRunApplication(void) {
    @autoreleasepool {
        if ([NSThread isMainThread]) {
            [[NSApplication sharedApplication] run];
        }
    }
}

void YTStopApplication(void) {
    YTOnMain(^{
        [YTPanel orderOut:nil];
        [NSApp stop:nil];
        NSEvent *event = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
                                            location:NSZeroPoint
                                       modifierFlags:0
                                           timestamp:0
                                        windowNumber:0
                                             context:nil
                                             subtype:0
                                               data1:0
                                               data2:0];
        [NSApp postEvent:event atStart:NO];
    });
}

void YTShowWaiting(const char *soundName) {
    NSString *sound = soundName == NULL ? @"" : [NSString stringWithUTF8String:soundName];
    YTOnMain(^{
        YTShow(@"hand.point.up.left.fill", NSColor.systemOrangeColor, @"请触摸 YubiKey", @"正在授权 SSH 签名");
        if (sound.length > 0 && ![sound isEqualToString:@"none"]) {
            [[NSSound soundNamed:sound] play];
        }
    });
}

void YTShowSuccess(void) {
    YTOnMain(^{
        YTShow(@"checkmark.circle.fill", NSColor.systemGreenColor, @"已授权", @"SSH 签名已完成");
        YTHideAfter(0.3, YTGeneration);
    });
}

void YTShowFailure(const char *message) {
    NSString *detail = message == NULL ? @"请重试" : [NSString stringWithUTF8String:message];
    YTOnMain(^{
        YTShow(@"xmark.circle.fill", NSColor.systemRedColor, @"授权失败", detail);
        YTHideAfter(2.5, YTGeneration);
    });
}

void YTShowAbout(void) {
    @autoreleasepool {
        if (![NSThread isMainThread]) {
            return;
        }
        NSApplication *application = [NSApplication sharedApplication];
        [application setActivationPolicy:NSApplicationActivationPolicyAccessory];
        YTSetApplicationIcon(application);
        [application finishLaunching];
        [application activateIgnoringOtherApps:YES];

        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"YubiTouch";
        alert.informativeText = @"面向 macOS、YubiKey PIV 和 OpenSSH 的独立开源项目。\n\nYubiTouch 与 Yubico 没有关联，也未获得 Yubico 的认可或背书。";
        [alert addButtonWithTitle:@"好"];
        [alert runModal];
    }
}

char *YTPromptPIN(int *status) {
    @autoreleasepool {
        if (status == NULL) {
            return NULL;
        }
        if (![NSThread isMainThread] || NSScreen.screens.count == 0) {
            *status = 2;
            return NULL;
        }
        NSApplication *application = [NSApplication sharedApplication];
        [application setActivationPolicy:NSApplicationActivationPolicyAccessory];
        YTSetApplicationIcon(application);
        [application finishLaunching];
        [application activateIgnoringOtherApps:YES];

        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"解锁 YubiKey PIV";
        alert.informativeText = @"输入 PIN 以加载 PIV provider。YubiTouch 不会保存此 PIN。";
        [alert addButtonWithTitle:@"继续"];
        [alert addButtonWithTitle:@"取消"];
        NSSecureTextField *field = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 280, 24)];
        field.placeholderString = @"PIV PIN";
        alert.accessoryView = field;
        [alert.window setInitialFirstResponder:field];

        NSModalResponse response = [alert runModal];
        if (response != NSAlertFirstButtonReturn) {
            *status = 1;
            return NULL;
        }
        NSString *value = field.stringValue;
        if (value.length == 0) {
            *status = 1;
            return NULL;
        }
        *status = 0;
        return strdup(value.UTF8String);
    }
}
