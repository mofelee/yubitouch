#import <Cocoa/Cocoa.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static NSPanel *YTPanel;
static NSView *YTContentView;
static NSImageView *YTIconView;
static NSImageView *YTApplicationIconView;
static NSTextField *YTTitleLabel;
static NSTextField *YTSubtitleLabel;
static NSButton *YTCancelButton;
static atomic_ullong YTCancelRequestID;
static unsigned long long YTCurrentRequestID;
static unsigned long long YTGeneration;

static void YTUpdatePanelAppearance(void);

@interface YTPanelContentView : NSView
@end

@implementation YTPanelContentView
- (void)viewDidChangeEffectiveAppearance {
    [super viewDidChangeEffectiveAppearance];
    YTUpdatePanelAppearance();
}
@end

@interface YTCancelTarget : NSObject
- (void)cancelSigning:(id)sender;
@end

@implementation YTCancelTarget
- (void)cancelSigning:(id)sender {
    (void)sender;
    atomic_store(&YTCancelRequestID, YTCurrentRequestID);
    YTCancelButton.enabled = NO;
}
@end

static YTCancelTarget *YTCancelTargetInstance;

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

static NSAppearance *YTEffectiveAppearance(void) {
    NSAppearance *appearance = YTContentView.effectiveAppearance;
    if (appearance == nil) {
        appearance = YTPanel.effectiveAppearance;
    }
    if (appearance == nil) {
        appearance = NSApp.effectiveAppearance;
    }
    return appearance;
}

static void YTUpdatePanelAppearance(void) {
    if (YTContentView == nil) {
        return;
    }
    // Dynamic NSColor behavior is lost when converted to CGColor, so resolve it again whenever appearance changes.
    dispatch_block_t update = ^{
        YTContentView.layer.backgroundColor = NSColor.windowBackgroundColor.CGColor;
        YTContentView.layer.borderColor = NSColor.separatorColor.CGColor;
        YTTitleLabel.textColor = NSColor.labelColor;
        YTSubtitleLabel.textColor = NSColor.secondaryLabelColor;
        YTCancelButton.contentTintColor = NSColor.labelColor;
    };
    NSAppearance *appearance = YTEffectiveAppearance();
    if (appearance == nil) {
        update();
    } else {
        [appearance performAsCurrentDrawingAppearance:update];
    }
}

static void YTBuildPanel(void) {
    if (YTPanel != nil) {
        return;
    }
    NSRect frame = NSMakeRect(0, 0, 420, 116);
    YTPanel = [[NSPanel alloc] initWithContentRect:frame
                                         styleMask:NSWindowStyleMaskBorderless | NSWindowStyleMaskNonactivatingPanel
                                           backing:NSBackingStoreBuffered
                                             defer:NO];
    YTPanel.level = NSStatusWindowLevel;
    YTPanel.opaque = NO;
    YTPanel.backgroundColor = [NSColor clearColor];
    YTPanel.hasShadow = YES;
    YTPanel.hidesOnDeactivate = NO;
    YTPanel.becomesKeyOnlyIfNeeded = YES;
    YTPanel.collectionBehavior = NSWindowCollectionBehaviorCanJoinAllSpaces |
                                 NSWindowCollectionBehaviorFullScreenAuxiliary |
                                 NSWindowCollectionBehaviorTransient;

    YTPanelContentView *content = [[YTPanelContentView alloc] initWithFrame:frame];
    content.wantsLayer = YES;
    content.layer.cornerRadius = 8.0;
    content.layer.borderWidth = 1.0;
    YTContentView = content;
    YTPanel.contentView = content;

    YTIconView = [[NSImageView alloc] initWithFrame:NSMakeRect(20, 34, 48, 48)];
    YTIconView.imageScaling = NSImageScaleProportionallyUpOrDown;
    [content addSubview:YTIconView];

    YTApplicationIconView = [[NSImageView alloc] initWithFrame:NSMakeRect(84, 60, 32, 32)];
    YTApplicationIconView.imageScaling = NSImageScaleProportionallyUpOrDown;
    YTApplicationIconView.hidden = YES;
    [content addSubview:YTApplicationIconView];

    YTTitleLabel = YTLabel(NSMakeRect(84, 62, 286, 28), 18, NSFontWeightSemibold, NSColor.labelColor);
    [content addSubview:YTTitleLabel];
    YTSubtitleLabel = YTLabel(NSMakeRect(84, 30, 316, 22), 13, NSFontWeightRegular, NSColor.secondaryLabelColor);
    [content addSubview:YTSubtitleLabel];

    YTCancelTargetInstance = [[YTCancelTarget alloc] init];
    NSImage *cancelImage = [NSImage imageWithSystemSymbolName:@"xmark" accessibilityDescription:@"取消签名"];
    YTCancelButton = [NSButton buttonWithImage:cancelImage
                                        target:YTCancelTargetInstance
                                        action:@selector(cancelSigning:)];
    YTCancelButton.frame = NSMakeRect(380, 76, 28, 28);
    YTCancelButton.bezelStyle = NSBezelStyleCircular;
    YTCancelButton.bordered = NO;
    YTCancelButton.toolTip = @"取消签名";
    YTCancelButton.accessibilityLabel = @"取消签名";
    YTCancelButton.hidden = YES;
    [content addSubview:YTCancelButton];
    YTUpdatePanelAppearance();
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

static NSImage *YTApplicationIcon(NSString *bundleIdentifier) {
    if (bundleIdentifier.length == 0) {
        return nil;
    }
    if ([bundleIdentifier isEqualToString:NSBundle.mainBundle.bundleIdentifier]) {
        return NSApp.applicationIconImage;
    }
    NSURL *applicationURL = [NSWorkspace.sharedWorkspace URLForApplicationWithBundleIdentifier:bundleIdentifier];
    if (applicationURL == nil) {
        return nil;
    }
    return [NSWorkspace.sharedWorkspace iconForFile:applicationURL.path];
}

static void YTShow(NSString *symbol, NSColor *color, NSString *title, NSString *subtitle, NSString *bundleIdentifier) {
    YTBuildPanel();
    YTUpdatePanelAppearance();
    YTGeneration++;
    YTIconView.image = YTSymbol(symbol, color);
    NSImage *applicationIcon = YTApplicationIcon(bundleIdentifier);
    YTApplicationIconView.image = applicationIcon;
    YTApplicationIconView.hidden = applicationIcon == nil;
    YTApplicationIconView.toolTip = applicationIcon == nil ? nil : title;
    YTTitleLabel.frame = applicationIcon == nil
        ? NSMakeRect(84, 62, 286, 28)
        : NSMakeRect(124, 62, 246, 28);
    YTTitleLabel.stringValue = title;
    YTTitleLabel.toolTip = title;
    YTSubtitleLabel.stringValue = subtitle;
    YTSubtitleLabel.toolTip = subtitle;
    YTPositionPanel();
    [YTPanel orderFrontRegardless];
}

static void YTHideAfter(NSTimeInterval delay, unsigned long long generation) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (generation == YTGeneration) {
            YTCurrentRequestID = 0;
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
        YTCurrentRequestID = 0;
        atomic_store(&YTCancelRequestID, 0);
        YTCancelButton.hidden = YES;
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

void YTShowWaiting(const char *soundName, const char *titleText, const char *subtitleText, const char *bundleIdentifierText, unsigned long long requestID) {
    NSString *sound = soundName == NULL ? @"" : [NSString stringWithUTF8String:soundName];
    NSString *title = titleText == NULL ? @"未知程序正在请求 SSH 签名" : [NSString stringWithUTF8String:titleText];
    NSString *subtitle = subtitleText == NULL ? @"请触摸 YubiKey" : [NSString stringWithUTF8String:subtitleText];
    NSString *bundleIdentifier = bundleIdentifierText == NULL ? @"" : [NSString stringWithUTF8String:bundleIdentifierText];
    YTOnMain(^{
        YTCurrentRequestID = requestID;
        atomic_store(&YTCancelRequestID, 0);
        YTShow(@"hand.point.up.left.fill", NSColor.systemOrangeColor, title, subtitle, bundleIdentifier);
        YTCancelButton.enabled = YES;
        YTCancelButton.hidden = NO;
        if (sound.length > 0 && ![sound isEqualToString:@"none"]) {
            [[NSSound soundNamed:sound] play];
        }
    });
}

void YTShowSuccess(const char *titleText, const char *bundleIdentifierText, unsigned long long requestID) {
    NSString *title = titleText == NULL ? @"请求已授权" : [NSString stringWithUTF8String:titleText];
    NSString *bundleIdentifier = bundleIdentifierText == NULL ? @"" : [NSString stringWithUTF8String:bundleIdentifierText];
    YTOnMain(^{
        if (YTCurrentRequestID != requestID) {
            return;
        }
        atomic_store(&YTCancelRequestID, 0);
        YTCancelButton.hidden = YES;
        YTShow(@"checkmark.circle.fill", NSColor.systemGreenColor, title, @"SSH 签名已完成", bundleIdentifier);
        YTHideAfter(0.3, YTGeneration);
    });
}

void YTShowFailure(const char *titleText, const char *message, const char *bundleIdentifierText, unsigned long long requestID) {
    NSString *title = titleText == NULL ? @"请求失败" : [NSString stringWithUTF8String:titleText];
    NSString *detail = message == NULL ? @"请重试" : [NSString stringWithUTF8String:message];
    NSString *bundleIdentifier = bundleIdentifierText == NULL ? @"" : [NSString stringWithUTF8String:bundleIdentifierText];
    YTOnMain(^{
        if (YTCurrentRequestID != requestID) {
            return;
        }
        atomic_store(&YTCancelRequestID, 0);
        YTCancelButton.hidden = YES;
        YTShow(@"xmark.circle.fill", NSColor.systemRedColor, title, detail, bundleIdentifier);
        YTHideAfter(2.5, YTGeneration);
    });
}

void YTHide(unsigned long long requestID) {
    YTOnMain(^{
        if (YTCurrentRequestID != requestID) {
            return;
        }
        YTCurrentRequestID = 0;
        atomic_store(&YTCancelRequestID, 0);
        YTCancelButton.hidden = YES;
        [YTPanel orderOut:nil];
    });
}

unsigned long long YTConsumeCancelRequest(void) {
    return atomic_exchange(&YTCancelRequestID, 0);
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
