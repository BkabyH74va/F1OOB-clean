#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) UITextView *logView;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    
    UIViewController *vc = [[UIViewController alloc] init];
    self.logView = [[UITextView alloc] initWithFrame:self.window.bounds];
    self.logView.editable = NO;
    self.logView.text = @"IOKit APFS Fuzzer\n\n";
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self fuzz];
    });
    
    return YES;
}

- (void)log:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingString:[msg stringByAppendingString:@"\n"]];
    });
}

- (void)fuzz {
    [self log:@"[1] Searching for APFS services..."];
    
    // Search for any service with "APFS" in the name
    io_iterator_t iterator;
    kern_return_t kr = IOServiceGetMatchingServices(0, IOServiceNameMatching("AppleAPFS"), &iterator);
    
    if (kr != KERN_SUCCESS) {
        [self log:@"No AppleAPFS services found"];
        // Try broader search
        kr = IOServiceGetMatchingServices(0, IOServiceMatching("IOService"), &iterator);
    }
    
    io_service_t service;
    int count = 0;
    while ((service = IOIteratorNext(iterator)) != 0) {
        count++;
        
        // Get service name
        io_name_t name;
        IORegistryEntryGetName(service, name);
        
        // Check if APFS-related
        NSString *nameStr = [NSString stringWithUTF8String:name];
        if ([nameStr containsString:@"APFS"] || [nameStr containsString:@"apfs"] || 
            [nameStr containsString:@"Volume"] || [nameStr containsString:@"Disk"]) {
            
            [self log:[NSString stringWithFormat:@"[2] Found: %@ (0x%x)", nameStr, service]];
            
            // Try to open
            io_connect_t conn;
            kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
            if (kr == KERN_SUCCESS) {
                [self log:[NSString stringWithFormat:@"[3] Opened %@: 0x%x", nameStr, conn]];
                
                // Fuzz selectors
                for (int sel = 0; sel < 100; sel++) {
                    uint64_t input[10] = {0};
                    uint64_t output[10] = {0};
                    uint32_t outputCnt = 10;
                    
                    kr = IOConnectCallMethod(conn, sel, input, 10, NULL, 0, output, &outputCnt, NULL, NULL);
                    if (kr != KERN_SUCCESS && kr != 0xe00002c2) {
                        [self log:[NSString stringWithFormat:@"[4] %@ selector %d: 0x%x", nameStr, sel, kr]];
                    }
                }
                
                IOServiceClose(conn);
            } else {
                [self log:[NSString stringWithFormat:@"[3] Failed to open %@: 0x%x", nameStr, kr]];
            }
        }
        
        IOObjectRelease(service);
        if (count > 100) break;
    }
    
    IOObjectRelease(iterator);
    [self log:@"[5] Done"];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
