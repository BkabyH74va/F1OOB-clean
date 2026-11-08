#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) UITextView *logView;
@property (strong, nonatomic) NSMutableString *logBuffer;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    
    UIViewController *vc = [[UIViewController alloc] init];
    self.logView = [[UITextView alloc] initWithFrame:self.window.bounds];
    self.logView.editable = NO;
    self.logView.text = @"IOKit Enumerator Starting...\n";
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
    // Delay IOKit work to let UI fully load
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self enumerate];
    });
    
    return YES;
}

- (void)log:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingString:[msg stringByAppendingString:@"\n"]];
    });
}

- (void)enumerate {
    [self log:@"[1] Starting enumeration...\n"];
    
    int openable = 0, blocked = 0, notfound = 0, total = 0;
    
    NSArray *services = @[
        @"AppleAPFSVolume",
        @"AppleAPFSContainer",
        @"AppleAPFSVolumeBSDClient",
        @"AppleAPFSContainerBSDClient",
        @"AppleAPFSManager",
        @"AppleFileSystemDriver",
        @"AppleNVMeSMARTUserClient",
        @"IOHIDLibUserClient",
        @"IOAESAcceleratorUserClient",
        @"IOBlockStorageDevice",
        @"IOMedia",
        @"IOMediaBSDClient",
        @"IOUSBDevice",
        @"IOUSBHostDevice",
        @"IOBluetoothDevice",
        @"IOAudioDevice",
        @"IOGraphicsDevice",
        @"IONetworkInterface",
        @"IONetworkController",
        @"IOPlatformDevice",
        @"IOPlatformExpert",
        @"IOCPU",
        @"IOPowerDevice",
        @"IOService",
        @"IORegistryEntry",
    ];
    
    for (NSString *name in services) {
        total++;
        
        // Log on main thread
        dispatch_async(dispatch_get_main_queue(), ^{
            self.logView.text = [self.logView.text stringByAppendingString:[NSString stringWithFormat:@"Testing %@...\n", name]];
        });
        
        // Do IOKit work on background thread
        io_service_t service = IOServiceGetMatchingService(0, IOServiceMatching([name UTF8String]));
        if (!service) {
            notfound++;
            dispatch_async(dispatch_get_main_queue(), ^{
                self.logView.text = [self.logView.text stringByAppendingString:[NSString stringWithFormat:@"  %@ NOT FOUND\n", name]];
            });
            continue;
        }
        
        io_connect_t conn;
        kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
        
        if (kr == KERN_SUCCESS) {
            openable++;
            dispatch_async(dispatch_get_main_queue(), ^{
                self.logView.text = [self.logView.text stringByAppendingString:[NSString stringWithFormat:@"  *** %@ OPENED! ***\n", name]];
            });
            IOServiceClose(conn);
        } else if (kr == kIOReturnNotPermitted) {
            blocked++;
            dispatch_async(dispatch_get_main_queue(), ^{
                self.logView.text = [self.logView.text stringByAppendingString:[NSString stringWithFormat:@"  %@ BLOCKED\n", name]];
            });
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.logView.text = [self.logView.text stringByAppendingString:[NSString stringWithFormat:@"  %@ error: 0x%x\n", name, kr]];
            });
        }
        
        IOObjectRelease(service);
        
        // Critical: yield to prevent watchdog
        usleep(50000); // 50ms
    }
    
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingString:[NSString stringWithFormat:@"\n=== DONE: %d total, %d open, %d blocked, %d not found ===\n", total, openable, blocked, notfound]];
    });
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
