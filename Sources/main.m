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
    self.logView.text = @"IOKit Service Enumerator\n\n";
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
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
    [self log:@"[1] Enumerating IOKit services...\n"];
    
    int openable = 0, blocked = 0, notfound = 0, total = 0;
    
    // Services to test
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
        [self log:[NSString stringWithFormat:@"[2] Testing %@...", name]];
        
        io_service_t service = IOServiceGetMatchingService(0, IOServiceMatching([name UTF8String]));
        if (!service) {
            notfound++;
            [self log:[NSString stringWithFormat:@"  %@ NOT FOUND", name]];
            continue;
        }
        
        // Try to open
        io_connect_t conn;
        kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
        
        if (kr == KERN_SUCCESS) {
            openable++;
            [self log:[NSString stringWithFormat:@"  *** %@ OPENED! (CWE-862 candidate) ***", name]];
            IOServiceClose(conn);
        } else if (kr == kIOReturnNotPermitted) {
            blocked++;
            [self log:[NSString stringWithFormat:@"  %@ BLOCKED (sandbox)", name]];
        } else {
            [self log:[NSString stringWithFormat:@"  %@ error: 0x%x", name, kr]];
        }
        
        IOObjectRelease(service);
        
        // Small delay to prevent watchdog
        usleep(10000);
    }
    
    [self log:[NSString stringWithFormat:@"\n[3] Summary: %d total, %d openable, %d blocked, %d not found", total, openable, blocked, notfound]];
    
    if (openable > 0) {
        [self log:@"\n!!! CWE-862 CANDIDATES FOUND !!!"];
    } else {
        [self log:@"\nNo openable services found."];
    }
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
