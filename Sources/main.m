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
    self.logView.text = @"IOKit Property Enumerator\n\n";
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
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
    [self log:@"[1] Enumerating IOKit registry...\n"];
    
    // Get all services
    io_iterator_t iterator;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOService"), &iterator);
    if (kr != KERN_SUCCESS) {
        [self log:@"Failed to get services"];
        return;
    }
    
    int count = 0;
    int interesting = 0;
    io_service_t service;
    
    while ((service = IOIteratorNext(iterator)) && count < 500) {
        count++;
        
        // Get service name
        io_name_t name;
        if (IORegistryEntryGetName(service, name) == KERN_SUCCESS) {
            NSString *serviceName = [NSString stringWithUTF8String:name];
            
            // Get properties
            CFMutableDictionaryRef properties = NULL;
            kr = IORegistryEntryCreateCFProperties(service, &properties, kCFAllocatorDefault, kNilOptions);
            if (kr == KERN_SUCCESS && properties) {
                NSDictionary *props = (__bridge NSDictionary *)properties;
                
                // Look for interesting properties
                BOOL isInteresting = NO;
                NSString *reason = @"";
                
                // Check for user client class
                NSString *userClient = props[@"IOUserClientClass"];
                if (userClient) {
                    isInteresting = YES;
                    reason = [reason stringByAppendingString:@"[UserClient] "];
                }
                
                // Check for entitlement requirements
                NSString *entitlements = props[@"IOUserClientEntitlements"];
                if (entitlements) {
                    isInteresting = YES;
                    reason = [reason stringByAppendingString:@"[Entitlements] "];
                }
                
                // Check for privileged access
                NSNumber *privileged = props[@"IOPrivileged"];
                if (privileged && [privileged boolValue]) {
                    isInteresting = YES;
                    reason = [reason stringByAppendingString:@"[Privileged] "];
                }
                
                // Check for dangerous keys
                if (props[@"IOKitDebug"]) {
                    isInteresting = YES;
                    reason = [reason stringByAppendingString:@"[Debug] "];
                }
                
                if (isInteresting) {
                    interesting++;
                    NSString *msg = [NSString stringWithFormat:@"*** %@: %@ (%lu props)", serviceName, reason, (unsigned long)props.count];
                    [self log:msg];
                    
                    // Log all properties for interesting services
                    for (NSString *key in props) {
                        NSString *propMsg = [NSString stringWithFormat:@"    %@ = %@", key, props[key]];
                        [self log:propMsg];
                    }
                }
                
                CFRelease(properties);
            }
        }
        
        IOObjectRelease(service);
        
        // Yield to prevent watchdog
        if (count % 50 == 0) {
            usleep(10000);
            NSString *progress = [NSString stringWithFormat:@"... scanned %d services, %d interesting", count, interesting];
            [self log:progress];
        }
    }
    
    IOObjectRelease(iterator);
    
    NSString *summary = [NSString stringWithFormat:@"\n[2] Complete: %d services scanned, %d interesting found", count, interesting];
    [self log:summary];
    
    if (interesting == 0) {
        [self log:@"\nNo interesting services found. iOS 27.0.1 has locked down IOKit."];
    }
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
