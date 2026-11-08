#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

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
    
    [self log:@"=== XPC Service Fuzzer ==="];
    [self log:@"Target: APFS-related XPC services"];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self fuzzXPCServices];
    });
    
    return YES;
}

- (void)fuzzXPCServices {
    [self log:@"\n[1] Searching for APFS XPC services..."];
    
    // Known APFS-related XPC services
    NSArray *services = @[
        @"com.apple.apfs.kext.xpc",
        @"com.apple.filesystems.apfs",
        @"com.apple.diskmanagementd",
        @"com.apple.storagekitd",
        @"com.apple.corestorage",
        @"com.apple.filesystems.hfs.kext",
    ];
    
    for (NSString *serviceName in services) {
        [self log:[NSString stringWithFormat:@"[2] Trying %@...", serviceName]];
        
        NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:serviceName options:0];
        
        // Set up interface
        connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(NSObject)];
        
        // Set up error handler
        connection.invalidationHandler = ^{
            [self log:[NSString stringWithFormat:@"[3] %@ connection invalidated", serviceName]];
        };
        
        connection.interruptionHandler = ^{
            [self log:[NSString stringWithFormat:@"[3] %@ connection interrupted", serviceName]];
        };
        
        [connection resume];
        
        // Try to send messages
        id remoteObject = [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
            [self log:[NSString stringWithFormat:@"[4] %@ error: %@", serviceName, error.localizedDescription]];
        }];
        
        // Send various selectors
        for (int i = 0; i < 20; i++) {
            SEL selector = NSSelectorFromString([NSString stringWithFormat:@"method%d", i]);
            if ([remoteObject respondsToSelector:selector]) {
                [self log:[NSString stringWithFormat:@"[5] %@ responds to %@!", serviceName, NSStringFromSelector(selector)]];
            }
        }
        
        // Try generic method
        @try {
            [remoteObject performSelector:@selector(description)];
        } @catch (NSException *exception) {
            [self log:[NSString stringWithFormat:@"[6] %@ exception: %@", serviceName, exception.reason]];
        }
        
        [connection invalidate];
    }
    
    [self log:@"\n=== Fuzz Complete ==="];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
