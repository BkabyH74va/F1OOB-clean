#import <UIKit/UIKit.h>
#import <xpc/xpc.h>

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
    self.logView.text = @"XPC Fuzzer\n\n";
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self fuzz];
    });
    
    return YES;
}

- (void)fuzz {
    NSArray *services = @[
        @"com.apple.apfs.kext.xpc",
        @"com.apple.filesystems.apfs",
        @"com.apple.diskmanagementd",
        @"com.apple.storagekitd",
    ];
    
    for (NSString *name in services) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.logView.text = [self.logView.text stringByAppendingString:[NSString stringWithFormat:@"Trying %@...\n", name]];
        });
        
        // Use low-level XPC API — available on iOS
        xpc_connection_t conn = xpc_connection_create_mach_service([name UTF8String], NULL, 0);
        
        if (conn) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.logView.text = [self.logView.text stringByAppendingString:[NSString stringWithFormat:@"%@ connected!\n", name]];
            });
            
            // Set event handler
            xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
                xpc_type_t type = xpc_get_type(event);
                if (type == XPC_TYPE_ERROR) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        self.logView.text = [self.logView.text stringByAppendingString:[NSString stringWithFormat:@"%@ error: %s\n", name, xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION)]];
                    });
                }
            });
            
            xpc_connection_resume(conn);
            
            // Send a test message
            xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
            xpc_dictionary_set_string(msg, "command", "test");
            xpc_connection_send_message(conn, msg);
            
            [NSThread sleepForTimeInterval:0.5];
            xpc_release(msg);
            xpc_connection_cancel(conn);
            xpc_release(conn);
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.logView.text = [self.logView.text stringByAppendingString:[NSString stringWithFormat:@"%@ failed\n", name]];
            });
        }
    }
    
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingString:@"Done\n"];
    });
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
