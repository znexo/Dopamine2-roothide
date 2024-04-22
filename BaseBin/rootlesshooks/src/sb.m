#import <Foundation/Foundation.h>
#import "common.h"
#import <roothide.h>

@interface XBSnapshotContainerIdentity : NSObject
@property NSString* bundleIdentifier;
@end

#include <substrate.h>
#if defined(__clang__)
#if __has_feature(objc_arc)
#define _LOGOS_SELF_TYPE_NORMAL __unsafe_unretained
#define _LOGOS_SELF_TYPE_INIT __attribute__((ns_consumed))
#define _LOGOS_SELF_CONST const
#define _LOGOS_RETURN_RETAINED __attribute__((ns_returns_retained))
#else
#define _LOGOS_SELF_TYPE_NORMAL
#define _LOGOS_SELF_TYPE_INIT
#define _LOGOS_SELF_CONST
#define _LOGOS_RETURN_RETAINED
#endif
#else
#define _LOGOS_SELF_TYPE_NORMAL
#define _LOGOS_SELF_TYPE_INIT
#define _LOGOS_SELF_CONST
#define _LOGOS_RETURN_RETAINED
#endif

@class XBSnapshotContainerIdentity; 
static NSString * (*orig_snapshotContainerPath)(_LOGOS_SELF_TYPE_NORMAL XBSnapshotContainerIdentity* _LOGOS_SELF_CONST, SEL); static NSString * replaced_snapshotContainerPath(_LOGOS_SELF_TYPE_NORMAL XBSnapshotContainerIdentity *const self, SEL _cmd);

static NSString * replaced_snapshotContainerPath(_LOGOS_SELF_TYPE_NORMAL XBSnapshotContainerIdentity* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd) {
    NSString* path = orig_snapshotContainerPath(self, _cmd);

    if([path hasPrefix:@"/var/mobile/Library/SplashBoard/Snapshots/"] && ![self.bundleIdentifier hasPrefix:@"com.apple."]) {
        NSLog(@"snapshotContainerPath redirect %@ : %@", self.bundleIdentifier, path);
        path = jbroot(path);
    }

    return path;
}

void sbInit(void)
{
	NSLog(@"sbInit...");
	Class XBSnapshotContainerIdentityClass = objc_getClass("XBSnapshotContainerIdentity");
    MSHookMessageEx(XBSnapshotContainerIdentityClass, @selector(snapshotContainerPath), (IMP) &replaced_snapshotContainerPath, (IMP*)&orig_snapshotContainerPath);
}
