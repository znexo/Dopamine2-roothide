#import <Foundation/Foundation.h>
#include "common.h"
#include <roothide.h>
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

@class _LSCanOpenURLManager;
@class _LSQueryContext;

static BOOL
(*orig_canOpenURL)(_LOGOS_SELF_TYPE_NORMAL _LSCanOpenURLManager *_LOGOS_SELF_CONST, SEL, NSURL *, BOOL, BOOL,
                   NSXPCConnection *, NSError *);

static BOOL
replaced_canOpenURL(_LOGOS_SELF_TYPE_NORMAL _LSCanOpenURLManager *const self, SEL _cmd, NSURL *url, BOOL ispublic,
                    BOOL isprivate, NSXPCConnection *xpc, NSError *err);

static NSMutableDictionary *
(*orig_resolveQueries)(_LOGOS_SELF_TYPE_NORMAL _LSQueryContext *_LOGOS_SELF_CONST, SEL, id, NSXPCConnection *,
                       NSError *);

static NSMutableDictionary *
replaced_resolveQueries(_LOGOS_SELF_TYPE_NORMAL _LSQueryContext *const self, SEL _cmd, id queries, NSXPCConnection *xpc,
                        NSError *err);


static BOOL
replaced_canOpenURL(_LOGOS_SELF_TYPE_NORMAL _LSCanOpenURLManager *_LOGOS_SELF_CONST __unused self, SEL __unused _cmd,
                    NSURL *url, BOOL ispublic, BOOL isprivate, NSXPCConnection *xpc, NSError *err) {
    char pathbuf[PATH_MAX] = {0};
    if (xpc) {

        proc_pidpath(xpc.processIdentifier, pathbuf, sizeof(pathbuf));
    }

    NSLog(@"canOpenURL:%@ publicSchemes:%d privateSchemes:%d XPCConnection:%@ proc:%d,%s", url, ispublic, isprivate,
          xpc, xpc.processIdentifier, pathbuf);


    NSArray *jbschemes = @[
            @"filza",
            @"db-lmvo0l08204d0a0",
            @"boxsdk-810yk37nbrpwaee5907xc4iz8c1ay3my",
            @"com.googleusercontent.apps.802910049260-0hf6uv6nsj21itl94v66tphcqnfl172r",
            @"sileo",
            @"zbra",
            @"santander",
            @"icleaner",
            @"xina",
            @"ssh",
            @"apt-repo",
            @"cydia",
            @"activator",
            @"postbox",
    ];

    if (xpc && isNormalAppPath(pathbuf)) {
        if ([jbschemes containsObject:url.scheme.lowercaseString]) {
            NSLog(@"block %@ for %s", url, pathbuf);
            return NO;
        }
    }

    return orig_canOpenURL(self, _cmd, url, ispublic, isprivate, xpc, err);
}

static NSMutableDictionary *
replaced_resolveQueries(_LOGOS_SELF_TYPE_NORMAL _LSQueryContext *_LOGOS_SELF_CONST __unused self, SEL __unused _cmd,
                        id queries, NSXPCConnection *xpc, NSError *err) {
    NSMutableDictionary *result = orig_resolveQueries(self, _cmd, queries, xpc, err);

    char pathbuf[PATH_MAX] = {0};
    if (xpc) {
        proc_pidpath(xpc.processIdentifier, pathbuf, sizeof(pathbuf));
    }

    NSLog(@"_resolveQueries:%@ XPCConnection:%@ count=%ld proc:%d,%s", queries, xpc, result.count,
          xpc.processIdentifier, pathbuf);

    if (result) {
        NSLog(@"result=%@", result.class);

        for (id key in result) {
            NSLog(@"result=%@, %@", [key class], [result[key] class]);
            if ([key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithUnits")]) {


                if (xpc && isNormalAppPath(pathbuf)) {
                    NSMutableIndexSet *removed = [[NSMutableIndexSet alloc] init];
                    for (int i = 0; i < [result[key] count]; i++) {
                        id plugin = result[key][i];
                        id appbundle = [plugin performSelector:@selector(containingBundle)];

                        if (!appbundle) continue;

                        NSURL *bundleURL = [appbundle performSelector:@selector(bundleURL)];
                        if (isJailbreakPath(bundleURL.path.fileSystemRepresentation)) {
                            NSLog(@"remove %@ for %s", plugin, pathbuf);
                            [removed addIndex:i];
                        }
                    }

                    [result[key] removeObjectsAtIndexes:removed];

                    NSMutableArray *units = [[key valueForKey:@"_pluginUnits"] mutableCopy];
                    [units removeObjectsAtIndexes:removed];
                    [key setValue:[units copy] forKey:@"_pluginUnits"];

                }
            }
        }
        NSLog(@"result=%@", result);
    }

    return result;
}


NSURL *(*orig_LSGetInboxURLForBundleIdentifier)(NSString *bundleIdentifier) =NULL;

NSURL *new_LSGetInboxURLForBundleIdentifier(NSString *bundleIdentifier) {
    NSURL *pathURL = orig_LSGetInboxURLForBundleIdentifier(bundleIdentifier);

    if (![bundleIdentifier hasPrefix:@"com.apple."]
        && [pathURL.path hasPrefix:@"/var/mobile/Library/Application Support/Containers/"]) {
        NSLog(@"redirect Inbox %@ : %@", bundleIdentifier, pathURL);
        pathURL = [NSURL fileURLWithPath:jbroot(pathURL.path)];
    }

    return pathURL;
}


void lsdInit(void) {
    NSLog(@"lsdInit...");

    MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");
    void *_LSGetInboxURLForBundleIdentifier = MSFindSymbol(coreServicesImage, "__LSGetInboxURLForBundleIdentifier");
    NSLog(@"coreServicesImage=%p, _LSGetInboxURLForBundleIdentifier=%p", coreServicesImage,
          _LSGetInboxURLForBundleIdentifier);
    if (_LSGetInboxURLForBundleIdentifier) {
        MSHookFunction(_LSGetInboxURLForBundleIdentifier, (void *) &new_LSGetInboxURLForBundleIdentifier,
                       (void **) &orig_LSGetInboxURLForBundleIdentifier);
    }

    Class LSCanOpenURLManagerClass = objc_getClass("_LSCanOpenURLManager");
    MSHookMessageEx(LSCanOpenURLManagerClass,
                    @selector(canOpenURL:publicSchemes:privateSchemes:XPCConnection:error:),
                    (IMP) &replaced_canOpenURL,
                    (IMP *) &orig_canOpenURL);
    Class LSQueryContextClass = objc_getClass("_LSQueryContext");
    MSHookMessageEx(LSQueryContextClass,
                    @selector(_resolveQueries:XPCConnection:error:),
                    (IMP) &replaced_resolveQueries,
                    (IMP *) &orig_resolveQueries);
}
