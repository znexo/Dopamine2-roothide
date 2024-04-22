#import <Foundation/Foundation.h>
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

//@class MIGlobalConfiguration;
//static NSMutableDictionary * (*orig_bundleIDMapForBundlesInDirectory)(_LOGOS_SELF_TYPE_NORMAL MIGlobalConfiguration* _LOGOS_SELF_CONST, SEL, NSURL *, NSString *, NSSet *); static NSMutableDictionary * new_bundleIDMapForBundlesInDirectory(_LOGOS_SELF_TYPE_NORMAL MIGlobalConfiguration *const self, SEL _cmd, NSURL *directoryURL, NSString *extension, NSSet *additionalKeys);
//
//static NSMutableDictionary * new_bundleIDMapForBundlesInDirectory(_LOGOS_SELF_TYPE_NORMAL MIGlobalConfiguration* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSURL * directoryURL, NSString * extension, NSSet * additionalKeys) {
//	NSLog(@"_bundleIDMapForBundlesInDirectory(%@, %@, %@)", directoryURL, extension, additionalKeys);
//
//	if ([directoryURL.path isEqualToString:@"/Applications"] && [extension isEqualToString:@"app"]) {
//		NSMutableDictionary *origMap = orig_bundleIDMapForBundlesInDirectory(self, _cmd, directoryURL, extension, additionalKeys);
//
//		NSURL *rootlessAppDir = [NSURL fileURLWithPath:@"/var/jb/Applications" isDirectory:YES];
//		NSMutableDictionary *rootlessAppsMap = orig_bundleIDMapForBundlesInDirectory(self, _cmd, rootlessAppDir, extension, additionalKeys);
//		[origMap addEntriesFromDictionary:rootlessAppsMap];
//		return origMap;
//	}
//
//	return orig_bundleIDMapForBundlesInDirectory(self, _cmd, directoryURL, extension, additionalKeys);
//}

void installdInit(void)
{
//    BOOTLOOP RISK, DO NOT TOUCH
//	  Class MIGlobalConfigurationClass = objc_getClass("MIGlobalConfiguration");
//    MSHookMessageEx(MIGlobalConfigurationClass, @selector(_bundleIDMapForBundlesInDirectory:withExtension:loadingAdditionalKeys:), (IMP) &new_bundleIDMapForBundlesInDirectory, (IMP*)&orig_bundleIDMapForBundlesInDirectory);
}
