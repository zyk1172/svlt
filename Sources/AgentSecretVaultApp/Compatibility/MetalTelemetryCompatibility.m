#import <Foundation/Foundation.h>

// Intentionally left without runtime hooks.
//
// An early macOS 27 beta workaround added NSString-style selectors to the
// private __NSCFNumber class at image load time. That changed Foundation
// behavior process-wide and could affect unrelated framework code. The
// workaround has been retired; compatibility issues must be handled without
// mutating Foundation classes or private runtime implementations.
