/*!
 *	Copyright 2015 Apple Inc. All rights reserved.
 *
 *	APPLE NEED TO KNOW CONFIDENTIAL
 *
 *  FileSigner.h
 *  FileSigningBundle
 *
 */

#import <Foundation/Foundation.h>


@interface FileSigner : NSObject

- (void)getSignature:(NSDictionary *)context;
- (void)writeSignature:(NSDictionary *)context;
- (void)checkSignature:(NSDictionary *)context;
- (void)signString:(NSDictionary *)context;
- (void)checkString:(NSDictionary *)context;
@end
