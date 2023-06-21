/*!
 *	Copyright 2015 Apple Inc. All rights reserved.
 *
 *	APPLE NEED TO KNOW CONFIDENTIAL
 */

#import "FileSigner.h"
#import <CommonCrypto/CommonDigest.h>
#import <AtlasLogging/AtlasLogging.h>
#import "FileSigning.h"
// Static SHA1 salt
#define mySalt "54c2eac76b0343717cb686d6d42120a47bea32f0"

#define errDomain @"com.Apple.HWTE.FileSigner"

@interface FileSigner ()
{
    NSData *salt1;
    NSData *salt2;
}

-(NSString*)sigPathForFile:(NSString*)input;

@end

@implementation FileSigner

- (instancetype)init
{
    self = [super init];

    if (self)
    {
        unsigned int p1[] = {0x54c2eac7,
            0x6b034371,
            0x7cb686d6,
            0xd42120a4,
            0x7bea32f0};
        // A bit more obfuscation. The actual result doesn't matter, just that it's done consistently
        unsigned int p2[] = {p1[1], p1[2], (p1[3] << 16) ^ (p1[3] >> 16), p1[4], p1[0]};
        salt1 = [NSData dataWithBytes:p1 length:20];
        salt2 = [NSData dataWithBytes:p2 length:20];
    }

    return self;
}


- (BOOL)writeSignature:(NSDictionary *)context error:(NSError ** )error
{
         
        NSString *computedHash = [self getSignature:context error:error];
        
        NSString *sigFilePath = [self sigPathForFile:context[@"targetfile"]];
        
        NSFileManager *filemgr = [[NSFileManager alloc] init];
        BOOL isDir = false;
        if([filemgr fileExistsAtPath:sigFilePath isDirectory:&isDir]) {
            [filemgr removeItemAtPath:sigFilePath error:error];
        }
        if(*error != nil) {
           ATKLogError("%@", (*error).localizedDescription);
            return FALSE;
        }
        
        [computedHash writeToFile:sigFilePath atomically:true encoding:NSUTF8StringEncoding error:error];
        if(*error != nil) {
           ATKLogError("%@", (*error).localizedDescription);
            return FALSE;
        }
        ATKLog("Hash write successful");
        return TRUE;
}

- (void)checkSignature:(NSDictionary *)context
{
    [self getSignature:context];
    if(context.records.overallRecordStatus != TRUE) {
        return;
    }
    
    [context runTest:^CTRecordStatus (NSError *__autoreleasing *error) {
        NSString *computedHash = context.output;
        
        NSString *sigFilePath = [self sigPathForFile:context[@"targetfile"]];
        
        NSFileManager *filemgr = [[NSFileManager alloc] init];
        BOOL isDir = false;
        if(![filemgr fileExistsAtPath:sigFilePath isDirectory:&isDir]) {
            *error = [NSError errorWithDomain:errDomain code:1 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"File does not exist: %@", sigFilePath]}];
           ATKLogError("%@", (*error).localizedDescription);
            return FALSE;
        }
        
        if(isDir) {
            *error = [NSError errorWithDomain:errDomain code:1 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Is a directory: %@", sigFilePath]}];
           ATKLogError("%@", (*error).localizedDescription);
            return FALSE;
        }
        
        NSString *readHash = [NSString stringWithContentsOfFile:sigFilePath encoding:NSUTF8StringEncoding error:error];
        if(*error != nil) {
           ATKLogError("%@", (*error).localizedDescription);
            return FALSE;
        }
        
        if([readHash compare:computedHash] != NSOrderedSame) {
            *error = [NSError errorWithDomain:errDomain code:3 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Hash mismatch against: %@", sigFilePath]}];
           ATKLogError("%@", (*error).localizedDescription);
            return FALSE;
        }
        
       ATKLog("Hash check successful.");
        return TRUE;
    }];
}

- (NSString *)getSignature:(NSDictionary *)context error:(NSError **)error
{
        NSData *salt = nil;
        if(!context[@"areFilesSecure"]) {
            // Use an alternate set of keys if station is not secure
           ATKLogError("Station files are insecure");
            salt = salt1;

        } else {
           ATKLog("Station file are secure");
            salt = salt2;
        }
        
        NSString *targetfilePath = context[@"targetfile"];
        NSFileManager *filemgr = [[NSFileManager alloc] init];
        BOOL isDir = false;
        if(![filemgr fileExistsAtPath:targetfilePath isDirectory:&isDir]) {
            *error = [NSError errorWithDomain:errDomain code:1 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"File does not exist: %@", targetfilePath]}];
           ATKLogError("%@", (*error).localizedDescription);
            return FALSE;
        }
        
        if(isDir) {
            *error = [NSError errorWithDomain:errDomain code:1 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Is a directory: %@", targetfilePath]}];
           ATKLogError("%@", (*error).localizedDescription);
            return FALSE;
        }
        
        //Read it
        NSMutableData *fileData = [NSMutableData dataWithContentsOfFile:targetfilePath];
        //Salt it
        [fileData appendData:salt];
        //Hash it
        unsigned char digest[CC_SHA1_DIGEST_LENGTH];
        CC_SHA1(fileData.bytes, (CC_LONG)fileData.length, digest);
        
        //Format into NSString
        NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH];
        for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        {
            [result appendFormat:@"%02x", digest[i]];
        }
        
        return result;
}

- (void)signString:(NSDictionary *)context
{
        NSData *salt = nil;
        if(!context[@"areFilesSecure"]) {
//        if(false) {   //For debug testing
            // Use an alternate set of keys if station is not secure
           ATKLogError("Station files are insecure");
            salt = salt1;
            //*error = [NSError errorWithDomain:errDomain code:2 userInfo:@{NSLocalizedDescriptionKey : @"Station Sequence/Resource File Security Failed!"}];
            //CTLog(CTLOG_LEVEL_ERR, @"%@", (*error).localizedDescription);
            //return FALSE;
        } else {
           ATKLog("Station file are secure");
            salt = salt2;
        }
        
        NSString *inputString = context[@"input"];
        NSString *nonWhitePlainString = [[[inputString stringByReplacingOccurrencesOfString:@"\n"
                                                                                 withString:@""] stringByReplacingOccurrencesOfString:@"\r"
                                          withString:@""] stringByReplacingOccurrencesOfString:@" "
                                         withString:@""];
        
        //Read it
        NSData *stringData = [nonWhitePlainString dataUsingEncoding:NSUTF8StringEncoding];
        stringData = [stringData subdataWithRange:NSMakeRange(0, [stringData length] - 1)];
        NSMutableData *mutableData = [NSMutableData dataWithData:stringData];
        //Salt it
        [mutableData appendData:salt];
        //Hash it
        unsigned char digest[CC_SHA1_DIGEST_LENGTH];
        CC_SHA1(mutableData.bytes, (CC_LONG)mutableData.length, digest);
        
        //Format into NSString
        NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH];
        for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        {
            [result appendFormat:@"%02x", digest[i]];
        }
        
       ATKLog("Hashing: %@\nResult:%@", nonWhitePlainString, result);
        
        context.output = [NSString stringWithFormat:@"%@\n%@", inputString, result];
        
        return TRUE;
    }];
}

- (BOOL)checkString:(NSDictionary *)context
{
    [context runTest:^CTRecordStatus (NSError *__autoreleasing *error) {
        NSData *salt = nil;
        if(!context.areFilesSecure) {
//        if(false) {   //For debug testing
            // Use an alternate set of keys if station is not secure
           ATKLogError("Station files are insecure");
            salt = salt1;
            //*error = [NSError errorWithDomain:errDomain code:2 userInfo:@{NSLocalizedDescriptionKey : @"Station Sequence/Resource File Security Failed!"}];
            //CTLog(CTLOG_LEVEL_ERR, @"%@", (*error).localizedDescription);
            //return FALSE;
        } else {
           ATKLog("Station file are secure");
            salt = salt2;
        }
        
        NSString *inputString = context[@"input"];
        
        //Chop out the last line, which is the hash
        NSArray *inputArray = [inputString componentsSeparatedByString:@"\n"];
        if([inputArray count] < 2) {
            *error = [NSError errorWithDomain:errDomain code:3 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"No hash found in: %@", inputString]}];
           ATKLogError("%@", (*error).localizedDescription);
            return FALSE;
        }
        NSString *hashString = inputArray[[inputArray count]-1];
        NSRange plainRange = NSMakeRange(0, [inputString length] - [hashString length] - 1);
        NSString *plainString = [inputString substringWithRange:plainRange];
        NSString *nonWhitePlainString = [[[plainString stringByReplacingOccurrencesOfString:@"\n"
                                                                               withString:@""] stringByReplacingOccurrencesOfString:@"\r"
                                         withString:@""] stringByReplacingOccurrencesOfString:@" "
                                        withString:@""];
        
        //Read it
        NSData *stringData = [nonWhitePlainString dataUsingEncoding:NSUTF8StringEncoding];
        stringData = [stringData subdataWithRange:NSMakeRange(0, [stringData length] - 1)];
        NSMutableData *mutableData = [NSMutableData dataWithData:stringData];
        //Salt it
        [mutableData appendData:salt];
        //Hash it
        unsigned char digest[CC_SHA1_DIGEST_LENGTH];
        CC_SHA1(mutableData.bytes, (CC_LONG)mutableData.length, digest);
        
        //Format into NSString
        NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH];
        for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        {
            [result appendFormat:@"%02x", digest[i]];
        }
        
       ATKLog("Hashing: %@\nResult: %@\nGiven: %@", nonWhitePlainString, result, hashString);
       ATKLog("LengthResult: %lu\nLengthGiven: %lu", [result length], [hashString length]);
        NSComparisonResult compared = [hashString compare:result options:0 range:NSMakeRange(0, [result length])];
       ATKLog("Compare Result: %lu", compared);
        if(compared != NSOrderedSame) {
            *error = [NSError errorWithDomain:errDomain code:3 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Hash mismatch"]}];
           ATKLogError("%@", (*error).localizedDescription);
            return FALSE;
        }
        context.output = plainString;
        return TRUE;
}

-(NSString*)sigPathForFile:(NSString*)input
{
    //Find the matching file
    NSString *sigFileDir = [input stringByDeletingLastPathComponent];
    NSString *sigFileName = [NSString stringWithFormat:@".%@.sig", [input lastPathComponent]];
    NSString *sigFilePath = [NSString stringWithFormat:@"%@/%@", sigFileDir, sigFileName];
    
    return sigFilePath;
}

@end
