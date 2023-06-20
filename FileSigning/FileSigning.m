//
//  FileSigning.m
//  FileSigning
//
//  Created by varrior on 2023/6/20.
//

#import <AtlasLuaSequencer/AtlasLuaSequencer.h>
#import <AtlasLogging/AtlasLogging.h>
#import "FileSigning.h"

@implementation FileSigning

@end

#pragma mark -
#pragma mark Plugin Entry Point Functions

id PluginContextConstructor()
{
    return [FileSigning new];
}

NSDictionary *PluginFunctionTable()
{
    NSDictionary *fTable = @{
        // @"functionName" : @[ @[ ATKSelector(functionSignature), <arguments> ] ]
    };

    return fTable;
}

NSDictionary *PluginConstantTable()
{
    return @{
        //@"PI" : @M_PI
    };
}
