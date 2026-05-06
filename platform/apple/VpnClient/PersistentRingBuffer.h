#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PersistentRingBufferReadResult : NSObject

@property(nonatomic, copy, readonly) NSArray<NSString *> *records;
@property(nonatomic, readonly) uint64_t nextSequence;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

@interface PersistentRingBuffer : NSObject

- (instancetype)initWithPath:(NSString *)path;
- (BOOL)appendRecord:(NSString *)record;
- (nullable PersistentRingBufferReadResult *)readAll;
- (nullable PersistentRingBufferReadResult *)readSince:(NSNumber *_Nullable)nextSequence;
- (BOOL)clear;

@end

NS_ASSUME_NONNULL_END