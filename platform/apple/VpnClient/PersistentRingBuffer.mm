#import "PersistentRingBuffer.h"

#include "vpn/trusttunnel/persistent_ring_buffer.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

static NSMutableArray<NSString *> *convert_records(const std::vector<std::string> &records) {
    NSMutableArray<NSString *> *result = [[NSMutableArray alloc] initWithCapacity:records.size()];
    for (const std::string &record : records) {
        NSString *value = [[NSString alloc] initWithBytes:record.data()
                                                   length:record.size()
                                                 encoding:NSUTF8StringEncoding];
        if (value == nil) {
            return nil;
        }
        [result addObject:value];
    }
    return result;
}

@interface PersistentRingBufferReadResult ()

@property(nonatomic, copy, readwrite) NSArray<NSString *> *records;
@property(nonatomic, readwrite) uint64_t nextSequence;

- (instancetype)initWithRecords:(NSArray<NSString *> *)records nextSequence:(uint64_t)nextSequence;

@end

@implementation PersistentRingBufferReadResult

- (instancetype)initWithRecords:(NSArray<NSString *> *)records nextSequence:(uint64_t)nextSequence {
    self = [super init];
    if (self != nil) {
        self.records = records;
        self.nextSequence = nextSequence;
    }
    return self;
}

@end

static PersistentRingBufferReadResult *convert_result(const ag::RingBufferReadResult &result) {
    NSMutableArray<NSString *> *records = convert_records(result.records);
    if (records == nil) {
        return nil;
    }

    return [[PersistentRingBufferReadResult alloc] initWithRecords:records nextSequence:result.next_sequence];
}

@implementation PersistentRingBuffer {
    std::unique_ptr<ag::PersistentRingBuffer> _buffer;
}

- (instancetype)initWithPath:(NSString *)path {
    self = [super init];
    if (self != nil) {
        _buffer = std::make_unique<ag::PersistentRingBuffer>(std::string(path.UTF8String));
    }
    return self;
}

- (BOOL)appendRecord:(NSString *)record {
    return _buffer->append(std::string_view(record.UTF8String));
}

- (PersistentRingBufferReadResult *)readAll {
    std::optional<ag::RingBufferReadResult> result = _buffer->read_all();
    if (!result.has_value()) {
        return nil;
    }

    return convert_result(*result);
}

- (PersistentRingBufferReadResult *)readSince:(NSNumber * _Nullable)nextSequence {
    std::optional<uint64_t> native_next_sequence = std::nullopt;
    if (nextSequence != nil) {
        native_next_sequence = nextSequence.unsignedLongLongValue;
    }

    std::optional<ag::RingBufferReadResult> result = _buffer->read_since(native_next_sequence);
    if (!result.has_value()) {
        return nil;
    }

    return convert_result(*result);
}

- (BOOL)clear {
    return _buffer->clear();
}

@end