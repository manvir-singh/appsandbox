#ifndef ASB_FRAME_RLE_H
#define ASB_FRAME_RLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"

#define ASB_FRAME_PIXEL_BYTES 4u

/* The wire rectangle contains four signed 32-bit coordinates. */
typedef struct {
    int32_t left, top, right, bottom;
} AsbFrameRect;

typedef struct {
    uint8_t *data;
    size_t capacity;
} AsbFrameBuffer;

static inline int asb_frame_reserve(AsbFrameBuffer *buffer, size_t size)
{
    if (size <= buffer->capacity) return 1;

    uint8_t *data = (uint8_t *)realloc(buffer->data, size);
    if (!data) return 0;
    buffer->data = data;
    buffer->capacity = size;
    return 1;
}

/* Clip in place so that the same rectangle can be used to copy the pixels. */
static inline uint64_t asb_frame_rect_bytes(AsbFrameRect *rect, uint32_t width,
                                            uint32_t height)
{
    if (width > INT32_MAX || height > INT32_MAX) return 0;
    if (rect->left < 0) rect->left = 0;
    if (rect->top < 0) rect->top = 0;
    if (rect->right > (int32_t)width) rect->right = (int32_t)width;
    if (rect->bottom > (int32_t)height) rect->bottom = (int32_t)height;
    if (rect->left >= rect->right || rect->top >= rect->bottom) return 0;

    return (uint64_t)(rect->right - rect->left) * (rect->bottom - rect->top) *
           ASB_FRAME_PIXEL_BYTES;
}

static inline uint32_t asb_frame_payload_bytes(uint32_t wire_size, uint32_t width,
                                                uint32_t height, uint32_t stride,
                                                const AsbFrameRect *rects,
                                                uint32_t rect_count, uint32_t max_bytes)
{
    uint64_t full_size = (uint64_t)stride * height;
    if (!width || !height || (uint64_t)width * ASB_FRAME_PIXEL_BYTES > stride ||
        full_size > max_bytes)
        return 0;

    uint32_t size = (uint32_t)full_size;
    if (rect_count) {
        size = 0;
        for (uint32_t i = 0; i < rect_count; ++i) {
            AsbFrameRect rect = rects[i];
            uint64_t bytes = asb_frame_rect_bytes(&rect, width, height);
            if (bytes > max_bytes - size) return 0;
            size += (uint32_t)bytes;
        }
    }

    if (wire_size & ASB_FRAME_RLE_FLAG) {
        uint32_t packed = wire_size & ~ASB_FRAME_RLE_FLAG;
        return packed && packed < size ? size : 0;
    }
    return wire_size == size ? size : 0;
}

/* Each packet starts with a byte holding the pixel count minus one in the
 * low seven bits. The high bit selects one repeated pixel or literal pixels.
 * Packets can be concatenated across rows and dirty rectangles. */
static inline size_t asb_frame_encode(const uint8_t *src, size_t stride,
                                      size_t row_bytes, uint32_t height,
                                      uint8_t *dst, size_t capacity)
{
    if (!row_bytes || row_bytes % ASB_FRAME_PIXEL_BYTES || stride < row_bytes ||
        !height || height - 1 > (SIZE_MAX - row_bytes) / stride)
        return 0;

    size_t written = 0;
    for (uint32_t row = 0; row < height; ++row) {
        const uint8_t *pixels = src + (size_t)row * stride;
        size_t remaining = row_bytes / ASB_FRAME_PIXEL_BYTES;
        while (remaining) {
            size_t limit = remaining < 128 ? remaining : 128;
            size_t count = 1;
            int repeated = remaining > 1 &&
                memcmp(pixels, pixels + ASB_FRAME_PIXEL_BYTES, ASB_FRAME_PIXEL_BYTES) == 0;
            if (repeated) {
                while (count < limit &&
                       memcmp(pixels, pixels + count * ASB_FRAME_PIXEL_BYTES,
                              ASB_FRAME_PIXEL_BYTES) == 0)
                    ++count;
            } else {
                while (count < limit) {
                    const uint8_t *next = pixels + count * ASB_FRAME_PIXEL_BYTES;
                    if (count + 1 < remaining &&
                        memcmp(next, next + ASB_FRAME_PIXEL_BYTES, ASB_FRAME_PIXEL_BYTES) == 0)
                        break;
                    ++count;
                }
            }

            size_t pixel_bytes = count * ASB_FRAME_PIXEL_BYTES;
            size_t packet_bytes = repeated ? ASB_FRAME_PIXEL_BYTES : pixel_bytes;
            if (1 + packet_bytes > capacity - written) return 0;
            dst[written++] = (uint8_t)((repeated ? 0x80u : 0u) | (count - 1));
            memcpy(dst + written, pixels, packet_bytes);
            written += packet_bytes;
            pixels += pixel_bytes;
            remaining -= count;
        }
    }
    return written;
}

static inline int asb_frame_decode(const uint8_t *src, size_t size,
                                   uint8_t *dst, size_t decoded_size)
{
    size_t read = 0;
    size_t written = 0;
    while (read < size) {
        uint8_t control = src[read++];
        size_t pixel_bytes = ((control & 0x7fu) + 1) * ASB_FRAME_PIXEL_BYTES;
        int repeated = (control & 0x80u) != 0;
        size_t packet_bytes = repeated ? ASB_FRAME_PIXEL_BYTES : pixel_bytes;
        if (packet_bytes > size - read || pixel_bytes > decoded_size - written)
            return 0;

        if (repeated) {
            for (size_t offset = 0; offset < pixel_bytes; offset += ASB_FRAME_PIXEL_BYTES)
                memcpy(dst + written + offset, src + read, ASB_FRAME_PIXEL_BYTES);
        } else {
            memcpy(dst + written, src + read, pixel_bytes);
        }
        read += packet_bytes;
        written += pixel_bytes;
    }
    return decoded_size != 0 && written == decoded_size;
}

/* Apply a payload whose size and rectangles have already been validated. */
static inline void asb_frame_apply(uint8_t *dst, uint32_t dst_stride,
                                   const uint8_t *src, uint32_t src_stride,
                                   uint32_t width, uint32_t height,
                                   const AsbFrameRect *rects, uint32_t rect_count)
{
    if (!rect_count) {
        if (dst_stride == src_stride) {
            memcpy(dst, src, (size_t)src_stride * height);
        } else {
            size_t row_bytes = (size_t)width * ASB_FRAME_PIXEL_BYTES;
            for (uint32_t row = 0; row < height; ++row) {
                memcpy(dst + (size_t)row * dst_stride, src + (size_t)row * src_stride,
                       row_bytes);
            }
        }
        return;
    }

    for (uint32_t i = 0; i < rect_count; ++i) {
        AsbFrameRect rect = rects[i];
        if (!asb_frame_rect_bytes(&rect, width, height)) continue;

        size_t left = (size_t)rect.left * ASB_FRAME_PIXEL_BYTES;
        size_t row_bytes = (size_t)(rect.right - rect.left) * ASB_FRAME_PIXEL_BYTES;
        for (int32_t row = rect.top; row < rect.bottom; ++row) {
            memcpy(dst + (size_t)row * dst_stride + left, src, row_bytes);
            src += row_bytes;
        }
    }
}

#endif
