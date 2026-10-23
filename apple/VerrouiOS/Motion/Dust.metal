// Archiving an item (iPhone app only): its page turns to dust. Grains leave
// from left to right, drift up and to the right, speed up and fade. Applied
// by SwiftUI (`.layerEffect`, DustEffect.swift) to a snapshot of the page,
// only during the animation.
//
// Each output point shows the grain that landed there: the source is read
// back along the grain's drift, rounded to the grain grid so that each
// grain stays one solid square.

#include <metal_stdlib>
#include <SwiftUI/SwiftUI_Metal.h>
using namespace metal;

static float hash(float2 p) {
    return fract(sin(dot(p, float2(127.1, 311.7))) * 43758.5453);
}

[[ stitchable ]]
half4 Dust(float2 position, SwiftUI::Layer layer,
           float2 size,      // snapshot size, in points
           float progress,   // 0 → 1 over the animation
           float grain,      // grain side, in points
           float distance)   // how far the fastest grain goes, in points
{
    float2 cell = floor(position / grain);
    float r1 = hash(cell);
    float r2 = hash(cell + 17.31);
    float r3 = hash(cell + 41.77);
    // Left to right, a little bottom to top, with some scatter.
    // The sweep spans the whole animation: the last grains leave at the end.
    float start = (position.x / size.x) * 0.6 + (1.0 - position.y / size.y) * 0.08 + r1 * 0.12;
    float t = clamp((progress * 1.4 - start) / 0.6, 0.0, 1.0);
    if (t <= 0.0) {
        return layer.sample(position);
    }
    // Up and to the right, accelerating.
    float2 drift = float2(0.25 + r2 * 0.75, -(0.55 + r3 * 0.9)) * (t * t) * distance;
    float2 source = floor((position - drift) / grain) * grain + grain * 0.5;
    if (any(source < float2(0.0)) || any(source > size)) {
        return half4(0.0);
    }
    half4 color = layer.sample(source);
    // Grains thin out, then vanish.
    float keep = step(t * 0.85, r2 * 0.7 + 0.3);
    float fade = (1.0 - smoothstep(0.3, 1.0, t)) * keep;
    return color * half(fade);
}
