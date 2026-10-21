// Unlock ripple (iPhone app only): a ring starts from the button used and
// spreads over the lock screen background, distorting it, with a light
// highlight on its crest. Applied by SwiftUI (`.layerEffect`,
// RippleEffect.swift), only during the animation.

#include <metal_stdlib>
#include <SwiftUI/SwiftUI_Metal.h>
using namespace metal;

[[ stitchable ]]
half4 Ripple(float2 position, SwiftUI::Layer layer,
             float2 size,        // view size: the sample stays inside it
             float2 origin,      // ripple center, in view points
             float time,         // seconds since the start
             float amplitude,    // maximum displacement, in points
             float frequency,    // oscillations per second (in radians)
             float decay,        // damping
             float speed)        // propagation speed, in points per second
{
    float2 offset = position - origin;
    float distance = length(offset);
    // The ripple only reaches this point after distance / speed.
    float local = max(0.0, time - distance / speed);
    float wave = amplitude * sin(frequency * local) * exp(-decay * local);
    // At the exact center, no direction: nothing to displace.
    float2 direction = distance > 0.001 ? offset / distance : float2(0.0);
    // Sample kept inside the view: no transparent edge.
    float2 sample = clamp(position + wave * direction, float2(0.5), size - 0.5);
    half4 color = layer.sample(sample);
    // Brighter crest, slightly darker trough.
    color.rgb += half(0.35 * (wave / amplitude)) * color.a;
    return color;
}
