// Onde du déverrouillage (app iPhone seulement) : un anneau part du bouton
// utilisé et se propage sur le fond de l'écran verrouillé en le déformant,
// avec un reflet clair sur sa crête. Appliquée par SwiftUI
// (`.layerEffect`, RippleEffect.swift), seulement pendant l'animation.

#include <metal_stdlib>
#include <SwiftUI/SwiftUI_Metal.h>
using namespace metal;

[[ stitchable ]]
half4 Ripple(float2 position, SwiftUI::Layer layer,
             float2 size,        // taille de la vue : l'échantillon reste dedans
             float2 origin,      // centre de l'onde, en points de la vue
             float time,         // secondes depuis le départ
             float amplitude,    // déplacement maximal, en points
             float frequency,    // oscillations par seconde (en radians)
             float decay,        // amortissement
             float speed)        // vitesse de propagation, en points par seconde
{
    float2 offset = position - origin;
    float distance = length(offset);
    // L'onde n'atteint ce point qu'après distance / vitesse.
    float local = max(0.0, time - distance / speed);
    float wave = amplitude * sin(frequency * local) * exp(-decay * local);
    // Au centre exact, pas de direction : rien à déplacer.
    float2 direction = distance > 0.001 ? offset / distance : float2(0.0);
    // Échantillon gardé dans la vue : pas de bord transparent.
    float2 sample = clamp(position + wave * direction, float2(0.5), size - 0.5);
    half4 color = layer.sample(sample);
    // Crête plus claire, creux un peu plus sombre.
    color.rgb += half(0.35 * (wave / amplitude)) * color.a;
    return color;
}
