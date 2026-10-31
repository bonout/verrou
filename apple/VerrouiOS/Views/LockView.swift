import SwiftUI

/// Vault locked: Face ID (or Touch ID), otherwise the master password.
/// Same composition as the Mac's lock screen: accent halo, logo, rounded
/// title; the glass controls at the bottom of the screen (iOS 26).
///
/// On unlock (`departing`), the vault is already shown and usable
/// underneath: this screen no longer receives touches and fades out right
/// away, in a quarter of a second, without waiting for anything. During
/// this fade, the padlock's shackle jumps (keyframes), a ripple starts from
/// the button used (Metal shader, compiled ahead) and the logo flies
/// toward the vault (`matchedGeometryEffect`); a brief cross-fade with
/// "Reduce Motion".
struct LockView: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Vault open: the screen fades out above the vault.
    var departing = false
    /// End of the fade: the screen can leave the hierarchy.
    var departed: () -> Void = {}
    @State private var password = ""
    /// Password chosen rather than Face ID.
    @State private var usePassword = false
    /// Center of the main control (Face ID button or field), in screen
    /// space: the ripple's origin.
    @State private var controlCenter = CGPoint.zero
    @FocusState private var passwordFocused: Bool
    @Namespace private var logoSpace
    /// Appearance of the screen: a vault opened almost at once (under
    /// 0.3 s) shows with a simple fade, without the full animation.
    @State private var shownAt = Date()
    @State private var confirmLogout = false
    @ScaledMetric(relativeTo: .largeTitle) private var titleSize: CGFloat = 36

    /// Duration of the fade: the screen then leaves the hierarchy.
    static func departure(reduceMotion: Bool) -> Duration {
        reduceMotion ? .milliseconds(160) : .milliseconds(320)
    }

    private var flourish: Bool {
        departing && !reduceMotion && Date().timeIntervalSince(shownAt) > 0.3
    }

    var body: some View {
        KeyframeAnimator(initialValue: UnlockFrame(), trigger: departing) { frame in
            screen(flourish ? frame : UnlockFrame())
        } keyframes: { _ in
            // A brief jump of the shackle, played during the fade (never awaited).
            KeyframeTrack(\.shackle) {
                SpringKeyframe(1.15, duration: 0.1, spring: .snappy)
                SpringKeyframe(1, duration: 0.12, spring: .bouncy)
            }
            KeyframeTrack(\.ripple) {
                LinearKeyframe(RippleEffect.duration, duration: RippleEffect.duration)
            }
        }
        // The whole screen fades together, from the first frame: the vault
        // appears underneath right away. No delay: a delay doesn't apply to
        // the shader's layer, which would disappear before the text.
        .opacity(departing ? 0 : 1)
        // Slow then fast start: the shackle has time to open, visibly,
        // before the screen fades out.
        .animation(departing
                   ? (reduceMotion ? .linear(duration: 0.15) : .timingCurve(0.55, 0, 0.85, 1, duration: 0.3))
                   : .easeOut(duration: 0.15),
                   value: departing)
        .allowsHitTesting(!departing)
        .accessibilityHidden(departing)
        .task(id: departing) {
            guard departing else { return }
            Perf.mark("lock screen: fading out above the vault")
            // Task cancelled (view rebuilt): the next one takes over.
            do { try await Task.sleep(for: Self.departure(reduceMotion: reduceMotion)) } catch { return }
            if departing { departed() }
        }
        .animation(.snappy, value: model.unlockError)
        .sensoryFeedback(.error, trigger: model.unlockError) { _, new in new != nil }
        .onChange(of: model.unlockError) { _, error in
            if let error, !error.isEmpty { AccessibilityNotification.Announcement(error).post() }
        }
        .modifier(SignOutConfirmation(isPresented: $confirmLogout))
        #if DEBUG
        .onAppear { PhoneBenchDriver.lockShown = true }
        .onDisappear { PhoneBenchDriver.lockShown = false }
        #endif
        .onDisappear {
            Perf.mark("lock screen removed at +\(Perf.msSinceLaunch) ms from launch")
        }
        .onAppear {
            guard !departing else { return }
            Perf.mark("lock screen shown at +\(Perf.msSinceLaunch) ms from launch")
            if model.canUseBiometrics {
                Task { await model.promptBiometricsIfPossible() }
            }
            // The unlock ripple, compiled while Face ID waits: not at the
            // first unlock, where it would delay the frame.
            if !reduceMotion { RippleEffect.prewarm() }
        }
    }

    /// Debug builds: `VERROU_RIPPLE_AT=<seconds>` freezes the ripple at that
    /// moment on the lock screen (shader screenshots).
    private static let frozenRipple: Double? = {
        #if DEBUG
        ProcessInfo.processInfo.environment["VERROU_RIPPLE_AT"].flatMap(Double.init)
        #else
        nil
        #endif
    }()

    private func screen(_ frame: UnlockFrame) -> some View {
        ZStack {
            LockMeshBackground(rippleOrigin: controlCenter, rippleElapsed: Self.frozenRipple ?? frame.ripple,
                               frozen: departing)
            VStack(spacing: 28) {
                Spacer()
                VStack(spacing: 14) {
                    // The logo follows the "home" anchor, then the one at
                    // the top of the screen on departure, shrinking.
                    ZStack {
                        Color.clear
                            .matchedGeometryEffect(id: "home", in: logoSpace)
                        AppMark(size: 96, glow: !flourish, shackle: frame.shackle)
                            .scaleEffect(flourish ? 0.36 : 1)
                            .matchedGeometryEffect(id: flourish ? "dock" : "home", in: logoSpace,
                                                   properties: .position, isSource: false)
                    }
                    .frame(width: 96, height: 96)
                    .padding(.bottom, 6)
                    // The title leaves quickly: the logo alone flies to the vault.
                    VStack(spacing: 14) {
                        Text("Verrou")
                            .font(.system(size: titleSize, weight: .bold, design: .rounded))
                            .accessibilityAddTraits(.isHeader)
                        Text(subtitle)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .opacity(departing ? 0 : 1)
                    .animation(.easeOut(duration: 0.15), value: departing)
                }
                Spacer()
                LockControls(password: $password, usePassword: $usePassword, focused: $passwordFocused,
                             submit: submit)
                    .onGeometryChange(for: CGPoint.self) { proxy in
                        let frame = proxy.frame(in: .global)
                        return CGPoint(x: frame.midX, y: frame.minY + min(frame.height, 52) / 2)
                    } action: { controlCenter = $0 }
                    .opacity(departing ? 0 : 1)
                    .animation(.easeOut(duration: 0.12), value: departing)
                if let error = model.unlockError, !error.isEmpty {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .transition(.opacity.combined(with: .move(edge: .bottom)))
                }
                if model.mode == .vaultwarden, model.account != nil {
                    Button {
                        confirmLogout = true
                    } label: {
                        Text("Sign out of this iPhone")
                            .font(.footnote)
                            .frame(minHeight: 44)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .disabled(model.lockState == .unlocking)
                    .opacity(departing ? 0 : 1)
                    .accessibilityIdentifier("lock-sign-out")
                }
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 20)
            .frame(maxWidth: 520)
        }
        // The logo flies up, to where the vault is shown.
        .overlay(alignment: .top) {
            Color.clear
                .frame(width: 34, height: 34)
                .matchedGeometryEffect(id: "dock", in: logoSpace)
                .padding(.top, 4)
                .allowsHitTesting(false)
        }
        .animation(.spring(response: 0.24, dampingFraction: 0.9), value: flourish)
    }

    private var subtitle: String {
        guard model.mode == .vaultwarden, let account = model.account else {
            return String(localized: "Demo vault · read-only sample data")
        }
        let host = URL(string: account.server)?.host() ?? account.server
        return "\(account.email)\n\(host)"
    }

    private func submit() {
        let typed = password
        password = ""
        passwordFocused = false
        Task { await model.unlock(masterPassword: typed) }
    }
}

/// Animated values of the unlock (keyframes).
struct UnlockFrame {
    /// Shackle opening (`Padlock.shackle`).
    var shackle: CGFloat = 0
    /// Seconds elapsed of the ripple.
    var ripple: Double = 0
}

/// The controls: Face ID, or the master password when chosen (or without
/// Face ID). On iOS 26, the glass button morphs into the field
/// (`glassEffectID`); before, or with "Reduce Motion", a fade.
private struct LockControls: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Binding var password: String
    @Binding var usePassword: Bool
    var focused: FocusState<Bool>.Binding
    let submit: () -> Void
    @Namespace private var glass

    var body: some View {
        let biometrics = model.canUseBiometrics
        let morph = LiquidGlass.isAvailable && !reduceMotion
        GlassGroup(spacing: 14) {
            VStack(spacing: 14) {
                if biometrics && !usePassword {
                    BiometricUnlockButton(title: "Unlock with \(Biometrics.name)",
                                          symbol: Biometrics.symbolName,
                                          busy: model.lockState == .unlocking) {
                        Task { await model.unlockWithBiometrics() }
                    }
                    .glassMorphID("primary", in: glass, morph: morph)
                    Button {
                        usePassword = true
                    } label: {
                        Text("Use master password")
                            .frame(minHeight: 44)
                            .padding(.horizontal, 12)
                            .contentShape(Rectangle())
                    }
                    .font(.callout.weight(.medium))
                    .disabled(model.lockState == .unlocking)
                    .accessibilityIdentifier("lock-use-password")
                    .transition(.opacity)
                } else {
                    HStack(spacing: 10) {
                        MasterPasswordField(password: $password, busy: model.lockState == .unlocking,
                                            focused: focused, submit: submit)
                            .glassMorphID("primary", in: glass, morph: morph)
                        if biometrics {
                            Button {
                                usePassword = false
                                focused.wrappedValue = false
                                Task { await model.unlockWithBiometrics() }
                            } label: {
                                Image(systemName: Biometrics.symbolName)
                                    .font(.title2)
                                    .frame(width: 52, height: 52)
                                    .contentShape(Circle())
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(Theme.accent)
                            .glassSurface(Circle(), interactive: true)
                            .glassMorphID("biometrics", in: glass, morph: morph)
                            .accessibilityLabel("Unlock with \(Biometrics.name)")
                            .transition(.opacity)
                        }
                    }
                }
            }
        }
        .animation(morph ? .bouncy(duration: 0.45) : .easeInOut(duration: 0.25), value: usePassword)
        .onChange(of: usePassword) { _, chosen in
            guard chosen else { return }
            // The keyboard arrives once the field is in place.
            Task {
                try? await Task.sleep(for: .milliseconds(morph ? 380 : 200))
                if usePassword { focused.wrappedValue = true }
            }
        }
    }
}
