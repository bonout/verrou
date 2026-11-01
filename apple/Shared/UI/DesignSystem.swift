import SwiftUI

// Visual identity shared by the Mac, the iPhone and the AutoFill
// extension: logo (the padlock of the icon and of the browser extension),
// lock screen background, chips, counters, item row.
// Everything is drawn (no image): nothing heavy in the extension.

// MARK: Tokens

extension Theme {
    /// Logo gradient (top, bottom), the app icon's.
    static let brandTop = Color(red: 0.36, green: 0.42, blue: 1.0)
    static let brandBottom = Color(red: 0.20, green: 0.17, blue: 0.62)
    static let radiusSmall: CGFloat = 4
    static let radiusMedium: CGFloat = 8
    static let radiusLarge: CGFloat = 12
    /// Radius of the iPhone's cards (item page fields, generator).
    static let cardRadius: CGFloat = 16
    static let panelRadius: CGFloat = 24
    /// Green of the "online" state (foot of the Mac sidebar).
    static let online = Color.green
}

// MARK: Logo

/// Verrou's padlock: shackle, body and keyhole, after the extension's SVG
/// drawing (24 × 24 box).
struct Padlock: View {
    var size: CGFloat = 24
    /// Shackle opening: 0 closed, 1 raised and pivoted on its right leg
    /// (iPhone unlock animation). Beyond 1: slight spring overshoot.
    var shackle: CGFloat = 0
    var body: some View {
        Canvas { context, canvas in
            let unit = canvas.width / 24
            // Shackle raised then pivoted around the foot of its right leg.
            var shackleContext = context
            if shackle != 0 {
                let pivot = CGPoint(x: 16.5 * unit, y: 10.5 * unit)
                shackleContext.translateBy(x: 0, y: -2.6 * unit * shackle)
                shackleContext.translateBy(x: pivot.x, y: pivot.y)
                shackleContext.rotate(by: .degrees(22 * Double(max(0, shackle - 0.35)) / 0.65))
                shackleContext.translateBy(x: -pivot.x, y: -pivot.y)
            }
            var arc = Path()
            arc.move(to: CGPoint(x: 7.5 * unit, y: 10.5 * unit))
            arc.addLine(to: CGPoint(x: 7.5 * unit, y: 8 * unit))
            arc.addArc(center: CGPoint(x: 12 * unit, y: 8 * unit), radius: 4.5 * unit,
                       startAngle: .degrees(180), endAngle: .degrees(0), clockwise: false)
            arc.addLine(to: CGPoint(x: 16.5 * unit, y: 10.5 * unit))
            shackleContext.stroke(arc, with: .color(.white),
                                  style: StrokeStyle(lineWidth: 2.2 * unit, lineCap: .round))
            let body = Path(roundedRect: CGRect(x: 4.5 * unit, y: 10 * unit, width: 15 * unit, height: 11 * unit),
                            cornerRadius: 3 * unit, style: .continuous)
            context.fill(body, with: .linearGradient(
                Gradient(colors: [.white, Color(white: 0.9)]),
                startPoint: CGPoint(x: 0, y: 10 * unit), endPoint: CGPoint(x: 0, y: 21 * unit)))
            let hole = Path(ellipseIn: CGRect(x: 10.4 * unit, y: 13 * unit, width: 3.2 * unit, height: 3.2 * unit))
            context.fill(hole, with: .color(Theme.brandBottom.opacity(0.85)))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// The logo: the padlock on a rounded shield, like the app icon.
struct AppMark: View {
    var size: CGFloat = 64
    /// Colored halo under the logo (lock screens); without it, for small sizes.
    var glow = true
    /// Opening of the padlock's shackle (`Padlock.shackle`).
    var shackle: CGFloat = 0

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
                .fill(LinearGradient(colors: [Theme.brandTop, Theme.brandBottom],
                                     startPoint: .topLeading, endPoint: .bottomTrailing))
                .overlay(
                    RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
                        .strokeBorder(.white.opacity(0.18), lineWidth: max(0.5, size / 120)))
                .shadow(color: glow ? Theme.brandTop.opacity(0.35) : .clear,
                        radius: size * 0.18, y: size * 0.08)
            Padlock(size: size * 0.62, shackle: shackle)
                .offset(y: -size * 0.01)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

// MARK: Lock screen background

/// Background of the lock and sign-in screens: the window color and an
/// accent-colored halo coming from the top.
struct LockBackground: View {
    var body: some View {
        ZStack {
            #if canImport(AppKit)
            Color(nsColor: .windowBackgroundColor)
            RadialGradient(colors: [Theme.accent.opacity(0.18), .clear], center: .top, startRadius: 10, endRadius: 520)
            #else
            Color(.systemGroupedBackground)
            RadialGradient(colors: [Theme.accent.opacity(0.26), .clear], center: .top, startRadius: 0, endRadius: 560)
            RadialGradient(colors: [Theme.brandBottom.opacity(0.10), .clear], center: .bottomTrailing,
                           startRadius: 0, endRadius: 420)
            #endif
        }
        .ignoresSafeArea()
    }
}

// MARK: Chips and counters

/// Information chip (type, folder, sharing…): symbol and text on a tinted
/// background, never cut letter by letter.
struct Chip: View {
    let text: String
    let symbol: String
    let tint: Color

    var body: some View {
        Label {
            Text(text).foregroundStyle(tint == .secondary ? Color.secondary : Color.primary)
        } icon: {
            Image(systemName: symbol).foregroundStyle(tint == .secondary ? Color.secondary : tint)
        }
            .labelStyle(.titleAndIcon)
            .lineLimit(1)
            .truncationMode(.tail)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background((tint == .secondary ? Color.secondary : tint).opacity(0.12), in: Capsule())
    }
}

/// Counter with a colored dot: "● 3 reused".
struct CountCapsule: View {
    let text: String
    let tint: Color

    var body: some View {
        HStack(spacing: 4) {
            Circle().fill(tint).frame(width: 7, height: 7)
            Text(text)
                .font(.caption.weight(.medium))
                .monospacedDigit()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Theme.faintFill(0.6), in: Capsule())
    }
}

/// Solid label: trust level, severity.
struct Badge: View {
    let text: String
    /// `nil`: neutral background.
    let tint: Color?

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            // Dark text on yellow: white wouldn't be readable on it.
            .foregroundStyle(tint == nil ? Color.primary : tint == .yellow ? Color.black : Color.white)
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .background(tint.map { AnyShapeStyle($0) } ?? AnyShapeStyle(.quaternary), in: Capsule())
    }
}

/// An item's tags ("#dev"), wrapping when space runs out.
struct TagsRow: View {
    let tags: [String]

    var body: some View {
        FlowLayout(spacing: 8, lineSpacing: 6) {
            ForEach(tags, id: \.self) { tag in
                Text("#\(tag)")
                    .font(.caption.weight(.medium))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Theme.faintFill(0.7), in: Capsule())
            }
        }
    }
}

// MARK: Layout

/// Views side by side that wrap to the next line when space runs out (the
/// detail's chips). Each view keeps its ideal width, at most the
/// container's: a text too long is truncated, never cut letter by
/// letter.
struct FlowLayout: Layout {
    var spacing: CGFloat = 8
    var lineSpacing: CGFloat = 6
    /// Centered lines (iPhone header) rather than left-aligned.
    var centered = false

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews: subviews)
        let width = rows.map(\.width).max() ?? 0
        let height = rows.map(\.height).reduce(0, +) + lineSpacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: proposal.width.map { min($0, width) } ?? width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(width: bounds.width, subviews: subviews) {
            var x = centered ? bounds.minX + (bounds.width - row.width) / 2 : bounds.minX
            for (index, size) in zip(row.indices, row.sizes) {
                subviews[index].place(at: CGPoint(x: x, y: y + (row.height - size.height) / 2),
                                      proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += row.height + lineSpacing
        }
    }

    private struct Row {
        var indices: [Int] = []
        var sizes: [CGSize] = []
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func arrange(width maxWidth: CGFloat, subviews: Subviews) -> [Row] {
        var rows: [Row] = []
        var row = Row()
        for index in subviews.indices {
            let ideal = subviews[index].sizeThatFits(.unspecified)
            let width = min(ideal.width, maxWidth)
            let size = width < ideal.width
                ? subviews[index].sizeThatFits(ProposedViewSize(width: width, height: nil))
                : ideal
            let needed = row.indices.isEmpty ? size.width : row.width + spacing + size.width
            if !row.indices.isEmpty && needed > maxWidth {
                rows.append(row)
                row = Row()
            }
            row.width = row.indices.isEmpty ? size.width : row.width + spacing + size.width
            row.height = max(row.height, size.height)
            row.indices.append(index)
            row.sizes.append(size)
        }
        if !row.indices.isEmpty { rows.append(row) }
        return rows
    }
}

// MARK: Item row

/// Title (found characters highlighted) with favorite and sharing,
/// subtitle, then the indicators: the list row of the Mac, the iPhone and
/// the extension. No geometry or shadow: the row stays cheap to build while
/// scrolling.
struct ItemRowContent<Icon: View>: View {
    let summary: ItemSummary
    let highlights: [UInt32]
    /// On an accent background (selected Mac row): white text.
    var selected = false
    var spacing: CGFloat = 11
    var subtitleFont: Font = .callout
    /// "Protected" indicator (iPhone, extension).
    var showsProtection = false
    /// Passkeys view: the secondary line shows the passkey's site and user
    /// instead of the subtitle.
    var showsPasskey = false
    @ViewBuilder let icon: Icon

    var body: some View {
        HStack(spacing: spacing) {
            icon
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    HighlightedText(text: summary.title, highlights: highlights,
                                    tint: selected ? nil : Theme.accent)
                        .lineLimit(1)
                    if summary.favorite {
                        Image(systemName: "star.fill").font(.system(size: 9)).foregroundStyle(.yellow)
                            .accessibilityLabel("Favorite")
                    }
                    if let sharing = summary.sharing {
                        Image(systemName: "person.2.fill")
                            .font(.system(size: 9))
                            .foregroundStyle(selected ? AnyShapeStyle(Theme.onAccentSecondary()) : AnyShapeStyle(.indigo))
                            .help(sharing.label)
                            .accessibilityLabel("Shared")
                    }
                }
                if showsPasskey, let line = summary.passkeyLine {
                    Label {
                        Text(line)
                    } icon: {
                        Image(systemName: "person.badge.key.fill")
                    }
                    .labelStyle(CompactLabelStyle())
                    .font(subtitleFont)
                    .foregroundStyle(selected ? AnyShapeStyle(Theme.onAccentSecondary()) : AnyShapeStyle(.secondary))
                    .lineLimit(1)
                    .accessibilityLabel("Passkey \(line)")
                } else {
                    Text(summary.displaySubtitle)
                        .font(subtitleFont)
                        .foregroundStyle(selected ? AnyShapeStyle(Theme.onAccentSecondary()) : AnyShapeStyle(.secondary))
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
            if summary.pendingSync {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .font(.caption)
                    .foregroundStyle(selected ? .white : .orange)
                    .help("Pending sync")
                    .accessibilityLabel("Pending sync")
            }
            if showsProtection, summary.reprompt {
                Image(systemName: "lock.shield")
                    .font(.caption)
                    .foregroundStyle(selected ? .white : .orange)
                    .accessibilityLabel("Protected")
            }
            if summary.passkeyRpId != nil, !showsPasskey {
                Image(systemName: "person.badge.key")
                    .font(.caption)
                    .foregroundStyle(selected ? .white : .purple)
                    .help("Passkey")
                    .accessibilityLabel("Passkey")
            }
            if summary.hasTotp {
                Image(systemName: "clock.badge.checkmark")
                    .font(.caption)
                    .foregroundStyle(selected ? .white : .teal)
                    .help("One-time code")
                    .accessibilityLabel("One-time code")
            }
        }
        .foregroundStyle(selected ? Color.white : Color.primary)
    }
}

/// Icon and text tight, aligned on the baseline.
struct CompactLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 4) {
            configuration.icon.imageScale(.small)
            configuration.title
        }
    }
}
