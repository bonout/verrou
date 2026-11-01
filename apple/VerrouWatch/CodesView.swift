import SwiftUI

/// The pinned codes: title, site, the code in two halves and the countdown;
/// a tap shows one code large.
struct CodesView: View {
    let model: WatchModel

    var body: some View {
        NavigationStack {
            if model.codes.isEmpty {
                ContentUnavailableView {
                    Label("No pinned codes", systemImage: "pin")
                } description: {
                    Text("On your iPhone, open an item and turn on Show in widgets and on Apple Watch.")
                }
            } else {
                List(model.codes) { pinned in
                    NavigationLink(value: pinned.id) {
                        CodeRow(pinned: pinned)
                    }
                }
                .navigationTitle("Verrou")
                .navigationDestination(for: String.self) { id in
                    if let pinned = model.codes.first(where: { $0.id == id }) {
                        CodeDetail(pinned: pinned)
                    }
                }
            }
        }
    }
}

/// The time left in a code's window, as a ring that empties.
private struct CountdownRing: View {
    let code: PinnedCode.Code
    let date: Date
    var lineWidth: CGFloat = 3

    private var remaining: TimeInterval { max(0, code.end.timeIntervalSince(date)) }
    private var fraction: Double { remaining / code.end.timeIntervalSince(code.start) }

    var body: some View {
        Circle()
            .stroke(Color.secondary.opacity(0.3), lineWidth: lineWidth)
            .overlay {
                Circle()
                    .trim(from: 0, to: fraction)
                    .stroke(remaining <= 5 ? Color.orange : Color.accentColor,
                            style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
                    .rotationEffect(.degrees(-90))
            }
            .accessibilityHidden(true)
    }
}

private struct CodeRow: View {
    let pinned: PinnedCode

    var body: some View {
        // Redrawn every second: the countdown, and the new code at each
        // window's end.
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = pinned.code(at: context.date)
            HStack(spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(pinned.title)
                        .font(.headline)
                        .lineLimit(1)
                    if let host = pinned.host {
                        Text(host)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Text(code.grouped)
                        .font(.system(.title3, design: .monospaced, weight: .semibold))
                        .minimumScaleFactor(0.6)
                        .lineLimit(1)
                        .privacySensitive()
                }
                Spacer(minLength: 0)
                CountdownRing(code: code, date: context.date)
                    .frame(width: 22, height: 22)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("\(pinned.title): code \(code.value)"))
            .accessibilityValue(Text("\(Int(code.end.timeIntervalSince(context.date).rounded(.up))) seconds left"))
        }
    }
}

private struct CodeDetail: View {
    let pinned: PinnedCode

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = pinned.code(at: context.date)
            let seconds = Int(code.end.timeIntervalSince(context.date).rounded(.up))
            VStack(spacing: 8) {
                Text(pinned.title)
                    .font(.headline)
                    .lineLimit(1)
                if let host = pinned.host {
                    Text(host)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
                Text(code.grouped)
                    .font(.system(.largeTitle, design: .monospaced, weight: .semibold))
                    .minimumScaleFactor(0.5)
                    .lineLimit(1)
                    .privacySensitive()
                Spacer(minLength: 0)
                HStack(spacing: 8) {
                    CountdownRing(code: code, date: context.date, lineWidth: 2.5)
                        .frame(width: 16, height: 16)
                    Text("\(seconds) s")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("\(pinned.title): code \(code.value)"))
            .accessibilityValue(Text("\(seconds) seconds left"))
        }
        .navigationBarTitleDisplayMode(.inline)
    }
}
