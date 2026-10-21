import Darwin
import os

/// The extension's memory: iOS terminates an AutoFill extension that goes
/// over about 120 MB. The peak (maximum `phys_footprint`, what the system
/// measures) is logged at each step (`AUTOFILL_MEMORY`), which the
/// end-to-end test reads back.
enum Memory {
    private static let log = Logger(subsystem: "app.verrou.autofill", category: "memory")

    /// Current footprint and peak, in bytes.
    static func footprint() -> (current: UInt64, peak: UInt64)? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        return (info.phys_footprint, info.ledger_phys_footprint_peak > 0 ? UInt64(info.ledger_phys_footprint_peak) : info.phys_footprint)
    }

    static func log(_ step: String) {
        guard let (current, peak) = footprint() else { return }
        let mb = { (bytes: UInt64) in String(format: "%.1f", Double(bytes) / 1_048_576) }
        log.notice("AUTOFILL_MEMORY step=\(step, privacy: .public) current=\(mb(current), privacy: .public)MB peak=\(mb(peak), privacy: .public)MB")
    }
}
