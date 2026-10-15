import Darwin
import os

/// Mémoire de l'extension : iOS met fin à une extension de remplissage qui
/// dépasse environ 120 Mo. Le pic (`phys_footprint` maximal, ce que mesure
/// le système) est noté à chaque étape dans le journal (`AUTOFILL_MEMORY`),
/// que relit le test de bout en bout.
enum Memory {
    private static let log = Logger(subsystem: "app.verrou.autofill", category: "memory")

    /// Empreinte actuelle et pic, en octets.
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
