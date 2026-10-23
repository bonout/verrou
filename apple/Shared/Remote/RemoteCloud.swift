import CloudKit
import Foundation
import Security

/// The iPhone approvals' transport: the private database of the user's
/// iCloud account (`iCloud.app.verrou` container), so no server of ours.
/// Only sealed content goes through it (`RemoteApproval`).
///
/// - `verrou-pairing` zone: the iPhone's answer to the Mac's QR code, read
///   then erased by the Mac;
/// - one zone per iPhone (`approvals-<iPhone>`): the Mac's requests and the
///   iPhone's answers. The iPhone is subscribed to the requests of its zone
///   (alert notification, worded on the device: `remote.approval.*`), the
///   Mac to the answers (silent notification). Answers are fetched by their
///   identifier while a request waits: no query, no index.
///
/// Production environment, development builds included: the Mac signed by
/// the team (Developer ID) and the iPhone (TestFlight) talk to each other
/// whatever their signature. The record types are in
/// `apple/CloudKit/schema.ckdb`.
enum RemoteCloud {
    static let containerID = "iCloud.app.verrou"

    enum RecordType {
        static let pairing = "ApprovalPairing"
        static let request = "ApprovalRequest"
        static let response = "ApprovalResponse"
    }

    static let pairingZone = CKRecordZone.ID(zoneName: "verrou-pairing")

    static func zone(phone: String) -> CKRecordZone.ID {
        CKRecordZone.ID(zoneName: "approvals-\(phone)")
    }

    /// Without the iCloud entitlement (Mac signed ad hoc), `CKContainer`
    /// stops the app: the feature is hidden.
    static let isEntitled: Bool = {
        #if os(macOS)
        guard let task = SecTaskCreateFromSelf(nil),
              let value = SecTaskCopyValueForEntitlement(task, "com.apple.developer.icloud-container-identifiers" as CFString, nil),
              let containers = value as? [String] else { return false }
        return containers.contains(containerID)
        #else
        return true
        #endif
    }()

    private static let container = CKContainer(identifier: containerID)
    static var database: CKDatabase { container.privateCloudDatabase }

    /// iCloud account usable?
    static func accountAvailable() async -> Bool {
        (try? await container.accountStatus()) == .available
    }

    static func ensureZone(_ zone: CKRecordZone.ID) async throws {
        _ = try await database.modifyRecordZones(saving: [CKRecordZone(zoneID: zone)], deleting: [])
    }

    static func deleteZone(_ zone: CKRecordZone.ID) async {
        _ = try? await database.modifyRecordZones(saving: [], deleting: [zone])
    }

    /// Saves without reading first; urgent (`userInitiated`).
    static func save(_ records: [CKRecord]) async throws {
        let (results, _) = try await database.modifyRecords(saving: records, deleting: [], savePolicy: .allKeys)
        for (_, result) in results {
            if case .failure(let error) = result { throw error }
        }
    }

    static func delete(_ ids: [CKRecord.ID]) async {
        guard !ids.isEmpty else { return }
        _ = try? await database.modifyRecords(saving: [], deleting: ids)
    }

    /// The records that exist among `ids` (absent ones are not an error).
    static func fetch(_ ids: [CKRecord.ID]) async throws -> [CKRecord.ID: CKRecord] {
        guard !ids.isEmpty else { return [:] }
        let results = try await database.records(for: ids)
        var found: [CKRecord.ID: CKRecord] = [:]
        for (id, result) in results {
            switch result {
            case .success(let record): found[id] = record
            case .failure(let error as CKError) where error.code == .unknownItem: continue
            case .failure(let error): throw error
            }
        }
        return found
    }

    /// Everything in a zone (a few records at most: answered requests are
    /// erased).
    static func all(in zone: CKRecordZone.ID) async throws -> [CKRecord] {
        var records: [CKRecord] = []
        var token: CKServerChangeToken?
        var more = true
        while more {
            let changes = try await database.recordZoneChanges(inZoneWith: zone, since: token)
            for (_, result) in changes.modificationResultsByID {
                if case .success(let modification) = result { records.append(modification.record) }
            }
            token = changes.changeToken
            more = changes.moreComing
        }
        return records
    }

    // MARK: Subscriptions

    /// iPhone: an alert notification for each new request in its zone. The
    /// text is the app's (`remote.approval.title` / `.body`): nothing of the
    /// request appears in it.
    static func subscribeToRequests(phone: String) async throws {
        let subscription = CKQuerySubscription(recordType: RecordType.request, predicate: NSPredicate(value: true),
                                               subscriptionID: "requests-\(phone)", options: [.firesOnRecordCreation])
        subscription.zoneID = zone(phone: phone)
        let info = CKSubscription.NotificationInfo()
        info.titleLocalizationKey = "remote.approval.title"
        info.alertLocalizationKey = "remote.approval.body"
        info.soundName = "default"
        info.category = RemoteCloud.notificationCategory
        subscription.notificationInfo = info
        _ = try await database.modifySubscriptions(saving: [subscription], deleting: [])
    }

    /// Mac: a silent notification for each answer of this iPhone.
    static func subscribeToResponses(phone: String) async throws {
        let subscription = CKQuerySubscription(recordType: RecordType.response, predicate: NSPredicate(value: true),
                                               subscriptionID: "responses-\(phone)", options: [.firesOnRecordCreation])
        subscription.zoneID = zone(phone: phone)
        let info = CKSubscription.NotificationInfo()
        info.shouldSendContentAvailable = true
        subscription.notificationInfo = info
        _ = try await database.modifySubscriptions(saving: [subscription], deleting: [])
    }

    static func unsubscribe(_ ids: [String]) async {
        _ = try? await database.modifySubscriptions(saving: [], deleting: ids)
    }

    static let notificationCategory = "verrou.approval"

    /// A notification from these subscriptions?
    static func isApproval(_ userInfo: [AnyHashable: Any]) -> Bool {
        guard let note = CKNotification(fromRemoteNotificationDictionary: userInfo) else { return false }
        return note.subscriptionID?.hasPrefix("requests-") == true || note.subscriptionID?.hasPrefix("responses-") == true
    }

    // MARK: Records

    static func record(_ sealed: RemoteApproval.Sealed, phone: String) -> CKRecord {
        let record = CKRecord(recordType: RecordType.request,
                              recordID: CKRecord.ID(recordName: sealed.id, zoneID: zone(phone: phone)))
        record["mac"] = sealed.mac
        record["ephemeral"] = sealed.ephemeral
        record["box"] = sealed.box
        record["expires"] = sealed.expires
        record["signature"] = sealed.signature
        return record
    }

    static func sealed(from record: CKRecord) -> RemoteApproval.Sealed? {
        guard record.recordType == RecordType.request,
              let mac = record["mac"] as? String, let ephemeral = record["ephemeral"] as? Data,
              let box = record["box"] as? Data, let expires = record["expires"] as? Date,
              let signature = record["signature"] as? Data else { return nil }
        return RemoteApproval.Sealed(id: record.recordID.recordName, mac: mac, ephemeral: ephemeral, box: box,
                                     expires: expires, signature: signature)
    }

    static func responseID(request: String, phone: String) -> CKRecord.ID {
        CKRecord.ID(recordName: "answer-\(request)", zoneID: zone(phone: phone))
    }

    static func response(_ box: Data, request: String, phone: String) -> CKRecord {
        let record = CKRecord(recordType: RecordType.response, recordID: responseID(request: request, phone: phone))
        record["box"] = box
        return record
    }

    static func pairingRecord(payload: Data, proof: Data, name: String) -> CKRecord {
        let record = CKRecord(recordType: RecordType.pairing, recordID: CKRecord.ID(recordName: name, zoneID: pairingZone))
        record["payload"] = payload
        record["proof"] = proof
        return record
    }
}
