//! The payout report and the settle command.
//!
//! The mint pays services by hand. The report sums every open queue entry per
//! service, so the operator pays each service once. After paying, `pay` marks
//! exactly the entries that were paid completed, with one shared payment
//! reference.
//!
//! - Only open entries count. Declined and completed entries are left out.
//! - Sums are `u128`. Amounts are shown in ESP and in USD at 10^12 ESP per $1.
//! - If one service's entries have different payout memos, every memo is shown
//!   and the group is flagged. The mint does not pick one.
//! - `pay` takes the exact entry ids from the report. An entry queued after the
//!   report was run is not in that list and is never marked paid.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use sp_wire::ServiceDid;

use crate::queue::{Entry, Paid, Payment, Queue, QueueError, Status, date, dec, usd};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoLine {
    pub memo: String,
    pub entry_ids: Vec<String>,
    #[serde(with = "dec")]
    pub owed_esp: u128,
    pub owed_usd: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Group {
    /// The service's ID: its 33-byte AIR DID, 66 hex characters.
    pub service: String,
    #[serde(with = "dec")]
    pub owed_esp: u128,
    pub owed_usd: String,
    pub entries: usize,
    pub oldest_unix: u64,
    pub newest_unix: u64,
    pub oldest_date: String,
    pub newest_date: String,
    /// Oldest first.
    pub entry_ids: Vec<String>,
    /// One line for each different payout memo.
    pub memos: Vec<MemoLine>,
    /// True when the entries have more than one payout memo.
    pub memo_mismatch: bool,
}

/// Sum the open entries per service, services in key order.
pub fn report(queue: &Queue) -> Result<Vec<Group>, QueueError> {
    let mut by_service: BTreeMap<ServiceDid, Vec<&Entry>> = BTreeMap::new();
    for entry in queue.entries().filter(|e| e.status == Status::Open) {
        by_service.entry(entry.service).or_default().push(entry);
    }
    let mut groups = Vec::new();
    for (service, mut list) in by_service {
        list.sort_by(|a, b| {
            a.created_unix
                .cmp(&b.created_unix)
                .then_with(|| a.id.cmp(&b.id))
        });
        let mut owed: u128 = 0;
        let mut by_memo: BTreeMap<&str, (Vec<String>, u128)> = BTreeMap::new();
        for entry in &list {
            owed = owed
                .checked_add(entry.owed_esp)
                .ok_or(QueueError::Overflow)?;
            let line = by_memo.entry(entry.memo.as_str()).or_default();
            line.0.push(entry.id.clone());
            line.1 = line
                .1
                .checked_add(entry.owed_esp)
                .ok_or(QueueError::Overflow)?;
        }
        let oldest = list.first().map_or(0, |e| e.created_unix);
        let newest = list.last().map_or(0, |e| e.created_unix);
        let memos: Vec<MemoLine> = by_memo
            .into_iter()
            .map(|(memo, (entry_ids, owed_esp))| MemoLine {
                memo: memo.to_string(),
                entry_ids,
                owed_esp,
                owed_usd: usd(owed_esp),
            })
            .collect();
        groups.push(Group {
            service: service.to_hex(),
            owed_esp: owed,
            owed_usd: usd(owed),
            entries: list.len(),
            oldest_unix: oldest,
            newest_unix: newest,
            oldest_date: date(oldest),
            newest_date: date(newest),
            entry_ids: list.iter().map(|e| e.id.clone()).collect(),
            memo_mismatch: memos.len() > 1,
            memos,
        });
    }
    Ok(groups)
}

/// The report as plain text.
pub fn render_report(groups: &[Group]) -> String {
    if groups.is_empty() {
        return "nothing is owed: no open redemption entries\n".to_string();
    }
    let mut out = String::new();
    for g in groups {
        out.push_str(&format!("service {}\n", g.service));
        out.push_str(&format!(
            "  owed     {} USD ({} ESP)\n",
            g.owed_usd, g.owed_esp
        ));
        out.push_str(&format!(
            "  entries  {}, {} to {}\n",
            g.entries, g.oldest_date, g.newest_date
        ));
        if g.memo_mismatch {
            out.push_str(&format!(
                "  MEMO MISMATCH: {} different payout memos. Decide where to pay before settling; pay each memo's entries on its own\n",
                g.memos.len()
            ));
        }
        for m in &g.memos {
            out.push_str(&format!(
                "  memo     {}  ({} USD, {} ESP)\n",
                m.memo, m.owed_usd, m.owed_esp
            ));
            for id in &m.entry_ids {
                out.push_str(&format!("    entry  {id}\n"));
            }
        }
    }
    out
}

/// A settled payment as plain text.
pub fn render_paid(paid: &Paid) -> String {
    format!(
        "marked {} entr{} completed for {}: {} USD ({} ESP), payment reference {}\n",
        paid.entries,
        if paid.entries == 1 { "y" } else { "ies" },
        hex::encode(paid.service.serialize()),
        paid.paid_usd,
        paid.paid_esp,
        paid.payment_ref
    )
}

/// `esp-mint payouts [--json]`: the report, read from the queue file.
pub fn run_payouts(queue_path: &Path, args: &[String]) -> Result<String, String> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            other => return Err(format!("unexpected argument `{other}`")),
        }
    }
    let queue = Queue::open(queue_path).map_err(|e| e.to_string())?;
    let groups = report(&queue).map_err(|e| e.to_string())?;
    if json {
        serde_json::to_string_pretty(&groups)
            .map(|s| s + "\n")
            .map_err(|e| e.to_string())
    } else {
        Ok(render_report(&groups))
    }
}

/// A service as typed on the command line: its 33-byte DID in hex. A 32-byte
/// x-only key (the form before wire version 3) is refused, and the message says so.
pub fn parse_service(text: &str) -> Result<ServiceDid, String> {
    ServiceDid::parse(text).map_err(|e| e.to_string())
}

/// `esp-mint pay <service> <ref> <entry id>... [--mixed-memos]`.
pub fn run_pay(queue_path: &Path, args: &[String], now_unix: u64) -> Result<String, String> {
    let mut allow_mixed_memos = false;
    let mut words = Vec::new();
    for arg in args {
        if arg == "--mixed-memos" {
            allow_mixed_memos = true;
        } else {
            words.push(arg.clone());
        }
    }
    if words.len() < 3 {
        return Err("usage: esp-mint pay <service> <ref> <entry id>... [--mixed-memos]".into());
    }
    let service = parse_service(&words[0])?;
    let payment_ref = words[1].clone();
    let entry_ids = &words[2..];
    let mut queue = Queue::open(queue_path).map_err(|e| e.to_string())?;
    let paid = queue
        .complete(&Payment {
            service,
            payment_ref: &payment_ref,
            entry_ids,
            allow_mixed_memos,
            now_unix,
        })
        .map_err(|e| e.to_string())?;
    Ok(render_paid(&paid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::ESP_PER_USD;
    use std::fs;
    use std::path::PathBuf;

    const G_DID: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const OTHER_DID: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    /// 2026-10-09 00:00:00 UTC.
    const DAY1: u64 = 20_735 * 86_400;
    const DAY: u64 = 86_400;

    fn xyz() -> ServiceDid {
        parse_service(G_DID).unwrap()
    }

    fn abc() -> ServiceDid {
        parse_service(OTHER_DID).unwrap()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("esp-mint-payouts-{}-{name}", {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn pay_args<'a>(
        service: ServiceDid,
        payment_ref: &'a str,
        entry_ids: &'a [String],
        now_unix: u64,
    ) -> Payment<'a> {
        Payment {
            service,
            payment_ref,
            entry_ids,
            allow_mixed_memos: false,
            now_unix,
        }
    }

    #[test]
    fn xyz_redeems_10_on_day_1_and_5_on_day_2_and_the_report_has_one_line_owing_15() {
        let dir = scratch("group");
        let mut q = Queue::open(&dir.join("queue.json")).unwrap();
        q.add(Entry::open(
            "e2",
            xyz(),
            5 * ESP_PER_USD,
            "btc:bc1qxyz",
            DAY1 + DAY,
        ))
        .unwrap();
        q.add(Entry::open(
            "e1",
            xyz(),
            10 * ESP_PER_USD,
            "btc:bc1qxyz",
            DAY1,
        ))
        .unwrap();
        q.add(Entry::open(
            "a1",
            abc(),
            7 * ESP_PER_USD,
            "wire:abc",
            DAY1 + 5,
        ))
        .unwrap();

        let groups = report(&q).unwrap();
        assert_eq!(groups.len(), 2);
        let g = groups.iter().find(|g| g.service == G_DID).unwrap();
        assert_eq!(g.owed_esp, 15 * ESP_PER_USD);
        assert_eq!(g.owed_usd, "15.000000000000");
        assert_eq!(g.entries, 2);
        assert_eq!(g.oldest_unix, DAY1);
        assert_eq!(g.newest_unix, DAY1 + DAY);
        assert_eq!(
            (g.oldest_date.as_str(), g.newest_date.as_str()),
            ("2026-10-09", "2026-10-10")
        );
        assert_eq!(g.entry_ids, ids(&["e1", "e2"]));
        assert_eq!(g.memos.len(), 1);
        assert_eq!(g.memos[0].memo, "btc:bc1qxyz");
        assert!(!g.memo_mismatch);
        let other = groups.iter().find(|g| g.service == OTHER_DID).unwrap();
        assert_eq!((other.owed_esp, other.entries), (7 * ESP_PER_USD, 1));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sums_are_u128_and_do_not_wrap() {
        let dir = scratch("sums");
        let mut q = Queue::open(&dir.join("queue.json")).unwrap();
        let a = u128::from(u64::MAX) * 1_000_000;
        q.add(Entry::open("a", xyz(), a, "m", DAY1)).unwrap();
        q.add(Entry::open("b", xyz(), a, "m", DAY1 + 1)).unwrap();
        let groups = report(&q).unwrap();
        assert_eq!(groups[0].owed_esp, 2 * a);
        // and a sum past u128 is an error, not a wrapped number
        q.add(Entry::open("c", xyz(), u128::MAX - a, "m", DAY1 + 2))
            .unwrap();
        assert!(matches!(report(&q), Err(QueueError::Overflow)));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn declined_and_completed_entries_are_left_out() {
        let dir = scratch("filter");
        let path = dir.join("queue.json");
        let mut q = Queue::open(&path).unwrap();
        q.add(Entry::open("open", xyz(), 4 * ESP_PER_USD, "m", DAY1))
            .unwrap();
        q.add(Entry::open("paid", xyz(), 100 * ESP_PER_USD, "m", DAY1))
            .unwrap();
        q.add(Entry::open("gone", abc(), 50 * ESP_PER_USD, "m", DAY1))
            .unwrap();
        q.complete(&pay_args(xyz(), "wire-1", &ids(&["paid"]), DAY1 + 10))
            .unwrap();
        // declining is not built; the file is how a declined entry would look
        let mut text: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        text["gone"]["status"] = "declined".into();
        fs::write(&path, serde_json::to_vec(&text).unwrap()).unwrap();

        let q = Queue::open(&path).unwrap();
        let groups = report(&q).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].service, G_DID);
        assert_eq!(groups[0].owed_esp, 4 * ESP_PER_USD);
        assert_eq!(groups[0].entry_ids, ids(&["open"]));
        assert_eq!(
            render_report(&[]),
            "nothing is owed: no open redemption entries\n"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_entry_added_after_the_report_is_not_marked_paid() {
        let dir = scratch("late");
        let path = dir.join("queue.json");
        let mut q = Queue::open(&path).unwrap();
        q.add(Entry::open("e1", xyz(), 10 * ESP_PER_USD, "m", DAY1))
            .unwrap();
        q.add(Entry::open("e2", xyz(), 5 * ESP_PER_USD, "m", DAY1 + DAY))
            .unwrap();
        let reported = report(&q).unwrap()[0].entry_ids.clone();
        assert_eq!(reported, ids(&["e1", "e2"]));

        // a third redemption lands while the operator is paying
        q.add(Entry::open(
            "e3",
            xyz(),
            3 * ESP_PER_USD,
            "m",
            DAY1 + 2 * DAY,
        ))
        .unwrap();
        let paid = q
            .complete(&pay_args(xyz(), "wire-9", &reported, DAY1 + 3 * DAY))
            .unwrap();
        assert_eq!(paid.entries, 2);
        assert_eq!(paid.paid_esp, 15 * ESP_PER_USD);
        assert_eq!(paid.paid_usd, "15.000000000000");

        let q = Queue::open(&path).unwrap();
        assert_eq!(q.get("e1").unwrap().status, Status::Completed);
        assert_eq!(q.get("e1").unwrap().payment_ref.as_deref(), Some("wire-9"));
        assert_eq!(q.get("e2").unwrap().payment_ref.as_deref(), Some("wire-9"));
        assert_eq!(q.get("e3").unwrap().status, Status::Open);
        assert_eq!(q.get("e3").unwrap().payment_ref, None);
        // the next report owes only the late one
        let next = report(&q).unwrap();
        assert_eq!(next[0].entry_ids, ids(&["e3"]));
        assert_eq!(next[0].owed_esp, 3 * ESP_PER_USD);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn different_payout_memos_are_all_shown_and_flagged_and_not_paid_together() {
        let dir = scratch("memo");
        let mut q = Queue::open(&dir.join("queue.json")).unwrap();
        q.add(Entry::open(
            "e1",
            xyz(),
            10 * ESP_PER_USD,
            "btc:bc1qold",
            DAY1,
        ))
        .unwrap();
        q.add(Entry::open(
            "e2",
            xyz(),
            5 * ESP_PER_USD,
            "btc:bc1qnew",
            DAY1 + DAY,
        ))
        .unwrap();
        q.add(Entry::open(
            "e3",
            xyz(),
            ESP_PER_USD,
            "btc:bc1qnew",
            DAY1 + DAY,
        ))
        .unwrap();

        let groups = report(&q).unwrap();
        let g = &groups[0];
        assert!(g.memo_mismatch);
        assert_eq!(g.owed_esp, 16 * ESP_PER_USD);
        assert_eq!(g.memos.len(), 2);
        let new = g.memos.iter().find(|m| m.memo == "btc:bc1qnew").unwrap();
        assert_eq!(new.entry_ids, ids(&["e2", "e3"]));
        assert_eq!(new.owed_esp, 6 * ESP_PER_USD);
        let text = render_report(&groups);
        assert!(text.contains("MEMO MISMATCH: 2 different payout memos"));
        assert!(text.contains("btc:bc1qold") && text.contains("btc:bc1qnew"));

        // paying both in one go is refused unless the operator allows it
        let all = ids(&["e1", "e2", "e3"]);
        let err = q
            .complete(&pay_args(xyz(), "wire-1", &all, DAY1))
            .unwrap_err();
        assert!(
            matches!(err, QueueError::MixedMemos(ref m) if m.len() == 2),
            "{err}"
        );
        assert!(q.entries().all(|e| e.status == Status::Open));
        // one destination at a time works
        q.complete(&pay_args(xyz(), "wire-2", &ids(&["e2", "e3"]), DAY1))
            .unwrap();
        assert_eq!(q.get("e1").unwrap().status, Status::Open);
        // and the operator can override when one payment really covers both
        q.add(Entry::open(
            "e4",
            xyz(),
            2 * ESP_PER_USD,
            "btc:bc1qthird",
            DAY1 + 2 * DAY,
        ))
        .unwrap();
        let rest = ids(&["e1", "e4"]);
        let mut mixed = pay_args(xyz(), "wire-3", &rest, DAY1);
        mixed.allow_mixed_memos = true;
        let paid = q.complete(&mixed).unwrap();
        assert_eq!(paid.paid_esp, 12 * ESP_PER_USD);
        assert!(q.entries().all(|e| e.status == Status::Completed));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_payout_leaves_every_entry_open() {
        let dir = scratch("fail");
        let path = dir.join("queue.json");
        let mut q = Queue::open(&path).unwrap();
        q.add(Entry::open("e1", xyz(), 10 * ESP_PER_USD, "m", DAY1))
            .unwrap();
        q.add(Entry::open("e2", xyz(), 5 * ESP_PER_USD, "m", DAY1))
            .unwrap();
        q.add(Entry::open("a1", abc(), 5 * ESP_PER_USD, "m", DAY1))
            .unwrap();
        q.complete(&pay_args(xyz(), "old", &ids(&["e2"]), DAY1))
            .unwrap();
        let before = fs::read_to_string(&path).unwrap();

        // every refusal changes nothing
        let refused: Vec<(&str, Vec<String>, ServiceDid)> = vec![
            ("r", ids(&[]), xyz()),
            ("", ids(&["e1"]), xyz()),
            ("r", ids(&["e1", "missing"]), xyz()),
            ("r", ids(&["e1", "e1"]), xyz()),
            ("r", ids(&["e1", "e2"]), xyz()),
            ("r", ids(&["e1", "a1"]), xyz()),
        ];
        for (payment_ref, entry_ids, service) in &refused {
            let err = q
                .complete(&pay_args(*service, payment_ref, entry_ids, DAY1))
                .unwrap_err();
            assert!(err.is_refusal(), "{err}");
            assert_eq!(q.get("e1").unwrap().status, Status::Open);
            assert_eq!(q.get("a1").unwrap().status, Status::Open);
            assert_eq!(fs::read_to_string(&path).unwrap(), before);
        }
        assert!(matches!(
            q.complete(&pay_args(xyz(), "r", &ids(&["missing"]), DAY1)),
            Err(QueueError::Unknown(_))
        ));
        assert!(matches!(
            q.complete(&pay_args(xyz(), "r", &ids(&["e2"]), DAY1)),
            Err(QueueError::NotOpen {
                status: Status::Completed,
                ..
            })
        ));
        assert!(matches!(
            q.complete(&pay_args(xyz(), "r", &ids(&["a1"]), DAY1)),
            Err(QueueError::WrongService(_))
        ));

        // a write that fails leaves them open, in memory too
        fs::remove_dir_all(&dir).unwrap();
        let err = q
            .complete(&pay_args(xyz(), "wire-5", &ids(&["e1"]), DAY1))
            .unwrap_err();
        assert!(
            matches!(err, QueueError::Io(_)) && !err.is_refusal(),
            "{err}"
        );
        assert_eq!(q.get("e1").unwrap().status, Status::Open);
        assert_eq!(q.get("e1").unwrap().payment_ref, None);
        assert_eq!(report(&q).unwrap()[0].entry_ids, ids(&["e1"]));
    }

    #[test]
    fn the_command_line_helpers_list_and_settle() {
        let dir = scratch("cli");
        let path = dir.join("queue.json");
        let mut q = Queue::open(&path).unwrap();
        q.add(Entry::open("e1", xyz(), 10 * ESP_PER_USD, "btc:x", DAY1))
            .unwrap();
        q.add(Entry::open(
            "e2",
            xyz(),
            5 * ESP_PER_USD,
            "btc:x",
            DAY1 + DAY,
        ))
        .unwrap();

        let text = run_payouts(&path, &[]).unwrap();
        assert!(text.contains(&format!("service {G_DID}")));
        assert!(text.contains("owed     15.000000000000 USD (15000000000000 ESP)"));
        let json: serde_json::Value =
            serde_json::from_str(&run_payouts(&path, &["--json".to_string()]).unwrap()).unwrap();
        assert_eq!(json[0]["owed_esp"], "15000000000000");
        assert_eq!(json[0]["entries"], 2);
        assert!(run_payouts(&path, &["--nope".to_string()]).is_err());

        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(run_pay(&path, &args(&[G_DID, "ref"]), DAY1).is_err());
        assert!(run_pay(&path, &args(&["zz", "ref", "e1"]), DAY1).is_err());
        // The 32-byte x-only form of wire version 2 is refused, with a message that says so.
        let old_form = &G_DID[2..];
        let refused = run_pay(&path, &args(&[old_form, "ref", "e1"]), DAY1).unwrap_err();
        assert!(refused.contains("x-only"), "{refused}");
        let done = run_pay(&path, &args(&[G_DID, "wire-1", "e1", "e2"]), DAY1).unwrap();
        assert!(done.contains("marked 2 entries completed"));
        assert!(done.contains("15.000000000000 USD") && done.contains("wire-1"));
        assert_eq!(
            run_payouts(&path, &[]).unwrap(),
            "nothing is owed: no open redemption entries\n"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
