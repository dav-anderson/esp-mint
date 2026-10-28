//! The ESP mint's key stream against an air_server started in this process: a
//! day of more services than a record may hold is split into buckets, and
//! services that come later are added as new parts, with every record under the
//! size the operator set. Port 5702 is needed, as for the other AIR tests.

mod common;

use std::path::PathBuf;

use esp_mint::keys::MasterSecret;
use esp_mint::stream::{Live, LiveGen, Published, Settings, Stream};
use esp_mint::terms::Terms;
use secp256k1::SecretKey;
use sp_wire::ServiceDid;
use sp_wire::air_request::addr;
use sp_wire::air_request::client::{self, block_on_new_runtime};
use sp_wire::air_request::stream::{Cell, DayCell, DayRecord, read_cell};
use sp_wire::seal::SecretKey as DidKey;

/// 1,800,000,000 s is day 20,833; with m = 365 the first day published is 21,198.
const T0: u64 = 1_800_000_000;
const DAY: u64 = 21_198;
/// 34 bytes of header and 200 services of 2,145 bytes: a record of at most 200.
const RECORD_MAX: usize = 34 + 200 * 2_145;
const GENERATION: [u8; 8] = [7; 8];

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("esp-mint-stream-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The service whose secret key is `n` (as a 32-byte big-endian number).
fn did_of(n: u64) -> ServiceDid {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    let key = SecretKey::from_slice(&bytes).unwrap();
    ServiceDid::from_slice(&key.public_key(secp256k1::SECP256K1).serialize()).unwrap()
}

fn live() -> Live {
    Live {
        current: LiveGen {
            epoch: 0,
            id: GENERATION,
            master: MasterSecret::from_bytes([0x42; 32]),
        },
        previous: None,
    }
}

fn settings() -> Settings {
    Settings {
        days_ahead: 1,
        record_max_bytes: RECORD_MAX,
        max_services: 1_000,
        maturity_days: 365,
    }
}

fn terms(from: u64, to: u64) -> Vec<Terms> {
    (from..=to)
        .map(|n| Terms {
            service: did_of(n),
            redeemable_after_day: DAY,
        })
        .collect()
}

struct Reader {
    server: sp_wire::air_request::client::ServerRef,
    mint: ServiceDid,
}

impl Reader {
    fn part(&self, bucket: u32, part: u32) -> Option<DayRecord> {
        let (server, mint) = (self.server.clone(), self.mint);
        let cell = Cell::Day(DayCell {
            generation: GENERATION,
            day: DAY,
            bucket,
            part,
        });
        block_on_new_runtime(move || async move {
            let client = client::connect(&server).await?;
            read_cell(&client, &mint, &cell, 10).await
        })
        .unwrap()
        .unwrap()
        .map(|bytes| {
            let record = DayRecord::decode(&bytes).unwrap();
            assert!(bytes.len() <= RECORD_MAX, "a part over the size setting");
            record
        })
    }

    /// The way a wallet finds a service: part 0 of bucket 0 says how many
    /// buckets the day has, then the parts of the service's bucket are read from
    /// 0 until one holds it. `None` when no part does.
    fn find(&self, service: &ServiceDid) -> Option<(u32, u32)> {
        let buckets = self.part(0, 0).expect("part 0 of bucket 0").buckets;
        let bucket = sp_wire::air_request::stream::bucket_of(service, buckets);
        let mut part = 0;
        while let Some(record) = self.part(bucket, part) {
            assert_eq!((record.bucket, record.part), (bucket, part));
            if record.services.iter().any(|s| s.service == *service) {
                return Some((bucket, part));
            }
            part += 1;
        }
        None
    }
}

/// Fails if a day of 300 services is not two buckets of 152 and 148 services,
/// each one record, or if the 150 services added afterwards are not new parts 1
/// of the same two buckets (77 and 73 services), or if any service is missing,
/// twice in its bucket, or in the other bucket, or if any record is over the size
/// setting, or if a mint that starts again writes anything. The literals are
/// worked out apart from the code: bucket of service n is the first 8 bytes of
/// sha256("sp-esp-bucket-v0" || the service's 33 bytes) as a number, mod 2, for
/// the service whose secret key is n.
#[test]
fn a_day_over_the_record_size_is_bucketed_and_services_added_later_are_new_parts() {
    let server = common::server();
    let dir = scratch("buckets");
    let key = DidKey::new();
    let mint = addr::key_to_did(&key.public_key());
    let reader = Reader {
        server: (*server).clone(),
        mint,
    };
    let stream = Stream::open(&dir, (*server).clone(), 10, &key).unwrap();

    stream.note(&live(), &terms(1, 300)).unwrap();
    // 152 services in bucket 0 and 148 in bucket 1: 34 + 152 x 2,145 = 326,074
    // and 34 + 148 x 2,145 = 317,494 bytes.
    assert_eq!(
        stream.publish(&settings(), &live(), T0).unwrap(),
        Published {
            control: 1,
            parts: 2,
            bytes: 643_568
        }
    );
    let (zero, one) = (reader.part(0, 0).unwrap(), reader.part(1, 0).unwrap());
    assert_eq!((zero.buckets, one.buckets), (2, 2));
    assert_eq!((zero.services.len(), one.services.len()), (152, 148));
    assert!(reader.part(0, 1).is_none() && reader.part(1, 1).is_none());
    assert!(reader.part(2, 0).is_none());
    for n in 1..=300 {
        assert_eq!(reader.find(&did_of(n)).map(|f| f.1), Some(0), "service {n}");
    }
    assert_eq!(reader.find(&did_of(301)), None);

    // 150 more services: 77 in bucket 0 and 73 in bucket 1, as parts 1. The
    // bucket count stays 2 and parts 0 are as they were.
    stream.note(&live(), &terms(301, 450)).unwrap();
    assert_eq!(
        stream.publish(&settings(), &live(), T0).unwrap(),
        Published {
            control: 0,
            parts: 2,
            bytes: 321_818
        }
    );
    assert_eq!(reader.part(0, 0).unwrap(), zero);
    assert_eq!(reader.part(1, 0).unwrap(), one);
    let (zero1, one1) = (reader.part(0, 1).unwrap(), reader.part(1, 1).unwrap());
    assert_eq!((zero1.buckets, one1.buckets), (2, 2));
    assert_eq!((zero1.services.len(), one1.services.len()), (77, 73));
    assert!(reader.part(0, 2).is_none() && reader.part(1, 2).is_none());
    let mut in_part_one = 0;
    for n in 1..=450 {
        let (bucket, part) = reader.find(&did_of(n)).expect("every service is found");
        assert_eq!(part, u32::from(n > 300), "service {n}");
        in_part_one += part;
        // exactly once in its bucket
        let seen: usize = (0..=part)
            .map(|p| {
                reader
                    .part(bucket, p)
                    .unwrap()
                    .services
                    .iter()
                    .filter(|s| s.service == did_of(n))
                    .count()
            })
            .sum();
        assert_eq!(seen, 1, "service {n}");
    }
    assert_eq!(in_part_one, 150);

    // A mint that starts again from its folder has nothing to write.
    drop(stream);
    let again = Stream::open(&dir, (*server).clone(), 10, &key).unwrap();
    assert_eq!(
        again.publish(&settings(), &live(), T0).unwrap(),
        Published::default()
    );
    assert_eq!(again.service_count(), 450);
    std::fs::remove_dir_all(&dir).unwrap();
}
